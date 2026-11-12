import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { Icon } from "../components/Icon";
import { AppIcon } from "../components/AppIcon";
import { adapterLabel, engine, type AdapterKind } from "../lib/engine";
import { persisted } from "../lib/persist";
import { bytes } from "../lib/format";
import { fileName } from "../lib/path";
import { formatGb, quota } from "../lib/quota";
import { blockHosts, blocksHosts, refreshRules } from "../lib/rules";

// quote a CSV field when it holds a comma, quote, or newline
function csvCell(v: string | number): string {
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const SPANS = ["day", "week", "month"] as const;
type Span = (typeof SPANS)[number];

interface UsageBucket {
  app: string;
  bucket_start_ms: number;
  bytes: { sent: number; recv: number };
}
interface AppTotal {
  app: string;
  sent: number;
  recv: number;
}
interface HostUsage {
  app: string;
  host: string;
  bytes: { sent: number; recv: number };
}
interface AdapterUsageRow {
  kind: AdapterKind;
  bytes: { sent: number; recv: number };
}

// history names a host by the address itself when no lookup named it
const isAddress = (host: string) => host.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

function since(span: Span): number {
  const now = Date.now();
  if (span === "day") {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    return d.getTime();
  }
  return now - (span === "week" ? 7 : 30) * 86_400_000;
}

// historical data usage per app, backed by the SQLite rollup store.
export function Usage() {
  const [span, setSpan] = persisted<Span>("usage.span", "day");
  const [loadError, setLoadError] = createSignal(false);

  // key on the engine's online state too, so history loads once the service
  // connects even if this tab was opened during startup
  const [totals] = createResource(
    () => ({ span: span(), online: engine.online() }),
    async ({ span: s }): Promise<AppTotal[]> => {
    const from = since(s);
    const now = Date.now();
    let buckets: UsageBucket[] = [];
    try {
      buckets = await invoke<UsageBucket[]>("get_usage", {
        fromMs: from,
        toMs: now,
        granularity: "day",
      });
      setLoadError(false);
    } catch {
      setLoadError(true);
      return [];
    }
    const map = new Map<string, AppTotal>();
    for (const b of buckets) {
      const e = map.get(b.app) ?? { app: b.app, sent: 0, recv: 0 };
      e.sent += b.bytes.sent;
      e.recv += b.bytes.recv;
      map.set(b.app, e);
    }
    return [...map.values()].sort((a, b) => b.sent + b.recv - (a.sent + a.recv));
  });

  const [byAdapter] = createResource(
    () => ({ span: span(), online: engine.online() }),
    async ({ span: s }): Promise<AdapterUsageRow[]> => {
      try {
        return await invoke<AdapterUsageRow[]>("get_adapter_usage", {
          fromMs: since(s),
          toMs: Date.now(),
        });
      } catch {
        return [];
      }
    },
  );

  const [opened, setOpened] = createSignal<string>();
  const [hosts] = createResource(
    () => {
      const path = opened();
      return path ? { path, span: span(), online: engine.online() } : undefined;
    },
    async ({ path, span: s }): Promise<HostUsage[]> => {
      try {
        return await invoke<HostUsage[]>("get_host_usage", { path, fromMs: since(s), toMs: Date.now() });
      } catch {
        return [];
      }
    },
  );
  const HOSTS_SHOWN = 12;
  createEffect(() => {
    if (engine.online()) void refreshRules();
  });
  const [blockErr, setBlockErr] = createSignal("");

  const HostBlock = (props: { app: string; host: string }) => {
    // a name can only be blocked at the addresses this session saw it resolve to
    const [addresses] = createResource(
      () => engine.online() && props.host,
      async (host): Promise<string[]> =>
        isAddress(host) ? [host] : await invoke<string[]>("host_addresses", { host }).catch(() => []),
    );
    const [busy, setBusy] = createSignal(false);
    const known = () => addresses() ?? [];
    const block = async () => {
      setBusy(true);
      setBlockErr("");
      try {
        await blockHosts(props.app, known());
      } catch (error) {
        setBlockErr(`Could not block ${props.host}: ${String(error)}`);
      } finally {
        setBusy(false);
      }
    };
    return (
      <Show
        when={!blocksHosts(props.app, known())}
        fallback={<span class="usage-blocked" title="Unblock it from the Protect tab">blocked</span>}
      >
        <button
          class="block-btn"
          title={known().length ? "block" : "No address is known for this host yet"}
          aria-label={`Block ${props.host}`}
          aria-busy={busy()}
          disabled={busy() || !known().length}
          onClick={() => void block()}
        >
          <Icon name="block" size={13} />
        </button>
      </Show>
    );
  };
  const hostPeak = () => (hosts() ?? []).reduce((m, h) => Math.max(m, h.bytes.sent + h.bytes.recv), 1);

  const list = () => totals() ?? [];
  const adapterRows = () => (byAdapter() ?? []).filter((a) => a.bytes.sent + a.bytes.recv > 0);
  const totalDown = () => list().reduce((n, a) => n + a.recv, 0);
  const totalUp = () => list().reduce((n, a) => n + a.sent, 0);
  const peak = createMemo(() => list().reduce((m, a) => Math.max(m, a.sent + a.recv), 1));

  const [exportErr, setExportErr] = createSignal("");
  const exportCsv = async () => {
    setExportErr("");
    const header = ["app", "path", "sent_bytes", "recv_bytes", "total_bytes"];
    const lines = [header.join(",")];
    for (const a of list()) {
      lines.push(
        [fileName(a.app), a.app, a.sent, a.recv, a.sent + a.recv].map(csvCell).join(","),
      );
    }
    try {
      const path = await invoke<string>("save_download", {
        name: `iris-usage-${span()}.csv`,
        contents: lines.join("\n"),
      });
      await revealItemInDir(path);
    } catch (e) {
      setExportErr(String(e));
    }
  };

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Usage</h2>
          <span class="sub">history by app and period</span>
        </div>
        <div class="actions">
          <div class="seg" role="group" aria-label="period">
            <For each={SPANS}>
              {(s) => (
                <button
                  classList={{ on: span() === s }}
                  aria-pressed={span() === s}
                  onClick={() => setSpan(s)}
                >
                  {s}
                </button>
              )}
            </For>
          </div>
          <button class="btn" onClick={exportCsv} disabled={list().length === 0} title="Export this period to CSV in Downloads">
            <Icon name="download" /> Export
          </button>
        </div>
      </div>
      <Show when={exportErr()}>
        <div class="tool-err">{exportErr()}</div>
      </Show>
      <Show when={blockErr()}>
        <div class="tool-err" role="alert">{blockErr()}</div>
      </Show>

      <Show when={quota.plan()}>
        {(plan) => (
        <div class="quota" classList={{ warn: quota.fraction() >= 0.8, over: quota.fraction() >= 1 }}>
          <div class="quota-head">
            <span class="label">data plan this period</span>
            <span class="quota-nums">{formatGb(plan().used)} <span class="of">of</span> {formatGb(plan().limit.bytes)}</span>
          </div>
          <div class="meter quota-bar">
            <span style={{ width: `${quota.fraction() * 100}%` }} />
          </div>
          <div class="quota-foot">
            {Math.round(quota.fraction() * 100)}% used, {formatGb(quota.remaining())} left
          </div>
        </div>
        )}
      </Show>

      <div class="tiles">
        <div class="tile"><div class="k">downloaded</div><div class="v">{bytes(totalDown())}</div></div>
        <div class="tile"><div class="k">uploaded</div><div class="v">{bytes(totalUp())}</div></div>
        <div class="tile">
          <div class="k">top app</div>
          <div class="v" style={{ "font-size": "var(--fz-h)" }}>{list()[0] ? fileName(list()[0].app) : "–"}</div>
        </div>
      </div>

      <Show when={adapterRows().length > 0}>
        <div class="tiles">
          <For each={adapterRows()}>
            {(a) => (
              <div class="tile">
                <div class="k">{adapterLabel(a.kind)}</div>
                <div class="v">{bytes(a.bytes.sent + a.bytes.recv)}</div>
                <div class="sub">
                  <span class="dn">↓ {bytes(a.bytes.recv)}</span>
                  <span class="up">↑ {bytes(a.bytes.sent)}</span>
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>

      <Show
        when={list().length > 0}
        fallback={
          <div class="empty">
            <Icon name="clock" class="glyph" size={44} />
            <h3>{totals.loading ? "Loading history…" : loadError() ? "Couldn't load history" : "No history yet"}</h3>
            <p>
              {loadError() && !totals.loading
                ? "The engine couldn't return usage history. It may be offline, or the history store is unavailable."
                : `Iris keeps a rolling record of how much each app sends and receives. This ${span()}'s totals show up here once traffic is recorded.`}
            </p>
          </div>
        }
      >
        <div class="rows">
          <For each={list()}>
            {(a) => (
              <>
              <button
                class="row usage"
                aria-expanded={opened() === a.app}
                title="Show the hosts this app exchanged data with"
                onClick={() => setOpened((current) => (current === a.app ? undefined : a.app))}
              >
                <AppIcon path={a.app} />
                <div class="meta">
                  <span class="name">{fileName(a.app)}</span>
                  <div class="meter"><span style={{ width: `${((a.sent + a.recv) / peak()) * 100}%` }} /></div>
                </div>
                <span class="grow" />
                <span class="usage-nums">
                  <span class="dn">↓ {bytes(a.recv)}</span>
                  <span class="up">↑ {bytes(a.sent)}</span>
                </span>
              </button>
              <Show when={opened() === a.app}>
                <div class="usage-hosts">
                  <Show
                    when={(hosts() ?? []).length > 0}
                    fallback={<span class="usage-hosts-empty">{hosts.loading ? "loading hosts…" : "no per-host history for this period yet"}</span>}
                  >
                    <For each={(hosts() ?? []).slice(0, HOSTS_SHOWN)}>
                      {(h) => (
                        <div class="usage-host">
                          <span class="name" title={h.host}>{h.host}</span>
                          <div class="meter"><span style={{ width: `${((h.bytes.sent + h.bytes.recv) / hostPeak()) * 100}%` }} /></div>
                          <span class="usage-nums">
                            <span class="dn">↓ {bytes(h.bytes.recv)}</span>
                            <span class="up">↑ {bytes(h.bytes.sent)}</span>
                          </span>
                          <HostBlock app={a.app} host={h.host} />
                        </div>
                      )}
                    </For>
                    <Show when={(hosts() ?? []).length > HOSTS_SHOWN}>
                      <span class="usage-hosts-empty">and {(hosts() ?? []).length - HOSTS_SHOWN} more</span>
                    </Show>
                  </Show>
                </div>
              </Show>
              </>
            )}
          </For>
        </div>
      </Show>
    </section>
  );
}
