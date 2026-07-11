import { createMemo, createResource, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "../components/Icon";
import { AppIcon } from "../components/AppIcon";
import { persisted } from "../lib/persist";
import { bytes } from "../lib/format";

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

function fileName(path: string): string {
  const seg = path.split(/[\\/]/).pop();
  return seg && seg.length ? seg : path;
}
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

  const [totals] = createResource(span, async (s): Promise<AppTotal[]> => {
    const from = since(s);
    const now = Date.now();
    let buckets: UsageBucket[] = [];
    try {
      buckets = await invoke<UsageBucket[]>("get_usage", {
        fromMs: from,
        toMs: now,
        granularity: "day",
      });
    } catch {
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

  const list = () => totals() ?? [];
  const totalDown = () => list().reduce((n, a) => n + a.recv, 0);
  const totalUp = () => list().reduce((n, a) => n + a.sent, 0);
  const peak = createMemo(() => list().reduce((m, a) => Math.max(m, a.sent + a.recv), 1));

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
                <button classList={{ on: span() === s }} onClick={() => setSpan(s)}>{s}</button>
              )}
            </For>
          </div>
        </div>
      </div>

      <div class="tiles">
        <div class="tile"><div class="k">downloaded</div><div class="v">{bytes(totalDown())}</div></div>
        <div class="tile"><div class="k">uploaded</div><div class="v">{bytes(totalUp())}</div></div>
        <div class="tile">
          <div class="k">top app</div>
          <div class="v" style={{ "font-size": "var(--fz-h)" }}>{list()[0] ? fileName(list()[0].app) : "–"}</div>
        </div>
      </div>

      <Show
        when={list().length > 0}
        fallback={
          <div class="empty">
            <Icon name="clock" class="glyph" size={44} />
            <h3>No history yet</h3>
            <p>
              Iris keeps a rolling record of how much each app sends and receives. This {span()}'s
              totals show up here once traffic is recorded.
            </p>
          </div>
        }
      >
        <div class="rows">
          <For each={list()}>
            {(a) => (
              <div class="row usage">
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
              </div>
            )}
          </For>
        </div>
      </Show>
    </section>
  );
}
