import { createMemo, createResource, createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { BandwidthGraph, type Sample } from "../components/BandwidthGraph";
import { AppIcon } from "../components/AppIcon";
import { adapterLabel, engine } from "../lib/engine";
import { rate } from "../lib/format";

const RANGES = ["5m", "1h", "24h", "7d"] as const;

interface UsageBucket {
  app: string;
  bucket_start_ms: number;
  bytes: { sent: number; recv: number };
}

// history windows past the live 5m ring come from the usage rollups: pick the
// bucket granularity, then turn each bucket's byte total back into an average
// rate (bytes/sec) so the same graph renders history and live data the same way
const HISTORY: Record<string, { granularity: string; ms: number; widthSec: number }> = {
  "1h": { granularity: "minute", ms: 3_600_000, widthSec: 60 },
  "24h": { granularity: "hour", ms: 86_400_000, widthSec: 3_600 },
  "7d": { granularity: "day", ms: 7 * 86_400_000, widthSec: 86_400 },
};

function fileName(path: string): string {
  const seg = path.split(/[\\/]/).pop();
  return seg && seg.length ? seg : path;
}

// the scope: a live, scrolling picture of bandwidth, with the apps driving it
// right now listed underneath.
export function Graph() {
  const [range, setRange] = createSignal<(typeof RANGES)[number]>("5m");

  const [history] = createResource(
    () => ({ range: range(), online: engine.online() }),
    async ({ range: r }): Promise<Sample[]> => {
      const cfg = HISTORY[r];
      if (!cfg) return []; // 5m uses the live ring, not history
      const now = Date.now();
      let buckets: UsageBucket[] = [];
      try {
        buckets = await invoke<UsageBucket[]>("get_usage", {
          fromMs: now - cfg.ms,
          toMs: now,
          granularity: cfg.granularity,
        });
      } catch {
        return [];
      }
      const byBucket = new Map<number, { sent: number; recv: number }>();
      for (const b of buckets) {
        const e = byBucket.get(b.bucket_start_ms) ?? { sent: 0, recv: 0 };
        e.sent += b.bytes.sent;
        e.recv += b.bytes.recv;
        byBucket.set(b.bucket_start_ms, e);
      }
      return [...byBucket.entries()]
        .sort((a, b) => a[0] - b[0])
        .map(([, v]) => ({ sent: v.sent / cfg.widthSec, recv: v.recv / cfg.widthSec }));
    },
  );

  const series = (): Sample[] => (range() === "5m" ? engine.ring() : history() ?? []);
  const peak = () => series().reduce((m, s) => Math.max(m, s.sent, s.recv), 0);

  const top = createMemo(() =>
    engine
      .apps()
      .map((a) => ({
        app: a.app,
        name: a.name ?? fileName(a.app),
        dn: a.rate_recv,
        up: a.rate_sent,
        total: a.rate_recv + a.rate_sent,
      }))
      .filter((a) => a.total > 0)
      .sort((x, y) => y.total - x.total)
      .slice(0, 6),
  );
  const topPeak = () => Math.max(1, ...top().map((a) => a.total));

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Graph</h2>
          <span class="sub">bandwidth over time</span>
        </div>
        <div class="actions">
          <div class="legend">
            <span class="key recv" /> received
            <span class="key sent" /> sent
          </div>
          <div class="seg" role="group" aria-label="time range">
            <For each={RANGES}>
              {(r) => (
                <button classList={{ on: range() === r }} onClick={() => setRange(r)}>{r}</button>
              )}
            </For>
          </div>
        </div>
      </div>

      <BandwidthGraph height={300} data={series} />

      <div class="scope-foot">
        <span class="label">window</span>
        <b>{range()}</b>
        <span class="sp" />
        <span class="label">peak</span>
        <b>{peak() > 0 ? rate(peak()) : "–"}</b>
      </div>

      <Show when={engine.adapters().length > 0}>
        <div class="tiles adapters">
          <For each={engine.adapters()}>
            {(a) => (
              <div class="tile">
                <div class="k">{adapterLabel(a.kind)}</div>
                <div class="v">{rate(a.rate_recv + a.rate_sent)}</div>
                <div class="sub">
                  <span class="dn">↓ {rate(a.rate_recv)}</span>
                  <span class="up">↑ {rate(a.rate_sent)}</span>
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>

      <div class="top-apps">
        <div class="label">top consumers</div>
        <For each={top()} fallback={<div class="picker-empty">no traffic right now</div>}>
          {(a) => (
            <div class="top-row">
              <AppIcon path={a.app} />
              <span class="name">{a.name}</span>
              <div class="meter"><span style={{ width: `${(a.total / topPeak()) * 100}%` }} /></div>
              <span class="top-rate">
                <span class="dn">↓ {rate(a.dn)}</span>
                <Show when={a.up > 0}><span class="up">↑ {rate(a.up)}</span></Show>
              </span>
            </div>
          )}
        </For>
      </div>
    </section>
  );
}
