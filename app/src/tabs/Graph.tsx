import { createMemo, createSignal, For, Show } from "solid-js";
import { BandwidthGraph } from "../components/BandwidthGraph";
import { AppIcon } from "../components/AppIcon";
import { engine } from "../lib/engine";
import { rate } from "../lib/format";

const RANGES = ["5m", "1h", "24h", "7d"] as const;

function fileName(path: string): string {
  const seg = path.split(/[\\/]/).pop();
  return seg && seg.length ? seg : path;
}

// the scope: a live, scrolling picture of bandwidth, with the apps driving it
// right now listed underneath.
export function Graph() {
  const [range, setRange] = createSignal<(typeof RANGES)[number]>("5m");
  const peak = () => engine.ring().reduce((m, s) => Math.max(m, s.sent, s.recv), 0);

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

      <BandwidthGraph height={300} data={engine.ring} />

      <div class="scope-foot">
        <span class="label">window</span>
        <b>{range()}</b>
        <span class="sp" />
        <span class="label">peak</span>
        <b>{peak() > 0 ? rate(peak()) : "–"}</b>
      </div>

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
