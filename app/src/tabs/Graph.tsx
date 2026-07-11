import { createSignal, For } from "solid-js";
import { BandwidthGraph } from "../components/BandwidthGraph";
import { engine } from "../lib/engine";
import { rate } from "../lib/format";

const RANGES = ["5m", "1h", "24h", "7d"] as const;

// the scope: a live, scrolling picture of bandwidth (GlassWire's signature).
// idles as a powered-on instrument until the engine feeds real samples.
export function Graph() {
  const [range, setRange] = createSignal<(typeof RANGES)[number]>("5m");
  const peak = () => engine.ring().reduce((m, s) => Math.max(m, s.sent, s.recv), 0);

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
                <button classList={{ on: range() === r }} onClick={() => setRange(r)}>
                  {r}
                </button>
              )}
            </For>
          </div>
        </div>
      </div>

      <BandwidthGraph height={340} data={engine.ring} />

      <div class="scope-foot">
        <span class="label">window</span>
        <b>{range()}</b>
        <span class="sp" />
        <span class="label">peak</span>
        <b>{peak() > 0 ? rate(peak()) : "—"}</b>
      </div>
    </section>
  );
}
