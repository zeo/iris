import { createSignal, For } from "solid-js";
import { Icon } from "../components/Icon";

const SPANS = ["day", "week", "month"] as const;

// historical data usage per app / host / day, backed by the SQLite rollup store.
export function Usage() {
  const [span, setSpan] = createSignal<(typeof SPANS)[number]>("day");

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
                <button classList={{ on: span() === s }} onClick={() => setSpan(s)}>
                  {s}
                </button>
              )}
            </For>
          </div>
        </div>
      </div>

      <div class="tiles">
        <div class="tile">
          <div class="k">downloaded</div>
          <div class="v">0<span class="unit">B</span></div>
        </div>
        <div class="tile">
          <div class="k">uploaded</div>
          <div class="v">0<span class="unit">B</span></div>
        </div>
        <div class="tile">
          <div class="k">top app</div>
          <div class="v" style={{ "font-size": "var(--fz-h)" }}>—</div>
        </div>
      </div>

      <div class="empty">
        <Icon name="clock" class="glyph" size={44} />
        <h3>No history yet</h3>
        <p>
          Iris keeps a rolling record of how much each app sends and receives, collapsed down over
          time so it stays light. This {span()}'s totals will appear here.
        </p>
      </div>
    </section>
  );
}
