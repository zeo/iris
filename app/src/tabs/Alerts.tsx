import { createSignal, For } from "solid-js";
import { Icon } from "../components/Icon";

const FILTERS = ["all", "new apps", "blocks"] as const;

// first-seen "new app connected" events and block notices, mirrored to tray
// toasts. durable, so alerts raised while the window was closed appear on launch.
export function Alerts() {
  const [filter, setFilter] = createSignal<(typeof FILTERS)[number]>("all");

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Alerts</h2>
          <span class="sub">first-seen apps and blocks</span>
        </div>
        <div class="actions">
          <div class="seg" role="group" aria-label="filter">
            <For each={FILTERS}>
              {(f) => (
                <button classList={{ on: filter() === f }} onClick={() => setFilter(f)}>
                  {f}
                </button>
              )}
            </For>
          </div>
        </div>
      </div>

      <div class="empty">
        <Icon name="bell" class="glyph" size={44} />
        <h3>Nothing to report</h3>
        <p>
          The first time a new program reaches the network, Iris flags it here and raises a tray
          notification, so nothing connects without you knowing.
        </p>
      </div>
    </section>
  );
}
