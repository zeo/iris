import { createSignal } from "solid-js";
import { Icon } from "../components/Icon";

// live per-app / per-connection table (NetLimiter "Activity"), monitor-only.
// the toolbar and columns are the real chrome; rows stream in over IPC once the
// ETW monitor is running.
export function Activity() {
  const [q, setQ] = createSignal("");

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Activity</h2>
          <span class="sub">live per-app traffic</span>
        </div>
        <div class="actions">
          <label class="field">
            <Icon name="search" />
            <input
              placeholder="filter apps…"
              value={q()}
              onInput={(e) => setQ(e.currentTarget.value)}
            />
          </label>
          <button class="btn icon" title="columns" aria-label="columns">
            <Icon name="filter" />
          </button>
        </div>
      </div>

      <div class="tiles">
        <div class="tile">
          <div class="k">active apps</div>
          <div class="v">0</div>
        </div>
        <div class="tile">
          <div class="k">connections</div>
          <div class="v">0</div>
        </div>
        <div class="tile">
          <div class="k">download</div>
          <div class="v">0<span class="unit">B/s</span></div>
        </div>
        <div class="tile">
          <div class="k">upload</div>
          <div class="v">0<span class="unit">B/s</span></div>
        </div>
      </div>

      <div class="empty">
        <Icon name="activity" class="glyph" size={44} />
        <h3>Waiting for the engine</h3>
        <p>
          Up and down rates, connection counts, and the remote endpoints each app is talking to will
          stream in here in real time.
        </p>
      </div>
    </section>
  );
}
