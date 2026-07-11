import { createSignal } from "solid-js";
import { Icon } from "../components/Icon";

// per-app allow/block rules (GlassWire "Protect"). the rule list, add-rule flow,
// and per-app toggles wire to the WFP rule manager over IPC.
export function Protect() {
  const [q, setQ] = createSignal("");

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Protect</h2>
          <span class="sub">per-app allow and block rules</span>
        </div>
        <div class="actions">
          <label class="field">
            <Icon name="search" />
            <input
              placeholder="find an app…"
              value={q()}
              onInput={(e) => setQ(e.currentTarget.value)}
            />
          </label>
          <button class="btn" title="add a rule">
            <Icon name="plus" />
            Add rule
          </button>
        </div>
      </div>

      <div class="tiles">
        <div class="tile">
          <div class="k">enforced rules</div>
          <div class="v">0</div>
        </div>
        <div class="tile">
          <div class="k">blocked apps</div>
          <div class="v">0</div>
        </div>
        <div class="tile">
          <div class="k">mode</div>
          <div class="v" style={{ "font-size": "var(--fz-h)" }}>Ask</div>
        </div>
      </div>

      <div class="empty">
        <Icon name="shield" class="glyph" size={44} />
        <h3>No rules yet</h3>
        <p>
          Every app that reaches the network shows up here. Block one and Iris stops it at the
          Windows filtering layer — the rule holds even while this window is closed.
        </p>
      </div>
    </section>
  );
}
