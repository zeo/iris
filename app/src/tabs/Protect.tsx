import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { Icon } from "../components/Icon";
import { AppIcon } from "../components/AppIcon";
import { engine } from "../lib/engine";
import { addRule, refreshRules, removeRule, rules, setRuleEnabled } from "../lib/rules";

function fileName(path: string): string {
  const seg = path.split(/[\\/]/).pop();
  return seg && seg.length ? seg : path;
}

// per-app allow/block rules enforced at the Windows Filtering Platform.
// blocking also works from the Activity tab.
export function Protect() {
  const [q, setQ] = createSignal("");
  const [adding, setAdding] = createSignal(false);
  const [action, setAction] = createSignal<"block" | "allow">("block");
  const [direction, setDirection] = createSignal<"outbound" | "inbound">("outbound");
  const add = (path: string) => addRule(path, direction(), action());
  const [exportErr, setExportErr] = createSignal("");
  const exportRules = async () => {
    setExportErr("");
    const data = rules().map((r) => ({
      app: r.rule.app,
      direction: r.rule.direction,
      action: r.rule.action,
      enabled: r.enabled,
    }));
    try {
      const path = await invoke<string>("save_download", {
        name: "iris-rules.json",
        contents: JSON.stringify(data, null, 2),
      });
      await revealItemInDir(path);
    } catch (e) {
      setExportErr(String(e));
    }
  };
  // (re)load rules whenever the engine is connected, so a view opened while the
  // service is still starting fills in once it comes online instead of staying
  // stuck on "No rules yet"
  createEffect(() => {
    if (engine.online()) refreshRules();
  });

  const list = createMemo(() => {
    const needle = q().trim().toLowerCase();
    const r = rules();
    return needle ? r.filter((x) => x.rule.app.includes(needle)) : r;
  });
  const blockedCount = () => rules().filter((r) => r.enabled && r.rule.action === "block").length;

  // apps without a rule for the currently-selected action+direction, offered in
  // the add picker (a covered app can still get a rule for the other direction)
  const candidates = createMemo(() => {
    const covered = new Set(
      rules()
        .filter((r) => r.rule.action === action() && r.rule.direction === direction())
        .map((r) => r.rule.app),
    );
    return engine.apps().filter((a) => !covered.has(a.app));
  });

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
            <input placeholder="find a rule…" value={q()} onInput={(e) => setQ(e.currentTarget.value)} />
          </label>
          <button class="btn" onClick={() => setAdding((v) => !v)}>
            <Icon name="plus" />
            Add rule
          </button>
          <button class="btn" onClick={exportRules} disabled={rules().length === 0} title="Back up rules to a JSON file in Downloads">
            <Icon name="download" /> Export
          </button>
        </div>
      </div>
      <Show when={exportErr()}>
        <div class="tool-err">{exportErr()}</div>
      </Show>

      <div class="tiles">
        <div class="tile"><div class="k">rules</div><div class="v">{rules().length}</div></div>
        <div class="tile"><div class="k">blocked apps</div><div class="v">{blockedCount()}</div></div>
        <div class="tile"><div class="k">enforcement</div><div class="v" style={{ "font-size": "var(--fz-h)" }}>WFP</div></div>
      </div>

      <Show when={adding()}>
        <div class="panel picker">
          <div class="picker-head">
            <span class="label">add a rule for an active app</span>
            <div class="picker-opts">
              <div class="seg" role="group" aria-label="action">
                <button classList={{ on: action() === "block" }} onClick={() => setAction("block")}>block</button>
                <button classList={{ on: action() === "allow" }} onClick={() => setAction("allow")}>allow</button>
              </div>
              <div class="seg" role="group" aria-label="direction">
                <button classList={{ on: direction() === "outbound" }} onClick={() => setDirection("outbound")}>out</button>
                <button classList={{ on: direction() === "inbound" }} onClick={() => setDirection("inbound")}>in</button>
              </div>
            </div>
            <button class="iconbtn" onClick={() => setAdding(false)} aria-label="close"><Icon name="x" /></button>
          </div>
          <div class="picker-list">
            <For each={candidates()} fallback={<div class="picker-empty">no other active apps</div>}>
              {(a) => (
                <button class="picker-row" onClick={() => add(a.app)}>
                  <AppIcon path={a.app} />
                  <span class="name">{a.name ?? fileName(a.app)}</span>
                  <span class="grow" />
                  <span class="block-tag" classList={{ allow: action() === "allow" }}>
                    <Icon name={action() === "allow" ? "shield" : "block"} size={13} /> {action()} {direction() === "outbound" ? "out" : "in"}
                  </span>
                </button>
              )}
            </For>
          </div>
        </div>
      </Show>

      <Show
        when={list().length > 0}
        fallback={
          <div class="empty">
            <Icon name="shield" class="glyph" size={44} />
            <h3>No rules yet</h3>
            <p>
              Block an app here or from Activity and Iris stops it at the Windows filtering layer.
              The rule holds even while this window is closed.
            </p>
          </div>
        }
      >
        <div class="rows">
          <For each={list()}>
            {(r) => (
              <div class="row" classList={{ dim: !r.enabled }}>
                <AppIcon path={r.rule.app} />
                <div class="meta">
                  <span class="name">{fileName(r.rule.app)}</span>
                  <span class="path">{r.rule.app}</span>
                </div>
                <span class="grow" />
                <span class="tag" classList={{ block: r.rule.action === "block", allow: r.rule.action === "allow" }}>
                  {r.rule.action} · {r.rule.direction === "outbound" ? "out" : "in"}
                </span>
                <button
                  class="rocker"
                  role="switch"
                  aria-checked={r.enabled}
                  onClick={() => setRuleEnabled(r.id, !r.enabled)}
                  title={r.enabled ? "enforcing" : "paused"}
                >
                  <span class="knob" />
                </button>
                <button class="iconbtn danger" onClick={() => removeRule(r.id)} aria-label="remove rule">
                  <Icon name="x" />
                </button>
              </div>
            )}
          </For>
        </div>
      </Show>
    </section>
  );
}
