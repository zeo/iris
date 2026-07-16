import { createEffect, createSignal, For, Show } from "solid-js";
import { Icon } from "../components/Icon";
import { engine } from "../lib/engine";
import { capLabel, grantAndEnable, plugins, refreshPlugins, setEnabled, type PluginInfo } from "../lib/plugins";

// installed plugins: their declared powers, the consent they were granted, and
// an on/off switch. a plugin runs out of process under a restricted token, and
// only ever with the capabilities the user approves here.
export function Plugins() {
  const [consent, setConsent] = createSignal<PluginInfo | null>(null);
  const [err, setErr] = createSignal("");
  const [toggling, setToggling] = createSignal<Set<string>>(new Set());

  createEffect(() => {
    if (engine.online()) refreshPlugins();
  });

  const allow = async (p: PluginInfo) => {
    setErr("");
    try {
      await grantAndEnable(p);
      setConsent(null);
    } catch (e) {
      setErr(String(e));
    }
  };
  const toggle = async (p: PluginInfo, on: boolean) => {
    if (toggling().has(p.id)) return;
    setToggling((current) => new Set(current).add(p.id));
    setErr("");
    try {
      await setEnabled(p.id, on);
    } catch (e) {
      setErr(String(e));
    } finally {
      setToggling((current) => {
        const next = new Set(current);
        next.delete(p.id);
        return next;
      });
    }
  };

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Plugins</h2>
          <span class="sub">out-of-process enrichers, sandboxed and consented</span>
        </div>
      </div>

      <Show when={err()}>
        <div class="tool-err">{err()}</div>
      </Show>

      <Show
        when={plugins().length > 0}
        fallback={
          <div class="empty">
            <Icon name="plug" class="glyph" size={44} />
            <h3>No plugins installed</h3>
            <p>
              Plugins extend Iris with extra endpoint intelligence. Each runs in its own restricted
              process and only with the powers you approve. Installed plugins live under
              ProgramData\Iris\plugins and appear here to review and enable.
            </p>
          </div>
        }
      >
        <div class="rows">
          <For each={plugins()}>
            {(p) => (
              <div class="row plugin" classList={{ dim: p.granted && !p.enabled }}>
                <span class="plug-badge" classList={{ on: p.enabled }}>
                  <Icon name="plug" size={15} />
                </span>
                <div class="meta">
                  <span class="name">
                    {p.name} <span class="ver">{p.version}</span>
                  </span>
                  <span class="path">{p.description || p.id}</span>
                  <div class="caps">
                    <For each={p.capabilities}>{(c) => <span class="cap">{capLabel(c)}</span>}</For>
                    <Show when={p.egress.length > 0}>
                      <span class="cap net">reaches {p.egress.length} host{p.egress.length === 1 ? "" : "s"}</span>
                    </Show>
                  </div>
                </div>
                <span class="grow" />
                <Show
                  when={p.granted}
                  fallback={
                    <button class="btn" onClick={() => setConsent(p)}>
                      Review &amp; enable
                    </button>
                  }
                >
                  <button
                    class="rocker"
                    role="switch"
                    aria-checked={p.enabled}
                    disabled={toggling().has(p.id)}
                    onClick={() => toggle(p, !p.enabled)}
                    title={p.enabled ? "enabled" : "disabled"}
                  >
                    <span class="knob" />
                  </button>
                </Show>
              </div>
            )}
          </For>
        </div>
      </Show>

      <Show when={consent()} keyed>
        {(p) => (
          <div class="panel picker consent">
            <div class="picker-head">
              <span class="label">allow {p.name}?</span>
              <button class="iconbtn" onClick={() => setConsent(null)} aria-label="close"><Icon name="x" /></button>
            </div>
            <div class="consent-body">
              <p class="consent-lead">This plugin will be able to:</p>
              <ul class="consent-list">
                <For each={p.capabilities}>{(c) => <li><Icon name="check" size={13} /> {capLabel(c)}</li>}</For>
              </ul>
              <Show when={p.egress.length > 0}>
                <p class="consent-lead">And connect to:</p>
                <ul class="consent-list">
                  <For each={p.egress}>{(h) => <li><Icon name="globe" size={13} /> {h}</li>}</For>
                </ul>
              </Show>
              <p class="consent-note">
                It runs in a restricted process and cannot change firewall rules or reach anything
                else. You can turn it off at any time.
              </p>
            </div>
            <div class="consent-actions">
              <button class="btn ghost" onClick={() => setConsent(null)}>Cancel</button>
              <button class="btn" onClick={() => allow(p)}>Allow and enable</button>
            </div>
          </div>
        )}
      </Show>
    </section>
  );
}
