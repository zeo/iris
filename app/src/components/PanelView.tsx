import { createSignal, For, Match, onCleanup, onMount, Show, Switch } from "solid-js";
import { Icon } from "./Icon";
import { Sparkline } from "./Sparkline";
import { engine } from "../lib/engine";
import { fetchPanel, type Panel, type Widget } from "../lib/plugins";

// how often an open panel tab re-asks its plugin for fresh state
const PANEL_REFRESH_MS = 5_000;

// renders a plugin's declarative panel with the same primitives the built-in
// tabs use. the plugin only ever supplies data, never markup or script.
export function PanelView(props: { id: string; name: string }) {
  const [panel, setPanel] = createSignal<Panel | null>(null);
  const [err, setErr] = createSignal("");

  const load = async () => {
    if (!engine.online()) return;
    try {
      const fresh = await fetchPanel(props.id);
      // keep the same object when the poll returns identical data, so the
      // widget rows (and their canvases) are not torn down and rebuilt every 5s
      setPanel((prev) => (JSON.stringify(prev) === JSON.stringify(fresh) ? prev : fresh));
      setErr("");
    } catch (e) {
      setErr(String(e));
    }
  };

  onMount(() => {
    load();
    const timer = setInterval(load, PANEL_REFRESH_MS);
    onCleanup(() => clearInterval(timer));
  });

  // consecutive stats sit side by side as tiles, like the built-in summaries
  const grouped = () => {
    const widgets = panel()?.widgets ?? [];
    const out: (Widget | { Stats: { label: string; value: string }[] })[] = [];
    for (const w of widgets) {
      const last = out[out.length - 1];
      if ("Stat" in w) {
        if (last && "Stats" in last) last.Stats.push(w.Stat);
        else out.push({ Stats: [w.Stat] });
      } else {
        out.push(w);
      }
    }
    return out;
  };

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>{panel()?.title ?? props.name}</h2>
          <span class="sub">plugin panel</span>
        </div>
      </div>

      <Show when={err()}>
        <div class="tool-err">{err()}</div>
      </Show>

      <Show
        when={panel()}
        fallback={
          <Show when={!err()}>
            <div class="empty">
              <Icon name="plug" class="glyph" size={44} />
              <h3>Waiting for {props.name}</h3>
              <p>The plugin has not published a panel yet.</p>
            </div>
          </Show>
        }
      >
        <For each={grouped()}>
          {(w) => (
            <Switch>
              <Match when={"Stats" in w && w}>
                {(stats) => (
                  <div class="tiles">
                    <For each={stats().Stats}>
                      {(s) => (
                        <div class="tile">
                          <div class="k">{s.label}</div>
                          <div class="v">{s.value}</div>
                        </div>
                      )}
                    </For>
                  </div>
                )}
              </Match>
              <Match when={"Kv" in w && w}>
                {(kv) => (
                  <div class="panel props pw">
                    <For each={kv().Kv}>
                      {([k, v]) => (
                        <div class="prow">
                          <span class="pk">{k}</span>
                          <span class="pv">{v}</span>
                        </div>
                      )}
                    </For>
                  </div>
                )}
              </Match>
              <Match when={"Table" in w && w}>
                {(t) => (
                  <div class="panel pw scrollx">
                    <table class="tbl">
                      <thead>
                        <tr>
                          <For each={t().Table.columns}>{(c) => <th>{c}</th>}</For>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={t().Table.rows}>
                          {(row) => (
                            <tr>
                              <For each={row.slice(0, t().Table.columns.length)}>
                                {(cell) => <td>{cell}</td>}
                              </For>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </div>
                )}
              </Match>
              <Match when={"BadgeRow" in w && w}>
                {(b) => (
                  <div class="badge-row pw">
                    <For each={b().BadgeRow}>
                      {([label, severity]) => (
                        <span class="tag" classList={{ warn: severity === "warn", danger: severity === "danger" }}>
                          {label}
                        </span>
                      )}
                    </For>
                  </div>
                )}
              </Match>
              <Match when={"Sparkline" in w && w}>
                {(s) => (
                  <div class="panel pw spark-widget">
                    <div class="plabel">{s().Sparkline.label}</div>
                    <div class="spark-well">
                      <Sparkline data={() => s().Sparkline.points.map((p) => ({ sent: p, recv: 0 }))} />
                    </div>
                  </div>
                )}
              </Match>
              <Match when={"Note" in w && w}>
                {(n) => <p class="panel-note pw">{n().Note}</p>}
              </Match>
            </Switch>
          )}
        </For>
      </Show>
    </section>
  );
}
