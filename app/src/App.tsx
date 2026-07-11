import { createSignal, For, Show, type JSX } from "solid-js";
import { Titlebar } from "./components/Titlebar";
import { Icon } from "./components/Icon";
import { createTheme } from "./lib/theme";
import { Protect } from "./tabs/Protect";
import { Activity } from "./tabs/Activity";
import { Graph } from "./tabs/Graph";
import { Usage } from "./tabs/Usage";
import { Alerts } from "./tabs/Alerts";

type TabId = "protect" | "activity" | "graph" | "usage" | "alerts";

const TABS: { id: TabId; label: string; icon: string; view: () => JSX.Element }[] = [
  { id: "protect", label: "Protect", icon: "shield", view: Protect },
  { id: "activity", label: "Activity", icon: "activity", view: Activity },
  { id: "graph", label: "Graph", icon: "graph", view: Graph },
  { id: "usage", label: "Usage", icon: "clock", view: Usage },
  { id: "alerts", label: "Alerts", icon: "bell", view: Alerts },
];

export function App() {
  const theme = createTheme();
  const [tab, setTab] = createSignal<TabId>("activity");
  const current = () => TABS.find((t) => t.id === tab()) ?? TABS[1];

  // live readout — zero until the engine streams; kept here so every tab shares
  // one source of truth for the always-on monitor.
  const [down] = createSignal(0);
  const [up] = createSignal(0);
  const online = () => false;

  return (
    <div class="app">
      <Titlebar theme={theme.pref()} onCycleTheme={theme.cycle} down={down()} up={up()} />

      <nav class="bar tabs" role="tablist" aria-label="sections">
        <For each={TABS}>
          {(t) => (
            <button
              class="tab"
              classList={{ on: tab() === t.id }}
              role="tab"
              aria-selected={tab() === t.id}
              onClick={() => setTab(t.id)}
            >
              <Icon name={t.icon} class="ti" />
              {t.label}
            </button>
          )}
        </For>
      </nav>

      <main class="content" role="tabpanel">
        <Show when={current()} keyed>
          {(t) => (
            <div class="view">
              <t.view />
            </div>
          )}
        </Show>
      </main>

      <footer class="sb">
        <span class="cell">
          <span class="lamp" classList={{ live: online(), off: !online() }} />
          engine <b>{online() ? "online" : "offline"}</b>
        </span>
        <span class="cell">
          section <b>{current().label}</b>
        </span>
        <span class="sp" />
        <span class="cell">iris v{__APP_VERSION__}</span>
      </footer>
    </div>
  );
}
