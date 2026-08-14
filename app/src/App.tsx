import { createEffect, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { Titlebar } from "./components/Titlebar";
import { Icon } from "./components/Icon";
import { createTheme } from "./lib/theme";
import { engine, initEngine, setTickCadence } from "./lib/engine";
import { initAlerts, refreshAlerts, unackedCount } from "./lib/alerts";
import { initQuota } from "./lib/quota";
import { autoUpdate } from "./lib/updater";
import { Protect } from "./tabs/Protect";
import { Activity } from "./tabs/Activity";
import { Graph } from "./tabs/Graph";
import { Usage } from "./tabs/Usage";
import { Alerts } from "./tabs/Alerts";
import { Plugins } from "./tabs/Plugins";
import { Settings } from "./tabs/Settings";
import { PanelView } from "./components/PanelView";
import { panelPlugins, refreshPlugins } from "./lib/plugins";
import { ResizeEdges } from "./components/ResizeEdges";

interface Tab {
  id: string;
  label: string;
  icon: string;
  view: () => JSX.Element;
}

const TABS: Tab[] = [
  { id: "protect", label: "Protect", icon: "shield", view: Protect },
  { id: "activity", label: "Activity", icon: "activity", view: Activity },
  { id: "graph", label: "Graph", icon: "graph", view: Graph },
  { id: "usage", label: "Usage", icon: "clock", view: Usage },
  { id: "alerts", label: "Alerts", icon: "bell", view: Alerts },
  { id: "plugins", label: "Plugins", icon: "plug", view: Plugins },
  { id: "settings", label: "Settings", icon: "settings", view: Settings },
];

const tabId = (id: string) => `tab-${encodeURIComponent(id)}`;
const panelId = (id: string) => `panel-${encodeURIComponent(id)}`;

export function App() {
  const theme = createTheme();
  const [tab, setTab] = createSignal("protect");

  // enabled plugins with a panel grant appear as their own tabs, between the
  // built-ins and Settings
  const allTabs = (): Tab[] => {
    const dynamic: Tab[] = panelPlugins().map((p) => ({
      id: `panel:${p.id}`,
      label: p.name,
      icon: "plug",
      view: () => <PanelView id={p.id} name={p.name} />,
    }));
    const base = TABS.slice(0, -1);
    return [...base, ...dynamic, TABS[TABS.length - 1]];
  };
  const current = () => allTabs().find((t) => t.id === tab()) ?? TABS[0];
  const moveTabFocus = (event: KeyboardEvent, id: string) => {
    const tabs = allTabs();
    const index = tabs.findIndex((t) => t.id === id);
    if (index < 0) return;

    let next = index;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else return;

    event.preventDefault();
    const nextTab = tabs[next];
    setTab(nextTab.id);
    document.getElementById(tabId(nextTab.id))?.focus();
  };

  createEffect(() => {
    const liveView = tab() === "activity" || tab() === "graph";
    const cadenceMs = liveView ? 1000 : 4000;
    setTickCadence(cadenceMs);
    void invoke("set_tick_details", { enabled: tab() === "activity", cadenceMs });
  });

  onMount(() => {
    initEngine();
    initAlerts();
    initQuota();
    autoUpdate();
  });

  // the tab list depends on the plugin catalog, so load it with the engine
  createEffect(() => {
    if (engine.online()) {
      refreshPlugins();
      void refreshAlerts();
    }
  });

  // offer to install the background service if the engine stays unreachable
  const [offerInstall, setOfferInstall] = createSignal(false);
  const [installing, setInstalling] = createSignal(false);
  const [installError, setInstallError] = createSignal<string>();
  createEffect(() => {
    const current = engine.online() && engine.version() === __APP_VERSION__;
    if (current) {
      setOfferInstall(false);
      return;
    }
    const delay = engine.online() ? 0 : 8000;
    const t = setTimeout(() => setOfferInstall(true), delay);
    onCleanup(() => clearTimeout(t));
  });
  const installService = async () => {
    setInstalling(true);
    setInstallError(undefined);
    try {
      await invoke("install_service");
      setOfferInstall(false);
    } catch (error) {
      setInstallError(String(error));
    }
    setInstalling(false);
  };

  return (
    <div class="app">
      <ResizeEdges />
      <Titlebar
        theme={theme.pref()}
        onCycleTheme={theme.cycle}
        down={engine.down()}
        up={engine.up()}
      />

      <nav class="bar tabs" role="tablist" aria-label="sections" aria-orientation="horizontal">
        <For each={allTabs()}>
          {(t) => (
            <button
              id={tabId(t.id)}
              class="tab"
              classList={{ on: tab() === t.id }}
              role="tab"
              aria-selected={tab() === t.id}
              aria-controls={panelId(t.id)}
              tabindex={tab() === t.id ? 0 : -1}
              onClick={() => setTab(t.id)}
              onKeyDown={(event) => moveTabFocus(event, t.id)}
            >
              <Icon name={t.icon} class="ti" />
              {t.label}
              <Show when={t.id === "alerts" && unackedCount() > 0}>
                <span class="badge">{unackedCount()}</span>
              </Show>
            </button>
          )}
        </For>
      </nav>

      <Show when={offerInstall()}>
        <div class="install-banner">
          <Icon name="shield" />
          <span>
            {installError() ??
              (engine.online()
                ? "The Iris engine needs to be updated to match this version of Iris."
                : "The Iris engine service isn't running. Install it to start monitoring in the background.")}
          </span>
          <span class="grow" />
          <button class="btn" onClick={installService} disabled={installing()}>
            {installing() ? "Installing…" : "Install service"}
          </button>
        </div>
      </Show>

      <main class="content">
        <Show when={current()} keyed>
          {(t) => (
            <div
              id={panelId(t.id)}
              class="view"
              role="tabpanel"
              aria-labelledby={tabId(t.id)}
              tabindex={0}
            >
              <t.view />
            </div>
          )}
        </Show>
      </main>

      <footer class="sb">
        <span class="cell">
          <span class="lamp" classList={{ live: engine.online(), off: !engine.online() }} />
          engine <b>{engine.online() ? "online" : "offline"}</b>
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
