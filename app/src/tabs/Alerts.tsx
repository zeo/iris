import { createMemo, For, onMount, Show } from "solid-js";
import { Icon } from "../components/Icon";
import { AppIcon } from "../components/AppIcon";
import { ackAlert, ackAll, alerts, fileName, initAlerts, refreshAlerts, type Alert } from "../lib/alerts";
import { persisted } from "../lib/persist";

const FILTERS = ["all", "new apps", "blocks"] as const;

function ago(atMs: number): string {
  const s = Math.max(0, Math.floor((Date.now() - atMs) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// first-seen "new app connected" events and block notices, mirrored to tray
// toasts. durable, so alerts raised while the window was closed appear on launch.
export function Alerts() {
  const [filter, setFilter] = persisted<(typeof FILTERS)[number]>("alerts.filter", "all");
  onMount(() => {
    initAlerts();
    refreshAlerts();
  });

  const list = createMemo(() => {
    const f = filter();
    let a = alerts();
    if (f === "new apps") a = a.filter((x) => x.kind.kind === "new_app");
    else if (f === "blocks") a = a.filter((x) => x.kind.kind === "blocked");
    return a;
  });

  const title = (a: Alert) =>
    a.kind.kind === "new_app"
      ? "initiated its first network connection."
      : "was blocked from connecting.";

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
                <button classList={{ on: filter() === f }} onClick={() => setFilter(f)}>{f}</button>
              )}
            </For>
          </div>
          <button class="btn" onClick={ackAll}>
            <Icon name="check" /> Mark all read
          </button>
        </div>
      </div>

      <Show
        when={list().length > 0}
        fallback={
          <div class="empty">
            <Icon name="bell" class="glyph" size={44} />
            <h3>Nothing to report</h3>
            <p>
              The first time a new program reaches the network, Iris flags it here and raises a tray
              notification, so nothing connects without you knowing.
            </p>
          </div>
        }
      >
        <div class="rows">
          <For each={list()}>
            {(a) => {
              const blocked = a.kind.kind === "blocked";
              return (
                <div class="row alert" classList={{ unread: !a.acknowledged }} onClick={() => ackAlert(a.id)}>
                  <span class="unread-dot" />
                  <span class="alert-badge" classList={{ block: blocked }}>
                    {blocked ? <Icon name="block" size={13} /> : "NEW"}
                  </span>
                  <AppIcon path={a.kind.app} />
                  <div class="alert-body">
                    <b>{fileName(a.kind.app)}</b> {title(a)}
                  </div>
                  <div class="alert-when">
                    <span class="alert-cat">{blocked ? "Blocked connection" : "First network activity"}</span>
                    <span class="alert-time">{ago(a.at_ms)}</span>
                  </div>
                </div>
              );
            }}
          </For>
        </div>
      </Show>
    </section>
  );
}
