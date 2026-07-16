import { createMemo, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { Icon } from "../components/Icon";
import { AppIcon } from "../components/AppIcon";
import {
  ackAlert,
  ackAll,
  alerts,
  decideAlert,
  fileName,
  initAlerts,
  needsDecision,
  refreshAlerts,
  type Alert,
} from "../lib/alerts";
import { persisted } from "../lib/persist";

const FILTERS = ["all", "new apps", "blocks", "flags"] as const;

function ago(atMs: number, nowMs: number): string {
  const s = Math.max(0, Math.floor((nowMs - atMs) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// first-seen "new app connected" events and block notices, mirrored to tray
// toasts. durable, so alerts raised while the window was closed appear on launch.
export function Alerts() {
  const [filter, setFilter] = persisted<(typeof FILTERS)[number]>("alerts.filter", "all");
  // a coarse clock so relative timestamps re-derive instead of freezing at the
  // value they had when their row first rendered
  const [now, setNow] = createSignal(Date.now());
  const [deciding, setDeciding] = createSignal<number>();
  const [decisionError, setDecisionError] = createSignal("");
  onMount(() => {
    initAlerts();
    refreshAlerts();
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    onCleanup(() => clearInterval(timer));
  });

  // the store can hold hundreds of alerts; render a bounded window so we don't
  // mount that many rows (each with its own icon lookup) at once
  const RENDER_CAP = 200;
  const list = createMemo(() => {
    const f = filter();
    let a = alerts();
    if (f === "new apps") a = a.filter((x) => x.kind.kind === "new_app");
    else if (f === "blocks") a = a.filter((x) => x.kind.kind === "blocked");
    else if (f === "flags") a = a.filter((x) => x.kind.kind === "plugin");
    return a;
  });
  const shown = createMemo(() => list().slice(0, RENDER_CAP));

  const title = (a: Alert) =>
    a.kind.kind === "new_app"
      ? "initiated its first network connection."
      : "was blocked from connecting.";

  const decide = async (event: MouseEvent, alert: Alert, action: "allow" | "block") => {
    event.stopPropagation();
    if (deciding() !== undefined) return;
    setDeciding(alert.id);
    setDecisionError("");
    try {
      await decideAlert(alert.id, action);
    } catch (reason) {
      setDecisionError(String(reason));
    } finally {
      setDeciding(undefined);
    }
  };

  const flagRow = (a: Alert, k: Extract<Alert["kind"], { kind: "plugin" }>) => (
    <div class="row alert" classList={{ unread: !a.acknowledged }} onClick={() => ackAlert(a.id)}>
      <span class="unread-dot" />
      <span class="alert-badge block">
        <Icon name="eye" size={13} />
      </span>
      <div class="alert-body">{k.message}</div>
      <div class="alert-when">
        <span class="alert-cat">{k.source}</span>
        <span class="alert-time">{ago(a.at_ms, now())}</span>
      </div>
    </div>
  );

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Alerts</h2>
          <span class="sub">first-seen apps, blocks, and flags</span>
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
          <For each={shown()}>
            {(a) => {
              const k = a.kind;
              if (k.kind === "plugin") return flagRow(a, k);
              const blocked = k.kind === "blocked";
              return (
                <div
                  class="row alert"
                  classList={{ unread: !a.acknowledged, decision: needsDecision(a) }}
                  onClick={() => !needsDecision(a) && ackAlert(a.id)}
                >
                  <span class="unread-dot" />
                  <span class="alert-badge" classList={{ block: blocked }}>
                    {blocked ? <Icon name="block" size={13} /> : "NEW"}
                  </span>
                  <AppIcon path={k.app} />
                  <div class="alert-body">
                    <b>{fileName(k.app)}</b> {title(a)}
                  </div>
                  <Show when={needsDecision(a)}>
                    <div class="alert-decisions">
                      <button
                        class="alert-decision block"
                        disabled={deciding() !== undefined}
                        onClick={(event) => decide(event, a, "block")}
                      >
                        Block
                      </button>
                      <button
                        class="alert-decision allow"
                        disabled={deciding() !== undefined}
                        onClick={(event) => decide(event, a, "allow")}
                      >
                        {deciding() === a.id ? "Applying…" : "Allow"}
                      </button>
                    </div>
                  </Show>
                  <div class="alert-when">
                    <span class="alert-cat">{blocked ? "Blocked connection" : "First network activity"}</span>
                    <span class="alert-time">{ago(a.at_ms, now())}</span>
                  </div>
                </div>
              );
            }}
          </For>
        </div>
        <Show when={list().length > shown().length}>
          <div class="rows-more">showing {shown().length} of {list().length} · mark read to clear the rest</div>
        </Show>
        <Show when={decisionError()}>
          <div class="alert-decision-error">{decisionError()}</div>
        </Show>
      </Show>
    </section>
  );
}
