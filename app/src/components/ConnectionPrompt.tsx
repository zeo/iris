import { createEffect, createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  type Alert,
  type AlertKind,
  fileName,
  needsDecision,
  visibleDecisionPrompts,
} from "../lib/alerts";
import { AppIcon } from "./AppIcon";
import { Icon } from "./Icon";

const MAX_VISIBLE = 3;

function destination(remote: Extract<AlertKind, { kind: "new_app" }>["remote"]): string {
  return remote ? `${remote.addr}:${remote.port}` : "Network access";
}

export function ConnectionPrompt() {
  const [alerts, setAlerts] = createSignal<Alert[]>([]);
  const [dismissed, setDismissed] = createSignal<Set<number>>(new Set());
  const [busy, setBusy] = createSignal<number>();
  const [error, setError] = createSignal<{ id: number; message: string }>();
  const visible = () => visibleDecisionPrompts(alerts(), dismissed(), MAX_VISIBLE);

  const refresh = async () => {
    try {
      setAlerts(await invoke<Alert[]>("list_alerts", { unackedOnly: true }));
    } catch (reason) {
      setError({ id: 0, message: String(reason) });
    }
  };

  onMount(async () => {
    const unlistenAlert = await listen<Alert>("engine-alert", ({ payload }) => {
      if (needsDecision(payload)) {
        setAlerts((current) => [payload, ...current.filter((alert) => alert.id !== payload.id)]);
      }
    });
    const unlistenRefresh = await listen("connection-prompts-refresh", refresh);
    onCleanup(() => {
      unlistenAlert();
      unlistenRefresh();
    });
    await refresh();
  });

  createEffect(() => {
    void invoke("resize_connection_prompts", { count: visible().length });
  });

  const dismiss = (id: number) => {
    setDismissed((current) => new Set(current).add(id));
  };

  const decide = async (alert: Alert, action: "allow" | "block") => {
    if (busy() !== undefined) return;
    setBusy(alert.id);
    setError(undefined);
    try {
      await invoke("decide_alert", { id: alert.id, action });
      setAlerts((current) => current.filter((candidate) => candidate.id !== alert.id));
    } catch (reason) {
      setError({ id: alert.id, message: String(reason) });
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <main class="connection-prompt-stack">
      <For each={visible()}>
        {(alert) => {
          const application = alert.kind as Extract<AlertKind, { kind: "new_app" }>;
          return (
            <section class="connection-prompt">
              <header data-tauri-drag-region>
                <span class="prompt-mark"><Icon name="shield" /></span>
                <span><b>New network connection</b><small>Choose how Iris should handle this application</small></span>
                <button class="iconbtn" aria-label="dismiss" onClick={() => dismiss(alert.id)}>
                  <Icon name="x" />
                </button>
              </header>
              <div class="prompt-app">
                <AppIcon path={application.app} />
                <span><b>{fileName(application.app)}</b><small>{application.app}</small></span>
              </div>
              <div class="prompt-target">
                <span><small>Destination</small><b>{destination(application.remote)}</b></span>
                <span><small>Protocol</small><b>{application.remote?.protocol.toUpperCase() ?? "Unknown"}</b></span>
                <span><small>Direction</small><b>{application.direction ?? "outbound"}</b></span>
              </div>
              <Show when={error()?.id === alert.id}><div class="prompt-error">{error()?.message}</div></Show>
              <footer>
                <button class="prompt-btn block" disabled={busy() !== undefined} onClick={() => decide(alert, "block")}>Block</button>
                <button class="prompt-btn allow" disabled={busy() !== undefined} onClick={() => decide(alert, "allow")}>
                  {busy() === alert.id ? "Applying…" : "Allow"}
                </button>
              </footer>
            </section>
          );
        }}
      </For>
    </main>
  );
}
