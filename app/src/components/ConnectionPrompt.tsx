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

const MAX_VISIBLE = 2;

function destination(remote: Extract<AlertKind, { kind: "new_app" }>["remote"]): string {
  return remote ? `${remote.addr}:${remote.port}` : "Network access";
}

export function ConnectionPrompt() {
  const [alerts, setAlerts] = createSignal<Alert[]>([]);
  const [dismissed, setDismissed] = createSignal<Set<number>>(new Set());
  const [busy, setBusy] = createSignal<Set<number>>(new Set());
  const [error, setError] = createSignal<{ id: number; message: string }>();
  const visible = () => visibleDecisionPrompts(alerts(), dismissed(), MAX_VISIBLE);
  // each stacked prompt decides independently, so track in-flight ids as a set
  // rather than a single value that would freeze the whole stack
  const isBusy = (id: number) => busy().has(id);

  const refresh = async () => {
    try {
      setAlerts(await invoke<Alert[]>("list_alerts", { unackedOnly: true }));
    } catch (reason) {
      setError({ id: 0, message: String(reason) });
    }
  };

  onMount(() => {
    // register cleanup synchronously: an onCleanup after an await runs outside
    // the owner scope and would silently fail to unregister these listeners
    let disposed = false;
    const unlisteners: Array<() => void> = [];
    const track = (pending: Promise<() => void>) => {
      void pending.then((unlisten) => (disposed ? unlisten() : unlisteners.push(unlisten)));
    };
    track(
      listen<Alert>("engine-alert", ({ payload }) => {
        if (needsDecision(payload)) {
          setAlerts((current) => [payload, ...current.filter((alert) => alert.id !== payload.id)]);
        }
      }),
    );
    track(listen("connection-prompts-refresh", refresh));
    // Escape defers the front card (same as its dismiss X); it never decides,
    // so a stray key can't allow or block a connection
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      const stack = visible();
      if (stack.length) dismiss(stack[stack.length - 1].id);
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => {
      disposed = true;
      for (const unlisten of unlisteners) unlisten();
      window.removeEventListener("keydown", onKey);
    });
    void refresh();
  });

  createEffect(() => {
    void invoke("resize_connection_prompts", { count: visible().length });
  });

  const dismiss = (id: number) => {
    setDismissed((current) => new Set(current).add(id));
  };

  const decide = async (alert: Alert, action: "allow" | "block") => {
    if (isBusy(alert.id)) return;
    setBusy((current) => new Set(current).add(alert.id));
    setError(undefined);
    try {
      await invoke("decide_alert", { id: alert.id, action });
      setAlerts((current) => current.filter((candidate) => candidate.id !== alert.id));
    } catch (reason) {
      setError({ id: alert.id, message: String(reason) });
    } finally {
      setBusy((current) => {
        const next = new Set(current);
        next.delete(alert.id);
        return next;
      });
    }
  };

  return (
    <main class="connection-prompt-stack">
      <Show when={error()?.id === 0}>
        <div class="prompt-error">{error()?.message}</div>
      </Show>
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
                <button class="prompt-btn block" disabled={isBusy(alert.id)} onClick={() => decide(alert, "block")}>Block</button>
                <button class="prompt-btn allow" disabled={isBusy(alert.id)} onClick={() => decide(alert, "allow")}>
                  {isBusy(alert.id) ? "Applying…" : "Allow"}
                </button>
              </footer>
            </section>
          );
        }}
      </For>
    </main>
  );
}
