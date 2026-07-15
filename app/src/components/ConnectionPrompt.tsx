import { createSignal, onMount, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { type Alert, type AlertKind, fileName } from "../lib/alerts";
import { AppIcon } from "./AppIcon";
import { Icon } from "./Icon";

function destination(remote: Extract<AlertKind, { kind: "new_app" }>["remote"]): string {
  return remote ? `${remote.addr}:${remote.port}` : "Network access";
}

export function ConnectionPrompt(props: { alertId: number }) {
  const [alert, setAlert] = createSignal<Alert>();
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const newApp = (): Extract<AlertKind, { kind: "new_app" }> | undefined => {
    const kind = alert()?.kind;
    return kind?.kind === "new_app" ? kind : undefined;
  };

  onMount(async () => {
    try {
      const alerts = await invoke<Alert[]>("list_alerts", { unackedOnly: false });
      const match = alerts.find((candidate) => candidate.id === props.alertId);
      if (match?.kind.kind === "new_app" && !match.acknowledged) setAlert(match);
      else await getCurrentWindow().close();
    } catch (reason) {
      setError(String(reason));
    }
  });

  const decide = async (action: "allow" | "block") => {
    const current = alert();
    if (!current || current.kind.kind !== "new_app" || busy()) return;
    setBusy(true);
    setError("");
    try {
      await invoke("decide_alert", { id: current.id, action });
      await getCurrentWindow().close();
    } catch (reason) {
      setError(String(reason));
      setBusy(false);
    }
  };

  return (
    <main class="connection-prompt">
      <header data-tauri-drag-region>
        <span class="prompt-mark"><Icon name="shield" /></span>
        <span><b>New network connection</b><small>Choose how Iris should handle this application</small></span>
        <button class="iconbtn" aria-label="dismiss" onClick={() => getCurrentWindow().close()}>
          <Icon name="x" />
        </button>
      </header>
      <Show when={alert()} fallback={<div class="prompt-loading">Reading connection details…</div>}>
        <Show when={newApp()}>
          {(application) => (
            <>
              <div class="prompt-app">
                <AppIcon path={application().app} />
                <span><b>{fileName(application().app)}</b><small>{application().app}</small></span>
              </div>
              <div class="prompt-target">
                <span><small>Destination</small><b>{destination(application().remote)}</b></span>
                <span><small>Protocol</small><b>{application().remote?.protocol.toUpperCase() ?? "Unknown"}</b></span>
                <span><small>Direction</small><b>{application().direction ?? "outbound"}</b></span>
              </div>
            </>
          )}
        </Show>
      </Show>
      <Show when={error()}><div class="prompt-error">{error()}</div></Show>
      <footer>
        <button class="prompt-btn block" disabled={busy() || !alert()} onClick={() => decide("block")}>
          Block
        </button>
        <button class="prompt-btn allow" disabled={busy() || !alert()} onClick={() => decide("allow")}>
          {busy() ? "Applying…" : "Allow"}
        </button>
      </footer>
    </main>
  );
}
