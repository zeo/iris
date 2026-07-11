import { createSignal, For, onMount, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "../components/Icon";
import { engine } from "../lib/engine";
import { checkNow } from "../lib/updater";
import {
  rateUnits,
  setRateUnits,
  setShowNotifications,
  showNotifications,
  type RateUnits,
} from "../lib/settings";

const UNIT_OPTS: { id: RateUnits; label: string }[] = [
  { id: "bytes", label: "bytes/s" },
  { id: "bits", label: "bits/s" },
];

export function Settings() {
  const [atLogin, setAtLogin] = createSignal(false);
  const [busy, setBusy] = createSignal("");
  const [update, setUpdate] = createSignal("");
  const [svcMsg, setSvcMsg] = createSignal("");

  onMount(async () => {
    try {
      setAtLogin(await invoke<boolean>("get_launch_at_login"));
    } catch {
      /* non-windows or unreadable */
    }
  });

  const toggleLogin = async () => {
    const next = !atLogin();
    setAtLogin(next); // optimistic
    try {
      await invoke("set_launch_at_login", { enabled: next });
    } catch (e) {
      setAtLogin(!next); // revert on failure
      setSvcMsg(String(e));
    }
  };

  const runService = async (cmd: "install_service" | "uninstall_service", label: string) => {
    setBusy(label);
    setSvcMsg("");
    try {
      await invoke(cmd);
      setSvcMsg(cmd === "install_service" ? "Engine installed." : "Engine removed.");
    } catch (e) {
      setSvcMsg(String(e));
    }
    setBusy("");
  };

  const check = async () => {
    setUpdate("Checking…");
    setUpdate(await checkNow());
  };

  return (
    <section>
      <div class="head">
        <div class="titles">
          <h2>Settings</h2>
          <span class="sub">display, notifications, startup, and the engine</span>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">Display</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Throughput units</span>
            <span class="set-desc">How rates are shown across the app. Totals stay in bytes.</span>
          </div>
          <div class="seg" role="group" aria-label="throughput units">
            <For each={UNIT_OPTS}>
              {(o) => (
                <button classList={{ on: rateUnits() === o.id }} onClick={() => setRateUnits(o.id)}>
                  {o.label}
                </button>
              )}
            </For>
          </div>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">Notifications</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Desktop notifications</span>
            <span class="set-desc">Raise a tray notification for a new app or a blocked connection.</span>
          </div>
          <button
            class="rocker"
            role="switch"
            aria-checked={showNotifications()}
            onClick={() => setShowNotifications(!showNotifications())}
          >
            <span class="knob" />
          </button>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">Startup</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Launch at login</span>
            <span class="set-desc">Start Iris in the tray when you sign in to Windows.</span>
          </div>
          <button class="rocker" role="switch" aria-checked={atLogin()} onClick={toggleLogin}>
            <span class="knob" />
          </button>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">Engine</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Background service</span>
            <span class="set-desc">
              The privileged engine that monitors and enforces rules, even with this window closed.
            </span>
          </div>
          <div class="set-status">
            <span class="lamp" classList={{ live: engine.online(), off: !engine.online() }} />
            {engine.online() ? `online · v${engine.version() ?? "?"}` : "offline"}
          </div>
        </div>
        <div class="set-actions">
          <button class="btn" disabled={!!busy()} onClick={() => runService("install_service", "install")}>
            {busy() === "install" ? "Installing…" : "Install / repair"}
          </button>
          <button
            class="btn"
            data-variant="danger"
            disabled={!!busy()}
            onClick={() => runService("uninstall_service", "uninstall")}
          >
            {busy() === "uninstall" ? "Removing…" : "Uninstall"}
          </button>
          <Show when={svcMsg()}>
            <span class="set-msg">{svcMsg()}</span>
          </Show>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">About</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Iris</span>
            <span class="set-desc">
              Version {__APP_VERSION__}. Country data by DB-IP (CC-BY-4.0).
            </span>
          </div>
          <button class="btn" onClick={check}>
            <Icon name="download" /> Check for updates
          </button>
        </div>
        <Show when={update()}>
          <div class="set-actions">
            <span class="set-msg">{update()}</span>
          </div>
        </Show>
      </div>
    </section>
  );
}
