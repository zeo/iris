import { createSignal, For, onMount, Show } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "../components/Icon";
import { engine } from "../lib/engine";
import { checkNow } from "../lib/updater";
import { profileState, refreshProfiles, saveProfiles, withNetwork, type Profile } from "../lib/profiles";
import type { FirewallMode } from "../lib/rules";
import {
  billingResetDay,
  dataCapGb,
  rateUnits,
  setBillingResetDay,
  setDataCapGb,
  setRateUnits,
  setShowNotifications,
  showNotifications,
  setTrayGraph,
  trayGraph,
  type RateUnits,
} from "../lib/settings";

const MODE_OPTS: { id: FirewallMode; label: string }[] = [
  { id: "ask", label: "ask" },
  { id: "notify", label: "allow + notify" },
  { id: "lockdown", label: "lockdown" },
];

const MODE_DESC: Record<FirewallMode, string> = {
  ask: "A new app stays blocked until you allow it from its prompt.",
  notify: "A new app connects right away and its prompt arrives afterwards.",
  lockdown: "Every connection off this machine is blocked, whatever the rules say.",
};

const UNIT_OPTS: { id: RateUnits; label: string }[] = [
  { id: "bytes", label: "bytes/s" },
  { id: "bits", label: "bits/s" },
];

export function Settings() {
  const [atLogin, setAtLogin] = createSignal(false);
  const [busy, setBusy] = createSignal("");
  const [update, setUpdate] = createSignal("");
  const [svcMsg, setSvcMsg] = createSignal("");
  const [granted, setGranted] = createSignal(false);
  const [grantMsg, setGrantMsg] = createSignal("");
  const [mode, setMode] = createSignal<FirewallMode>();
  const [modeMsg, setModeMsg] = createSignal("");

  const readMode = async () => {
    try {
      setMode(await invoke<FirewallMode>("firewall_mode"));
    } catch {
      /* engine offline */
    }
  };

  const [profileName, setProfileName] = createSignal("");
  const [profileMsg, setProfileMsg] = createSignal("");
  const changeProfiles = async (profiles: Profile[], manual: string | null) => {
    if (busy()) return;
    setBusy("profiles");
    setProfileMsg("");
    try {
      await saveProfiles(profiles, manual);
    } catch (error) {
      setProfileMsg(String(error));
    }
    await readMode();
    setBusy("");
  };
  const profiles = () => profileState()?.profiles ?? [];
  const manual = () => profileState()?.manual ?? null;
  const addProfile = () => {
    const name = profileName().trim();
    const network = profileState()?.network;
    if (!name) return;
    if (profiles().some((profile) => profile.name === name)) {
      setProfileMsg(`There is already a profile named ${name}.`);
      return;
    }
    const added = [...profiles(), { name, networks: [] }];
    setProfileName("");
    void changeProfiles(network ? withNetwork(added, name, network) : added, manual());
  };
  const setProfileMode = (name: string, next: FirewallMode | undefined) =>
    changeProfiles(
      profiles().map((profile) => (profile.name === name ? { ...profile, mode: next } : profile)),
      manual(),
    );

  const chooseMode = async (next: FirewallMode) => {
    if (next === mode() || busy()) return;
    setBusy("mode");
    setModeMsg("");
    try {
      await invoke("set_firewall_mode", { mode: next });
    } catch (error) {
      setModeMsg(String(error));
    }
    await readMode();
    setBusy("");
  };

  const readGrant = async () => {
    try {
      setGranted(await invoke<boolean>("rule_grant"));
    } catch {
      /* engine offline */
    }
  };

  onMount(async () => {
    try {
      setAtLogin(await invoke<boolean>("get_launch_at_login"));
    } catch {
      /* non-windows or unreadable */
    }
    void readGrant();
    void readMode();
    void refreshProfiles();
  });

  const toggleGrant = async () => {
    const next = !granted();
    setBusy("grant");
    setGrantMsg("");
    try {
      await invoke("set_rule_grant", { granted: next });
      // trust the engine's answer over the optimistic one: the grant names a
      // specific account, and only the engine can say whether it matched
      await readGrant();
    } catch (error) {
      setGrantMsg(String(error));
    }
    setBusy("");
  };

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
                <button classList={{ on: rateUnits() === o.id }} aria-pressed={rateUnits() === o.id} onClick={() => setRateUnits(o.id)}>
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
            aria-label="Desktop notifications"
            onClick={() => setShowNotifications(!showNotifications())}
          >
            <span class="knob" />
          </button>
        </div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Live graph in the tray</span>
            <span class="set-desc">Draw download and upload into the tray icon; hover it for the current rates.</span>
          </div>
          <button
            class="rocker"
            role="switch"
            aria-checked={trayGraph()}
            aria-label="Live graph in the tray"
            onClick={() => setTrayGraph(!trayGraph())}
          >
            <span class="knob" />
          </button>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">Firewall</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">New applications</span>
            <span class="set-desc">
              {MODE_DESC[mode() ?? "ask"]} The tray menu switches this too.
              <Show when={profiles().find((profile) => profile.name === profileState()?.active)?.mode}>
                {" "}The {profileState()?.active} profile sets this mode while it is active; lockdown still overrides it.
              </Show>
            </span>
            <Show when={modeMsg()}><span class="set-desc">{modeMsg()}</span></Show>
          </div>
          <div class="seg" role="group" aria-label="Firewall mode">
            <For each={MODE_OPTS}>
              {(option) => (
                <button
                  classList={{ on: mode() === option.id }}
                  aria-pressed={mode() === option.id}
                  disabled={busy() === "mode" || mode() === undefined}
                  onClick={() => void chooseMode(option.id)}
                >
                  {option.label}
                </button>
              )}
            </For>
          </div>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">Network profiles</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">This network</span>
            <span class="set-desc">
              {profileState()?.network?.label ?? "No default route right now."}
              {profileState()?.active ? ` Profile in force: ${profileState()?.active}.` : " No profile matches it."}
            </span>
            <Show when={profileMsg()}><span class="set-desc">{profileMsg()}</span></Show>
          </div>
          <label class="field">
            <input
              aria-label="New profile name"
              placeholder="profile for this network"
              value={profileName()}
              onInput={(event) => setProfileName(event.currentTarget.value)}
              onKeyDown={(event) => event.key === "Enter" && addProfile()}
            />
          </label>
          <button class="btn" disabled={busy() === "profiles" || !profileName().trim()} onClick={addProfile}>Add</button>
        </div>
        <For each={profiles()}>
          {(profile) => (
            <div class="set-row">
              <div class="set-meta">
                <span class="set-name">
                  {profile.name}
                  <Show when={profileState()?.active === profile.name}> · active</Show>
                </span>
                <span class="set-desc">
                  {profile.networks.length ? profile.networks.map((network) => network.label).join(", ") : "no networks yet"}
                </span>
              </div>
              <div class="seg" role="group" aria-label={`${profile.name} mode`}>
                <For each={[undefined, ...MODE_OPTS.map((option) => option.id)]}>
                  {(option) => (
                    <button
                      classList={{ on: profile.mode === option }}
                      aria-pressed={profile.mode === option}
                      disabled={busy() === "profiles"}
                      onClick={() => void setProfileMode(profile.name, option)}
                    >
                      {option ? MODE_OPTS.find((choice) => choice.id === option)?.label : "global mode"}
                    </button>
                  )}
                </For>
              </div>
              <Show when={profileState()?.network && !profile.networks.some((network) => network.key === profileState()?.network?.key)}>
                <button
                  class="btn"
                  disabled={busy() === "profiles"}
                  onClick={() => void changeProfiles(withNetwork(profiles(), profile.name, profileState()!.network!), manual())}
                >
                  Use here
                </button>
              </Show>
              <button
                class="btn"
                classList={{ on: manual() === profile.name }}
                aria-pressed={manual() === profile.name}
                disabled={busy() === "profiles"}
                title="Keep this profile active on every network until unpinned"
                onClick={() => void changeProfiles(profiles(), manual() === profile.name ? null : profile.name)}
              >
                {manual() === profile.name ? "Unpin" : "Pin"}
              </button>
              <button
                class="iconbtn"
                aria-label={`Delete ${profile.name}`}
                disabled={busy() === "profiles"}
                onClick={() =>
                  void changeProfiles(
                    profiles().filter((other) => other.name !== profile.name),
                    manual() === profile.name ? null : manual(),
                  )
                }
              >
                <Icon name="x" />
              </button>
            </div>
          )}
        </For>
      </div>

      <div class="set-group">
        <div class="set-section">Rule changes</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Change rules without asking</span>
            <span class="set-desc">
              Authorize this account once so blocking or allowing an app stops prompting for
              elevation. Turning it back off asks once more, then restores the prompt every time.
            </span>
            <Show when={grantMsg()}><span class="set-desc">{grantMsg()}</span></Show>
          </div>
          <button
            class="rocker"
            role="switch"
            aria-checked={granted()}
            aria-label="Change rules without asking"
            disabled={busy() === "grant"}
            onClick={() => void toggleGrant()}
          >
            <span class="knob" />
          </button>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">Data plan</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Monthly cap</span>
            <span class="set-desc">Set a cap to track usage against and get warned near the limit. 0 turns it off.</span>
          </div>
          <label class="num-field">
            <input
              type="number"
              min="0"
              step="1"
              aria-label="Monthly data cap in gigabytes"
              value={dataCapGb()}
              onInput={(e) => setDataCapGb(Math.max(0, Number(e.currentTarget.value) || 0))}
            />
            <span class="unit">GB</span>
          </label>
        </div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Resets on day</span>
            <span class="set-desc">Day of the month the billing period restarts (1 to 28).</span>
          </div>
          <label class="num-field">
            <input
              type="number"
              min="1"
              max="28"
              step="1"
              aria-label="Billing reset day"
              value={billingResetDay()}
              onInput={(e) =>
                setBillingResetDay(Math.min(28, Math.max(1, Math.round(Number(e.currentTarget.value) || 1))))
              }
            />
          </label>
        </div>
      </div>

      <div class="set-group">
        <div class="set-section">Startup</div>
        <div class="set-row">
          <div class="set-meta">
            <span class="set-name">Launch at login</span>
            <span class="set-desc">Start Iris in the tray when you sign in.</span>
          </div>
          <button
            class="rocker"
            role="switch"
            aria-checked={atLogin()}
            aria-label="Launch at login"
            onClick={toggleLogin}
          >
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
