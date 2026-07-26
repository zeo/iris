import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

interface Update {
  version: string;
}

// check the release feed once on launch; if a newer signed build is published,
// pull it down, install it, and restart into it. every failure mode here is
// expected during normal use (offline, no release yet, running from a dev
// build) so nothing is surfaced to the user
export async function autoUpdate(): Promise<void> {
  if (import.meta.env.DEV) return;
  try {
    const update = await invoke<Update | null>("check_installer_update");
    if (!update) return;
    await invoke("install_installer_update");
  } catch {
    /* no reachable feed or no newer build */
  }
}

// a manual check from Settings; returns a short status to show the user
export async function checkNow(): Promise<string> {
  try {
    const update = await invoke<Update | null>("check_installer_update");
    if (!update) return "You are on the latest version.";
    await invoke("install_installer_update");
    return "Installing update…";
  } catch {
    await openUrl("https://github.com/zeo/iris/releases/latest");
    return "Could not reach the update feed.";
  }
}
