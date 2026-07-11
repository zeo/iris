import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

// check the release feed once on launch; if a newer signed build is published,
// pull it down, install it, and restart into it. every failure mode here is
// expected during normal use (offline, no release yet, running from a dev
// build) so nothing is surfaced to the user
export async function autoUpdate(): Promise<void> {
  if (import.meta.env.DEV) return;
  try {
    const update = await check();
    if (!update) return;
    await update.downloadAndInstall();
    await relaunch();
  } catch {
    /* no reachable feed or no newer build */
  }
}

// a manual check from Settings; returns a short status to show the user
export async function checkNow(): Promise<string> {
  try {
    const update = await check();
    if (!update) return "You are on the latest version.";
    await update.downloadAndInstall();
    await relaunch();
    return "Installing update…";
  } catch {
    return "Could not reach the update feed.";
  }
}
