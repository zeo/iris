import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

interface Update {
  version: string;
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
