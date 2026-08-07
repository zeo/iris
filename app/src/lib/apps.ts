import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

export interface KnownApp {
  app: string;
  name: string | null;
  last_seen: number;
  /// whether the executable is still on disk; a rule cannot be enforced without it
  installed: boolean;
}

const [knownApps, setKnownApps] = createSignal<KnownApp[]>([]);
export { knownApps };

export async function refreshKnownApps(): Promise<void> {
  try {
    setKnownApps(await invoke<KnownApp[]>("list_apps"));
  } catch {
    /* engine offline */
  }
}

export async function forgetKnownApp(path: string): Promise<void> {
  try {
    await invoke("forget_app", { path });
    setKnownApps((apps) => apps.filter((app) => app.app !== path));
  } catch {
    /* engine offline */
  }
}

/// clear a whole group of apps in one engine round trip; returns how many went
export async function forgetKnownApps(paths: string[]): Promise<number> {
  if (paths.length === 0) return 0;
  const gone = new Set(paths);
  const removed = await invoke<number>("forget_apps", { paths });
  setKnownApps((apps) => apps.filter((app) => !gone.has(app.app)));
  return removed;
}
