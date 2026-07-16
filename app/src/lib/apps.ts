import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

export interface KnownApp {
  app: string;
  name: string | null;
  last_seen: number;
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
