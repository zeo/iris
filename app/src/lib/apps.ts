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
  setKnownApps(await invoke<KnownApp[]>("list_apps"));
}

export async function forgetKnownApp(path: string): Promise<void> {
  await invoke("forget_app", { path });
  setKnownApps((apps) => apps.filter((app) => app.app !== path));
}
