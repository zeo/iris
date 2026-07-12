import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

export interface PluginInfo {
  id: string;
  name: string;
  version: string;
  description: string;
  capabilities: string[];
  egress: string[];
  granted: boolean;
  enabled: boolean;
}

const [plugins, setPlugins] = createSignal<PluginInfo[]>([]);
export { plugins };

export async function refreshPlugins(): Promise<void> {
  try {
    setPlugins(await invoke<PluginInfo[]>("list_plugins"));
  } catch {
    /* engine offline */
  }
}

// grant consent to a plugin's full declared capabilities and egress, then
// enable it. the service clamps whatever we send to the manifest ceiling.
export async function grantAndEnable(p: PluginInfo): Promise<void> {
  await invoke("grant_plugin", { id: p.id, caps: p.capabilities, egress: p.egress });
  await refreshPlugins();
}

export async function setEnabled(id: string, enabled: boolean): Promise<void> {
  await invoke("set_plugin_enabled", { id, enabled });
  await refreshPlugins();
}

// human-readable descriptions for the consent sheet
const CAP_LABELS: Record<string, string> = {
  "observe:ticks": "watch live traffic",
  "observe:alerts": "see alerts as they happen",
  "enrich:endpoint": "annotate remote endpoints",
  "enrich:app": "annotate applications",
  "emit:alerts": "raise its own alerts",
};
export function capLabel(cap: string): string {
  return CAP_LABELS[cap] ?? cap;
}
