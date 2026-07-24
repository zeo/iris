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
const [publishedPanels, setPublishedPanels] = createSignal<Set<string>>(new Set());
let refreshId = 0;
export { plugins };

export async function refreshPlugins(): Promise<void> {
  const currentRefresh = ++refreshId;
  try {
    const catalog = await invoke<PluginInfo[]>("list_plugins");
    if (currentRefresh !== refreshId) return;
    setPlugins(catalog);
    const panelIds = await Promise.all(
      catalog
        .filter((plugin) => plugin.enabled && plugin.capabilities.includes("ui:panel"))
        .map(async (plugin) => {
          try {
            await invoke<Panel>("get_plugin_panel", { id: plugin.id });
            return plugin.id;
          } catch {
            return null;
          }
        }),
    );
    if (currentRefresh !== refreshId) return;
    setPublishedPanels(new Set(panelIds.filter((id): id is string => id !== null)));
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
  "emit:rule-proposals": "suggest firewall rules for your review",
  "ui:panel": "show its own panel tab",
};
export function capLabel(cap: string): string {
  return CAP_LABELS[cap] ?? cap;
}

// the declarative panel a plugin returns for its tab (externally-tagged enums
// over the wire, mirroring iris-core's Panel/Widget)
export type Severity = "info" | "warn" | "danger";
export type Widget =
  | { Stat: { label: string; value: string } }
  | { Kv: [string, string][] }
  | { Table: { columns: string[]; rows: string[][] } }
  | { BadgeRow: [string, Severity][] }
  | { Sparkline: { label: string; points: number[] } }
  | { Note: string };
export interface Panel {
  title: string;
  widgets: Widget[];
}

// enabled plugins with a panel ready to render
export const panelPlugins = () =>
  plugins().filter((plugin) => publishedPanels().has(plugin.id));

export async function fetchPanel(id: string): Promise<Panel> {
  return invoke<Panel>("get_plugin_panel", { id });
}
