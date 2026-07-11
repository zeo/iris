import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

export interface Rule {
  app: string;
  direction: "inbound" | "outbound";
  action: "allow" | "block";
  label: string | null;
}
export interface StoredRule {
  id: number;
  rule: Rule;
  filter_ids: number[];
  enabled: boolean;
}

const [rules, setRules] = createSignal<StoredRule[]>([]);
export { rules };

export async function refreshRules(): Promise<void> {
  try {
    setRules(await invoke<StoredRule[]>("list_rules"));
  } catch {
    /* engine offline */
  }
}

/// is there an enabled block rule covering this app path?
export function isBlocked(path: string): boolean {
  const p = path.toLowerCase();
  return rules().some((r) => r.enabled && r.rule.action === "block" && r.rule.app === p);
}

export async function blockApp(path: string): Promise<void> {
  await invoke("add_rule", { path, direction: "outbound", action: "block" });
  await refreshRules();
}

export async function unblockApp(path: string): Promise<void> {
  const p = path.toLowerCase();
  const hits = rules().filter((r) => r.rule.action === "block" && r.rule.app === p);
  for (const r of hits) await invoke("remove_rule", { id: r.id });
  await refreshRules();
}

export async function removeRule(id: number): Promise<void> {
  await invoke("remove_rule", { id });
  await refreshRules();
}

export async function setRuleEnabled(id: number, enabled: boolean): Promise<void> {
  await invoke("set_rule_enabled", { id, enabled });
  await refreshRules();
}
