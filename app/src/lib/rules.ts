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

// rule mutations are privileged: they install SYSTEM-enforced WFP filters, so
// each one launches the engine elevated (a UAC prompt) and the service only
// accepts the change over its admin-only pipe. these reject if the prompt is
// declined.
export async function addRule(
  path: string,
  direction: "inbound" | "outbound",
  action: "allow" | "block",
): Promise<void> {
  await invoke("rule_add", { path, direction, action });
  await refreshRules();
}

export async function blockApp(path: string): Promise<void> {
  await invoke("rule_add", { path, direction: "outbound", action: "block" });
  await refreshRules();
}

export async function unblockApp(path: string): Promise<void> {
  const p = path.toLowerCase();
  const hits = rules().filter((r) => r.rule.action === "block" && r.rule.app === p);
  for (const r of hits) await invoke("rule_remove", { id: r.id });
  await refreshRules();
}

export async function removeRule(id: number): Promise<void> {
  await invoke("rule_remove", { id });
  await refreshRules();
}

export async function setRuleEnabled(id: number, enabled: boolean): Promise<void> {
  await invoke("rule_set_enabled", { id, enabled });
  await refreshRules();
}
