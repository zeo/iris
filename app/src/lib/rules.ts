import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { pathKey } from "./path";

export interface RuleScope {
  remote?: { addr: string; prefix: number };
  ports?: { start: number; end: number };
  protocol?: "tcp" | "udp";
}
export type FirewallMode = "ask" | "notify" | "lockdown";
export type RuleLifetime =
  | { kind: "permanent" }
  | { kind: "until_restart" }
  | { kind: "until"; at_ms: number };
export interface Rule {
  app: string;
  direction: "inbound" | "outbound";
  action: "allow" | "block";
  label: string | null;
  scope?: RuleScope;
  lifetime?: RuleLifetime;
  profile?: string;
}

/// what the rule editor sends besides app, direction, and action
export interface RuleOptions {
  remote?: string;
  ports?: string;
  protocol?: "tcp" | "udp";
  /// minutes until it lapses; 0 lasts until the engine restarts
  minutes?: number;
  profile?: string;
}
export interface StoredRule {
  id: number;
  rule: Rule;
  filter_ids: number[];
  enabled: boolean;
}

const [rules, setRules] = createSignal<StoredRule[]>([]);
export { rules };

/// a rule over all of an app's traffic in its direction, the kind the Protect
/// matrix shows as that direction's decision
export const coversWholeApp = (rule: Rule): boolean =>
  !rule.scope?.remote && !rule.scope?.ports && !rule.scope?.protocol;

export const isPermanent = (rule: Rule): boolean => (rule.lifetime?.kind ?? "permanent") === "permanent";

/// whether the engine enforces the rule while `active` is the profile in force
export const appliesIn = (rule: Rule, active: string | null): boolean => !rule.profile || rule.profile === active;

export function describeScope(rule: Rule): string {
  const { remote, ports, protocol } = rule.scope ?? {};
  const parts = [
    remote && (remote.prefix === (remote.addr.includes(":") ? 128 : 32) ? remote.addr : `${remote.addr}/${remote.prefix}`),
    ports && (ports.start === ports.end ? `port ${ports.start}` : `ports ${ports.start}-${ports.end}`),
    protocol?.toUpperCase(),
  ].filter(Boolean);
  if (rule.profile) parts.push(`${rule.profile} profile`);
  return parts.length ? parts.join(" · ") : "all traffic";
}

export function describeLifetime(rule: Rule, now = Date.now()): string {
  const lifetime = rule.lifetime ?? { kind: "permanent" };
  if (lifetime.kind === "permanent") return "permanent";
  if (lifetime.kind === "until_restart") return "until restart";
  const minutes = Math.max(0, Math.ceil((lifetime.at_ms - now) / 60_000));
  return minutes >= 120 ? `${Math.round(minutes / 60)} h left` : `${minutes} min left`;
}

export async function refreshRules(): Promise<void> {
  try {
    setRules(await invoke<StoredRule[]>("list_rules"));
  } catch {
    /* engine offline */
  }
}

/// is there an enabled block rule covering this app path?
export function isBlocked(path: string): boolean {
  const p = pathKey(path);
  return rules().some(
    (r) => r.enabled && r.rule.action === "block" && r.rule.app === p && coversWholeApp(r.rule),
  );
}

// rule mutations are privileged and only accepted over the admin endpoint
export async function addRule(
  path: string,
  direction: "inbound" | "outbound",
  action: "allow" | "block",
  options?: RuleOptions,
): Promise<void> {
  await invoke("rule_add", { path, direction, action, options });
  await refreshRules();
}

export async function blockApp(path: string): Promise<void> {
  await invoke("rule_add", { path, direction: "outbound", action: "block" });
  await refreshRules();
}

export async function unblockApp(path: string): Promise<void> {
  const p = pathKey(path);
  const hits = rules().filter((r) => r.rule.action === "block" && r.rule.app === p && coversWholeApp(r.rule));
  // one round trip per rule, but never leave a half-finished unblock behind:
  // a failure on the second rule (engine restart, declined prompt) must still
  // report, and the caller's catch shows it
  try {
    for (const r of hits) await invoke("rule_remove", { id: r.id });
  } finally {
  await refreshRules();
  }
}

export async function removeRule(id: number): Promise<void> {
  await invoke("rule_remove", { id });
  await refreshRules();
}

export async function setRuleEnabled(id: number, enabled: boolean): Promise<void> {
  await invoke("rule_set_enabled", { id, enabled });
  await refreshRules();
}
