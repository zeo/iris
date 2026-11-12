import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { fileName } from "./path";

export type AlertKind =
  | {
      kind: "new_app";
      app: string;
      remote: { addr: string; port: number; protocol: "tcp" | "udp" } | null;
      direction: "inbound" | "outbound" | null;
    }
  | { kind: "blocked"; app: string; remote: { addr: string; port: number } }
  | { kind: "plugin"; source: string; message: string }
  | {
      kind: "watch";
      reason: "binary_changed" | "traffic_spike" | "new_host" | "gateway_changed" | "quota" | "caps_paused";
      app: string | null;
      message: string;
    };

export interface Alert {
  id: number;
  at_ms: number;
  kind: AlertKind;
  acknowledged: boolean;
}

// repeated drops of one connection by an iris filter, folded into one row
export interface BlockedConnection {
  app: string;
  remote: { addr: string; port: number; protocol: "tcp" | "udp" };
  direction: "inbound" | "outbound";
  first_ms: number;
  last_ms: number;
  count: number;
}

// only the windows engine records what its filters drop
export const blockedLogSupported = navigator.userAgent.includes("Windows");

export function blockedSummary(row: BlockedConnection): string {
  const { addr, port } = row.remote;
  const host = addr.includes(":") ? `[${addr}]` : addr;
  const remote = port ? `${host}:${port}` : addr;
  const verb = row.direction === "inbound" ? "accepting" : "reaching";
  const times = row.count > 1 ? `, ${row.count} times` : "";
  return `was blocked from ${verb} ${remote}${times}.`;
}

export async function listBlocked(limit: number): Promise<BlockedConnection[]> {
  try {
    return await invoke<BlockedConnection[]>("list_blocked", { limit });
  } catch {
    return [];
  }
}

const [alerts, setAlerts] = createSignal<Alert[]>([]);
export { alerts };

export const unackedCount = () => alerts().filter((a) => !a.acknowledged).length;

export const needsDecision = (alert: Alert): boolean =>
  !alert.acknowledged &&
  alert.kind.kind === "new_app" &&
  alert.kind.remote !== null &&
  alert.kind.direction !== null;

// which alerts get a passing info card rather than the actionable prompt.
// the card itself is raised by the Rust host (notify.rs), which stays alive
// even when this webview is hidden, throttled, or suspended in the tray; this
// predicate is kept here as the single documented mirror of that logic.
export const needsNativeNotification = (alert: Alert): boolean => !needsDecision(alert);

export const decisionAlreadySettled = (reason: unknown): boolean =>
  String(reason).includes("connection decision is no longer pending");

export const visibleDecisionPrompts = (
  alerts: Alert[],
  dismissed: ReadonlySet<number>,
  limit = 3,
): Alert[] =>
  alerts
    .filter((alert) => needsDecision(alert) && !dismissed.has(alert.id))
    .slice(0, limit)
    .reverse();

// the one host a prompt answer may be limited to; an unspecified address
// names no host
export const promptHost = (alert: Alert): string | undefined => {
  const remote = alert.kind.kind === "new_app" ? alert.kind.remote : null;
  return remote && remote.addr !== "0.0.0.0" && remote.addr !== "::" ? remote.addr : undefined;
};

export { fileName };

let started = false;
export function initAlerts() {
  if (started) return;
  started = true;
  void refreshAlerts();
  listen<Alert>("engine-alert", (e) => {
    setAlerts((a) => [e.payload, ...a.filter((x) => x.id !== e.payload.id)].slice(0, 500));
  });
}

export async function refreshAlerts(): Promise<void> {
  try {
    setAlerts(await invoke<Alert[]>("list_alerts", { unackedOnly: false }));
  } catch {
    /* offline */
  }
}

export async function ackAlert(id: number): Promise<void> {
  try {
    await invoke("ack_alert", { id });
    setAlerts((a) => a.map((x) => (x.id === id ? { ...x, acknowledged: true } : x)));
  } catch {
    /* offline */
  }
}

export async function ackAll(): Promise<void> {
  const ids = alerts()
    .filter((x) => !x.acknowledged && !needsDecision(x))
    .map((x) => x.id);
  if (ids.length === 0) return;
  const acked = new Set<number>();
  await Promise.all(
    ids.map((id) =>
      invoke("ack_alert", { id })
        .then(() => void acked.add(id))
        .catch(() => {}),
    ),
  );
  setAlerts((current) => current.map((x) => (acked.has(x.id) ? { ...x, acknowledged: true } : x)));
}

export async function decideAlert(id: number, action: "allow" | "block"): Promise<void> {
  await invoke("decide_alert", { id, action });
  setAlerts((current) =>
    current.map((alert) => (alert.id === id ? { ...alert, acknowledged: true } : alert)),
  );
}
