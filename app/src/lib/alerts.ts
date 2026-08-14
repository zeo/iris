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
  | { kind: "plugin"; source: string; message: string };

export interface Alert {
  id: number;
  at_ms: number;
  kind: AlertKind;
  acknowledged: boolean;
}

const [alerts, setAlerts] = createSignal<Alert[]>([]);
export { alerts };

export const unackedCount = () => alerts().filter((a) => !a.acknowledged).length;

export const needsDecision = (alert: Alert): boolean =>
  !alert.acknowledged &&
  alert.kind.kind === "new_app" &&
  alert.kind.remote !== null &&
  alert.kind.direction !== null;

// which alerts get a generic desktop toast rather than the actionable prompt.
// the toast itself is raised by the Rust host (notify.rs), which stays alive
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
