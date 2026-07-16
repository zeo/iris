import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { showNotifications } from "./settings";

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

export const needsNativeNotification = (alert: Alert): boolean => !needsDecision(alert);

export const visibleDecisionPrompts = (
  alerts: Alert[],
  dismissed: ReadonlySet<number>,
  limit = 3,
): Alert[] =>
  alerts
    .filter((alert) => needsDecision(alert) && !dismissed.has(alert.id))
    .slice(0, limit)
    .reverse();

export function fileName(path: string): string {
  const seg = path.split(/[\\/]/).pop();
  return seg && seg.length ? seg : path;
}

let started = false;
export function initAlerts() {
  if (started) return;
  started = true;
  void restoreDecisionPrompts();
  listen<Alert>("engine-alert", (e) => {
    setAlerts((a) => [e.payload, ...a.filter((x) => x.id !== e.payload.id)].slice(0, 500));
    void toast(e.payload);
  });
}

export async function restoreDecisionPrompts(): Promise<void> {
  await refreshAlerts();
  try {
    await invoke("restore_connection_prompts");
  } catch {
    /* offline */
  }
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

async function toast(a: Alert): Promise<void> {
  if (!showNotifications() || !needsNativeNotification(a)) return;
  let title: string;
  let body: string;
  if (a.kind.kind === "plugin") {
    title = a.kind.source;
    body = a.kind.message;
  } else {
    const name = fileName(a.kind.app);
    const isNew = a.kind.kind === "new_app";
    title = isNew ? "New app on the network" : "Connection blocked";
    body = isNew ? `${name} connected for the first time` : `Blocked ${name}`;
  }
  try {
    let granted = await isPermissionGranted();
    if (!granted) granted = (await requestPermission()) === "granted";
    if (granted) sendNotification({ title, body });
  } catch {
    /* notifications unavailable */
  }
}
