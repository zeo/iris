import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";

export type AlertKind =
  | { kind: "new_app"; app: string }
  | { kind: "blocked"; app: string; remote: { addr: string; port: number } };

export interface Alert {
  id: number;
  at_ms: number;
  kind: AlertKind;
  acknowledged: boolean;
}

const [alerts, setAlerts] = createSignal<Alert[]>([]);
export { alerts };

export const unackedCount = () => alerts().filter((a) => !a.acknowledged).length;

function appOf(a: Alert): string {
  return a.kind.app;
}
export function fileName(path: string): string {
  const seg = path.split(/[\\/]/).pop();
  return seg && seg.length ? seg : path;
}

let started = false;
export function initAlerts() {
  if (started) return;
  started = true;
  refreshAlerts();
  listen<Alert>("engine-alert", (e) => {
    setAlerts((a) => [e.payload, ...a.filter((x) => x.id !== e.payload.id)].slice(0, 500));
    void toast(e.payload);
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
  for (const a of alerts().filter((x) => !x.acknowledged)) await ackAlert(a.id);
}

async function toast(a: Alert): Promise<void> {
  const name = fileName(appOf(a));
  const isNew = a.kind.kind === "new_app";
  const title = isNew ? "New app on the network" : "Connection blocked";
  const body = isNew ? `${name} connected for the first time` : `Blocked ${name}`;
  try {
    let granted = await isPermissionGranted();
    if (!granted) granted = (await requestPermission()) === "granted";
    if (granted) sendNotification({ title, body });
  } catch {
    /* notifications unavailable */
  }
}
