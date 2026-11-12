import { createEffect, createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { engine } from "./engine";
import { pathKey } from "./path";

// the engine counts quotas and raises their alerts, so they hold while this
// webview is closed; this module only mirrors them for the meter and editors

export type QuotaPeriod = "day" | "week" | "month";

/** what an app's quota does once spent; the engine reads a missing one as block */
export type QuotaAction = "block" | { throttle: { bytes_per_sec: number } };

export interface QuotaLimit {
  period: QuotaPeriod;
  bytes: number;
  reset_day: number;
  action?: QuotaAction;
}

/** the speed a throttle quota slows its app to, or null for one that blocks */
export const throttleRate = (limit: QuotaLimit): number | null =>
  typeof limit.action === "object" ? limit.action.throttle.bytes_per_sec : null;

export interface Quota {
  /** null for the machine-wide data plan */
  app: string | null;
  limit: QuotaLimit;
  used: number;
  period_start_ms: number;
  period_end_ms: number;
}

// data plans are quoted decimally, so quotas keep their own formatting rather
// than the binary byte formatter used elsewhere
export const GB = 1_000_000_000;
const POLL_MS = 60 * 1000;

const [quotas, setQuotas] = createSignal<Quota[]>([]);

export function formatGb(bytesValue: number): string {
  return `${(bytesValue / GB).toFixed(1)} GB`;
}

const plan = () => quotas().find((q) => q.app === null);

export const quota = {
  plan,
  forApp: (path: string) => quotas().find((q) => q.app !== null && pathKey(q.app) === pathKey(path)),
  fraction: () => {
    const p = plan();
    return p ? Math.min(p.used / p.limit.bytes, 1) : 0;
  },
  remaining: () => {
    const p = plan();
    return p ? Math.max(0, p.limit.bytes - p.used) : 0;
  },
};

/** whether the engine answered */
export async function refreshQuotas(): Promise<boolean> {
  if (!engine.online()) return false;
  try {
    setQuotas(await invoke<Quota[]>("list_quotas"));
    return true;
  } catch {
    return false;
  }
}

/** set or clear one quota; a null path is the machine-wide data plan */
export async function setQuota(path: string | null, limit: QuotaLimit | null) {
  await invoke("set_quota", { path, limit });
  await refreshQuotas();
}

// the data plan used to live in this webview's storage; hand it to the engine
// once, the first time the engine answers without one
const LEGACY_CAP = "settings.dataCapGb";
const LEGACY_DAY = "settings.billingResetDay";
async function migrateLegacyPlan() {
  const capGb = Number(localStorage.getItem(LEGACY_CAP) ?? 0);
  if (!(capGb > 0) || plan()) {
    localStorage.removeItem(LEGACY_CAP);
    localStorage.removeItem(LEGACY_DAY);
    return;
  }
  const day = Math.min(28, Math.max(1, Math.round(Number(localStorage.getItem(LEGACY_DAY) ?? 1) || 1)));
  await setQuota(null, { period: "month", bytes: Math.round(capGb * GB), reset_day: day });
  localStorage.removeItem(LEGACY_CAP);
  localStorage.removeItem(LEGACY_DAY);
}

let started = false;
export function initQuota() {
  if (started) return;
  started = true;
  createEffect(() => {
    if (!engine.online()) return;
    void refreshQuotas().then(async (answered) => {
      if (answered) await migrateLegacyPlan().catch(() => {});
    });
  });
  setInterval(() => void refreshQuotas(), POLL_MS);
}
