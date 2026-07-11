import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { engine } from "./engine";
import { billingResetDay, dataCapGb, showNotifications } from "./settings";

interface UsageBucket {
  app: string;
  bucket_start_ms: number;
  bytes: { sent: number; recv: number };
}

// data plans are quoted decimally, so the quota is entirely decimal GB and keeps
// its own formatting rather than the binary byte formatter used elsewhere
const GB = 1_000_000_000;
const POLL_MS = 5 * 60 * 1000;

const [periodBytes, setPeriodBytes] = createSignal(0);

/// ms timestamp of the most recent billing reset at or before `now`
export function periodStart(resetDay: number, now: number): number {
  const d = new Date(now);
  const day = Math.min(Math.max(Math.round(resetDay), 1), 28);
  let start = new Date(d.getFullYear(), d.getMonth(), day, 0, 0, 0, 0);
  if (start.getTime() > now) {
    start = new Date(d.getFullYear(), d.getMonth() - 1, day, 0, 0, 0, 0);
  }
  return start.getTime();
}

export function formatGb(bytesValue: number): string {
  return `${(bytesValue / GB).toFixed(1)} GB`;
}

export const quota = {
  used: periodBytes,
  capBytes: () => dataCapGb() * GB,
  fraction: () => {
    const cap = dataCapGb() * GB;
    return cap > 0 ? Math.min(periodBytes() / cap, 1) : 0;
  },
  remaining: () => Math.max(0, dataCapGb() * GB - periodBytes()),
};

let started = false;
export function initQuota() {
  if (started) return;
  started = true;
  void refresh();
  setInterval(() => void refresh(), POLL_MS);
}

async function refresh() {
  if (dataCapGb() <= 0 || !engine.online()) return;
  const now = Date.now();
  const from = periodStart(billingResetDay(), now);
  let buckets: UsageBucket[] = [];
  try {
    buckets = await invoke<UsageBucket[]>("get_usage", {
      fromMs: from,
      toMs: now,
      granularity: "day",
    });
  } catch {
    return;
  }
  const total = buckets.reduce((n, b) => n + b.bytes.sent + b.bytes.recv, 0);
  setPeriodBytes(total);
  maybeNotify(from, total);
}

// notify once per threshold per billing period, tracked in localStorage
function maybeNotify(periodFrom: number, total: number) {
  if (!showNotifications()) return;
  const cap = dataCapGb() * GB;
  if (cap <= 0) return;
  const fraction = total / cap;
  const key = `quota.notified.${periodFrom}`;
  let done: number[] = [];
  try {
    done = JSON.parse(localStorage.getItem(key) ?? "[]");
  } catch {
    done = [];
  }
  for (const threshold of [80, 100]) {
    if (fraction * 100 >= threshold && !done.includes(threshold)) {
      done.push(threshold);
      void notify(threshold, total, cap);
    }
  }
  try {
    localStorage.setItem(key, JSON.stringify(done));
  } catch {
    /* ignore */
  }
}

async function notify(pct: number, total: number, cap: number) {
  const title = pct >= 100 ? "Data plan used up" : `Data plan ${pct}% used`;
  const body = `${formatGb(total)} of ${formatGb(cap)} this period`;
  try {
    let granted = await isPermissionGranted();
    if (!granted) granted = (await requestPermission()) === "granted";
    if (granted) sendNotification({ title, body });
  } catch {
    /* notifications unavailable */
  }
}
