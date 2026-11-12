import { invoke } from "@tauri-apps/api/core";
import { createSignal } from "solid-js";
import { persisted } from "./persist";

// user preferences that live only in the UI. anything the engine must enforce
// (retention, autostart) goes through a command instead.

export type RateUnits = "bytes" | "bits";

// throughput display: bytes/s (MiB/s) or bits/s (Mbit/s, the way link speeds are
// usually quoted). totals always stay in bytes.
const [rateUnits, setRateUnits] = persisted<RateUnits>("settings.rateUnits", "bytes");

// which kinds of passing card show; decision prompts always do
export type InfoKind = "new_app" | "watch" | "quota" | "caps" | "plugin";
type InfoCards = Record<InfoKind, boolean>;
const ALL_CARDS: InfoCards = { new_app: true, watch: true, quota: true, caps: true, plugin: true };

// the rust host acts on these and saves them so they hold from boot with this
// webview closed; it owns them, and this module shows and edits its copy
interface HostPrefs {
  notifications: boolean;
  tray_graph: boolean;
  info_cards: InfoCards;
}
const [showNotifications, setNotificationsSignal] = createSignal(true);
const [infoCards, setInfoCardsSignal] = createSignal<InfoCards>(ALL_CARDS);
const [trayGraph, setTrayGraphSignal] = createSignal(true);

const host = <T>(command: string, args?: Record<string, unknown>): Promise<T | undefined> => {
  try {
    return invoke<T>(command, args).catch(() => undefined);
  } catch {
    /* host command unavailable (tests, plain browser) */
    return Promise.resolve(undefined);
  }
};

const setShowNotifications = (enabled: boolean): boolean => {
  setNotificationsSignal(enabled);
  void host("set_notifications_enabled", { enabled });
  return enabled;
};
const setInfoCards = (cards: InfoCards) => {
  setInfoCardsSignal(cards);
  void host("set_info_cards", { cards });
};
const setInfoCard = (kind: InfoKind, enabled: boolean) => setInfoCards({ ...infoCards(), [kind]: enabled });
const setTrayGraph = (enabled: boolean): boolean => {
  setTrayGraphSignal(enabled);
  void host("set_tray_graph", { enabled });
  return enabled;
};

// before 0.2.0 these lived only in this webview's storage
const LEGACY_KEYS = ["settings.notifications", "settings.trayGraph", "settings.infoCards"];
const legacy = (key: string): unknown => {
  try {
    const raw = localStorage.getItem(key);
    return raw == null ? undefined : JSON.parse(raw);
  } catch {
    return undefined;
  }
};

void host<HostPrefs | null>("host_prefs").then((prefs) => {
  if (prefs === undefined) return;
  if (prefs) {
    setNotificationsSignal(prefs.notifications);
    setInfoCardsSignal({ ...ALL_CARDS, ...prefs.info_cards });
    setTrayGraphSignal(prefs.tray_graph);
  } else {
    // the host has saved nothing yet: carry over what an older version kept here
    const notifications = legacy("settings.notifications");
    if (typeof notifications === "boolean") setShowNotifications(notifications);
    const cards = legacy("settings.infoCards");
    if (cards && typeof cards === "object") setInfoCards({ ...ALL_CARDS, ...(cards as Partial<InfoCards>) });
    const graph = legacy("settings.trayGraph");
    if (typeof graph === "boolean") setTrayGraph(graph);
  }
  try {
    for (const key of LEGACY_KEYS) localStorage.removeItem(key);
  } catch {
    /* storage unavailable */
  }
});


export {
  rateUnits,
  setRateUnits,
  showNotifications,
  setShowNotifications,
  infoCards,
  setInfoCard,
  trayGraph,
  setTrayGraph,
};
