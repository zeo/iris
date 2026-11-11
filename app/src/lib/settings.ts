import { invoke } from "@tauri-apps/api/core";
import { persisted } from "./persist";

// user preferences that live only in the UI. anything the engine must enforce
// (retention, autostart) goes through a command instead.

export type RateUnits = "bytes" | "bits";

// throughput display: bytes/s (MiB/s) or bits/s (Mbit/s, the way link speeds are
// usually quoted). totals always stay in bytes.
const [rateUnits, setRateUnits] = persisted<RateUnits>("settings.rateUnits", "bytes");

// whether an alert that needs no answer raises a passing card. the card is
// raised by the Rust host, which saves the preference so it holds from boot
// while this webview is closed; it is mirrored there on load and on change.
const [showNotifications, setShowNotificationsSignal] = persisted<boolean>(
  "settings.notifications",
  true,
);
const syncNotifications = (enabled: boolean) => {
  try {
    void invoke("set_notifications_enabled", { enabled }).catch(() => {});
  } catch {
    /* host command unavailable (tests, plain browser) */
  }
};
const setShowNotifications = (enabled: boolean): boolean => {
  setShowNotificationsSignal(enabled);
  syncNotifications(enabled);
  return enabled;
};
syncNotifications(showNotifications());

// the live throughput graph in the tray icon, drawn by the Rust host
const [trayGraph, setTrayGraphSignal] = persisted<boolean>("settings.trayGraph", true);
const syncTrayGraph = (enabled: boolean) => {
  try {
    void invoke("set_tray_graph", { enabled }).catch(() => {});
  } catch {
    /* host command unavailable (tests, plain browser) */
  }
};
const setTrayGraph = (enabled: boolean): boolean => {
  setTrayGraphSignal(enabled);
  syncTrayGraph(enabled);
  return enabled;
};
syncTrayGraph(trayGraph());


export {
  rateUnits,
  setRateUnits,
  showNotifications,
  setShowNotifications,
  trayGraph,
  setTrayGraph,
};
