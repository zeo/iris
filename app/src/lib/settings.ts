import { persisted } from "./persist";

// user preferences that live only in the UI. anything the engine must enforce
// (retention, autostart) goes through a command instead.

export type RateUnits = "bytes" | "bits";

// throughput display: bytes/s (MiB/s) or bits/s (Mbit/s, the way link speeds are
// usually quoted). totals always stay in bytes.
const [rateUnits, setRateUnits] = persisted<RateUnits>("settings.rateUnits", "bytes");

// whether a first-seen / blocked alert also raises a desktop notification
const [showNotifications, setShowNotifications] = persisted<boolean>(
  "settings.notifications",
  true,
);

// optional monthly data plan: a cap in GB (0 = no plan) and the day of the month
// the billing period resets. drives the quota meter and quota notifications.
const [dataCapGb, setDataCapGb] = persisted<number>("settings.dataCapGb", 0);
const [billingResetDay, setBillingResetDay] = persisted<number>("settings.billingResetDay", 1);

export {
  rateUnits,
  setRateUnits,
  showNotifications,
  setShowNotifications,
  dataCapGb,
  setDataCapGb,
  billingResetDay,
  setBillingResetDay,
};
