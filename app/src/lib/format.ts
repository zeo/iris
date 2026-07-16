// byte + rate formatting shared across the activity table, graph, and statusbar.
// totals use binary byte units (powers of 1024); throughput follows the user's
// units preference (bytes/s, or bits/s the way link speeds are usually quoted).

import { rateUnits } from "./settings";

const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];
const BIT_UNITS = ["bit", "Kbit", "Mbit", "Gbit", "Tbit"];

function scale(n: number, base: number, units: string[]): string {
  if (n < 1) return `0 ${units[0]}`;
  // nudge past float error at exact powers so 1024 reads "1.0 KiB", not "1024 B"
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(base) + 1e-9));
  const v = n / Math.pow(base, i);
  const dp = v >= 100 || i === 0 ? 0 : 1;
  return `${v.toFixed(dp)} ${units[i]}`;
}

export function bytes(n: number): string {
  return scale(n, 1024, BYTE_UNITS);
}

export function rate(bytesPerSec: number): string {
  if (rateUnits() === "bits") {
    // bits are quoted decimally (1 Mbit/s = 10^6 bit/s)
    return `${scale(bytesPerSec * 8, 1000, BIT_UNITS)}/s`;
  }
  return `${bytes(bytesPerSec)}/s`;
}
