// byte + rate formatting shared across the activity table, graph, and statusbar.
// binary units (powers of 1024) shown with a trailing /s for rates.

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];

export function bytes(n: number): string {
  if (n < 1) return "0 B";
  const i = Math.min(UNITS.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const v = n / Math.pow(1024, i);
  const dp = v >= 100 || i === 0 ? 0 : 1;
  return `${v.toFixed(dp)} ${UNITS[i]}`;
}

export function rate(bytesPerSec: number): string {
  return `${bytes(bytesPerSec)}/s`;
}
