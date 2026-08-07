import { describe, expect, it } from "vitest";

import { isDormantRule, isInactive, type AppRow } from "./Protect";

const NOW = 1_800_000_000_000;
const DAY = 86_400_000;

const rule = (over: Partial<AppRow["rules"][number]> = {}) => ({
  id: 1,
  rule: {
    app: "c:\\program files\\hwinfo64\\hwinfo64.exe",
    direction: "outbound" as const,
    action: "block" as const,
    label: null,
  },
  filter_ids: [1],
  enabled: true,
  ...over,
});

const row = (over: Partial<AppRow> = {}): AppRow => ({
  app: "c:\\program files\\hwinfo64\\hwinfo64.exe",
  rules: [],
  ...over,
});

describe("a rule the engine could not install", () => {
  // the case that shipped as a silent lie: an enabled block rule whose
  // executable is gone has no WFP filter behind it and enforces nothing
  it("is dormant when it is enabled with no backing filter", () => {
    expect(isDormantRule(row({ rules: [rule({ filter_ids: [] })] }), "outbound")).toBe(true);
  });

  it("is not dormant once a filter backs it", () => {
    expect(isDormantRule(row({ rules: [rule()] }), "outbound")).toBe(false);
  });

  it("is not dormant when the rule is switched off, which is already visible", () => {
    expect(
      isDormantRule(row({ rules: [rule({ filter_ids: [], enabled: false })] }), "outbound"),
    ).toBe(false);
  });

  it("does not report a dormant rule against the other direction", () => {
    expect(isDormantRule(row({ rules: [rule({ filter_ids: [] })] }), "inbound")).toBe(false);
  });
});

describe("inactive apps", () => {
  it("counts an app with no traffic for over thirty days", () => {
    expect(isInactive(row({ lastSeen: NOW - 31 * DAY, installed: true }), NOW)).toBe(true);
    expect(isInactive(row({ lastSeen: NOW - 29 * DAY, installed: true }), NOW)).toBe(false);
  });

  it("counts an uninstalled program however recently it ran", () => {
    expect(isInactive(row({ lastSeen: NOW - 60_000, installed: false }), NOW)).toBe(true);
  });

  it("never sweeps an app that is on the network right now", () => {
    const live = row({
      lastSeen: NOW - 400 * DAY,
      installed: false,
      sample: { online: true } as AppRow["sample"],
    });
    expect(isInactive(live, NOW)).toBe(false);
  });

  it("keeps an app whose age is unknown rather than guessing it is stale", () => {
    expect(isInactive(row({ installed: true }), NOW)).toBe(false);
  });
});
