import { describe, expect, it } from "vitest";

import {
  isDormantRule,
  isInactive,
  PROTECT_OVERSCAN,
  PROTECT_ROW_HEIGHT,
  visibleRowWindow,
  type AppRow,
} from "./Protect";

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

describe("row windowing", () => {
  it("returns an empty window when there are no rows", () => {
    expect(visibleRowWindow(0, 0, 620, 200)).toEqual({
      start: 0,
      end: 0,
      topPx: 0,
      bottomPx: 0,
    });
  });

  it("renders all rows with zero spacers when the list fits within the viewport and overscan", () => {
    expect(visibleRowWindow(7, 0, 620, 200)).toEqual({
      start: 0,
      end: 7,
      topPx: 0,
      bottomPx: 0,
    });
  });

  it("clamps the initial scrollTop = 0 window and preserves total height", () => {
    const win = visibleRowWindow(200, 0, 620, 200);
    expect(win.start).toBe(0);
    expect(win.topPx).toBe(0);
    expect(win.end).toBe(Math.ceil((620 - 200) / PROTECT_ROW_HEIGHT) + PROTECT_OVERSCAN);
    expect(win.topPx + (win.end - win.start) * PROTECT_ROW_HEIGHT + win.bottomPx).toBe(
      200 * PROTECT_ROW_HEIGHT,
    );
  });

  it("tracks middle scroll offsets with overscan on both sides", () => {
    const win = visibleRowWindow(200, 2000, 620, 200);
    const expectedStart = Math.floor(1800 / PROTECT_ROW_HEIGHT) - PROTECT_OVERSCAN;
    const expectedEnd = Math.ceil(2420 / PROTECT_ROW_HEIGHT) + PROTECT_OVERSCAN;
    expect(win.start).toBe(expectedStart);
    expect(win.end).toBe(expectedEnd);
    expect(win.topPx).toBe(expectedStart * PROTECT_ROW_HEIGHT);
    expect(win.bottomPx).toBe((200 - expectedEnd) * PROTECT_ROW_HEIGHT);
  });

  it("mounts zero rows while keeping full spacer height when scrolled completely above or below a section", () => {
    const below = visibleRowWindow(50, 0, 620, 10_000);
    expect(below).toEqual({
      start: 0,
      end: 0,
      topPx: 0,
      bottomPx: 50 * PROTECT_ROW_HEIGHT,
    });

    const above = visibleRowWindow(200, 12_000, 620, 200);
    expect(above).toEqual({
      start: 200,
      end: 200,
      topPx: 200 * PROTECT_ROW_HEIGHT,
      bottomPx: 0,
    });
  });
});
