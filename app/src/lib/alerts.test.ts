import { describe, expect, it } from "vitest";
import {
  blockedSummary,
  decisionAlreadySettled,
  needsDecision,
  needsNativeNotification,
  promptHost,
  visibleDecisionPrompts,
  type Alert,
} from "./alerts";

const pending = {
  id: 7,
  at_ms: 1,
  acknowledged: false,
  kind: {
    kind: "new_app",
    app: "/usr/bin/browser",
    remote: { addr: "203.0.113.7", port: 443, protocol: "tcp" },
    direction: "outbound",
  },
} satisfies Alert;

describe("needsDecision", () => {
  it("recognizes a decision settled by another prompt", () => {
    expect(decisionAlreadySettled("connection decision is no longer pending")).toBe(true);
    expect(decisionAlreadySettled("the engine is offline")).toBe(false);
  });

  it("keeps live connection requests actionable until they are decided", () => {
    expect(needsDecision(pending)).toBe(true);
    expect(needsDecision({ ...pending, acknowledged: true })).toBe(false);
    expect(
      needsDecision({
        ...pending,
        kind: { ...pending.kind, remote: null },
      }),
    ).toBe(false);
  });

  it("uses the actionable prompt without also raising a generic notification", () => {
    expect(needsNativeNotification(pending)).toBe(false);
    expect(needsNativeNotification({ ...pending, acknowledged: true })).toBe(true);
    expect(
      needsNativeNotification({
        ...pending,
        kind: {
          kind: "blocked",
          app: pending.kind.app,
          remote: { addr: "203.0.113.7", port: 443 },
        },
      }),
    ).toBe(true);
  });

  it("keeps two prompts visible and pulls the queue down after dismissal", () => {
    const queued = [4, 3, 2, 1].map((id) => ({ ...pending, id }));
    expect(visibleDecisionPrompts(queued, new Set(), 2).map((alert) => alert.id)).toEqual([3, 4]);
    expect(visibleDecisionPrompts(queued, new Set([4]), 2).map((alert) => alert.id)).toEqual([2, 3]);
  });

  it("summarizes a blocked row with its remote and how often it was tried", () => {
    const row = {
      app: "c:\apps\game.exe",
      remote: { addr: "203.0.113.7", port: 443, protocol: "tcp" as const },
      direction: "outbound" as const,
      first_ms: 1,
      last_ms: 2,
      count: 40,
    };
    expect(blockedSummary(row)).toBe("was blocked from reaching 203.0.113.7:443, 40 times.");
    expect(blockedSummary({ ...row, count: 1, direction: "inbound" })).toBe(
      "was blocked from accepting 203.0.113.7:443.",
    );
    expect(blockedSummary({ ...row, count: 1, remote: { ...row.remote, addr: "2001:db8::1" } })).toBe(
      "was blocked from reaching [2001:db8::1]:443.",
    );
  });
});

describe("promptHost", () => {
  it("offers the prompt's own address as the host to limit an answer to", () => {
    expect(promptHost(pending)).toBe("203.0.113.7");
  });

  it("offers no host when the prompt has no usable address", () => {
    expect(promptHost({ ...pending, kind: { ...pending.kind, remote: null } })).toBeUndefined();
    const anywhere = { ...pending.kind.remote, addr: "::" };
    expect(promptHost({ ...pending, kind: { ...pending.kind, remote: anywhere } })).toBeUndefined();
  });
});
