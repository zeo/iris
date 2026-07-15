import { describe, expect, it } from "vitest";
import {
  needsDecision,
  needsNativeNotification,
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

  it("keeps three prompts visible and pulls the queue down after dismissal", () => {
    const queued = [4, 3, 2, 1].map((id) => ({ ...pending, id }));
    expect(visibleDecisionPrompts(queued, new Set()).map((alert) => alert.id)).toEqual([4, 3, 2]);
    expect(visibleDecisionPrompts(queued, new Set([3])).map((alert) => alert.id)).toEqual([4, 2, 1]);
  });
});
