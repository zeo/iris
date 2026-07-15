import { describe, expect, it } from "vitest";
import { needsDecision, type Alert } from "./alerts";

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
});
