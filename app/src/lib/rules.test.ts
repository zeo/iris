import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { coversWholeApp, describeLifetime, describeScope, isBlocked, refreshRules } from "./rules";

const blockedRule = {
  id: 1,
  rule: {
    app: "/opt/Foo/app",
    direction: "outbound" as const,
    action: "block" as const,
    label: null,
  },
  filter_ids: [1],
  enabled: true,
};

describe("Linux rule identity", () => {
  beforeEach(async () => {
    vi.stubGlobal("navigator", { userAgent: "X11; Linux x86_64" });
    invoke.mockResolvedValue([blockedRule]);
    await refreshRules();
  });

  it("preserves case-sensitive executable paths", () => {
    expect(isBlocked("/opt/Foo/app")).toBe(true);
    expect(isBlocked("/opt/foo/app")).toBe(false);
  });
});

describe("scoped rules", () => {
  const scoped = {
    ...blockedRule.rule,
    scope: { remote: { addr: "203.0.113.0", prefix: 24 }, ports: { start: 443, end: 443 }, protocol: "tcp" as const },
  };

  it("keeps a narrowed block out of the whole-app decision", async () => {
    invoke.mockResolvedValueOnce([{ ...blockedRule, rule: scoped }]);
    await refreshRules();
    expect(coversWholeApp(scoped)).toBe(false);
    expect(isBlocked("/opt/Foo/app")).toBe(false);
  });

  it("describes scope and remaining lifetime", () => {
    expect(describeScope(scoped)).toBe("203.0.113.0/24 · port 443 · TCP");
    expect(describeScope({ ...scoped, scope: { remote: { addr: "1.2.3.4", prefix: 32 } } })).toBe("1.2.3.4");
    expect(describeScope(blockedRule.rule)).toBe("all traffic");
    expect(describeLifetime({ ...scoped, lifetime: { kind: "until", at_ms: 90 * 60_000 } }, 0)).toBe("90 min left");
    expect(describeLifetime({ ...scoped, lifetime: { kind: "until_restart" } })).toBe("until restart");
  });
});
