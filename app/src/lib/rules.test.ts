import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { isBlocked, refreshRules } from "./rules";

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
