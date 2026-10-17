import { describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

import { withNetwork } from "./profiles";
import { appliesIn } from "./rules";

const home = { key: "mac:aa", label: "Ethernet via 192.168.1.1" };

describe("network profiles", () => {
  it("moves a network to the chosen profile so it never matches two", () => {
    const profiles = [
      { name: "Home", networks: [] },
      { name: "Public", networks: [home] },
    ];
    const next = withNetwork(profiles, "Home", home);
    expect(next[0].networks).toEqual([home]);
    expect(next[1].networks).toEqual([]);
    expect(withNetwork(next, "Home", home)[0].networks).toHaveLength(1);
  });

  it("enforces a profile rule only while its profile is active", () => {
    const rule = { app: "/usr/bin/x", direction: "outbound" as const, action: "block" as const, label: null };
    expect(appliesIn(rule, null)).toBe(true);
    expect(appliesIn({ ...rule, profile: "Public" }, "Public")).toBe(true);
    expect(appliesIn({ ...rule, profile: "Public" }, "Home")).toBe(false);
    expect(appliesIn({ ...rule, profile: "Public" }, null)).toBe(false);
  });
});
