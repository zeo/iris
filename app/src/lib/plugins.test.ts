import { beforeEach, expect, test, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { panelPlugins, refreshPlugins, type PluginInfo } from "./plugins";

const labPlugin: PluginInfo = {
  id: "dev.iris.lab",
  name: "Lab Test Plugin",
  version: "0.1.0",
  description: "test fixture",
  capabilities: ["ui:panel"],
  egress: [],
  granted: true,
  enabled: true,
};

beforeEach(() => {
  invoke.mockReset();
});

test("only publishes a plugin tab when its panel is available", async () => {
  invoke.mockResolvedValueOnce([labPlugin]).mockRejectedValueOnce(new Error("no panel"));
  await refreshPlugins();
  expect(panelPlugins()).toEqual([]);

  invoke.mockResolvedValueOnce([labPlugin]).mockResolvedValueOnce({
    title: "Lab",
    widgets: [],
  });
  await refreshPlugins();
  expect(panelPlugins()).toEqual([labPlugin]);
});
