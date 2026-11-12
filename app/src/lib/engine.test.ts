import { describe, expect, it } from "vitest";
import { serviceOffer } from "./engine";

describe("serviceOffer", () => {
  it("offers nothing while the engine matches the app", () => {
    expect(serviceOffer(true, "0.2.2", false, "0.2.2")).toBeNull();
  });

  it("asks for an update at once when the engine runs another version", () => {
    expect(serviceOffer(true, "0.2.1", false, "0.2.2")?.delayMs).toBe(0);
  });

  it("asks for an update at once on a protocol mismatch, not after the offline wait", () => {
    const offer = serviceOffer(false, null, true, "0.2.2");
    expect(offer?.delayMs).toBe(0);
    expect(offer?.message).toContain("needs to be updated");
  });

  it("waits before calling an unreachable engine not running", () => {
    const offer = serviceOffer(false, null, false, "0.2.2");
    expect(offer?.delayMs).toBe(8000);
    expect(offer?.message).toContain("isn't running");
  });
});
