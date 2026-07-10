import { afterEach, describe, expect, it, vi } from "vitest";
import { SmartAccountEventEmitter } from "./events";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SmartAccountEventEmitter", () => {
  it("delivers events to subscribers", () => {
    const emitter = new SmartAccountEventEmitter();
    const seen: string[] = [];
    emitter.on("walletConnected", ({ contractId }) => seen.push(contractId));

    emitter.emit("walletConnected", { contractId: "C1", credentialId: "cred" });

    expect(seen).toEqual(["C1"]);
  });

  it("isolates a throwing listener and still runs the others", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const emitter = new SmartAccountEventEmitter();
    const ran: string[] = [];
    emitter.on("walletDisconnected", () => {
      throw new Error("listener boom");
    });
    emitter.on("walletDisconnected", () => ran.push("second"));

    expect(() =>
      emitter.emit("walletDisconnected", { contractId: "C1" })
    ).not.toThrow();
    expect(ran).toEqual(["second"]);
  });

  it("routes listener errors to console.error by default", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const emitter = new SmartAccountEventEmitter();
    emitter.on("walletDisconnected", () => {
      throw new Error("listener boom");
    });

    emitter.emit("walletDisconnected", { contractId: "C1" });

    expect(consoleError).toHaveBeenCalledOnce();
    expect(consoleError.mock.calls[0][0]).toContain("walletDisconnected");
  });

  it("uses a custom error handler when provided", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const emitter = new SmartAccountEventEmitter();
    const handler = vi.fn();
    emitter.setErrorHandler(handler);
    emitter.on("walletDisconnected", () => {
      throw new Error("listener boom");
    });

    emitter.emit("walletDisconnected", { contractId: "C1" });

    expect(handler).toHaveBeenCalledOnce();
    expect(consoleError).not.toHaveBeenCalled();
  });

  it("silences listener errors when the handler is cleared", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const emitter = new SmartAccountEventEmitter();
    emitter.setErrorHandler(undefined);
    emitter.on("walletDisconnected", () => {
      throw new Error("listener boom");
    });

    expect(() =>
      emitter.emit("walletDisconnected", { contractId: "C1" })
    ).not.toThrow();
    expect(consoleError).not.toHaveBeenCalled();
  });
});
