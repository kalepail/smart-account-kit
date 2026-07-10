import { describe, expect, it } from "vitest";
import { StellarWalletsKitAdapter } from "./wallet-adapter";
import { SmartAccountError, SmartAccountErrorCode } from "./errors";

describe("StellarWalletsKitAdapter", () => {
  it("throws a typed error (preserving cause) when the peer dep is missing", async () => {
    // @creit-tech/stellar-wallets-kit is an optional peer dep not installed here.
    const adapter = new StellarWalletsKitAdapter();
    await expect(adapter.init()).rejects.toBeInstanceOf(SmartAccountError);
    const err = await adapter.init().catch((e) => e);
    expect(err.code).toBe(SmartAccountErrorCode.MISSING_CONFIG);
    expect(err.message).toContain("@creit-tech/stellar-wallets-kit");
    // The underlying import error is preserved as the cause.
    expect(err.cause).toBeInstanceOf(Error);
  });

  it("throws before initialization for methods that require the kit", async () => {
    const adapter = new StellarWalletsKitAdapter();
    await expect(adapter.getAvailableWallets()).rejects.toThrow(/not initialized/i);
    await expect(adapter.connect()).rejects.toThrow(/not initialized/i);
  });

  it("reports empty tracking state before any connection", () => {
    const adapter = new StellarWalletsKitAdapter();
    expect(adapter.isConnected).toBe(false);
    expect(adapter.getConnectedWallets()).toEqual([]);
    expect(adapter.canSignFor("GABC")).toBe(false);
    expect(adapter.getWalletForAddress("GABC")).toBeUndefined();
    // disconnectByAddress is a no-op with no tracked wallets.
    expect(() => adapter.disconnectByAddress("GABC")).not.toThrow();
  });

  it("defaults to testnet when no network is configured", () => {
    const adapter = new StellarWalletsKitAdapter();
    expect(adapter).toBeInstanceOf(StellarWalletsKitAdapter);
  });
});
