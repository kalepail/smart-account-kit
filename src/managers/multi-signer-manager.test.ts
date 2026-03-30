import { describe, expect, it, vi } from "vitest";
import { MultiSignerManager } from "./multi-signer-manager";
import {
  makeAccount,
  makeDelegatedSigner,
  makeExternalSigner,
} from "./test-utils";

function makeDeps() {
  const externalSigners = {
    canSignFor: vi.fn(),
    signAuthEntry: vi.fn(),
  };

  const deps = {
    getContractId: vi.fn().mockReturnValue("CCONTRACT"),
    isConnected: vi.fn().mockReturnValue(true),
    getRules: vi.fn(),
    requireWallet: vi.fn(() => ({ wallet: {} })),
    externalSigners,
    rpc: {
      getLatestLedger: vi.fn(),
      getAccount: vi.fn(),
      simulateTransaction: vi.fn(),
    } as any,
    networkPassphrase: "Test SDF Network ; September 2015",
    timeoutInSeconds: 30,
    deployerKeypair: { publicKey: () => "GAAAA" } as any,
    deployerPublicKey: "GAAAA",
    signAuthEntry: vi.fn(),
    sendAndPoll: vi.fn(),
    hasSourceAccountAuth: vi.fn().mockReturnValue(false),
    executeTransfer: vi.fn(),
    shouldUseFeeSponsoring: vi.fn().mockReturnValue(false),
  };

  return deps;
}

describe("MultiSignerManager", () => {
  it("returns no signers when disconnected and deduplicates connected signers", async () => {
    const deps = makeDeps();
    deps.isConnected.mockReturnValue(false);
    const manager = new MultiSignerManager(deps);

    await expect(manager.getAvailableSigners()).resolves.toEqual([]);
    expect(deps.getRules).not.toHaveBeenCalled();

    deps.isConnected.mockReturnValue(true);
    const signerA = makeDelegatedSigner(1);
    const signerB = makeExternalSigner(2, 3, 4);
    deps.getRules.mockResolvedValue([
      { signers: [signerA, signerB] },
      { signers: [signerA] },
    ]);

    await expect(manager.getAvailableSigners()).resolves.toEqual([signerA, signerB]);
    expect(deps.getRules).toHaveBeenCalledWith({
      tag: "Default",
      values: undefined,
    });
  });

  it("extracts credential ids and matches signers correctly", () => {
    const deps = makeDeps();
    const manager = new MultiSignerManager(deps);
    const delegated = makeDelegatedSigner(7);
    const external = makeExternalSigner(8, 9, 10);
    const credentialId = Buffer.alloc(20, 10).toString("base64url");
    const delegatedAddress = makeAccount(7);

    expect(manager.extractCredentialId(external)).toBe(credentialId);
    expect(manager.extractCredentialId(delegated)).toBeNull();
    expect(manager.signerMatchesCredential(external, credentialId)).toBe(true);
    expect(manager.signerMatchesCredential(external, "wrong")).toBe(false);
    expect(manager.signerMatchesAddress(delegated, delegatedAddress)).toBe(true);
    expect(manager.signerMatchesAddress(external, delegatedAddress)).toBe(false);
  });

  it("detects when multi-signer flows are needed", () => {
    const deps = makeDeps();
    const manager = new MultiSignerManager(deps);
    const delegated = makeDelegatedSigner(1);
    const external = makeExternalSigner(2, 3, 4);

    expect(manager.needsMultiSigner([external])).toBe(false);
    expect(manager.needsMultiSigner([delegated])).toBe(true);
    expect(manager.needsMultiSigner([external, delegated])).toBe(true);
  });

  it("builds selected signers from available signers", () => {
    const deps = makeDeps();
    const manager = new MultiSignerManager(deps);
    const passkeySigner = makeExternalSigner(1, 2, 3);
    const otherPasskeySigner = makeExternalSigner(4, 5, 6);
    const delegatedSigner = makeDelegatedSigner(7);
    deps.externalSigners.canSignFor.mockImplementation((address: string) => address === makeAccount(7));

    const selected = manager.buildSelectedSigners(
      [passkeySigner, otherPasskeySigner, delegatedSigner],
      Buffer.alloc(20, 3).toString("base64url")
    );

    expect(selected).toEqual([
      {
        signer: passkeySigner,
        type: "passkey",
        credentialId: Buffer.alloc(20, 3).toString("base64url"),
      },
      {
        signer: delegatedSigner,
        type: "wallet",
        walletAddress: makeAccount(7),
      },
    ]);
  });

  it("executes transactions without auth entries directly", async () => {
    const deps = makeDeps();
    const manager = new MultiSignerManager(deps);
    const assembledTx = {
      built: {
        operations: [
          {
            type: "invokeHostFunction",
            auth: [],
          },
        ],
      },
      signAndSend: vi.fn().mockResolvedValue({
        status: "SUCCESS",
        hash: "tx-1",
      }),
    } as any;

    const result = await manager.operation(assembledTx, [], {});

    expect(assembledTx.signAndSend).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      success: true,
      hash: "tx-1",
      error: undefined,
    });
  });

  it("delegates transfer execution to the kit-level transfer path", async () => {
    const deps = makeDeps();
    deps.executeTransfer.mockResolvedValue({ success: true, hash: "tx-2" });
    const manager = new MultiSignerManager(deps);
    const selectedSigners = [makeDelegatedSigner(1)];

    const result = await manager.transfer(
      "CCONTRACT",
      makeAccount(2),
      5,
      selectedSigners,
      { onLog: vi.fn() }
    );

    expect(deps.executeTransfer).toHaveBeenCalledWith(
      "CCONTRACT",
      makeAccount(2),
      5,
      selectedSigners,
      { onLog: expect.any(Function) }
    );
    expect(result).toEqual({ success: true, hash: "tx-2" });
  });
});
