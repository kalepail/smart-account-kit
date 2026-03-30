import { afterEach, describe, expect, it, vi } from "vitest";
const { assembleTransactionMock } = vi.hoisted(() => ({
  assembleTransactionMock: vi.fn(),
}));

vi.mock("@stellar/stellar-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@stellar/stellar-sdk")>();
  return {
    ...actual,
    rpc: {
      ...actual.rpc,
      assembleTransaction: assembleTransactionMock,
    },
  };
});

vi.mock("../kit/tx-ops", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../kit/tx-ops")>();
  return {
    ...actual,
    simulateHostFunction: vi.fn(),
  };
});

import { Account, Address, Keypair, Operation, TransactionBuilder, xdr } from "@stellar/stellar-sdk";
import { MultiSignerManager } from "./multi-signer-manager";
import { simulateHostFunction } from "../kit/tx-ops";
import {
  makeAccount,
  makeAddressAuthEntry,
  makeContract,
  makeDelegatedSigner,
  makeExternalSigner,
} from "./test-utils";

function makeDeps() {
  const externalSigners = {
    canSignFor: vi.fn(),
    signAuthEntry: vi.fn(),
  };

  const deps = {
    getContractId: vi.fn().mockReturnValue(makeContract(99)),
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
    deployerKeypair: Keypair.fromRawEd25519Seed(Buffer.alloc(32, 5)),
    deployerPublicKey: Keypair.fromRawEd25519Seed(Buffer.alloc(32, 5)).publicKey(),
    signAuthEntry: vi.fn(),
    sendAndPoll: vi.fn(),
    hasSourceAccountAuth: vi.fn().mockReturnValue(false),
    shouldUseFeeSponsoring: vi.fn().mockReturnValue(false),
  };

  return deps;
}

function makeBuiltTransaction(auth: xdr.SorobanAuthorizationEntry[] = []) {
  return new TransactionBuilder(new Account(makeAccount(77), "1"), {
    fee: "100",
    networkPassphrase: "Test SDF Network ; September 2015",
  })
    .addOperation(
      Operation.invokeHostFunction({
        func: xdr.HostFunction.hostFunctionTypeInvokeContract(
          new xdr.InvokeContractArgs({
            contractAddress: Address.fromString(makeContract(31)).toScAddress(),
            functionName: "ping",
            args: [],
          })
        ),
        auth,
      })
    )
    .setTimeout(30)
    .build();
}

describe("MultiSignerManager", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    assembleTransactionMock.mockReset();
  });

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

  it("builds selected signers from the active passkey and connected delegated wallets", () => {
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

  it("detects when multi-signer flows are needed", () => {
    const deps = makeDeps();
    const manager = new MultiSignerManager(deps);
    const delegated = makeDelegatedSigner(1);
    const external = makeExternalSigner(2, 3, 4);

    expect(manager.needsMultiSigner([external])).toBe(false);
    expect(manager.needsMultiSigner([delegated])).toBe(true);
    expect(manager.needsMultiSigner([external, delegated])).toBe(true);
  });

  it("submits auth-less operations through sendAndPoll", async () => {
    const deps = makeDeps();
    deps.shouldUseFeeSponsoring.mockReturnValue(true);
    deps.sendAndPoll.mockResolvedValue({ success: true, hash: "tx-1" });
    const manager = new MultiSignerManager(deps);
    const assembledTx = {
      built: makeBuiltTransaction(),
      signAndSend: vi.fn().mockResolvedValue({
        status: "SUCCESS",
        hash: "tx-1",
      }),
    } as any;

    const result = await manager.operation(assembledTx, [], { forceMethod: "rpc" });

    expect(assembledTx.signAndSend).not.toHaveBeenCalled();
    expect(deps.sendAndPoll).toHaveBeenCalledTimes(1);
    expect(deps.sendAndPoll).toHaveBeenCalledWith(expect.anything(), { forceMethod: "rpc" });
    expect(result).toEqual({
      success: true,
      hash: "tx-1",
    });
  });

  it("builds transfer auth via simulation instead of delegating to the kit", async () => {
    const deps = makeDeps();
    const manager = new MultiSignerManager(deps);
    const selectedSigners = [makeDelegatedSigner(1)];
    vi.mocked(simulateHostFunction).mockRejectedValue(new Error("simulation failed"));

    const result = await manager.transfer(
      makeContract(11),
      makeAccount(2),
      5,
      selectedSigners,
      { onLog: vi.fn() }
    );

    expect(simulateHostFunction).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      success: false,
      hash: "",
      error: "simulation failed",
    });
  });

  it("fails fast on unsupported external auth entries", async () => {
    const deps = makeDeps();
    deps.rpc.getLatestLedger.mockResolvedValue({ sequence: 100 });
    const manager = new MultiSignerManager(deps);
    const unsupportedAddress = makeAccount(12);

    const result = await manager.operation(
      {
        built: {
          operations: [{
            type: "invokeHostFunction",
            func: xdr.HostFunction.hostFunctionTypeInvokeContract(
              new xdr.InvokeContractArgs({
                contractAddress: Address.fromString(makeContract(41)).toScAddress(),
                functionName: "ping",
                args: [],
              })
            ),
            auth: [makeAddressAuthEntry(unsupportedAddress)],
          }],
        },
      } as any,
      [],
      {}
    );

    expect(result).toEqual({
      success: false,
      hash: "",
      error: `Unsupported auth entry for ${unsupportedAddress}. Add an external signer for that address or remove it from the transaction.`,
    });
  });

  it("signs separate delegated auth entries before submission", async () => {
    const deps = makeDeps();
    const delegatedAddress = makeAccount(21);
    const authEntry = makeAddressAuthEntry(delegatedAddress);
    const preparedTx = { sign: vi.fn() };
    deps.externalSigners.canSignFor.mockReturnValue(true);
    deps.externalSigners.signAuthEntry.mockResolvedValue({
      signedAuthEntry: Buffer.alloc(64, 7).toString("base64"),
      signerAddress: delegatedAddress,
    });
    deps.rpc.getLatestLedger.mockResolvedValue({ sequence: 200 });
    deps.rpc.getAccount.mockResolvedValue(new Account(deps.deployerPublicKey, "1"));
    deps.rpc.simulateTransaction.mockResolvedValue({ result: { auth: [] } });
    deps.shouldUseFeeSponsoring.mockReturnValue(true);
    deps.sendAndPoll.mockResolvedValue({ success: true, hash: "tx-2" });
    assembleTransactionMock.mockReturnValue({
      build: () => preparedTx,
    });
    const manager = new MultiSignerManager(deps);

    const result = await manager.operation(
      {
        built: {
          operations: [{
            type: "invokeHostFunction",
            func: xdr.HostFunction.hostFunctionTypeInvokeContract(
              new xdr.InvokeContractArgs({
                contractAddress: Address.fromString(makeContract(42)).toScAddress(),
                functionName: "ping",
                args: [],
              })
            ),
            auth: [authEntry],
          }],
        },
      } as any,
      [{
        signer: makeDelegatedSigner(21),
        type: "wallet",
        walletAddress: delegatedAddress,
      }],
      {}
    );

    expect(deps.externalSigners.signAuthEntry).toHaveBeenCalledTimes(1);
    expect(assembleTransactionMock).toHaveBeenCalledTimes(1);
    expect(deps.sendAndPoll).toHaveBeenCalledWith(preparedTx, { forceMethod: undefined });
    expect(result).toEqual({ success: true, hash: "tx-2" });
  });

  it("fails fast when a wallet signer is missing contract signer metadata", async () => {
    const deps = makeDeps();
    const contractId = deps.getContractId();
    const walletAddress = makeAccount(22);
    deps.rpc.getLatestLedger.mockResolvedValue({ sequence: 300 });
    deps.externalSigners.canSignFor.mockImplementation((address: string) => address === walletAddress);
    const manager = new MultiSignerManager(deps);

    const result = await manager.operation(
      {
        built: {
          operations: [{
            type: "invokeHostFunction",
            func: xdr.HostFunction.hostFunctionTypeInvokeContract(
              new xdr.InvokeContractArgs({
                contractAddress: Address.fromString(makeContract(43)).toScAddress(),
                functionName: "ping",
                args: [],
              })
            ),
            auth: [makeAddressAuthEntry(contractId)],
          }],
        },
      } as any,
      [{
        type: "wallet",
        walletAddress,
      }],
      {}
    );

    expect(result).toEqual({
      success: false,
      hash: "",
      error: `Wallet signer ${walletAddress} is missing contract signer metadata. Use buildSelectedSigners() or provide the signer field explicitly.`,
    });
  });
});
