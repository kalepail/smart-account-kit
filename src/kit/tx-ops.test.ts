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

import { Account, Address, Keypair, StrKey, hash, rpc, xdr } from "@stellar/stellar-sdk";
import type { Transaction } from "@stellar/stellar-sdk";
import { FRIENDBOT_RESERVE_XLM } from "../constants";
import {
  fundWallet,
  getSubmissionMethod,
  hasSourceAccountAuth,
  sendAndPoll,
  shouldUseFeeSponsoring,
  sign,
  signAndSubmit,
} from "./tx-ops";

function makeAccount(seedByte: number): Keypair {
  return Keypair.fromRawEd25519Seed(Buffer.alloc(32, seedByte));
}

function makeContractAddress(label: string): string {
  return StrKey.encodeContract(hash(Buffer.from(label)));
}

function makeHostFunction(target = makeContractAddress("target")): xdr.HostFunction {
  return xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: Address.fromString(target).toScAddress(),
      functionName: "transfer",
      args: [],
    })
  );
}

function makeInvokeOperation(auth: xdr.SorobanAuthorizationEntry[] = []): {
  type: "invokeHostFunction";
  func: xdr.HostFunction;
  auth: xdr.SorobanAuthorizationEntry[];
} {
  return {
    type: "invokeHostFunction",
    func: makeHostFunction(),
    auth,
  };
}

function makeRootInvocation(target = makeContractAddress("target")): xdr.SorobanAuthorizedInvocation {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: Address.fromString(target).toScAddress(),
        functionName: "transfer",
        args: [],
      })
    ),
    subInvocations: [],
  });
}

function makeSourceAccountEntry(target = makeContractAddress("target")): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: makeRootInvocation(target),
  });
}

function makeAddressEntry(
  address: string,
  target = makeContractAddress("target")
): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(address).toScAddress(),
        nonce: xdr.Int64.fromString("1"),
        signatureExpirationLedger: 1,
        signature: xdr.ScVal.scvVoid(),
      })
    ),
    rootInvocation: makeRootInvocation(target),
  });
}

function makeAssembledTransaction(overrides?: Partial<{
  built: { operations: Operation.InvokeHostFunction[] };
  simulationData: { result: { auth: xdr.SorobanAuthorizationEntry[] } };
  signAuthEntries: (options: {
    address: string;
    authorizeEntry: (entry: xdr.SorobanAuthorizationEntry) => Promise<void>;
  }) => Promise<void>;
}>): any {
  return {
    built: overrides?.built,
    simulationData: overrides?.simulationData,
    signAuthEntries: overrides?.signAuthEntries ?? vi.fn(async () => {}),
  };
}

describe("tx-ops", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    assembleTransactionMock.mockReset();
  });

  it("selects the submission method from forceMethod and relayer presence", () => {
    expect(getSubmissionMethod(null)).toBe("rpc");
    expect(getSubmissionMethod({} as never)).toBe("relayer");
    expect(getSubmissionMethod({} as never, { forceMethod: "rpc" })).toBe("rpc");
    expect(shouldUseFeeSponsoring({} as never)).toBe(true);
    expect(shouldUseFeeSponsoring(null)).toBe(false);
  });

  it("detects source-account auth entries", () => {
    const tx = {
      operations: [{ type: "invokeHostFunction", auth: [makeSourceAccountEntry()] }],
    } as unknown as Transaction;

    const otherTx = {
      operations: [{ type: "invokeHostFunction", auth: [makeAddressEntry(makeAccount(1).publicKey())] }],
    } as unknown as Transaction;

    expect(hasSourceAccountAuth(tx)).toBe(true);
    expect(hasSourceAccountAuth(otherTx)).toBe(false);
  });

  it("sends through the relayer when configured", async () => {
    const invokeOp = makeInvokeOperation([makeAddressEntry(makeAccount(2).publicKey())]);
    const relayerSend = vi.fn().mockResolvedValue({
      success: true,
      hash: "relayer-hash",
    });
    const pollTransaction = vi.fn().mockResolvedValue({
      status: "SUCCESS",
      ledger: 99,
    });

    const result = await sendAndPoll(
      {
        rpc: {
          sendTransaction: vi.fn(),
          pollTransaction,
        } as never,
        relayer: {
          send: relayerSend,
        } as never,
      },
      {
        operations: [invokeOp],
      } as unknown as Transaction
    );

    const [funcXdr, authXdrs] = relayerSend.mock.calls[0];
    expect(typeof funcXdr).toBe("string");
    expect((authXdrs as string[])).toHaveLength(1);
    expect(pollTransaction).toHaveBeenCalledWith("relayer-hash", { attempts: 10 });
    expect(result).toEqual({
      success: true,
      hash: "relayer-hash",
      ledger: 99,
    });
  });

  it("returns an rpc submission error without polling", async () => {
    const sendTransaction = vi.fn().mockResolvedValue({
      status: "ERROR",
      hash: "rpc-hash",
      errorResult: {
        toXDR: () => "error-xdr",
      },
    });
    const pollTransaction = vi.fn();

    const result = await sendAndPoll(
      {
        rpc: {
          sendTransaction,
          pollTransaction,
        } as never,
        relayer: null,
      },
      {
        operations: [makeInvokeOperation()],
      } as unknown as Transaction
    );

    expect(sendTransaction).toHaveBeenCalledTimes(1);
    expect(pollTransaction).not.toHaveBeenCalled();
    expect(result).toEqual({
      success: false,
      hash: "rpc-hash",
      error: "error-xdr",
    });
  });

  it("signs auth entries with the resolved context rule ids", async () => {
    const authEntry = makeAddressEntry(makeAccount(3).publicKey());
    const resolveContextRuleIds = vi.fn().mockResolvedValue([7, 9]);
    const signAuthEntry = vi.fn().mockImplementation(async (entry, options) => {
      expect(options).toMatchObject({
        credentialId: "cred-id",
        expiration: 1234,
        contextRuleIds: [7, 9],
      });
      return entry;
    });
    const signAuthEntries = vi.fn(async ({ authorizeEntry }) => {
      await authorizeEntry(authEntry);
    });

    const tx = makeAssembledTransaction({
      simulationData: { result: { auth: [authEntry] } },
      signAuthEntries,
    });

    const result = await sign(
      {
        getContractId: () => makeContractAddress("contract"),
        getCredentialId: () => "cred-id",
        calculateExpiration: async () => 1234,
        signAuthEntry,
      },
      tx,
      {
        resolveContextRuleIds,
      }
    );

    expect(resolveContextRuleIds).toHaveBeenCalledWith(expect.anything(), 0);
    expect(signAuthEntry).toHaveBeenCalledTimes(1);
    expect(signAuthEntries).toHaveBeenCalledTimes(1);
    expect(result).toBe(tx);
  });

  it("signAndSubmit re-simulates and submits with the prepared transaction", async () => {
    const authEntry = makeAddressEntry(makeAccount(4).publicKey());
    const preparedTx = {
      sign: vi.fn(),
    };
    const signResimulateAndPrepare = vi.fn().mockResolvedValue(preparedTx);
    const sendAndPollMock = vi.fn().mockResolvedValue({
      success: true,
      hash: "tx-hash",
    });
    const tx = makeAssembledTransaction({
      built: { operations: [{ type: "invokeHostFunction", func: makeHostFunction() }] },
      simulationData: { result: { auth: [authEntry] } },
    });

    const result = await signAndSubmit(
      {
        getContractId: () => makeContractAddress("contract"),
        signResimulateAndPrepare,
        shouldUseFeeSponsoring: () => true,
        hasSourceAccountAuth: () => false,
        sendAndPoll: sendAndPollMock,
        deployerKeypair: makeAccount(5),
      },
      tx,
      {
        credentialId: "cred-id",
        expiration: 555,
        forceMethod: "rpc",
      }
    );

    expect(signResimulateAndPrepare).toHaveBeenCalledWith(expect.any(Object), tx.simulationData.result.auth, {
      credentialId: "cred-id",
      expiration: 555,
      resolveContextRuleIds: undefined,
    });
    expect(sendAndPollMock).toHaveBeenCalledWith(preparedTx, { forceMethod: "rpc" });
    expect(result).toEqual({
      success: true,
      hash: "tx-hash",
    });
  });

  it("returns an error when signAndSubmit is called without simulation data", async () => {
    const tx = makeAssembledTransaction({
      built: { operations: [{ type: "invokeHostFunction", func: makeHostFunction() }] },
    });

    const result = await signAndSubmit(
      {
        getContractId: () => makeContractAddress("contract"),
        signResimulateAndPrepare: vi.fn(),
        shouldUseFeeSponsoring: () => true,
        hasSourceAccountAuth: () => false,
        sendAndPoll: vi.fn(),
        deployerKeypair: makeAccount(6),
      },
      tx
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("No simulation data or auth entries");
  });

  it("fundWallet signs and submits the funded transfer amount", async () => {
    const account = new Account(makeAccount(7).publicKey(), "1");
    const preparedTx = {
      sign: vi.fn(),
    };
    const simulateTransaction = vi
      .fn()
      .mockResolvedValueOnce({
        result: { auth: [] },
        latestLedger: 100,
      })
      .mockResolvedValueOnce({
        result: { auth: [] },
        latestLedger: 100,
      });
    const sendAndPollMock = vi.fn().mockResolvedValue({
      success: true,
      hash: "fund-hash",
    });
    vi.spyOn(console, "warn").mockImplementation(() => {});
    assembleTransactionMock.mockReturnValue({
      build: () => preparedTx,
    });

    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 200 })) as typeof fetch);

    const result = await fundWallet(
      {
        getContractId: () => makeContractAddress("contract"),
        rpc: {
          getAccount: vi.fn().mockResolvedValue(account),
          getContractData: vi.fn().mockRejectedValue(new Error("missing balance")),
          simulateTransaction,
        } as never,
        networkPassphrase: "Test SDF Network ; September 2015",
        timeoutInSeconds: 30,
        shouldUseFeeSponsoring: () => false,
        hasSourceAccountAuth: () => false,
        sendAndPoll: sendAndPollMock,
      },
      makeContractAddress("token")
    );

    expect(simulateTransaction).toHaveBeenCalledTimes(2);
    expect(assembleTransactionMock).toHaveBeenCalledTimes(1);
    expect(preparedTx.sign).toHaveBeenCalledTimes(1);
    expect(sendAndPollMock).toHaveBeenCalledWith(preparedTx, { forceMethod: undefined });
    expect(result).toEqual({
      success: true,
      hash: "fund-hash",
      amount: 10_000 - FRIENDBOT_RESERVE_XLM,
    });
  });
});
