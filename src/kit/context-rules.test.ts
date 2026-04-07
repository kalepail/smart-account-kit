import { Address, Keypair, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import type { ContextRule, ContextRuleType, Signer } from "smart-account-kit-bindings";
import {
  readContextRule,
  buildInvocationContextTypes,
  decodeContextRuleResultXdr,
  findWebAuthnSignerForCredential,
  listContextRules,
  resolveContextRuleIdsForEntry,
} from "./context-rules";
import { buildKeyData } from "../utils";

function makeRule(
  id: number,
  contextType: ContextRuleType,
  signers: Signer[],
  policies: string[] = []
): ContextRule {
  return {
    id,
    context_type: contextType,
    name: `rule-${id}`,
    signers,
    signer_ids: signers.map((_signer, index) => index),
    policies,
    policy_ids: policies.map((_policy, index) => index),
    valid_until: undefined,
  };
}

function makeAccount(seedByte: number): string {
  return Keypair.fromRawEd25519Seed(Buffer.alloc(32, seedByte)).publicKey();
}

function makeWallet(rules: Record<number, ContextRule>) {
  return {
    async get_context_rule({ context_rule_id }: { context_rule_id: number }) {
      const result = rules[context_rule_id];
      if (!result) {
        throw new Error(`Rule ${context_rule_id} not found`);
      }
      return { result };
    },
  };
}

function makeExternalSigner(
  verifier: string,
  publicKeySeed: number,
  credentialSeed: number
): Signer {
  return {
    tag: "External",
    values: [
      verifier,
      buildKeyData(Buffer.alloc(65, publicKeySeed), Buffer.alloc(20, credentialSeed)),
    ],
  };
}

function makeAuthEntry(contractId: string): xdr.SorobanAuthorizationEntry {
  const invocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: Address.fromString(contractId).toScAddress(),
        functionName: "transfer",
        args: [],
      })
    ),
    subInvocations: [],
  });

  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(
          makeAccount(3)
        ).toScAddress(),
        nonce: xdr.Int64.fromString("1"),
        signatureExpirationLedger: 1,
        signature: xdr.ScVal.scvVoid(),
      })
    ),
    rootInvocation: invocation,
  });
}

describe("context-rules", () => {
  it("builds invocation context types from contract calls", () => {
    const entry = makeAuthEntry(
      "CDANWYENKH6PTTY6GDTMDAMYRHMU4SBRPX5NUDYDMTYVOIF32ASZFU4Y"
    );

    expect(buildInvocationContextTypes(entry)).toEqual([
      {
        tag: "CallContract",
        values: ["CDANWYENKH6PTTY6GDTMDAMYRHMU4SBRPX5NUDYDMTYVOIF32ASZFU4Y"],
      },
    ]);
  });

  it("lists active rules by exact ids discovered from the indexer", async () => {
    const delegated: Signer = {
      tag: "Delegated",
      values: ["GDQP2KPQGKIHYJGXNUIYOMHARUARCA6E6KGUWKZ4S6T7ZTZ4Q7SMX5VA"],
    };
    const rule1 = makeRule(7, { tag: "Default", values: undefined }, [delegated]);
    const rule2 = makeRule(11, { tag: "Default", values: undefined }, [delegated]);
    const wallet = makeWallet({
      7: rule1,
      11: rule2,
    });

    const rules = await listContextRules(wallet, {
      getContractDetailsFromIndexer: async () =>
        ({
          contractId: "C...",
          summary: {
            contract_id: "C...",
            context_rule_count: 2,
            external_signer_count: 0,
            delegated_signer_count: 1,
            native_signer_count: 0,
            first_seen_ledger: 1,
            last_seen_ledger: 2,
            context_rule_ids: [7, 11],
          },
          contextRules: [
            { context_rule_id: 11, signers: [], policies: [] },
            { context_rule_id: 7, signers: [], policies: [] },
          ],
        }),
    });

    expect(rules.map((rule) => rule.id)).toEqual([7, 11]);
  });

  it("refuses to list rules without an indexer-backed rule id source", async () => {
    const wallet = makeWallet({});

    await expect(listContextRules(wallet)).rejects.toThrow(/requires the indexer/i);
  });

  it("probes low rule ids directly when enabled and the indexer has not caught up yet", async () => {
    const delegated: Signer = {
      tag: "Delegated",
      values: [makeAccount(8)],
    };
    const wallet = makeWallet({
      0: makeRule(0, { tag: "Default", values: undefined }, [delegated]),
    });

    const rules = await listContextRules(wallet, {
      probeRuleIds: {
        maxRuleId: 4,
        maxConsecutiveMisses: 2,
      },
    });

    expect(rules.map((rule) => rule.id)).toEqual([0]);
  });

  it("merges probed rule ids with stale indexer ids when probing is enabled", async () => {
    const delegated: Signer = {
      tag: "Delegated",
      values: [makeAccount(8)],
    };
    const wallet = makeWallet({
      0: makeRule(0, { tag: "Default", values: undefined }, [delegated]),
      1: makeRule(1, { tag: "CallContract", values: [makeAccount(9)] }, [delegated]),
    });

    const rules = await listContextRules(wallet, {
      getContractDetailsFromIndexer: async () =>
        ({
          contractId: "C...",
          summary: {
            contract_id: "C...",
            context_rule_count: 1,
            external_signer_count: 0,
            delegated_signer_count: 1,
            native_signer_count: 0,
            first_seen_ledger: 1,
            last_seen_ledger: 1,
            context_rule_ids: [0],
          },
          contextRules: [
            { context_rule_id: 0, signers: [], policies: [] },
          ],
        }),
      probeRuleIds: {
        maxRuleId: 3,
        maxConsecutiveMisses: 2,
      },
    });

    expect(rules.map((rule) => rule.id)).toEqual([0, 1]);
  });

  it("filters out stale rule ids that no longer exist on-chain", async () => {
    const delegated: Signer = {
      tag: "Delegated",
      values: [makeAccount(8)],
    };
    const wallet = makeWallet({
      0: makeRule(0, { tag: "Default", values: undefined }, [delegated]),
    });

    const rules = await listContextRules(wallet, {
      getContractDetailsFromIndexer: async () =>
        ({
          contractId: "C...",
          summary: {
            contract_id: "C...",
            context_rule_count: 2,
            external_signer_count: 0,
            delegated_signer_count: 1,
            native_signer_count: 0,
            first_seen_ledger: 1,
            last_seen_ledger: 2,
            context_rule_ids: [0, 1],
          },
          contextRules: [
            { context_rule_id: 0, signers: [], policies: [] },
            { context_rule_id: 1, signers: [], policies: [] },
          ],
        }),
    });

    expect(rules.map((rule) => rule.id)).toEqual([0]);
  });

  it("resolves a unique context rule by exact signer set", async () => {
    const contractId = "CDANWYENKH6PTTY6GDTMDAMYRHMU4SBRPX5NUDYDMTYVOIF32ASZFU4Y";
    const signerA: Signer = {
      tag: "Delegated",
      values: [makeAccount(4)],
    };
    const signerB: Signer = {
      tag: "Delegated",
      values: [makeAccount(5)],
    };
    const wallet = makeWallet({
      2: makeRule(2, { tag: "CallContract", values: [contractId] }, [signerA]),
      5: makeRule(5, { tag: "CallContract", values: [contractId] }, [signerA, signerB]),
    });

    const contextRuleIds = await resolveContextRuleIdsForEntry(
      wallet,
      makeAuthEntry(contractId),
      [signerA, signerB],
      {
        getContractDetailsFromIndexer: async () =>
          ({
            contractId: "C...",
            summary: {
              contract_id: "C...",
              context_rule_count: 2,
              external_signer_count: 0,
              delegated_signer_count: 2,
              native_signer_count: 0,
              first_seen_ledger: 1,
              last_seen_ledger: 2,
              context_rule_ids: [2, 5],
            },
            contextRules: [
              { context_rule_id: 2, signers: [], policies: [] },
              { context_rule_id: 5, signers: [], policies: [] },
            ],
          }),
      }
    );

    expect(contextRuleIds).toEqual([5]);
  });

  it("finds the unique WebAuthn signer for a credential across active rules", async () => {
    const verifier = "CBSHV66WG7UV6FQVUTB67P3DZUEJ2KJ5X6JKQH5MFRAAFNFJUAJVXJYV";
    const signer = makeExternalSigner(verifier, 9, 4);
    const wallet = makeWallet({
      0: makeRule(0, { tag: "Default", values: undefined }, [signer]),
      1: makeRule(1, { tag: "CallContract", values: [makeAccount(9)] }, [signer]),
    });

    const resolvedSigner = await findWebAuthnSignerForCredential(
      wallet,
      Buffer.alloc(20, 4).toString("base64url"),
      {
        probeRuleIds: {
          maxRuleId: 3,
          maxConsecutiveMisses: 2,
        },
      }
    );

    expect(resolvedSigner).toEqual(signer);
  });

  it("decodes current on-chain context rule XDR without the generic spec decoder", () => {
    const rule = decodeContextRuleResultXdr(
      "AAAAEQAAAAEAAAAGAAAADwAAAAxjb250ZXh0X3R5cGUAAAAQAAAAAQAAAAEAAAAPAAAAB0RlZmF1bHQAAAAADwAAAAJpZAAAAAAAAwAAAAAAAAAPAAAABG5hbWUAAAAOAAAACG11bHRpc2lnAAAADwAAAAhwb2xpY2llcwAAABAAAAABAAAAAAAAAA8AAAAHc2lnbmVycwAAAAAQAAAAAQAAAAEAAAAQAAAAAQAAAAMAAAAPAAAACEV4dGVybmFsAAAAEgAAAAFkevvWN+lfFhWkw++/Y80InSk9v5KoH6wsQAK0qaATWwAAAA0AAABVBGpkWd9ATmaxASDAotqYT29IUVJTQQZAHUSdBt4RcvRvfInCDIUr0yJMoNJshArXwXmy01MrFLXLzsb6BQhcTEcy3/P5n6TiIqVBkIn8/K2hsVx+oQAAAAAAAA8AAAALdmFsaWRfdW50aWwAAAAAAQ=="
    );

    expect(rule).toEqual({
      context_type: { tag: "Default", values: undefined },
      id: 0,
      name: "multisig",
      policies: [],
      policy_ids: [],
      signers: [
        {
          tag: "External",
          values: [
            "CBSHV66WG7UV6FQVUTB67P3DZUEJ2KJ5X6JKQH5MFRAAFNFJUAJVXJYV",
            Buffer.from(
              "046a6459df404e66b10120c0a2da984f6f485152534106401d449d06de1172f46f7c89c20c852bd3224ca0d26c840ad7c179b2d3532b14b5cbcec6fa05085c4c4732dff3f99fa4e222a5419089fcfcada1b15c7ea1",
              "hex"
            ),
          ],
        },
      ],
      signer_ids: [],
      valid_until: undefined,
    });
  });

  it("hydrates signer_ids and policy_ids for RPC-decoded rules when omitted from XDR", async () => {
    const verifier = "CBSHV66WG7UV6FQVUTB67P3DZUEJ2KJ5X6JKQH5MFRAAFNFJUAJVXJYV";
    const signer = makeExternalSigner(verifier, 9, 4);
    const policyAddress = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
    const contractId = "CDANWYENKH6PTTY6GDTMDAMYRHMU4SBRPX5NUDYDMTYVOIF32ASZFU4Y";
    const wallet = {
      async get_policy_id() {
        return { result: 41 };
      },
      async get_signer_id() {
        return { result: 29 };
      },
    };

    const retval = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("context_type"),
        val: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Default")]),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("id"),
        val: xdr.ScVal.scvU32(0),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("name"),
        val: xdr.ScVal.scvString("multisig"),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("policies"),
        val: xdr.ScVal.scvVec([
          xdr.ScVal.scvAddress(Address.fromString(policyAddress).toScAddress()),
        ]),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("signers"),
        val: xdr.ScVal.scvVec([
          xdr.ScVal.scvVec([
            xdr.ScVal.scvSymbol("External"),
            xdr.ScVal.scvAddress(Address.fromString(verifier).toScAddress()),
            xdr.ScVal.scvBytes(Buffer.from(signer.values[1])),
          ]),
        ]),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("valid_until"),
        val: xdr.ScVal.scvVoid(),
      }),
    ]);

    const rpcClient = {
      async simulateTransaction() {
        return {
          result: {
            retval,
          },
        };
      },
    };

    const rule = await readContextRule(wallet as any, 0, {
      rpc: rpcClient as any,
      contractId,
      networkPassphrase: "Test SDF Network ; September 2015",
    });

    expect(rule.policy_ids).toEqual([41]);
    expect(rule.signer_ids).toEqual([29]);
  });
});
