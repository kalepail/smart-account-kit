import { Address, Keypair, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import type { ContextRule, ContextRuleType, Signer } from "smart-account-kit-bindings";
import {
  buildInvocationContextTypes,
  listContextRules,
  resolveContextRuleIdsForEntry,
} from "./context-rules";

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
    signer_ids: signers.map((_, index) => index + 1),
    policies,
    policy_ids: policies.map((_, index) => index + 1),
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
});
