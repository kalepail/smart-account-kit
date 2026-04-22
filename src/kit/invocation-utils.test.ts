import { Address, Keypair, hash, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import type { ContextRule, ContextRuleType, Signer } from "smart-account-kit-bindings";
import {
  countAuthContexts,
  walkInvocationTree,
  validateContextRuleIds,
  hintContextRuleIds,
  resolveContextRuleIds,
} from "./invocation-utils";

function makeRule(
  id: number,
  contextType: ContextRuleType,
  name?: string
): ContextRule {
  return {
    id,
    context_type: contextType,
    name: name ?? `rule-${id}`,
    signers: [],
    signer_ids: [],
    policies: [],
    policy_ids: [],
    valid_until: undefined,
  };
}

function makeAccount(seedByte: number): string {
  return Keypair.fromRawEd25519Seed(Buffer.alloc(32, seedByte)).publicKey();
}

function makeContractInvocation(
  contractId: string,
  functionName: string,
  subInvocations: xdr.SorobanAuthorizedInvocation[] = []
): xdr.SorobanAuthorizedInvocation {
  return new xdr.SorobanAuthorizedInvocation({
    function:
      xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(contractId).toScAddress(),
          functionName,
          args: [],
        })
      ),
    subInvocations,
  });
}

function makeAuthEntry(
  rootInvocation: xdr.SorobanAuthorizedInvocation
): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(makeAccount(99)).toScAddress(),
        nonce: xdr.Int64.fromString("1"),
        signatureExpirationLedger: 1,
        signature: xdr.ScVal.scvVoid(),
      })
    ),
    rootInvocation,
  });
}

function makeCreateContractInvocation(
  wasmHash: Buffer,
  subInvocations: xdr.SorobanAuthorizedInvocation[] = []
): xdr.SorobanAuthorizedInvocation {
  return new xdr.SorobanAuthorizedInvocation({
    function:
      xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractHostFn(
        new xdr.CreateContractArgs({
          contractIdPreimage:
            xdr.ContractIdPreimage.contractIdPreimageFromAddress(
              new xdr.ContractIdPreimageFromAddress({
                address: xdr.ScAddress.scAddressTypeAccount(
                  xdr.PublicKey.publicKeyTypeEd25519(Buffer.alloc(32))
                ),
                salt: Buffer.alloc(32),
              })
            ),
          executable:
            xdr.ContractExecutable.contractExecutableWasm(wasmHash),
        })
      ),
    subInvocations,
  });
}

// Stable contract addresses for tests
const CONTRACT_A = "CDANWYENKH6PTTY6GDTMDAMYRHMU4SBRPX5NUDYDMTYVOIF32ASZFU4Y";
const CONTRACT_B = "CBSHV66WG7UV6FQVUTB67P3DZUEJ2KJ5X6JKQH5MFRAAFNFJUAJVXJYV";
const CONTRACT_C = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

describe("invocation-utils", () => {
  // ==========================================================================
  // countAuthContexts
  // ==========================================================================

  it("counts a single invocation as 1", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");

    expect(countAuthContexts(invocation)).toBe(1);
  });

  it("counts root + 2 sub-invocations as 3", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "deposit", [
      makeContractInvocation(CONTRACT_B, "transfer"),
      makeContractInvocation(CONTRACT_C, "approve"),
    ]);

    expect(countAuthContexts(invocation)).toBe(3);
  });

  it("counts a deeply nested chain (3 levels) as 3", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "swap", [
      makeContractInvocation(CONTRACT_B, "deposit", [
        makeContractInvocation(CONTRACT_C, "transfer"),
      ]),
    ]);

    expect(countAuthContexts(invocation)).toBe(3);
  });

  // ==========================================================================
  // walkInvocationTree
  // ==========================================================================

  it("walks a single contract call and returns one node", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");
    const nodes = walkInvocationTree(invocation);

    expect(nodes).toEqual([
      { index: 0, contractAddress: CONTRACT_A, functionName: "transfer" },
    ]);
  });

  it("walks nested calls in depth-first order with sequential indices", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "deposit", [
      makeContractInvocation(CONTRACT_B, "transfer"),
      makeContractInvocation(CONTRACT_C, "approve"),
    ]);

    const nodes = walkInvocationTree(invocation);

    expect(nodes).toEqual([
      { index: 0, contractAddress: CONTRACT_A, functionName: "deposit" },
      { index: 1, contractAddress: CONTRACT_B, functionName: "transfer" },
      { index: 2, contractAddress: CONTRACT_C, functionName: "approve" },
    ]);
  });

  it("walks a deeply nested chain in depth-first order", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "swap", [
      makeContractInvocation(CONTRACT_B, "deposit", [
        makeContractInvocation(CONTRACT_C, "transfer"),
      ]),
    ]);

    const nodes = walkInvocationTree(invocation);

    expect(nodes).toEqual([
      { index: 0, contractAddress: CONTRACT_A, functionName: "swap" },
      { index: 1, contractAddress: CONTRACT_B, functionName: "deposit" },
      { index: 2, contractAddress: CONTRACT_C, functionName: "transfer" },
    ]);
  });

  it("walks a create-contract invocation and populates wasmHash", () => {
    const wasmHash = hash(Buffer.from("test-wasm"));
    const invocation = makeCreateContractInvocation(wasmHash);
    const nodes = walkInvocationTree(invocation);

    expect(nodes).toHaveLength(1);
    expect(nodes[0].contractAddress).toBeUndefined();
    expect(nodes[0].functionName).toBeUndefined();
    expect(nodes[0].wasmHash).toEqual(wasmHash);
  });

  it("walks a mixed tree with contract calls and create-contract", () => {
    const wasmHash = hash(Buffer.from("deploy"));
    const invocation = makeContractInvocation(CONTRACT_A, "deploy", [
      makeCreateContractInvocation(wasmHash),
    ]);
    const nodes = walkInvocationTree(invocation);

    expect(nodes).toHaveLength(2);
    expect(nodes[0].contractAddress).toBe(CONTRACT_A);
    expect(nodes[0].wasmHash).toBeUndefined();
    expect(nodes[1].contractAddress).toBeUndefined();
    expect(nodes[1].wasmHash).toEqual(wasmHash);
  });

  // ==========================================================================
  // validateContextRuleIds
  // ==========================================================================

  it("passes silently when contextRuleIds length matches", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "deposit", [
      makeContractInvocation(CONTRACT_B, "transfer"),
    ]);

    expect(() => validateContextRuleIds([0, 1], invocation)).not.toThrow();
  });

  it("throws a descriptive error when length mismatches", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "deposit", [
      makeContractInvocation(CONTRACT_B, "transfer"),
    ]);

    expect(() => validateContextRuleIds([0], invocation)).toThrow(
      /contextRuleIds length \(1\) does not match auth_contexts count \(2\)/
    );
  });

  it("includes the tree dump and tip in the error message", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "deposit", [
      makeContractInvocation(CONTRACT_B, "transfer"),
    ]);

    try {
      validateContextRuleIds([], invocation);
      expect.unreachable("should have thrown");
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain(CONTRACT_A);
      expect(message).toContain("deposit");
      expect(message).toContain(CONTRACT_B);
      expect(message).toContain("transfer");
      expect(message).toContain("contextRuleIds: [0, 0]");
      expect(message).toContain("kit.hintContextRuleIds");
    }
  });

  // ==========================================================================
  // hintContextRuleIds
  // ==========================================================================

  it("prefers a CallContract rule over a Default rule", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");
    const rules = [
      makeRule(0, { tag: "Default", values: undefined }, "default"),
      makeRule(1, { tag: "CallContract", values: [CONTRACT_A] }, "token-transfer"),
    ];

    const hints = hintContextRuleIds(invocation, rules);

    expect(hints).toHaveLength(1);
    expect(hints[0].suggestedRuleId).toBe(1);
    expect(hints[0].matchingRules[0].contextType).toBe("CallContract");
    expect(hints[0].matchingRules[1].contextType).toBe("Default");
  });

  it("falls back to Default when no specific rule matches", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");
    const rules = [
      makeRule(0, { tag: "Default", values: undefined }, "default"),
      makeRule(1, { tag: "CallContract", values: [CONTRACT_B] }, "other-contract"),
    ];

    const hints = hintContextRuleIds(invocation, rules);

    expect(hints).toHaveLength(1);
    expect(hints[0].suggestedRuleId).toBe(0);
    expect(hints[0].matchingRules).toHaveLength(1);
    expect(hints[0].matchingRules[0].contextType).toBe("Default");
  });

  it("sorts matchingRules by specificity (CallContract > Default)", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");
    const rules = [
      makeRule(0, { tag: "Default", values: undefined }),
      makeRule(1, { tag: "CallContract", values: [CONTRACT_A] }),
      makeRule(2, { tag: "Default", values: undefined }),
    ];

    const hints = hintContextRuleIds(invocation, rules);
    const types = hints[0].matchingRules.map((m) => m.contextType);

    expect(types).toEqual(["CallContract", "Default", "Default"]);
  });

  it("falls back to defaultRuleId when no rules match at all", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");

    const hints = hintContextRuleIds(invocation, [], 42);

    expect(hints).toHaveLength(1);
    expect(hints[0].suggestedRuleId).toBe(42);
    expect(hints[0].matchingRules).toHaveLength(0);
  });

  it("resolves a nested tree with mixed specific and default rules", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "deposit", [
      makeContractInvocation(CONTRACT_B, "transfer"),
    ]);
    const rules = [
      makeRule(0, { tag: "Default", values: undefined }, "default"),
      makeRule(1, { tag: "CallContract", values: [CONTRACT_A] }, "deposit-rule"),
    ];

    const hints = hintContextRuleIds(invocation, rules);

    expect(hints).toHaveLength(2);
    // Deposit contract has a specific CallContract rule
    expect(hints[0].suggestedRuleId).toBe(1);
    expect(hints[0].contractAddress).toBe(CONTRACT_A);
    expect(hints[0].functionName).toBe("deposit");
    // Transfer contract only matches the Default rule
    expect(hints[1].suggestedRuleId).toBe(0);
    expect(hints[1].contractAddress).toBe(CONTRACT_B);
    expect(hints[1].functionName).toBe("transfer");
  });

  it("matches a CreateContract rule to a create-contract invocation", () => {
    const wasmHash = hash(Buffer.from("test-wasm"));
    const invocation = makeCreateContractInvocation(wasmHash);
    const rules = [
      makeRule(0, { tag: "Default", values: undefined }, "default"),
      makeRule(1, { tag: "CreateContract", values: [wasmHash] }, "deployer"),
    ];

    const hints = hintContextRuleIds(invocation, rules);

    expect(hints).toHaveLength(1);
    expect(hints[0].suggestedRuleId).toBe(1);
    expect(hints[0].matchingRules[0].contextType).toBe("CreateContract");
    expect(hints[0].matchingRules[1].contextType).toBe("Default");
  });

  it("does not match a CreateContract rule to a contract-call invocation", () => {
    const wasmHash = hash(Buffer.from("test-wasm"));
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");
    const rules = [
      makeRule(0, { tag: "Default", values: undefined }),
      makeRule(1, { tag: "CreateContract", values: [wasmHash] }),
    ];

    const hints = hintContextRuleIds(invocation, rules);

    expect(hints[0].suggestedRuleId).toBe(0);
    expect(hints[0].matchingRules).toHaveLength(1);
    expect(hints[0].matchingRules[0].contextType).toBe("Default");
  });

  it("includes node metadata in each hint", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");
    const hints = hintContextRuleIds(invocation, [], 0);

    expect(hints[0].index).toBe(0);
    expect(hints[0].contractAddress).toBe(CONTRACT_A);
    expect(hints[0].functionName).toBe("transfer");
  });

  // ==========================================================================
  // resolveContextRuleIds
  // ==========================================================================

  it("returns an array of suggested rule IDs", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "deposit", [
      makeContractInvocation(CONTRACT_B, "transfer"),
    ]);
    const rules = [
      makeRule(0, { tag: "Default", values: undefined }),
      makeRule(1, { tag: "CallContract", values: [CONTRACT_A] }),
    ];

    const ruleIds = resolveContextRuleIds(invocation, rules);

    expect(ruleIds).toEqual([1, 0]);
  });

  it("uses defaultRuleId for all nodes when no rules are provided", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "deposit", [
      makeContractInvocation(CONTRACT_B, "transfer"),
    ]);

    const ruleIds = resolveContextRuleIds(invocation, [], 5);

    expect(ruleIds).toEqual([5, 5]);
  });

  it("uses 0 as the default fallback rule ID", () => {
    const invocation = makeContractInvocation(CONTRACT_A, "transfer");

    const ruleIds = resolveContextRuleIds(invocation, []);

    expect(ruleIds).toEqual([0]);
  });
});
