import {
  Account,
  Address,
  Keypair,
  Operation,
  TransactionBuilder,
  hash,
  rpc,
  xdr,
} from "@stellar/stellar-sdk";
import base64url from "base64url";
import type {
  ContextRule,
  ContextRuleType,
  Signer as ContractSigner,
} from "smart-account-kit-bindings";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import {
  collectUniqueSigners,
  getCredentialIdFromSigner,
  signersEqual,
} from "../signer-utils";
import type { ContractDetailsResponse } from "../indexer";
import { BASE_FEE } from "../constants";
import { walkInvocationTree } from "./invocation-utils";

type ContextRuleQueryClient = {
  get_context_rule: (args: { context_rule_id: number }) => Promise<AssembledTransaction<ContextRule>>;
  get_policy_id?: (args: { policy: string }) => Promise<AssembledTransaction<number>>;
  get_signer_id?: (args: { signer: ContractSigner }) => Promise<AssembledTransaction<number>>;
};

type ContextRuleReadDeps = {
  rpc?: rpc.Server;
  contractId?: string;
  networkPassphrase?: string;
  timeoutInSeconds?: number;
};

type ContextRuleDiscoveryDeps = {
  getContractDetailsFromIndexer?: () => Promise<ContractDetailsResponse | null>;
  probeRuleIds?: {
    maxRuleId?: number;
    maxConsecutiveMisses?: number;
  };
} & ContextRuleReadDeps;

const DEFAULT_MAX_PROBED_RULE_ID = 8;
const DEFAULT_MAX_CONSECUTIVE_PROBE_MISSES = 3;
const DEFAULT_READ_TIMEOUT_SECONDS = 30;
const READ_ONLY_SIM_ACCOUNT = new Account(
  Keypair.fromRawEd25519Seed(hash(Buffer.from("smart-account-kit-context-rule-read")))
    .publicKey(),
  "0"
);

export function contextRuleTypeKey(contextType: ContextRuleType): string {
  if (contextType.tag === "Default") {
    return "Default";
  }

  if (contextType.tag === "CallContract") {
    return `CallContract:${contextType.values[0]}`;
  }

  return `CreateContract:${Buffer.from(contextType.values[0]).toString("hex")}`;
}

export function contextRuleTypeMatches(
  ruleType: ContextRuleType,
  requiredType: ContextRuleType
): boolean {
  return (
    ruleType.tag === "Default" ||
    contextRuleTypeKey(ruleType) === contextRuleTypeKey(requiredType)
  );
}

export function buildInvocationContextTypes(
  entry: xdr.SorobanAuthorizationEntry
): ContextRuleType[] {
  return walkInvocationTree(entry.rootInvocation()).map((node) => {
    if (node.contractAddress) {
      return { tag: "CallContract", values: [node.contractAddress] } as ContextRuleType;
    }
    if (node.wasmHash) {
      return { tag: "CreateContract", values: [node.wasmHash] } as ContextRuleType;
    }
    throw new Error(
      "Unable to determine context type for invocation node"
    );
  });
}

function hasRpcReadConfig(
  deps?: ContextRuleReadDeps
): deps is Required<Pick<ContextRuleReadDeps, "rpc" | "contractId" | "networkPassphrase">> &
  ContextRuleReadDeps {
  return Boolean(deps?.rpc && deps.contractId && deps.networkPassphrase);
}

function decodeRequiredMapEntries(val: xdr.ScVal): Map<string, xdr.ScVal> {
  if (val.switch().name !== "scvMap") {
    throw new Error(`Expected context rule result to be a map, got ${val.switch().name}`);
  }

  const entries = new Map<string, xdr.ScVal>();
  for (const entry of val.map() ?? []) {
    if (entry.key().switch().name !== "scvSymbol") {
      throw new Error(`Expected context rule field key to be a symbol, got ${entry.key().switch().name}`);
    }
    entries.set(entry.key().sym().toString(), entry.val());
  }

  return entries;
}

function expectScVec(val: xdr.ScVal, label: string): xdr.ScVal[] {
  if (val.switch().name !== "scvVec") {
    throw new Error(`Expected ${label} to be a vec, got ${val.switch().name}`);
  }
  return val.vec() ?? [];
}

function expectScString(val: xdr.ScVal, label: string): string {
  if (val.switch().name !== "scvString") {
    throw new Error(`Expected ${label} to be a string, got ${val.switch().name}`);
  }
  return val.str().toString();
}

function expectScU32(val: xdr.ScVal, label: string): number {
  if (val.switch().name !== "scvU32") {
    throw new Error(`Expected ${label} to be a u32, got ${val.switch().name}`);
  }
  return val.u32();
}

function expectScAddress(val: xdr.ScVal, label: string): string {
  if (val.switch().name !== "scvAddress") {
    throw new Error(`Expected ${label} to be an address, got ${val.switch().name}`);
  }
  return Address.fromScAddress(val.address()).toString();
}

function decodeOptionalU32Vec(val: xdr.ScVal | undefined, label: string): number[] {
  if (!val || val.switch().name === "scvVoid") {
    return [];
  }

  return expectScVec(val, label).map((item, index) =>
    expectScU32(item, `${label}[${index}]`)
  );
}

function expectScBytes(val: xdr.ScVal, label: string): Buffer {
  if (val.switch().name !== "scvBytes") {
    throw new Error(`Expected ${label} to be bytes, got ${val.switch().name}`);
  }
  return Buffer.from(val.bytes());
}

function expectScSymbol(val: xdr.ScVal, label: string): string {
  if (val.switch().name !== "scvSymbol") {
    throw new Error(`Expected ${label} to be a symbol, got ${val.switch().name}`);
  }
  return val.sym().toString();
}

function decodeContextRuleType(val: xdr.ScVal): ContextRuleType {
  const parts = expectScVec(val, "context_type");
  if (parts.length === 0) {
    throw new Error("context_type vec is empty");
  }

  const tag = expectScSymbol(parts[0], "context_type tag");
  if (tag === "Default") {
    return { tag: "Default", values: undefined };
  }

  if (tag === "CallContract") {
    if (parts.length !== 2) {
      throw new Error(`CallContract context_type expected 2 items, got ${parts.length}`);
    }
    return { tag: "CallContract", values: [expectScAddress(parts[1], "call contract address")] };
  }

  if (tag === "CreateContract") {
    if (parts.length !== 2) {
      throw new Error(`CreateContract context_type expected 2 items, got ${parts.length}`);
    }
    return { tag: "CreateContract", values: [expectScBytes(parts[1], "create contract wasm hash")] };
  }

  throw new Error(`Unknown context rule type tag: ${tag}`);
}

function decodeSigner(val: xdr.ScVal): ContractSigner {
  const parts = expectScVec(val, "signer");
  if (parts.length === 0) {
    throw new Error("signer vec is empty");
  }

  const tag = expectScSymbol(parts[0], "signer tag");
  if (tag === "Delegated") {
    if (parts.length !== 2) {
      throw new Error(`Delegated signer expected 2 items, got ${parts.length}`);
    }
    return { tag: "Delegated", values: [expectScAddress(parts[1], "delegated signer address")] };
  }

  if (tag === "External") {
    if (parts.length !== 3) {
      throw new Error(`External signer expected 3 items, got ${parts.length}`);
    }
    return {
      tag: "External",
      values: [
        expectScAddress(parts[1], "external signer verifier"),
        expectScBytes(parts[2], "external signer key data"),
      ],
    };
  }

  throw new Error(`Unknown signer tag: ${tag}`);
}

export function decodeContextRuleResultXdr(resultXdr: string): ContextRule {
  const scVal = xdr.ScVal.fromXDR(resultXdr, "base64");
  const entries = decodeRequiredMapEntries(scVal);
  const policiesVal = entries.get("policies");
  const signersVal = entries.get("signers");
  const validUntilVal = entries.get("valid_until");
  const policyIdsVal = entries.get("policy_ids");
  const signerIdsVal = entries.get("signer_ids");

  if (!entries.has("context_type") || !entries.has("id") || !entries.has("name") || !policiesVal || !signersVal) {
    throw new Error("Context rule result is missing one or more required fields");
  }

  return {
    context_type: decodeContextRuleType(entries.get("context_type") as xdr.ScVal),
    id: expectScU32(entries.get("id") as xdr.ScVal, "context rule id"),
    name: expectScString(entries.get("name") as xdr.ScVal, "context rule name"),
    policies: expectScVec(policiesVal, "policies").map((policy, index) =>
      expectScAddress(policy, `policy[${index}]`)
    ),
    policy_ids: decodeOptionalU32Vec(policyIdsVal, "policy_ids"),
    signers: expectScVec(signersVal, "signers").map((signer) => decodeSigner(signer)),
    signer_ids: decodeOptionalU32Vec(signerIdsVal, "signer_ids"),
    valid_until: !validUntilVal || validUntilVal.switch().name === "scvVoid"
      ? undefined
      : expectScU32(validUntilVal, "valid_until"),
  } as ContextRule;
}

async function hydrateContextRuleIds(
  wallet: ContextRuleQueryClient,
  rule: ContextRule
): Promise<ContextRule> {
  const needsPolicyIds = rule.policies.length > 0 && rule.policy_ids.length !== rule.policies.length;
  const needsSignerIds = rule.signers.length > 0 && rule.signer_ids.length !== rule.signers.length;

  if (!needsPolicyIds && !needsSignerIds) {
    return rule;
  }

  const [policyIds, signerIds] = await Promise.all([
    needsPolicyIds
      ? wallet.get_policy_id
        ? Promise.all(
            rule.policies.map(async (policy) => {
              const result = (await wallet.get_policy_id?.({ policy }))?.result;
              if (result === undefined || result === null) {
                throw new Error(`Failed to resolve policy ID for ${policy}`);
              }
              return result;
            })
          )
        : Promise.resolve(rule.policy_ids)
      : Promise.resolve(rule.policy_ids),
    needsSignerIds
      ? wallet.get_signer_id
        ? Promise.all(
            rule.signers.map(async (signer) => {
              const result = (await wallet.get_signer_id?.({ signer }))?.result;
              if (result === undefined || result === null) {
                throw new Error(`Failed to resolve signer ID for hydrated context rule ${rule.id}`);
              }
              return result;
            })
          )
        : Promise.resolve(rule.signer_ids)
      : Promise.resolve(rule.signer_ids),
  ]);

  return {
    ...rule,
    policy_ids: policyIds,
    signer_ids: signerIds,
  };
}

async function readContextRuleFromRpc(
  contextRuleId: number,
  deps: Required<Pick<ContextRuleReadDeps, "rpc" | "contractId" | "networkPassphrase">> &
    ContextRuleReadDeps
): Promise<ContextRule> {
  const tx = new TransactionBuilder(READ_ONLY_SIM_ACCOUNT, {
    fee: BASE_FEE,
    networkPassphrase: deps.networkPassphrase,
  })
    .addOperation(
      Operation.invokeHostFunction({
        func: xdr.HostFunction.hostFunctionTypeInvokeContract(
          new xdr.InvokeContractArgs({
            contractAddress: Address.fromString(deps.contractId).toScAddress(),
            functionName: "get_context_rule",
            args: [xdr.ScVal.scvU32(contextRuleId)],
          })
        ),
        auth: [],
      })
    )
    .setTimeout(deps.timeoutInSeconds ?? DEFAULT_READ_TIMEOUT_SECONDS)
    .build();

  const sim = await deps.rpc.simulateTransaction(tx);
  if ("error" in sim && sim.error) {
    throw new Error(`Failed to fetch context rule ${contextRuleId}: ${sim.error}`);
  }

  const retval = "result" in sim ? sim.result?.retval : undefined;
  if (!retval) {
    throw new Error(`Context rule ${contextRuleId} returned no result`);
  }

  return decodeContextRuleResultXdr(retval.toXDR("base64"));
}

export async function readContextRule(
  wallet: ContextRuleQueryClient,
  contextRuleId: number,
  deps?: ContextRuleReadDeps
): Promise<ContextRule> {
  if (hasRpcReadConfig(deps)) {
    const rule = await readContextRuleFromRpc(contextRuleId, deps);
    return hydrateContextRuleIds(wallet, rule);
  }

  const ruleTx = await wallet.get_context_rule({ context_rule_id: contextRuleId });
  return ruleTx.result;
}

export async function listContextRules(
  wallet: ContextRuleQueryClient,
  deps?: ContextRuleDiscoveryDeps
): Promise<ContextRule[]> {
  const details = await deps?.getContractDetailsFromIndexer?.();
  const probeConfig = deps?.probeRuleIds;
  const discoveredRuleIds = new Set<number>(details?.contextRules.map((rule) => rule.context_rule_id) ?? []);

  if (probeConfig) {
    const maxRuleId = probeConfig.maxRuleId ?? DEFAULT_MAX_PROBED_RULE_ID;
    const maxConsecutiveMisses =
      probeConfig.maxConsecutiveMisses ?? DEFAULT_MAX_CONSECUTIVE_PROBE_MISSES;
    let misses = 0;

    for (let contextRuleId = 0; contextRuleId <= maxRuleId; contextRuleId += 1) {
      try {
        const rule = await readContextRule(wallet, contextRuleId, deps);
        discoveredRuleIds.add(rule.id);
        misses = 0;
      } catch {
        misses += 1;
        if (misses >= maxConsecutiveMisses) {
          break;
        }
      }
    }
  }

  if (discoveredRuleIds.size === 0) {
    if (details?.contextRules) {
      return [];
    }

    throw new Error(
      "Listing active context rules requires the indexer because the contract does not expose an iterator for active rule IDs."
    );
  }

  const contextRuleIds = [...discoveredRuleIds].sort((a, b) => a - b);
  const rules = await Promise.all(
    contextRuleIds.map(async (contextRuleId) => {
      try {
        return await readContextRule(wallet, contextRuleId, deps);
      } catch (error) {
        if (isMissingContextRuleError(error)) {
          return null;
        }
        throw error;
      }
    })
  );

  return rules
    .filter((rule): rule is ContextRule => rule !== null)
    .sort((a, b) => a.id - b.id);
}

export async function getFilteredContextRules(
  wallet: ContextRuleQueryClient,
  contextRuleType: ContextRuleType,
  deps?: ContextRuleDiscoveryDeps
): Promise<ContextRule[]> {
  const rules = await listContextRules(wallet, deps);
  return rules.filter(
    (rule) => contextRuleTypeKey(rule.context_type) === contextRuleTypeKey(contextRuleType)
  );
}

export async function findWebAuthnSignerInRules(
  wallet: ContextRuleQueryClient,
  contextRuleIds: number[],
  credentialId: Buffer,
  deps?: ContextRuleReadDeps
): Promise<ContractSigner> {
  for (const contextRuleId of contextRuleIds) {
    const rule = await readContextRule(wallet, contextRuleId, deps);

    for (const signer of rule.signers) {
      if (signer.tag !== "External") {
        continue;
      }

      const keyData = signer.values[1] as Buffer;
      if (keyData.length <= credentialId.length) {
        continue;
      }

      const suffix = keyData.slice(keyData.length - credentialId.length);
      if (suffix.equals(credentialId)) {
        return signer;
      }
    }
  }

  throw new Error(
    `No signer found for credential ID ${base64url.encode(Buffer.from(credentialId))} in context rules ${contextRuleIds.join(", ")}`
  );
}

export async function findWebAuthnSignerForCredential(
  wallet: ContextRuleQueryClient,
  credentialId: string,
  deps?: ContextRuleDiscoveryDeps
): Promise<ContractSigner> {
  const rules = await listContextRules(wallet, deps);
  const matchingSigners = collectUniqueSigners(
    rules.flatMap((rule) =>
      rule.signers.filter((signer) => getCredentialIdFromSigner(signer) === credentialId)
    )
  );

  if (matchingSigners.length === 1) {
    return matchingSigners[0];
  }

  if (matchingSigners.length === 0) {
    throw new Error(`No WebAuthn signer found for credential ID ${credentialId}`);
  }

  throw new Error(
    `Multiple WebAuthn signers matched credential ID ${credentialId}. Resolve the signer explicitly.`
  );
}

export async function resolveContextRuleIdsForEntry(
  wallet: ContextRuleQueryClient,
  entry: xdr.SorobanAuthorizationEntry,
  selectedSigners: ContractSigner[],
  deps?: ContextRuleDiscoveryDeps
): Promise<number[]> {
  const rules = await listContextRules(wallet, deps);
  const contexts = buildInvocationContextTypes(entry);

  return contexts.map((contextType) => {
    const candidates = rules.filter((rule) => {
      if (!contextRuleTypeMatches(rule.context_type, contextType)) {
        return false;
      }

      return true;
    });

    if (candidates.length === 1) {
      return candidates[0].id;
    }

    const exactSignerMatches = candidates.filter((rule) => {
      if (rule.signers.length !== selectedSigners.length) {
        return false;
      }

      return (
        selectedSigners.every((selectedSigner) =>
          rule.signers.some((ruleSigner) => signersEqual(ruleSigner, selectedSigner))
        ) &&
        rule.signers.every((ruleSigner) =>
          selectedSigners.some((selectedSigner) => signersEqual(ruleSigner, selectedSigner))
        )
      );
    });

    if (exactSignerMatches.length === 1) {
      return exactSignerMatches[0].id;
    }

    const signerSubsetMatches = candidates.filter((rule) => {
      if (rule.policies.length > 0) {
        return false;
      }

      return rule.signers.every((ruleSigner) =>
        selectedSigners.some((selectedSigner) => signersEqual(ruleSigner, selectedSigner))
      );
    });

    if (signerSubsetMatches.length === 1) {
      return signerSubsetMatches[0].id;
    }

    const ids = candidates.map((candidate) => candidate.id).join(", ");
    throw new Error(
      `Unable to resolve a unique context rule for ${contextRuleTypeKey(contextType)}. ` +
      `Provide contextRuleIds explicitly. Matched ${candidates.length} rule(s)${ids ? `: ${ids}` : ""}.`
    );
  });
}

function isMissingContextRuleError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  return (
    /ContextRuleNotFound/i.test(error.message) ||
    /Rule \d+ not found/i.test(error.message) ||
    /Error\(Contract,\s*#3000\)/i.test(error.message)
  );
}
