import { Address, xdr } from "@stellar/stellar-sdk";
import type {
  ContextRule,
  ContextRuleType,
  Signer as ContractSigner,
} from "smart-account-kit-bindings";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import { signersEqual } from "../signer-utils";
import type { ContractDetailsResponse } from "../indexer";

type ContextRuleQueryClient = {
  get_context_rule: (args: { context_rule_id: number }) => Promise<AssembledTransaction<ContextRule>>;
};

type ContextRuleDiscoveryDeps = {
  getContractDetailsFromIndexer?: () => Promise<ContractDetailsResponse | null>;
};

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
  const contexts: ContextRuleType[] = [];

  const walk = (invocation: xdr.SorobanAuthorizedInvocation) => {
    const fn = invocation.function();
    const switchName = fn.switch().name;

    if (switchName === "sorobanAuthorizedFunctionTypeContractFn") {
      const args = fn.contractFn();
      contexts.push({
        tag: "CallContract",
        values: [Address.fromScAddress(args.contractAddress()).toString()],
      });
    } else if (switchName.startsWith("sorobanAuthorizedFunctionTypeCreateContract")) {
      const wasmHash = extractCreateContractWasmHash(fn);
      if (!wasmHash) {
        throw new Error("Unable to extract WASM hash from create-contract authorization entry");
      }

      contexts.push({
        tag: "CreateContract",
        values: [wasmHash],
      });
    }

    for (const sub of invocation.subInvocations()) {
      walk(sub);
    }
  };

  walk(entry.rootInvocation());
  return contexts;
}

export async function listContextRules(
  wallet: ContextRuleQueryClient,
  deps?: ContextRuleDiscoveryDeps
): Promise<ContextRule[]> {
  const details = await deps?.getContractDetailsFromIndexer?.();
  const contextRuleIds = details?.contextRules.map((rule) => rule.context_rule_id);

  if (!contextRuleIds) {
    throw new Error(
      "Listing active context rules requires the indexer because the contract does not expose an iterator for active rule IDs."
    );
  }

  if (contextRuleIds.length === 0) {
    return [];
  }

  const rules = await Promise.all(
    contextRuleIds.map(async (contextRuleId) => {
      const ruleTx = await wallet.get_context_rule({ context_rule_id: contextRuleId });
      return ruleTx.result;
    })
  );

  return rules.sort((a, b) => a.id - b.id);
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
  credentialId: Buffer
): Promise<ContractSigner> {
  for (const contextRuleId of contextRuleIds) {
    const rule = (await wallet.get_context_rule({ context_rule_id: contextRuleId })).result;

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
    `No signer found for credential ID ${credentialId.toString("base64url")} in context rules ${contextRuleIds.join(", ")}`
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

function extractCreateContractWasmHash(
  fn: xdr.SorobanAuthorizedFunction
): Buffer | null {
  const candidates: Array<unknown> = [];
  const fnAny = fn as unknown as {
    createContractHostFn?: () => unknown;
    createContractWithCtorHostFn?: () => unknown;
    createContractWithConstructorHostFn?: () => unknown;
  };

  if (typeof fnAny.createContractHostFn === "function") {
    candidates.push(fnAny.createContractHostFn());
  }
  if (typeof fnAny.createContractWithCtorHostFn === "function") {
    candidates.push(fnAny.createContractWithCtorHostFn());
  }
  if (typeof fnAny.createContractWithConstructorHostFn === "function") {
    candidates.push(fnAny.createContractWithConstructorHostFn());
  }

  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== "object") {
      continue;
    }

    const ctx = candidate as { executable?: unknown };
    const executable = typeof ctx.executable === "function"
      ? (ctx.executable as () => unknown)()
      : ctx.executable;

    if (!executable || typeof executable !== "object") {
      continue;
    }

    const execAny = executable as {
      switch?: () => { name: string };
      wasm?: (() => Buffer) | Buffer;
    };
    const execSwitch = execAny.switch?.();

    if (execSwitch?.name !== "contractExecutableWasm") {
      continue;
    }

    const wasm = typeof execAny.wasm === "function" ? execAny.wasm() : execAny.wasm;
    if (wasm) {
      return Buffer.from(wasm);
    }
  }

  return null;
}
