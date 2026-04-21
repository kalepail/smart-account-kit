/**
 * Utilities for inspecting Soroban invocation trees and resolving context rule IDs.
 *
 * When the smart account's `__check_auth` is called, it receives one `auth_context`
 * per node in the `SorobanAuthorizedInvocation` tree, traversed depth-first. The
 * `AuthPayload.context_rule_ids` array must have exactly one entry per `auth_context`,
 * aligned by index.
 *
 * For a simple transfer there is one node -> `contextRuleIds: [0]`.
 * For a deposit that internally calls transfer there are two nodes ->
 * `contextRuleIds: [ruleForDeposit, ruleForTransfer]`.
 *
 * @example
 * ```typescript
 * // 1. Simulate the transaction to get auth entries
 * const simResult = await rpc.simulateTransaction(tx);
 * const authEntry = simResult.result!.auth[0];
 *
 * // 2. Inspect the tree to see how many auth_contexts there are
 * const nodes = walkInvocationTree(authEntry.rootInvocation());
 * // nodes[0] = { index: 0, contractAddress: "CB7Z...", functionName: "deposit" }
 * // nodes[1] = { index: 1, contractAddress: "CDSL...", functionName: "transfer" }
 *
 * // 3a. Let the kit auto-suggest rule IDs from on-chain rules
 * const hints = await kit.hintContextRuleIds(authEntry);
 * // hints[0].suggestedRuleId = 1  (CallContract rule for the deposit contract)
 * // hints[1].suggestedRuleId = 0  (Default rule)
 *
 * // 3b. Or get just the IDs if you trust the suggestions
 * const ruleIds = await kit.resolveContextRuleIds(authEntry);
 * // -> [1, 0]
 *
 * // 4. Pass to the signing operation
 * await kit.signAndSubmit(assembledTx, {
 *   resolveContextRuleIds: () => ruleIds,
 * });
 * ```
 *
 * @packageDocumentation
 */

import { Address, xdr } from "@stellar/stellar-sdk";
import type { ContextRule } from "smart-account-kit-bindings";

const CONTEXT_TYPE_SPECIFICITY: Record<string, number> = {
  CallContract: 0,
  CreateContract: 1,
  Default: 2,
};

// ============================================================================
// Types
// ============================================================================

/**
 * Metadata about a single node in a `SorobanAuthorizedInvocation` tree.
 * Each node corresponds to one `auth_context` passed to `__check_auth`.
 */
export interface InvocationNode {
  /** Zero-based position in the depth-first traversal — equals the index into `context_rule_ids`. */
  index: number;
  /** Contract address for contract-function invocations, undefined otherwise. */
  contractAddress?: string;
  /** Function name for contract-function invocations, undefined otherwise. */
  functionName?: string;
}

/**
 * A single on-chain context rule that matches an invocation node.
 */
export interface ContextRuleMatch {
  /** On-chain rule ID. */
  ruleId: number;
  /** Human-readable rule name. */
  ruleName: string;
  /** Why this rule matched: specific contract, wasm hash, or catch-all default. */
  contextType: "Default" | "CallContract" | "CreateContract";
  /** Human-readable description of why this rule was selected. */
  reason: string;
}

/**
 * Hint for a single auth_context node: which rules match and which is suggested.
 */
export interface InvocationContextHint {
  /** Zero-based index — use as the position in `contextRuleIds`. */
  index: number;
  /** Contract address (undefined for non-contract-function invocations). */
  contractAddress?: string;
  /** Function name (undefined for non-contract-function invocations). */
  functionName?: string;
  /**
   * Recommended rule ID for this context.
   * The most specific matching rule is preferred (CallContract > Default).
   * Falls back to `defaultRuleId` when no rule explicitly matches.
   */
  suggestedRuleId: number;
  /**
   * All rules that match this context, ordered by specificity.
   * Inspect this to detect ambiguity or choose a different rule.
   */
  matchingRules: ContextRuleMatch[];
}

// ============================================================================
// Tree Traversal
// ============================================================================

/**
 * Count the total number of auth_contexts that will be produced from an
 * invocation tree (depth-first, one per node).
 *
 * @param invocation - Root of the invocation tree
 * @returns Total number of auth_context entries
 *
 * @example
 * ```typescript
 * const count = countAuthContexts(authEntry.rootInvocation());
 * // For deposit -> transfer: count === 2
 * ```
 */
export function countAuthContexts(
  invocation: xdr.SorobanAuthorizedInvocation
): number {
  return walkInvocationTree(invocation).length;
}

/**
 * Walk an invocation tree depth-first and return a flat list of node metadata.
 * The list index matches the `context_rule_ids` position.
 *
 * @param invocation - Root of the invocation tree
 * @returns Flat array of node metadata in depth-first order
 *
 * @example
 * ```typescript
 * const nodes = walkInvocationTree(authEntry.rootInvocation());
 * // nodes[0] -> root invocation
 * // nodes[1] -> first sub-invocation
 * ```
 */
export function walkInvocationTree(
  invocation: xdr.SorobanAuthorizedInvocation
): InvocationNode[] {
  const nodes: InvocationNode[] = [];
  walkRecursive(invocation, nodes);
  return nodes;
}

function walkRecursive(
  invocation: xdr.SorobanAuthorizedInvocation,
  nodes: InvocationNode[]
): void {
  const fn = invocation.function();
  const node: InvocationNode = { index: nodes.length };

  if (fn.switch().name === "sorobanAuthorizedFunctionTypeContractFn") {
    const contractFn = fn.contractFn();
    node.contractAddress = Address.fromScAddress(
      contractFn.contractAddress()
    ).toString();
    node.functionName = contractFn.functionName().toString();
  }

  nodes.push(node);

  for (const sub of invocation.subInvocations()) {
    walkRecursive(sub, nodes);
  }
}

// ============================================================================
// Validation
// ============================================================================

/**
 * Validate that `contextRuleIds` length exactly matches the auth_contexts count
 * of the invocation tree. Throws a descriptive error on mismatch, including
 * the full tree so the caller can build the correct array.
 *
 * @param contextRuleIds - Array of context rule IDs to validate
 * @param invocation - Root of the invocation tree
 * @throws Error if the array length does not match the number of auth_contexts
 *
 * @example
 * ```typescript
 * // Throws if contextRuleIds.length !== auth_contexts count
 * validateContextRuleIds([0], authEntry.rootInvocation());
 * ```
 */
export function validateContextRuleIds(
  contextRuleIds: number[],
  invocation: xdr.SorobanAuthorizedInvocation
): void {
  const nodes = walkInvocationTree(invocation);
  if (contextRuleIds.length === nodes.length) return;

  const treeLines = nodes.map(
    (n) =>
      `  [${n.index}] ${
        n.contractAddress
          ? `${n.contractAddress}::${n.functionName ?? "?"}`
          : "<non-contract invocation>"
      }`
  );

  throw new Error(
    `contextRuleIds length (${contextRuleIds.length}) does not match ` +
      `auth_contexts count (${nodes.length}).\n` +
      `Invocation tree — ${nodes.length} auth_context${nodes.length === 1 ? "" : "s"} (depth-first):\n` +
      treeLines.join("\n") +
      "\n" +
      `Pass exactly ${nodes.length} rule ID${nodes.length === 1 ? "" : "s"}, e.g. ` +
      `contextRuleIds: [${nodes.map(() => "0").join(", ")}]\n` +
      `Tip: use kit.hintContextRuleIds(authEntry) to get per-node suggestions.`
  );
}

// ============================================================================
// Hint / Resolution
// ============================================================================

/**
 * For each auth_context node in the invocation tree, find all on-chain context
 * rules that match it and return a prioritised hint.
 *
 * Matching priority (most-specific first):
 * 1. `CallContract(address)` — matches when the node's contract address equals the rule value
 * 2. `CreateContract(wasmHash)` — matches when the node is a non-contract invocation
 * 3. `Default` — catch-all, matches every node
 *
 * When multiple rules of the same priority match, all are listed in `matchingRules`
 * so the caller can detect and resolve ambiguity manually.
 *
 * @param invocation - Root of the invocation tree (from `authEntry.rootInvocation()`)
 * @param rules - On-chain context rules to match against
 * @param defaultRuleId - Rule ID used when no rule explicitly matches (default 0)
 * @returns Array of hints, one per auth_context node
 *
 * @example
 * ```typescript
 * const hints = hintContextRuleIds(authEntry.rootInvocation(), rules);
 * // hints[0].suggestedRuleId = 1  (CallContract rule for deposit contract)
 * // hints[0].matchingRules = [{ ruleId: 1, contextType: "CallContract", ... }, ...]
 * ```
 */
export function hintContextRuleIds(
  invocation: xdr.SorobanAuthorizedInvocation,
  rules: ContextRule[],
  defaultRuleId: number = 0
): InvocationContextHint[] {
  const nodes = walkInvocationTree(invocation);

  return nodes.map((node) => {
    const matchingRules: ContextRuleMatch[] = [];

    for (const rule of rules) {
      const ct = rule.context_type;

      if (ct.tag === "CallContract") {
        if (node.contractAddress && ct.values[0] === node.contractAddress) {
          matchingRules.push({
            ruleId: rule.id,
            ruleName: rule.name,
            contextType: "CallContract",
            reason: `CallContract rule for ${node.contractAddress}`,
          });
        }
      } else if (ct.tag === "CreateContract") {
        if (!node.contractAddress) {
          matchingRules.push({
            ruleId: rule.id,
            ruleName: rule.name,
            contextType: "CreateContract",
            reason: "CreateContract rule",
          });
        }
      } else {
        matchingRules.push({
          ruleId: rule.id,
          ruleName: rule.name,
          contextType: "Default",
          reason: "Default rule (matches any context)",
        });
      }
    }

    matchingRules.sort(
      (a, b) =>
        CONTEXT_TYPE_SPECIFICITY[a.contextType] -
        CONTEXT_TYPE_SPECIFICITY[b.contextType]
    );

    const suggestedRuleId =
      matchingRules.length > 0 ? matchingRules[0].ruleId : defaultRuleId;

    return {
      index: node.index,
      contractAddress: node.contractAddress,
      functionName: node.functionName,
      suggestedRuleId,
      matchingRules,
    };
  });
}

/**
 * Resolve context rule IDs for every auth_context in an invocation tree by
 * matching each node against on-chain rules.
 *
 * This is the non-interactive version of {@link hintContextRuleIds} — it returns
 * only the suggested IDs. Use `hintContextRuleIds` when you need to inspect
 * or override individual suggestions.
 *
 * @param invocation - Root of the invocation tree
 * @param rules - On-chain context rules
 * @param defaultRuleId - Fallback rule ID when no rule matches (default 0)
 * @returns Array of rule IDs, one per auth_context, ready to pass as `contextRuleIds`
 *
 * @example
 * ```typescript
 * const ruleIds = resolveContextRuleIds(authEntry.rootInvocation(), rules);
 * // -> [1, 0]  (one ID per auth_context)
 * ```
 */
export function resolveContextRuleIds(
  invocation: xdr.SorobanAuthorizedInvocation,
  rules: ContextRule[],
  defaultRuleId: number = 0
): number[] {
  return hintContextRuleIds(invocation, rules, defaultRuleId).map(
    (h) => h.suggestedRuleId
  );
}
