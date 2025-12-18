/**
 * Context Rule Manager
 *
 * Manages context rules (authorization policies) for smart accounts.
 * Context rules define which signers and policies apply to specific
 * operation types (default, contract calls, contract creation).
 */

import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import type { Signer as ContractSigner, ContextRuleType, ContextRule } from "smart-account-kit-bindings";

/** Dependencies required by ContextRuleManager */
export interface ContextRuleManagerDeps {
  /** Get the connected wallet client, throws if not connected */
  requireWallet: () => {
    wallet: {
      add_context_rule: (args: {
        context_type: ContextRuleType;
        name: string;
        valid_until: number | undefined;
        signers: ContractSigner[];
        policies: Map<string, unknown>;
      }) => Promise<AssembledTransaction<ContextRule>>;
      get_context_rule: (args: { context_rule_id: number }) => Promise<AssembledTransaction<ContextRule | undefined>>;
      get_context_rules: (args: { context_rule_type: ContextRuleType }) => Promise<AssembledTransaction<ContextRule[]>>;
      remove_context_rule: (args: { context_rule_id: number }) => Promise<AssembledTransaction<null>>;
      update_context_rule_name: (args: { context_rule_id: number; name: string }) => Promise<AssembledTransaction<ContextRule>>;
      update_context_rule_valid_until: (args: { context_rule_id: number; valid_until: number | undefined }) => Promise<AssembledTransaction<ContextRule>>;
    };
  };
}

/**
 * Manages context rules for smart accounts.
 *
 * Context rules are the core authorization mechanism for smart accounts.
 * Each rule specifies:
 * - A context type (when the rule applies)
 * - A set of signers (who can authorize)
 * - A set of policies (additional constraints)
 * - An optional expiration
 *
 * @example
 * ```typescript
 * // Add a new context rule
 * const tx = await kit.rules.add(
 *   { tag: "Default", values: undefined },
 *   "My Rule",
 *   [passkeySigner, delegatedSigner],
 *   new Map([[policyAddress, thresholdParams]])
 * );
 * await tx.signAndSend();
 * ```
 */
export class ContextRuleManager {
  constructor(private deps: ContextRuleManagerDeps) {}

  /**
   * Add a new context rule to the smart account.
   *
   * @param contextType - When this rule applies (Default, CallContract, CreateContract)
   * @param name - Human-readable name for the rule
   * @param signers - Array of signers that can authorize under this rule
   * @param policies - Map of policy addresses to their parameters
   * @param validUntil - Optional ledger number when this rule expires
   * @returns Assembled transaction that creates the rule when signed and sent
   * @throws Error if not connected to a wallet
   */
  async add(
    contextType: ContextRuleType,
    name: string,
    signers: ContractSigner[],
    policies: Map<string, unknown>,
    validUntil?: number
  ) {
    return this.deps.requireWallet().wallet.add_context_rule({
      context_type: contextType,
      name,
      valid_until: validUntil,
      signers,
      policies,
    });
  }

  /**
   * Get a context rule by its ID.
   *
   * @param contextRuleId - The numeric ID of the rule to retrieve
   * @returns Assembled transaction that returns the rule (or undefined if not found)
   * @throws Error if not connected to a wallet
   */
  async get(contextRuleId: number) {
    return this.deps.requireWallet().wallet.get_context_rule({
      context_rule_id: contextRuleId,
    });
  }

  /**
   * Get all context rules of a specific type.
   *
   * @param contextRuleType - The type of rules to retrieve (Default, CallContract, CreateContract)
   * @returns Assembled transaction that returns an array of matching rules
   * @throws Error if not connected to a wallet
   */
  async getAll(contextRuleType: ContextRuleType) {
    return this.deps.requireWallet().wallet.get_context_rules({
      context_rule_type: contextRuleType,
    });
  }

  /**
   * Remove a context rule from the smart account.
   *
   * @param contextRuleId - The numeric ID of the rule to remove
   * @returns Assembled transaction that removes the rule when signed and sent
   * @throws Error if not connected to a wallet
   */
  async remove(contextRuleId: number) {
    return this.deps.requireWallet().wallet.remove_context_rule({
      context_rule_id: contextRuleId,
    });
  }

  /**
   * Update the name of a context rule.
   *
   * @param contextRuleId - The numeric ID of the rule to update
   * @param name - The new name for the rule
   * @returns Assembled transaction that updates the rule when signed and sent
   * @throws Error if not connected to a wallet
   */
  async updateName(contextRuleId: number, name: string) {
    return this.deps.requireWallet().wallet.update_context_rule_name({
      context_rule_id: contextRuleId,
      name,
    });
  }

  /**
   * Update the expiration of a context rule.
   *
   * @param contextRuleId - The numeric ID of the rule to update
   * @param validUntil - The new expiration ledger number (undefined for no expiration)
   * @returns Assembled transaction that updates the rule when signed and sent
   * @throws Error if not connected to a wallet
   */
  async updateExpiration(contextRuleId: number, validUntil?: number) {
    return this.deps.requireWallet().wallet.update_context_rule_valid_until({
      context_rule_id: contextRuleId,
      valid_until: validUntil,
    });
  }
}
