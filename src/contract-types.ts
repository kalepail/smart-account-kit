import type { Signer as ContractSigner } from "smart-account-kit-bindings";

export interface WebAuthnSigData {
  authenticator_data: Buffer;
  client_data: Buffer;
  signature: Buffer;
}

export interface SimpleThresholdAccountParams {
  threshold: number;
}

export interface WeightedThresholdAccountParams {
  signer_weights: Map<ContractSigner, number>;
  threshold: number;
}

export interface SpendingLimitAccountParams {
  period_ledgers: number;
  spending_limit: bigint;
}

/**
 * A single entry in the spending-limit policy's rolling history.
 * Mirrors the contract's `SpendingEntry`.
 */
export interface SpendingEntry {
  /** The amount spent in this transaction (stroops). */
  amount: bigint;
  /** The ledger sequence when this transaction occurred. */
  ledger_sequence: number;
}

/**
 * The spending-limit policy state for a (smart account, context rule) pair.
 * Mirrors the contract's `SpendingLimitData`.
 */
export interface SpendingLimitData {
  /** The spending limit for the period (stroops). */
  spending_limit: bigint;
  /** The period in ledgers over which the limit applies. */
  period_ledgers: number;
  /** Rolling history of spending transactions. */
  spending_history: SpendingEntry[];
  /** Cached total of all amounts in `spending_history`. */
  cached_total_spent: bigint;
}
