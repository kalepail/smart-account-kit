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
