/**
 * Smart Account Kit
 *
 * TypeScript SDK for deploying and managing OpenZeppelin Smart Account contracts
 * on Stellar/Soroban with WebAuthn passkey authentication.
 *
 * @packageDocumentation
 */

// Main client SDK
export { SmartAccountKit } from "./kit";

// Sub-manager types
export type {
  SignerManager,
  ContextRuleManager,
  PolicyManager,
  CredentialManager,
  MultiSignerManager,
  MultiSignerOptions,
} from "./kit";

// External signer types
export {
  ExternalSignerManager,
  type ExternalSigner,
  type WalletStorage,
} from "./external-signers";

// SDK Types
export type {
  // Configuration
  SmartAccountConfig,
  PolicyConfig,
  LaunchtubeConfig,

  // Credentials & Sessions
  StoredCredential,
  StoredSession,
  CredentialDeploymentStatus,
  StorageAdapter,

  // Results
  CreateWalletResult,
  ConnectWalletResult,
  TransactionResult,
  SubmissionOptions,

  // External Wallet Integration
  ExternalWalletAdapter,
  ConnectedWallet,

  // Multi-Signer
  SelectedSigner,
} from "./types";

// Contract Types (re-exported from bindings)
import type { Signer } from "smart-account-kit-bindings";
export type {
  // Contract Signer types
  Signer as ContractSigner,

  // Context Rules
  ContextRule,
  ContextRuleType,
  Meta as ContextRuleMeta,

  // WebAuthn signature data (contract format)
  WebAuthnSigData,

  // Signatures
  Signatures,

  // Policy types
  SimpleThresholdAccountParams,
  WeightedThresholdAccountParams,
  SpendingLimitAccountParams,
} from "smart-account-kit-bindings";

// SignerId is the same type as Signer - used for signature map keys
export type ContractSignerId = Signer;

// Storage adapters
export {
  MemoryStorage,
  LocalStorageAdapter,
  IndexedDBStorage,
} from "./storage";

// Constants (public API - implementation details are internal)
export {
  // Useful timing constants
  WEBAUTHN_TIMEOUT_MS,
  // Transaction/funding constants
  BASE_FEE,
  STROOPS_PER_XLM,
  FRIENDBOT_RESERVE_XLM,
} from "./constants";

// Error classes
export {
  SmartAccountError,
  SmartAccountErrorCode,
  WalletNotConnectedError,
  CredentialNotFoundError,
  SignerNotFoundError,
  SimulationError,
  SubmissionError,
  ValidationError,
  WebAuthnError,
  SessionError,
  wrapError,
} from "./errors";

// Utility functions (public API - low-level helpers are internal)
export {
  // Conversion utilities
  xlmToStroops,
  stroopsToXlm,
  // Validation utilities
  validateAddress,
  validateAmount,
  validateNotEmpty,
} from "./utils";

// Builder utilities
export {
  // Signer builders
  createDelegatedSigner,
  createExternalSigner,
  createWebAuthnSigner,
  createEd25519Signer,
  // Context rule type builders
  createDefaultContext,
  createCallContractContext,
  createCreateContractContext,
  // Policy parameter builders
  createThresholdParams,
  createWeightedThresholdParams,
  createSpendingLimitParams,
  // Time period constants (for spending limits)
  LEDGERS_PER_HOUR,
  LEDGERS_PER_DAY,
  LEDGERS_PER_WEEK,
  // Signer helper functions
  getCredentialIdFromSigner,
  describeSignerType,
  formatSignerForDisplay,
  signersEqual,
  getSignerKey,
  collectUniqueSigners,
  // Display helpers
  truncateAddress,
  formatContextType,
} from "./builders";

// Event emitter
export { SmartAccountEventEmitter } from "./events";
export type {
  SmartAccountEventMap,
  SmartAccountEvent,
  EventListener,
} from "./events";

// Indexer client for reverse lookups
export {
  IndexerClient,
  IndexerError,
  DEFAULT_INDEXER_URLS,
} from "./indexer";
export type {
  IndexerConfig,
  IndexedContractSummary,
  IndexedSigner,
  IndexedPolicy,
  IndexedContextRule,
  CredentialLookupResponse,
  AddressLookupResponse,
  ContractDetailsResponse,
  IndexerStatsResponse,
} from "./indexer";

// Launchtube client for fee-sponsored transactions
export { LaunchtubeClient } from "./launchtube";
export type {
  LaunchtubeResponse,
  LaunchtubeSendOptions,
} from "./launchtube";

// Wallet Adapters
export { StellarWalletsKitAdapter } from "./wallet-adapter";
export type { StellarWalletsKitAdapterConfig } from "./wallet-adapter";

// Re-export stellar-sdk types for convenience
export type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
