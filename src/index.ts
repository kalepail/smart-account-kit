/**
 * Smart Account Kit
 *
 * TypeScript SDK for deploying and managing OpenZeppelin Smart Account contracts
 * on Stellar with WebAuthn passkey authentication.
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

  // Credentials & Sessions
  StoredCredential,
  StoredSession,
  CredentialDeploymentStatus,
  StorageAdapter,

  // Results
  CreateWalletResult,
  ConnectWalletResult,
  TransactionResult,
  TransactionSuccess,
  TransactionFailure,
  SubmissionOptions,
  SubmissionMethod,

  // External Wallet Integration
  ExternalWalletAdapter,
  ConnectedWallet,

  // Multi-Signer
  SelectedSigner,
} from "./types";

// Contract Types (re-exported from bindings)
export type {
  // Contract Signer types
  Signer as ContractSigner,

  // Context Rules
  ContextRule,
  ContextRuleType,
  AuthPayload,
} from "smart-account-kit-bindings";
export type {
  WebAuthnSigData,
  SimpleThresholdAccountParams,
  WeightedThresholdAccountParams,
  SpendingLimitAccountParams,
} from "./contract-types";

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
  // Contract limits (mirror the deployed contract)
  MAX_SIGNERS,
  MAX_POLICIES,
  MAX_NAME_SIZE,
  MAX_EXTERNAL_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
} from "./constants";

// Client-side validation of contract limits
export {
  validateContextRule,
  validateContextRuleName,
  validateSigner,
  validateSigners,
  validatePolicyCount,
  validateExternalKeySize,
  validateValidUntil,
} from "./validation";

// Error classes
export {
  SmartAccountError,
  SmartAccountErrorCode,
  WalletNotConnectedError,
  CredentialNotFoundError,
  SignerNotFoundError,
  PolicyNotFoundError,
  SimulationError,
  SubmissionError,
  ValidationError,
  WebAuthnError,
  SessionError,
  ContractError,
  wrapError,
} from "./errors";

// Contract error decoding
export {
  CONTRACT_ERROR_REGISTRY,
  decodeContractError,
  contractErrorFromCode,
} from "./contract-errors";
export type {
  ContractErrorFamily,
  ContractErrorInfo,
} from "./contract-errors";

// Utility functions
export {
  xlmToStroops,
  stroopsToXlm,
  validateAddress,
  validateAmount,
  generateChallenge,
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
  // Compatibility helpers
  truncateAddress,
  describeSignerType,
  formatSignerForDisplay,
  formatContextType,
} from "./builders";
export {
  getCredentialIdFromSigner,
  signersEqual,
  getSignerKey,
  collectUniqueSigners,
} from "./signer-utils";

// Signer abstraction (Ed25519 + shared auth-digest core)
export { Ed25519Signer, computeEntryAuthDigest } from "./signers";
export type { AuthDigestSigner } from "./signers";

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

// Relayer client for fee-sponsored transactions via proxy
export { RelayerClient, RelayerErrorCodes } from "./relayer";
export type {
  RelayerResponse,
  RelayerSendOptions,
  RelayerErrorCode,
} from "./relayer";

// Wallet Adapters
export { StellarWalletsKitAdapter } from "./wallet-adapter";
export type { StellarWalletsKitAdapterConfig } from "./wallet-adapter";

// Re-export stellar-sdk types for convenience
export type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
