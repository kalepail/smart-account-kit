import type { contract } from "@stellar/stellar-sdk";
import type {
  SmartAccountConfig,
  StorageAdapter,
  StoredCredential,
  CreateWalletResult,
  ConnectWalletResult,
  TransactionResult,
  SubmissionOptions,
  SubmissionMethod,
  ExternalWalletAdapter,
  SelectedSigner,
  ConnectedWallet,
} from "../types";
import type {
  Client as SmartAccountClient,
  Signer as ContractSigner,
  ContextRuleType,
  WebAuthnSigData,
} from "smart-account-kit-bindings";

// Sub-manager Type Definitions

/** Signer management interface */
export interface SignerManager {
  /** Add a new passkey signer to a context rule */
  addPasskey(
    contextRuleId: number,
    appName: string,
    userName: string,
    options?: { nickname?: string }
  ): Promise<{
    credentialId: string;
    publicKey: Uint8Array;
    transaction: Awaited<ReturnType<SmartAccountClient["add_signer"]>>;
  }>;

  /** Add a delegated signer (Stellar account) to a context rule */
  addDelegated(
    contextRuleId: number,
    publicKey: string
  ): ReturnType<SmartAccountClient["add_signer"]>;

  /** Remove a signer from a context rule */
  remove(
    contextRuleId: number,
    signer: ContractSigner
  ): ReturnType<SmartAccountClient["remove_signer"]>;

  /** Remove a passkey signer by credential ID */
  removePasskey(
    contextRuleId: number,
    credentialId: string
  ): ReturnType<SmartAccountClient["remove_signer"]>;
}

/** Context rule management interface */
export interface ContextRuleManager {
  /** Add a new context rule */
  add(
    contextType: ContextRuleType,
    name: string,
    signers: ContractSigner[],
    policies: Map<string, unknown>,
    validUntil?: number
  ): ReturnType<SmartAccountClient["add_context_rule"]>;

  /** Get a context rule by ID */
  get(contextRuleId: number): ReturnType<SmartAccountClient["get_context_rule"]>;

  /** Get all context rules of a specific type */
  getAll(contextRuleType: ContextRuleType): ReturnType<SmartAccountClient["get_context_rules"]>;

  /** Remove a context rule */
  remove(contextRuleId: number): ReturnType<SmartAccountClient["remove_context_rule"]>;

  /** Update the name of a context rule */
  updateName(
    contextRuleId: number,
    name: string
  ): ReturnType<SmartAccountClient["update_context_rule_name"]>;

  /** Update the expiration of a context rule */
  updateExpiration(
    contextRuleId: number,
    validUntil?: number
  ): ReturnType<SmartAccountClient["update_context_rule_valid_until"]>;
}

/** Policy management interface */
export interface PolicyManager {
  /** Add a policy to a context rule */
  add(
    contextRuleId: number,
    policyAddress: string,
    installParams: unknown
  ): ReturnType<SmartAccountClient["add_policy"]>;

  /** Remove a policy from a context rule */
  remove(
    contextRuleId: number,
    policyAddress: string
  ): ReturnType<SmartAccountClient["remove_policy"]>;
}

/** Credential storage management interface */
export interface CredentialManager {
  /** Get all stored credentials */
  getAll(): Promise<StoredCredential[]>;

  /** Get credentials for the current wallet */
  getForWallet(): Promise<StoredCredential[]>;

  /** Get credentials that are pending deployment */
  getPending(): Promise<StoredCredential[]>;

  /**
   * Create a new passkey and save it to storage.
   * This handles the full WebAuthn registration flow internally.
   *
   * Use this to create passkeys for context rules without deploying a new wallet.
   * The passkey can later be added to a context rule as a signer.
   *
   * @param options - Creation options
   * @param options.nickname - Display name for the credential
   * @param options.appName - App name shown in authenticator (defaults to hostname)
   * @returns The created and stored credential
   *
   * @example
   * ```typescript
   * // Create a new passkey for adding to a context rule
   * const credential = await kit.credentials.create({ nickname: "Recovery Key" });
   *
   * // Later, add it as a signer to a context rule
   * const signer = createWebAuthnSigner(
   *   webauthnVerifierAddress,
   *   credential.publicKey,
   *   credential.credentialId
   * );
   * ```
   */
  create(options?: {
    nickname?: string;
    appName?: string;
  }): Promise<StoredCredential>;

  /**
   * Save a credential to storage.
   * Use this to import credentials created externally (e.g., passkeys created
   * for context rules that haven't been deployed yet).
   *
   * @param credential - The credential to save. At minimum requires:
   *   - credentialId: Base64URL encoded credential ID
   *   - publicKey: 65-byte secp256r1 public key
   * @param credential.credentialId - Base64URL encoded credential ID (required)
   * @param credential.publicKey - 65-byte secp256r1 public key (required)
   * @param credential.nickname - Optional display name
   * @param credential.verifierAddress - Optional verifier contract address
   * @param credential.contractId - Optional contract ID (empty string if not deployed)
   */
  save(credential: {
    credentialId: string;
    publicKey: Uint8Array;
    nickname?: string;
    verifierAddress?: string;
    contractId?: string;
  }): Promise<StoredCredential>;

  /** Deploy a wallet using an existing pending credential */
  deploy(
    credentialId: string,
    options?: { autoSubmit?: boolean }
  ): Promise<{
    contractId: string;
    signedTransaction: string;
    submitResult?: TransactionResult;
  }>;

  /** Clean up a credential from storage after successful deployment */
  markDeployed(credentialId: string): Promise<void>;

  /** Manually mark a credential as failed */
  markFailed(credentialId: string, error?: string): Promise<void>;

  /** Check if a credential's contract exists on-chain */
  sync(credentialId: string): Promise<boolean>;

  /** Sync all stored credentials with on-chain state */
  syncAll(): Promise<{ deployed: number; pending: number; failed: number }>;

  /** Delete a pending credential that was never deployed */
  delete(credentialId: string): Promise<void>;
}

/** Options for multi-signer operations */
export interface MultiSignerOptions {
  /** Logger function */
  onLog?: (message: string, type?: "info" | "success" | "error") => void;
}

/** Multi-signer management interface */
export interface MultiSignerManager {
  /**
   * Execute a generic smart account operation with multiple signers.
   * Takes a pre-built AssembledTransaction and handles the multi-signer flow.
   *
   * External signers must be registered via kit.externalSigners before calling.
   *
   * @param assembledTx - The AssembledTransaction from kit operations
   * @param selectedSigners - Array of signers to use for signing
   * @param options - Additional options (onLog)
   */
  operation<T>(
    assembledTx: contract.AssembledTransaction<T>,
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions
  ): Promise<TransactionResult>;

  /**
   * Execute a transfer with multiple signers.
   *
   * External signers must be registered via kit.externalSigners before calling.
   *
   * @param tokenContract - Token contract address
   * @param recipient - Recipient address
   * @param amount - Amount to transfer (in token units)
   * @param selectedSigners - Array of signers to use
   * @param options - Additional options (onLog)
   */
  transfer(
    tokenContract: string,
    recipient: string,
    amount: number,
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions
  ): Promise<TransactionResult>;

  /**
   * Get all available signers from on-chain context rules.
   */
  getAvailableSigners(): Promise<ContractSigner[]>;

  /**
   * Extract credential ID from an External signer's key_data.
   */
  extractCredentialId(signer: ContractSigner): string | null;

  /**
   * Check if a signer matches a given credential ID.
   */
  signerMatchesCredential(signer: ContractSigner, credentialId: string): boolean;

  /**
   * Check if a signer is a delegated signer for a given address.
   */
  signerMatchesAddress(signer: ContractSigner, address: string): boolean;

  /**
   * Check if multi-signer flow is needed for a set of signers.
   *
   * Returns true if:
   * - There are delegated signers (need external wallet signature)
   * - There are multiple signers (user may need to select which to use)
   *
   * @param signers - Array of signers to check
   */
  needsMultiSigner(signers: ContractSigner[]): boolean;

  /**
   * Build SelectedSigner array from signers for multi-signer operations.
   *
   * Determines which signers to use based on their type:
   * - Delegated signers → wallet signature needed
   * - External signers with credential ID → passkey signature needed
   *
   * @param signers - Array of signers
   * @param activeCredentialId - Optional active credential ID to prioritize
   */
  buildSelectedSigners(signers: ContractSigner[], activeCredentialId?: string | null): SelectedSigner[];
}

// These are public SDK types re-exported by kit.ts and index.ts.
export type {
  SmartAccountConfig,
  StorageAdapter,
  StoredCredential,
  CreateWalletResult,
  ConnectWalletResult,
  TransactionResult,
  SubmissionOptions,
  SubmissionMethod,
  ExternalWalletAdapter,
  SelectedSigner,
  ConnectedWallet,
  ContractSigner,
  WebAuthnSigData,
};
