/**
 * SmartAccountKit - Client-side SDK for Smart Account Management
 *
 * This is the main entry point for client applications to create and manage
 * smart wallets secured by WebAuthn passkeys.
 */

import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import {
  hash,
  xdr,
  Keypair,
  Address,
  TransactionBuilder,
  Operation,
  Transaction,
  rpc,
  contract,
} from "@stellar/stellar-sdk";
import base64url from "base64url";

const { Server: RpcServer, assembleTransaction } = rpc;
const { AssembledTransaction } = contract;

import type {
  SmartAccountConfig,
  StorageAdapter,
  StoredCredential,
  CreateWalletResult,
  ConnectWalletResult,
  TransactionResult,
  SubmissionOptions,
  ExternalWalletAdapter,
  SelectedSigner,
  ConnectedWallet,
} from "./types";
import { MemoryStorage } from "./storage/memory";
import {
  Client as SmartAccountClient,
  Signer as ContractSigner,
  ContextRuleType,
  WebAuthnSigData,
} from "smart-account-kit-bindings";

// Constants
import {
  WEBAUTHN_TIMEOUT_MS,
  BASE_FEE,
  FRIENDBOT_RESERVE_XLM,
  DEFAULT_SESSION_EXPIRY_MS,
  SECP256R1_PUBLIC_KEY_SIZE,
} from "./constants";

// Error classes
import {
  ValidationError,
  SmartAccountErrorCode,
} from "./errors";

// Utility functions
import {
  validateAddress,
  validateAmount,
  xlmToStroops,
  stroopsToXlm,
  buildKeyData,
  deriveContractAddress,
  extractPublicKeyFromAttestation,
  compactSignature,
  generateChallenge,
} from "./utils";

// Event emitter
import { SmartAccountEventEmitter } from "./events";

// External signer management
import { ExternalSignerManager, type ExternalSigner } from "./external-signers";

// Indexer client for contract discovery
import {
  IndexerClient,
  DEFAULT_INDEXER_URLS,
  type IndexedContractSummary,
  type ContractDetailsResponse,
} from "./indexer";

// Launchtube client for fee-sponsored transactions
import { LaunchtubeClient } from "./launchtube";

// Manager classes
import {
  SignerManager as SignerManagerClass,
  ContextRuleManager as ContextRuleManagerClass,
  PolicyManager as PolicyManagerClass,
  CredentialManager as CredentialManagerClass,
  MultiSignerManager as MultiSignerManagerClass,
} from "./managers";

// SignerId is the same type as Signer - used for signature map keys
type ContractSignerId = ContractSigner;

// ==========================================================================
// Sub-manager Type Definitions
// ==========================================================================

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


/**
 * External signer management interface.
 *
 * Provides unified management of G-address signers (Stellar accounts) for
 * multi-signature operations. Supports two methods:
 * 1. Raw secret key - stored in memory only (never persisted)
 * 2. External wallet via StellarWalletsKit (optional)
 *
 * @example
 * ```typescript
 * // Add from raw secret key (memory-only)
 * const { address } = kit.externalSigners.addFromSecret("S...");
 *
 * // Add from external wallet (if SWK configured)
 * const wallet = await kit.externalSigners.addFromWallet();
 *
 * // Check if we can sign for an address
 * if (kit.externalSigners.canSignFor("G...")) {
 *   // SDK will automatically use this signer during multi-sig operations
 * }
 * ```
 */

/**
 * SmartAccountKit - Main client SDK for smart account management
 *
 * @example
 * ```typescript
 * const kit = new SmartAccountKit({
 *   rpcUrl: 'https://soroban-testnet.stellar.org',
 *   networkPassphrase: 'Test SDF Network ; September 2015',
 *   accountWasmHash: '...',
 *   webauthnVerifierAddress: 'C...',
 * });
 *
 * // Create a new wallet
 * const { credentialId, contractId, signedTransaction } = await kit.createWallet('MyApp', 'user@example.com');
 *
 * // Connect to existing wallet
 * const { contractId } = await kit.connectWallet({ credentialId: 'savedCredentialId' });
 *
 * // Sign a transaction
 * const signedTx = await kit.sign(transaction);
 * ```
 */
export class SmartAccountKit {
  // Network configuration
  public readonly rpcUrl: string;
  public readonly networkPassphrase: string;
  public readonly rpc: InstanceType<typeof RpcServer>;

  // Contract configuration
  private readonly accountWasmHash: string;
  private readonly webauthnVerifierAddress: string;
  private readonly timeoutInSeconds: number;

  // WebAuthn configuration
  private readonly rpId?: string;
  private readonly rpName: string;
  private readonly webAuthn: {
    startRegistration: typeof startRegistration;
    startAuthentication: typeof startAuthentication;
  };

  // Storage
  private readonly storage: StorageAdapter;

  // External wallet adapter (optional)
  private readonly externalWalletAdapter?: ExternalWalletAdapter;

  // Session configuration
  private readonly sessionExpiryMs: number;

  // State
  private _credentialId?: string;
  private _contractId?: string;

  /** Smart account contract client (after connection) */
  public wallet?: SmartAccountClient;

  // Deployer keypair (used as source account for contract deployment)
  private readonly deployerKeypair: Keypair;

  // ==========================================================================
  // Sub-managers for organized access to contract methods
  // ==========================================================================

  /**
   * Signer management methods.
   * Add, remove, and manage signers on context rules.
   */
  public readonly signers: SignerManagerClass;

  /**
   * Context rule management methods.
   * Create, read, update, and delete context rules.
   */
  public readonly rules: ContextRuleManagerClass;

  /**
   * Policy management methods.
   * Add and remove policies from context rules.
   */
  public readonly policies: PolicyManagerClass;

  /**
   * Credential storage management methods.
   * Manage locally stored credentials for pending deployments.
   */
  public readonly credentials: CredentialManagerClass;

  /**
   * Event emitter for credential lifecycle events.
   * Subscribe to events like walletConnected, credentialCreated, etc.
   *
   * @example
   * ```typescript
   * kit.events.on('walletConnected', ({ contractId }) => {
   *   console.log('Connected to wallet:', contractId);
   * });
   * ```
   */
  public readonly events: SmartAccountEventEmitter;

  /**
   * Multi-signer operations.
   * Execute transactions that require multiple signers (passkeys + external wallets).
   *
   * @example
   * ```typescript
   * const selectedSigners = [
   *   { type: 'passkey', credentialId: 'abc123', label: 'My Passkey' },
   *   { type: 'wallet', walletAddress: 'G...', label: 'Freighter' },
   * ];
   * const result = await kit.multiSigners.transfer(
   *   tokenContract, recipient, amount, selectedSigners
   * );
   * ```
   */
  public readonly multiSigners: MultiSignerManagerClass;

  /**
   * External signer management.
   * Unified interface for managing G-address signers (Stellar accounts) for
   * multi-signature operations.
   *
   * Supports two methods of adding signers:
   * 1. Raw secret key (Keypair) - stored in memory only
   * 2. External wallet via StellarWalletsKit (if configured)
   *
   * @example
   * ```typescript
   * // Add from raw secret key (memory-only, lost on refresh)
   * const { address } = kit.externalSigners.addFromSecret("S...");
   *
   * // Add from external wallet (if SWK configured)
   * const wallet = await kit.externalSigners.addFromWallet();
   *
   * // List all external signers
   * const signers = kit.externalSigners.getAll();
   *
   * // Check if we can sign for an address
   * if (kit.externalSigners.canSignFor("G...")) {
   *   // SDK will automatically use this signer during multi-sig operations
   * }
   * ```
   */
  public readonly externalSigners: ExternalSignerManager;

  /**
   * Indexer client for discovering smart account contracts.
   *
   * The indexer enables reverse lookups from signer credentials to contracts,
   * which is essential for discovering which contracts a user has access to.
   *
   * This is automatically configured for known networks (testnet) if not
   * explicitly disabled via `indexerUrl: false` in the config.
   *
   * @example
   * ```typescript
   * // Check if indexer is available
   * if (kit.indexer) {
   *   // Discover contracts by credential ID
   *   const { contracts } = await kit.indexer.lookupByCredentialId(credentialId);
   *
   *   // Discover contracts by G-address
   *   const { contracts } = await kit.indexer.lookupByAddress('GABCD...');
   *
   *   // Get full contract details
   *   const details = await kit.indexer.getContractDetails('CABC...');
   * }
   * ```
   */
  public readonly indexer: IndexerClient | null;

  /**
   * Optional Launchtube client for fee-sponsored transaction submission.
   *
   * When configured, allows submitting transactions without paying fees -
   * the fees are sponsored by the Launchtube service.
   *
   * @example
   * ```typescript
   * // Configure Launchtube in the kit
   * const kit = new SmartAccountKit({
   *   // ... other config
   *   launchtube: {
   *     url: 'https://launchtube.xyz',
   *     jwt: 'your-jwt-token',
   *   },
   * });
   *
   * // Submit a transaction via Launchtube
   * if (kit.launchtube) {
   *   const result = await kit.launchtube.send(signedTransaction);
   *   console.log('Hash:', result.hash);
   * }
   * ```
   */
  public readonly launchtube: LaunchtubeClient | null;

  constructor(config: SmartAccountConfig) {
    // Validate required config
    if (!config.rpcUrl) throw new Error("rpcUrl is required");
    if (!config.networkPassphrase) throw new Error("networkPassphrase is required");
    if (!config.accountWasmHash) throw new Error("accountWasmHash is required");
    if (!config.webauthnVerifierAddress) throw new Error("webauthnVerifierAddress is required");

    // Network
    this.rpcUrl = config.rpcUrl;
    this.networkPassphrase = config.networkPassphrase;
    this.rpc = new RpcServer(config.rpcUrl);

    // Contracts
    this.accountWasmHash = config.accountWasmHash;
    this.webauthnVerifierAddress = config.webauthnVerifierAddress;
    this.timeoutInSeconds = config.timeoutInSeconds ?? 30;

    // WebAuthn
    this.rpId = config.rpId;
    this.rpName = config.rpName ?? "Smart Account";
    this.webAuthn = config.webAuthn ?? { startRegistration, startAuthentication };

    // Storage (default to memory if not provided)
    this.storage = config.storage ?? new MemoryStorage();

    // External wallet adapter (optional)
    this.externalWalletAdapter = config.externalWallet;

    // Session configuration
    this.sessionExpiryMs = config.sessionExpiryMs ?? DEFAULT_SESSION_EXPIRY_MS;

    // Indexer client for contract discovery
    // - If indexerUrl is explicitly set to false, disable indexer
    // - If indexerUrl is a string, use that URL
    // - Otherwise, try to use default URL for the network
    if (config.indexerUrl === false) {
      this.indexer = null;
    } else if (typeof config.indexerUrl === "string") {
      this.indexer = new IndexerClient({ baseUrl: config.indexerUrl });
    } else {
      // Try to use default URL for this network
      const defaultUrl = DEFAULT_INDEXER_URLS[this.networkPassphrase];
      this.indexer = defaultUrl
        ? new IndexerClient({ baseUrl: defaultUrl })
        : null;
    }

    // Launchtube client for fee-sponsored transactions (optional)
    // Only initialize if url is provided
    this.launchtube = config.launchtube?.url
      ? new LaunchtubeClient(config.launchtube)
      : null;

    // Deployer keypair - deterministically derived from network passphrase
    // This ensures the same deployer is used across all clients on the same network
    this.deployerKeypair = Keypair.fromRawEd25519Seed(
      hash(Buffer.from("openzeppelin-smart-account-kit"))
    );

    // Event emitter (initialized first as other managers may use it)
    this.events = new SmartAccountEventEmitter();

    // External signer manager - unified interface for G-address signers
    // Use localStorage for wallet persistence if available (browser environment)
    const walletStorage = typeof localStorage !== "undefined" ? localStorage : undefined;

    this.externalSigners = new ExternalSignerManager(
      this.networkPassphrase,
      this.externalWalletAdapter,
      walletStorage
    );

    // Initialize sub-managers with dependencies
    this.signers = new SignerManagerClass({
      requireWallet: () => this.requireWallet(),
      storage: this.storage,
      events: this.events,
      webauthnVerifierAddress: this.webauthnVerifierAddress,
      createPasskey: (appName, userName) => this.createPasskey(appName, userName),
    });

    this.rules = new ContextRuleManagerClass({
      requireWallet: () => this.requireWallet(),
    });

    this.policies = new PolicyManagerClass({
      requireWallet: () => this.requireWallet(),
    });

    this.credentials = new CredentialManagerClass({
      storage: this.storage,
      rpc: this.rpc,
      events: this.events,
      webauthnVerifierAddress: this.webauthnVerifierAddress,
      rpName: this.rpName,
      networkPassphrase: this.networkPassphrase,
      deployerKeypair: this.deployerKeypair,
      getContractId: () => this._contractId,
      setConnectedState: (contractId, credentialId) => {
        this._contractId = contractId;
        this._credentialId = credentialId;
      },
      initializeWallet: (contractId) => this.initializeWallet(contractId),
      createPasskey: (appName, userName) => this.createPasskey(appName, userName),
      buildDeployTransaction: (contractId, credentialIdBuffer, publicKey) =>
        this.buildDeployTransaction(contractId, credentialIdBuffer, publicKey),
      signWithDeployer: (tx) => this.signWithDeployer(tx as contract.AssembledTransaction<null>),
      submitDeploymentTx: (tx, credentialId, options) =>
        this.submitDeploymentTx(tx as contract.AssembledTransaction<null>, credentialId, options),
      deriveContractAddress: (credentialIdBuffer) =>
        deriveContractAddress(credentialIdBuffer, this.deployerKeypair.publicKey(), this.networkPassphrase),
      shouldUseLaunchtube: (options) => this.shouldUseLaunchtube(options),
    });

    this.multiSigners = new MultiSignerManagerClass({
      getContractId: () => this._contractId,
      isConnected: () => this.isConnected,
      getRules: (contextRuleType) => this.rules.getAll(contextRuleType),
      externalSigners: this.externalSigners,
      rpc: this.rpc,
      networkPassphrase: this.networkPassphrase,
      timeoutInSeconds: this.timeoutInSeconds,
      deployerKeypair: this.deployerKeypair,
      deployerPublicKey: this.deployerPublicKey,
      signAuthEntry: (entry, options) => this.signAuthEntry(entry, options),
      sendAndPoll: (tx) => this.sendAndPoll(tx),
      hasSourceAccountAuth: (tx) => this.hasSourceAccountAuth(tx),
      executeTransfer: (tokenContract, recipient, amount, selectedSigners, options) =>
        this.multiSignersTransfer(tokenContract, recipient, amount, selectedSigners, options),
      shouldUseLaunchtube: (options) => this.shouldUseLaunchtube(options),
    });
  }

  // ==========================================================================
  // Getters
  // ==========================================================================

  /** Currently connected credential ID (Base64URL encoded) */
  get credentialId(): string | undefined {
    return this._credentialId;
  }

  /** Currently connected contract ID */
  get contractId(): string | undefined {
    return this._contractId;
  }

  /** Check if connected to a wallet */
  get isConnected(): boolean {
    return !!this._contractId;
  }

  /**
   * Get the deployer public key (used as fee payer for transactions)
   *
   * This is a deterministic keypair derived from the network passphrase,
   * shared across all SDK instances on the same network.
   */
  get deployerPublicKey(): string {
    return this.deployerKeypair.publicKey();
  }

  // ==========================================================================
  // Contract Discovery (Indexer)
  // ==========================================================================

  /**
   * Discover smart account contracts associated with a credential ID.
   *
   * This uses the indexer to perform a reverse lookup from the credential ID
   * to find all contracts where this credential is registered as a signer.
   *
   * @param credentialId - The credential ID to look up (hex or base64url encoded)
   * @returns Array of contract summaries, or null if indexer is not available
   *
   * @example
   * ```typescript
   * // After WebAuthn authentication, find contracts for the credential
   * const contracts = await kit.discoverContractsByCredential(credentialId);
   * if (contracts && contracts.length > 0) {
   *   // User has access to these contracts
   *   console.log(`Found ${contracts.length} smart accounts`);
   * }
   * ```
   */
  async discoverContractsByCredential(
    credentialId: string
  ): Promise<IndexedContractSummary[] | null> {
    if (!this.indexer) return null;

    // Convert base64url to hex if needed
    const hexCredentialId = this.normalizeCredentialIdToHex(credentialId);

    const result = await this.indexer.lookupByCredentialId(hexCredentialId);
    return result.contracts;
  }

  /**
   * Discover smart account contracts associated with a Stellar address.
   *
   * This works for both G-addresses (Delegated signers) and C-addresses
   * (External signer verifier contracts).
   *
   * @param address - Stellar address (G... or C...)
   * @returns Array of contract summaries, or null if indexer is not available
   *
   * @example
   * ```typescript
   * // Find contracts where this G-address is a delegated signer
   * const contracts = await kit.discoverContractsByAddress('GABCD...');
   * ```
   */
  async discoverContractsByAddress(
    address: string
  ): Promise<IndexedContractSummary[] | null> {
    if (!this.indexer) return null;

    const result = await this.indexer.lookupByAddress(address);
    return result.contracts;
  }

  /**
   * Get detailed information about a smart account contract from the indexer.
   *
   * Returns the current state including active context rules, signers, and policies.
   * This is useful for displaying contract details without making on-chain calls.
   *
   * Note: For real-time data, use `kit.rules.getAll()` instead which queries on-chain.
   *
   * @param contractId - Smart account contract address (C...)
   * @returns Contract details or null if not found/indexer unavailable
   */
  async getContractDetailsFromIndexer(
    contractId: string
  ): Promise<ContractDetailsResponse | null> {
    if (!this.indexer) return null;
    return this.indexer.getContractDetails(contractId);
  }

  /**
   * Convert a credential ID to hex format.
   * Handles both base64url and hex inputs.
   * @internal
   */
  private normalizeCredentialIdToHex(credentialId: string): string {
    // If it looks like hex (only hex chars), return as-is
    if (/^[0-9a-fA-F]+$/.test(credentialId)) {
      return credentialId.toLowerCase();
    }

    // Otherwise, assume base64url and convert to hex
    try {
      const bytes = base64url.toBuffer(credentialId);
      return bytes.toString("hex");
    } catch {
      // If conversion fails, return original (let the API handle validation)
      return credentialId.toLowerCase();
    }
  }

  // ==========================================================================
  // Private Helpers - Connection Guards
  // ==========================================================================

  /**
   * Require that a wallet is connected and return the wallet client and contract ID.
   * Throws if not connected.
   * @internal
   */
  private requireWallet(): { wallet: SmartAccountClient; contractId: string } {
    if (!this._contractId || !this.wallet) {
      throw new Error("Not connected to a wallet");
    }
    return { wallet: this.wallet, contractId: this._contractId };
  }

  /**
   * Initialize the wallet client for a contract.
   * @internal
   */
  private initializeWallet(contractId: string): void {
    this.wallet = new SmartAccountClient({
      contractId,
      networkPassphrase: this.networkPassphrase,
      rpcUrl: this.rpcUrl,
    });
  }

  /**
   * Sign an assembled transaction with the deployer keypair.
   * @internal
   */
  private async signWithDeployer<T>(
    tx: contract.AssembledTransaction<T>
  ): Promise<void> {
    await tx.sign({
      signTransaction: async (txXdr: string) => {
        const parsedTx = TransactionBuilder.fromXDR(txXdr, this.networkPassphrase);
        parsedTx.sign(this.deployerKeypair);
        return {
          signedTxXdr: parsedTx.toXDR(),
          signerAddress: this.deployerKeypair.publicKey(),
        };
      },
    });
  }

  /**
   * Calculate expiration ledger from current ledger.
   * @internal
   */
  private async calculateExpiration(): Promise<number> {
    const { sequence } = await this.rpc.getLatestLedger();
    return sequence + Math.ceil(this.timeoutInSeconds / 5); // ~5 second ledgers
  }

  /**
   * Submit a deployment transaction and update credential storage.
   * On success, deletes the credential from storage.
   * On failure, marks it as failed for retry.
   * @internal
   */
  private async submitDeploymentTx<T>(
    tx: contract.AssembledTransaction<T>,
    credentialId: string,
    options?: SubmissionOptions
  ): Promise<TransactionResult> {
    try {
      let hash: string;
      let ledger: number | undefined;

      // Use Launchtube if configured and not explicitly skipped
      // Must use tx.signed (not tx.built) so the deployer's signature is preserved
      if (this.shouldUseLaunchtube(options) && tx.signed) {
        const launchtubeResult = await this.launchtube!.send(tx.signed);

        if (!launchtubeResult.success) {
          throw new Error(launchtubeResult.error ?? "Launchtube submission failed");
        }

        hash = launchtubeResult.hash ?? "";

        // Poll for confirmation
        const txResult = await this.rpc.pollTransaction(hash, { attempts: 10 });
        if (txResult.status === "SUCCESS") {
          ledger = txResult.ledger;
        } else if (txResult.status === "FAILED") {
          throw new Error("Transaction failed on-chain");
        }
      } else {
        // Use SDK's built-in send()
        const sentTx = await tx.send();
        const txResponse = sentTx.getTransactionResponse;
        hash = sentTx.sendTransactionResponse?.hash ?? "";
        ledger = txResponse?.status === "SUCCESS" ? txResponse.ledger : undefined;
      }

      // Success - delete credential from storage
      await this.storage.delete(credentialId);
      return {
        success: true,
        hash,
        ledger,
      };
    } catch (err) {
      const error = err instanceof Error ? err.message : "Transaction failed";
      // Failed - mark for retry
      await this.storage.update(credentialId, {
        deploymentStatus: "failed",
        deploymentError: error,
      });
      return {
        success: false,
        hash: "",
        error,
      };
    }
  }

  // ==========================================================================
  // Wallet Creation
  // ==========================================================================

  /**
   * Create a new smart wallet with a passkey as the primary signer
   *
   * @param appName - Application name (displayed to user during passkey creation)
   * @param userName - User identifier (displayed to user during passkey creation)
   * @param options - Additional options
   * @returns Wallet creation result with credential ID, contract ID, and signed transaction
   */
  async createWallet(
    appName: string,
    userName: string,
    options?: {
      nickname?: string;
      authenticatorSelection?: {
        authenticatorAttachment?: "platform" | "cross-platform";
        residentKey?: "discouraged" | "preferred" | "required";
        userVerification?: "discouraged" | "preferred" | "required";
      };
      /** If true, automatically submit and wait for confirmation. Default: false */
      autoSubmit?: boolean;
      /** If true and on testnet, fund the wallet via Friendbot after creation. Requires nativeTokenContract. */
      autoFund?: boolean;
      /** Native XLM token SAC address (required for autoFund) */
      nativeTokenContract?: string;
      /** Skip Launchtube and submit directly via RPC (default: false) */
      skipLaunchtube?: boolean;
    }
  ): Promise<CreateWalletResult & { submitResult?: TransactionResult; fundResult?: TransactionResult & { amount?: number } }> {
    // Step 1: Create a new passkey
    const { rawResponse, credentialId, publicKey } = await this.createPasskey(
      appName,
      userName,
      options?.authenticatorSelection
    );

    // Store credential as "pending" immediately after creation
    const storedCredential: StoredCredential = {
      credentialId,
      publicKey,
      contractId: deriveContractAddress(base64url.toBuffer(credentialId), this.deployerKeypair.publicKey(), this.networkPassphrase),
      nickname: options?.nickname ?? `${userName} - ${new Date().toLocaleDateString()}`,
      createdAt: Date.now(),
      transports: rawResponse?.response?.transports,
      isPrimary: true,
      deploymentStatus: "pending",
    };

    await this.storage.save(storedCredential);

    // Emit credential created event
    this.events.emit("credentialCreated", { credential: storedCredential });

    // Step 2: Derive contract address from credential ID
    const credentialIdBuffer = base64url.toBuffer(credentialId);
    const contractId = deriveContractAddress(credentialIdBuffer, this.deployerKeypair.publicKey(), this.networkPassphrase);

    // Step 3: Build and sign the deployment transaction
    const deployTx = await this.buildDeployTransaction(
      contractId,
      credentialIdBuffer,
      publicKey
    );

    // Sign the deployment transaction with the deployer keypair
    // Deployment uses source_account auth which requires envelope signature
    // This works with Launchtube because fee bump preserves inner tx signatures
    const submissionOpts = { skipLaunchtube: options?.skipLaunchtube };
    await this.signWithDeployer(deployTx);
    if (!deployTx.signed) {
      throw new Error("Failed to sign deployment transaction");
    }
    const signedTransaction = deployTx.signed.toXDR();

    // Step 4: Update state
    this._credentialId = credentialId;
    this._contractId = contractId;
    this.initializeWallet(contractId);

    // Emit wallet connected event
    this.events.emit("walletConnected", { contractId, credentialId });

    // Save session for future auto-connect
    const now = Date.now();
    await this.storage.saveSession({
      contractId,
      credentialId,
      connectedAt: now,
      expiresAt: now + this.sessionExpiryMs,
    });

    // Step 5: Optionally auto-submit using SDK's send() with exponential backoff
    const submitResult = options?.autoSubmit
      ? await this.submitDeploymentTx(deployTx, credentialId, submissionOpts)
      : undefined;

    // Step 6: Optionally fund the wallet on testnet (only if deployment succeeded)
    let fundResult: (TransactionResult & { amount?: number }) | undefined;
    if (options?.autoFund && submitResult?.success) {
      if (!options.nativeTokenContract) {
        fundResult = { success: false, hash: "", error: "nativeTokenContract is required for autoFund" };
      } else {
        fundResult = await this.fundWallet(options.nativeTokenContract, submissionOpts);
      }
    }

    return {
      rawResponse,
      credentialId,
      publicKey,
      contractId,
      signedTransaction,
      submitResult,
      fundResult,
    };
  }

  /**
   * Create a passkey without deploying a wallet.
   * Used internally for wallet creation and adding passkey signers.
   *
   * @internal
   */
  private async createPasskey(
    appName: string,
    userName: string,
    authenticatorSelection?: {
      authenticatorAttachment?: "platform" | "cross-platform";
      residentKey?: "discouraged" | "preferred" | "required";
      userVerification?: "discouraged" | "preferred" | "required";
    }
  ): Promise<{
    rawResponse: RegistrationResponseJSON;
    credentialId: string;
    publicKey: Uint8Array;
  }> {
    const now = new Date();
    const displayName = `${userName} — ${now.toLocaleString()}`;

    const options: PublicKeyCredentialCreationOptionsJSON = {
      challenge: generateChallenge(),
      rp: {
        id: this.rpId,
        name: appName || this.rpName,
      },
      user: {
        id: base64url(`${userName}:${now.getTime()}:${Math.random()}`),
        name: displayName,
        displayName,
      },
      authenticatorSelection: {
        residentKey: authenticatorSelection?.residentKey ?? "preferred",
        userVerification: authenticatorSelection?.userVerification ?? "preferred",
        authenticatorAttachment: authenticatorSelection?.authenticatorAttachment,
      },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }], // ES256 (P-256)
      timeout: WEBAUTHN_TIMEOUT_MS,
    };

    const rawResponse = await this.webAuthn.startRegistration({ optionsJSON: options });
    const publicKey = await extractPublicKeyFromAttestation(rawResponse.response);

    return {
      rawResponse,
      credentialId: rawResponse.id,
      publicKey,
    };
  }

  // ==========================================================================
  // Wallet Connection
  // ==========================================================================

  /**
   * Authenticate with a passkey without connecting to a specific contract.
   *
   * This is useful when you need to:
   * 1. Get the credential ID first
   * 2. Use the indexer to discover which contracts the passkey has access to
   * 3. Then connect to a specific contract using connectWallet({ contractId, credentialId })
   *
   * @returns The credential ID from the selected passkey
   *
   * @example
   * ```typescript
   * // Step 1: Authenticate to get credential ID
   * const { credentialId } = await kit.authenticatePasskey();
   *
   * // Step 2: Discover contracts via indexer
   * const contracts = await kit.discoverContractsByCredential(credentialId);
   *
   * // Step 3: Let user choose or connect to the first one
   * if (contracts && contracts.length > 0) {
   *   await kit.connectWallet({
   *     contractId: contracts[0].contract_id,
   *     credentialId
   *   });
   * }
   * ```
   */
  async authenticatePasskey(): Promise<{ credentialId: string; rawResponse: AuthenticationResponseJSON }> {
    const authOptions: PublicKeyCredentialRequestOptionsJSON = {
      challenge: generateChallenge(),
      rpId: this.rpId,
      userVerification: "preferred",
      timeout: WEBAUTHN_TIMEOUT_MS,
    };

    const rawResponse = await this.webAuthn.startAuthentication({ optionsJSON: authOptions });

    return {
      credentialId: rawResponse.id,
      rawResponse,
    };
  }

  /**
   * Connect to an existing smart wallet
   *
   * Behavior based on options:
   * - No options: Silent restore from storage, returns null if no stored session
   * - `{ prompt: true }`: Try stored session first, prompt user if none
   * - `{ fresh: true }`: Ignore stored session, always prompt user
   * - `{ credentialId }`: Connect using specific credential ID
   * - `{ contractId }`: Connect using specific contract ID
   *
   * @param options - Connection options
   * @returns Connection result, or null if no session and not prompting
   *
   * @example
   * ```typescript
   * // Page load - silent restore
   * const result = await kit.connectWallet();
   * if (!result) showConnectButton();
   *
   * // User clicks "Connect Wallet"
   * await kit.connectWallet({ prompt: true });
   *
   * // User clicks "Switch Wallet"
   * await kit.connectWallet({ fresh: true });
   * ```
   */
  async connectWallet(options?: {
    /** Use specific credential ID */
    credentialId?: string;
    /** Use specific contract ID */
    contractId?: string;
    /** Ignore stored session, always prompt user */
    fresh?: boolean;
    /** Prompt user if no stored session (default: false) */
    prompt?: boolean;
  }): Promise<ConnectWalletResult | null> {
    let credentialId = options?.credentialId;
    let contractId = options?.contractId;
    let rawResponse: AuthenticationResponseJSON | undefined;

    // If explicit credential or contract provided, use those
    if (credentialId || contractId) {
      return this.connectWithCredentials(credentialId, contractId);
    }

    // Check for stored session (unless fresh is requested)
    if (!options?.fresh) {
      const session = await this.storage.getSession();
      if (session) {
        // Check if session has expired
        if (session.expiresAt && Date.now() > session.expiresAt) {
          // Session expired - clear it and continue as if no session
          this.events.emit("sessionExpired", {
            contractId: session.contractId,
            credentialId: session.credentialId,
          });
          await this.storage.clearSession();
        } else {
          return this.connectWithCredentials(session.credentialId, session.contractId);
        }
      }
    }

    // No stored session - should we prompt?
    if (!options?.prompt && !options?.fresh) {
      // Silent mode with no session - return null
      return null;
    }

    // Prompt user to select a passkey
    const authOptions: PublicKeyCredentialRequestOptionsJSON = {
      challenge: generateChallenge(),
      rpId: this.rpId,
      userVerification: "preferred",
      timeout: WEBAUTHN_TIMEOUT_MS,
    };

    rawResponse = await this.webAuthn.startAuthentication({ optionsJSON: authOptions });
    credentialId = rawResponse.id;

    // Connect with the selected credential
    const result = await this.connectWithCredentials(credentialId);
    return {
      ...result,
      rawResponse,
    };
  }

  /**
   * Internal helper to connect with known credentials
   */
  private async connectWithCredentials(
    credentialId?: string,
    contractId?: string
  ): Promise<ConnectWalletResult> {
    // Try to find the credential in storage
    let credential: StoredCredential | null = null;
    if (credentialId) {
      credential = await this.storage.get(credentialId);
      if (credential) {
        contractId = credential.contractId;
      }
    }

    // If no contract ID yet, try to derive it from credential ID
    if (!contractId && credentialId) {
      const credentialIdBuffer = base64url.toBuffer(credentialId);
      contractId = deriveContractAddress(credentialIdBuffer, this.deployerKeypair.publicKey(), this.networkPassphrase);
    }

    if (!contractId) {
      throw new Error("Could not determine contract ID");
    }

    if (!credentialId) {
      throw new Error("Could not determine credential ID");
    }

    // Verify the contract exists on-chain
    try {
      await this.rpc.getContractData(
        contractId,
        xdr.ScVal.scvLedgerKeyContractInstance()
      );
    } catch {
      // Update credential status if we have it in storage
      if (credential && credential.deploymentStatus !== "failed") {
        await this.storage.update(credentialId, {
          deploymentStatus: "pending",
        });
      }
      throw new Error(
        `Smart account contract not found on-chain for credential ${credentialId}. ` +
        "The wallet may not have been deployed yet."
      );
    }

    // Contract exists - clean up pending credential from storage if present
    if (credential) {
      await this.storage.delete(credentialId);
    }

    // Update state
    this._credentialId = credentialId;
    this._contractId = contractId;
    this.initializeWallet(contractId);

    // Emit wallet connected event
    this.events.emit("walletConnected", { contractId, credentialId });

    // Save session for future auto-connect
    const now = Date.now();
    await this.storage.saveSession({
      contractId,
      credentialId,
      connectedAt: now,
      expiresAt: now + this.sessionExpiryMs,
    });

    return {
      credentialId,
      contractId,
      credential: credential ?? undefined,
    };
  }

  /**
   * Disconnect from the current wallet and clear stored session
   */
  async disconnect(): Promise<void> {
    const contractId = this._contractId;
    this._credentialId = undefined;
    this._contractId = undefined;
    this.wallet = undefined;
    await this.storage.clearSession();

    // Emit wallet disconnected event
    if (contractId) {
      this.events.emit("walletDisconnected", { contractId });
    }
  }

  // ==========================================================================
  // Transaction Signing
  // ==========================================================================

  /**
   * Sign a transaction's auth entries with a passkey.
   *
   * **IMPORTANT**: This method only signs authorization entries. It does NOT
   * re-simulate the transaction. For WebAuthn signatures, you MUST re-simulate
   * before submission because WebAuthn signatures are much larger than the
   * placeholders used during initial simulation.
   *
   * For most use cases, prefer `signAndSubmit()` which handles the full flow:
   * sign → re-simulate → assemble → submit.
   *
   * @param transaction - AssembledTransaction to sign
   * @param options - Signing options
   * @returns The transaction with signed auth entries (NOT ready for direct submission)
   */
  async sign<T>(
    transaction: contract.AssembledTransaction<T>,
    options?: {
      credentialId?: string;
      expiration?: number;
    }
  ): Promise<contract.AssembledTransaction<T>> {
    if (!this._contractId) {
      throw new Error("Not connected to a wallet. Call connectWallet() first.");
    }

    const credentialId = options?.credentialId ?? this._credentialId;

    // Get expiration ledger
    const expiration = options?.expiration ?? await this.calculateExpiration();

    // Sign each authorization entry for this contract
    await transaction.signAuthEntries({
      address: this._contractId,
      authorizeEntry: async (entry: xdr.SorobanAuthorizationEntry) => {
        const clone = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
        return this.signAuthEntry(clone, { credentialId, expiration });
      },
    });

    return transaction;
  }

  /**
   * Sign and submit a transaction with proper re-simulation for WebAuthn.
   *
   * This is the recommended method for submitting transactions signed by the
   * smart account's passkey. It handles the full flow:
   * 1. Sign authorization entries with WebAuthn
   * 2. Re-simulate with signed entries (required for accurate resource costs)
   * 3. Assemble the transaction with correct fees
   * 4. Sign with fee payer and submit
   *
   * @param transaction - AssembledTransaction to sign and submit
   * @param options - Signing options
   * @returns Transaction result
   */
  async signAndSubmit<T>(
    transaction: contract.AssembledTransaction<T>,
    options?: {
      credentialId?: string;
      expiration?: number;
      /** Skip Launchtube and submit directly via RPC (default: false) */
      skipLaunchtube?: boolean;
    }
  ): Promise<TransactionResult> {
    if (!this._contractId) {
      return { success: false, hash: "", error: "Not connected to a wallet. Call connectWallet() first." };
    }

    try {
      // Extract the operation from the transaction
      const builtTx = transaction.built;
      if (!builtTx) {
        return { success: false, hash: "", error: "Transaction has no built transaction" };
      }

      const operations = builtTx.operations;
      if (operations.length !== 1) {
        return { success: false, hash: "", error: "Expected exactly one operation" };
      }

      const operation = operations[0];
      if (operation.type !== "invokeHostFunction") {
        return { success: false, hash: "", error: "Expected invokeHostFunction operation" };
      }

      // Cast to the proper type after the type guard
      const invokeOp = operation as Operation.InvokeHostFunction;

      // Get auth entries from the transaction's simulation
      const simData = transaction.simulationData;
      if (!simData?.result?.auth) {
        return { success: false, hash: "", error: "No simulation data or auth entries" };
      }

      // Sign and re-simulate
      const preparedTx = await this.signResimulateAndPrepare(
        invokeOp.func,
        simData.result.auth,
        { credentialId: options?.credentialId, expiration: options?.expiration }
      );

      // Sign with deployer keypair if not using Launchtube, or if tx has source_account auth
      // (source_account auth requires envelope signature; Address auth has signature in entry)
      const submissionOpts = { skipLaunchtube: options?.skipLaunchtube };
      if (!this.shouldUseLaunchtube(submissionOpts) || this.hasSourceAccountAuth(preparedTx)) {
        preparedTx.sign(this.deployerKeypair);
      }

      // Submit and poll
      return this.sendAndPoll(preparedTx, submissionOpts);
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  /**
   * Sign a single authorization entry with a passkey.
   *
   * This is a low-level method useful for multi-signer flows.
   * For most use cases, prefer:
   * - `signAndSubmit()` for full sign + re-simulate + submit flow
   * - `sign()` to sign auth entries on an AssembledTransaction
   * - `multiSigners.operation()` for multi-signer operations
   *
   * @param entry - The authorization entry to sign
   * @param options - Signing options (credentialId, expiration)
   * @returns The signed authorization entry
   */
  async signAuthEntry(
    entry: xdr.SorobanAuthorizationEntry,
    options?: {
      credentialId?: string;
      expiration?: number;
    }
  ): Promise<xdr.SorobanAuthorizationEntry> {
    // Convert the entry to our own XDR types by round-tripping through XDR bytes.
    // This is necessary because the entry may come from a different stellar-sdk
    // module instance (e.g., full SDK vs minimal SDK, or Vite module duplication),
    // which causes instanceof checks and XDR type constructors to fail.
    const entryXdrBytes = entry.toXDR();
    const normalizedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entryXdrBytes);

    const credentials = normalizedEntry.credentials().address();

    // Set expiration - always calculate if not provided
    const expiration = options?.expiration ?? await this.calculateExpiration();
    credentials.signatureExpirationLedger(expiration);

    // Calculate signature payload
    const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
      new xdr.HashIdPreimageSorobanAuthorization({
        networkId: hash(Buffer.from(this.networkPassphrase)),
        nonce: credentials.nonce(),
        signatureExpirationLedger: credentials.signatureExpirationLedger(),
        invocation: normalizedEntry.rootInvocation(),
      })
    );
    const payload = hash(preimage.toXDR());

    // Get the credential ID to use
    const credentialId = options?.credentialId ?? this._credentialId;

    // Authenticate with WebAuthn
    const authOptions: PublicKeyCredentialRequestOptionsJSON = {
      challenge: base64url(payload),
      rpId: this.rpId,
      userVerification: "preferred",
      timeout: WEBAUTHN_TIMEOUT_MS,
      ...(credentialId && {
        allowCredentials: [{ id: credentialId, type: "public-key" }],
      }),
    };

    const authResponse = await this.webAuthn.startAuthentication({
      optionsJSON: authOptions,
    });

    // Process the signature
    const rawSignature = base64url.toBuffer(authResponse.response.signature);
    const compactedSignature = compactSignature(rawSignature);

    // Look up the full key_data from on-chain signers by matching credential ID suffix
    const credentialIdBuffer = base64url.toBuffer(authResponse.id);
    const keyData = await this.findKeyDataByCredentialId(credentialIdBuffer);

    // Build the SignerId for the contract
    // External signers use (verifier_address, key_data)
    // key_data = pubkey (65 bytes) + credentialId (variable bytes)
    const signerId: ContractSignerId = {
      tag: "External",
      values: [
        this.webauthnVerifierAddress, // verifier address
        keyData, // full key_data (pubkey + credentialId)
      ],
    };

    // Build the WebAuthn signature data
    const webAuthnSigData = {
      authenticator_data: base64url.toBuffer(authResponse.response.authenticatorData),
      client_data: base64url.toBuffer(authResponse.response.clientDataJSON),
      signature: Buffer.from(compactedSignature),
    };

    // Encode the signature using the wallet client's spec
    const scMapEntry = this.buildSignatureMapEntry(signerId, webAuthnSigData);

    // Add signature to credentials
    const currentSig = credentials.signature();
    if (currentSig.switch().name === "scvVoid") {
      credentials.signature(xdr.ScVal.scvVec([xdr.ScVal.scvMap([scMapEntry])]));
    } else {
      currentSig.vec()?.[0].map()?.push(scMapEntry);
    }

    // Sort the signature map entries by key (required for Soroban maps)
    // Soroban maps must be sorted by key XDR bytes
    const sigMap = credentials.signature().vec()?.[0].map();
    if (sigMap && sigMap.length > 1) {
      sigMap.sort((a, b) => {
        const aKeyXdr = a.key().toXDR("hex");
        const bKeyXdr = b.key().toXDR("hex");
        return aKeyXdr.localeCompare(bKeyXdr);
      });
    }

    // Update last used time
    if (credentialId) {
      await this.storage.update(credentialId, { lastUsedAt: Date.now() });
    }

    return normalizedEntry;
  }

  // ==========================================================================
  // Transaction Helpers
  // ==========================================================================

  /**
   * Fund a wallet on testnet using Friendbot
   *
   * Only works on Stellar testnet. Creates a temporary account, funds it
   * via Friendbot, then transfers XLM to the smart account contract.
   * This is necessary because Friendbot can't fund contract addresses directly.
   *
   * @param nativeTokenContract - Native XLM token SAC address (required for transfer)
   * @param options - Optional settings
   * @returns Whether the funding was successful, and the amount funded
   */
  async fundWallet(
    nativeTokenContract: string,
    options?: {
      /** Skip Launchtube and submit directly via RPC (default: false) */
      skipLaunchtube?: boolean;
    }
  ): Promise<TransactionResult & { amount?: number }> {
    if (!this._contractId) {
      return { success: false, hash: "", error: "Not connected to a wallet" };
    }

    // Check if we're on testnet
    if (!this.networkPassphrase.includes("Test")) {
      return {
        success: false,
        hash: "",
        error: "fundWallet() only works on testnet",
      };
    }

    try {
      // Step 1: Create a temporary keypair
      const tempKeypair = Keypair.random();

      // Step 2: Fund it with Friendbot
      const friendbotResponse = await fetch(
        `https://friendbot.stellar.org?addr=${tempKeypair.publicKey()}`
      );

      if (!friendbotResponse.ok) {
        const text = await friendbotResponse.text();
        return { success: false, hash: "", error: `Friendbot error: ${text}` };
      }

      // Step 3: Get the account balance via token contract and calculate transfer amount
      // Keep 5 XLM for fees and minimum balance
      const RESERVE_XLM = FRIENDBOT_RESERVE_XLM;
      let sourceAccount = await this.rpc.getAccount(tempKeypair.publicKey());

      // Query token contract for balance
      const tokenAddress = Address.fromString(nativeTokenContract);
      const fromAddress = Address.fromString(tempKeypair.publicKey());

      const balanceKey = xdr.ScVal.scvVec([
        xdr.ScVal.scvSymbol("Balance"),
        xdr.ScVal.scvAddress(fromAddress.toScAddress()),
      ]);

      let balanceXlm: number;
      try {
        const balanceData = await this.rpc.getContractData(
          nativeTokenContract,
          balanceKey
        );
        // Balance is stored as i128 in the contract data
        const val = balanceData.val.contractData().val();
        if (val.switch().name === "scvI128") {
          const i128 = val.i128();
          const lo = BigInt(i128.lo().toString());
          const hi = BigInt(i128.hi().toString());
          const balanceStroops = (hi << BigInt(64)) | lo;
          balanceXlm = stroopsToXlm(balanceStroops);
        } else {
          // Friendbot gives 10,000 XLM, fallback to that
          balanceXlm = 10_000;
        }
      } catch (error) {
        // If balance query fails, assume Friendbot default of 10,000 XLM
        console.warn("[SmartAccountKit] Failed to fetch temp account balance, using default:", error);
        balanceXlm = 10_000;
      }

      const transferAmount = balanceXlm - RESERVE_XLM;

      if (transferAmount <= 0) {
        return { success: false, hash: "", error: "Insufficient balance after reserve" };
      }

      // Step 4: Build a transfer transaction from temp account to smart wallet
      const amountInStroops = xlmToStroops(transferAmount);

      // Build the transfer call
      const toAddress = Address.fromString(this._contractId);

      // Create the transfer operation
      const transferOp = Operation.invokeHostFunction({
        func: xdr.HostFunction.hostFunctionTypeInvokeContract(
          new xdr.InvokeContractArgs({
            contractAddress: tokenAddress.toScAddress(),
            functionName: "transfer",
            args: [
              xdr.ScVal.scvAddress(fromAddress.toScAddress()),
              xdr.ScVal.scvAddress(toAddress.toScAddress()),
              xdr.ScVal.scvI128(
                new xdr.Int128Parts({
                  lo: xdr.Uint64.fromString((amountInStroops & BigInt("0xFFFFFFFFFFFFFFFF")).toString()),
                  hi: xdr.Int64.fromString((amountInStroops >> BigInt(64)).toString()),
                })
              ),
            ],
          })
        ),
        auth: [],
      });

      // Build transaction for simulation
      const simulationTx = new TransactionBuilder(sourceAccount, {
        fee: BASE_FEE,
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(transferOp)
        .setTimeout(30)
        .build();

      // Simulate
      const simResult = await this.rpc.simulateTransaction(simulationTx);

      if ("error" in simResult) {
        return { success: false, hash: "", error: `Simulation failed: ${simResult.error}` };
      }

      // Get auth entries and sign them with temp keypair
      const authEntries = simResult.result?.auth || [];
      const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];

      for (const entry of authEntries) {
        if (entry.credentials().switch().name !== "sorobanCredentialsAddress") {
          signedAuthEntries.push(entry);
          continue;
        }

        const credentials = entry.credentials().address();
        const currentLedger = simResult.latestLedger;
        credentials.signatureExpirationLedger(currentLedger + 100);

        // Calculate signature payload
        const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
          new xdr.HashIdPreimageSorobanAuthorization({
            networkId: hash(Buffer.from(this.networkPassphrase)),
            nonce: credentials.nonce(),
            signatureExpirationLedger: credentials.signatureExpirationLedger(),
            invocation: entry.rootInvocation(),
          })
        );
        const payload = hash(preimage.toXDR());

        // Sign with temp keypair
        const signature = tempKeypair.sign(payload);

        // Build Ed25519 signature format
        const sigEntry = new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("public_key"),
          val: xdr.ScVal.scvBytes(tempKeypair.rawPublicKey()),
        });
        const sigEntrySignature = new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("signature"),
          val: xdr.ScVal.scvBytes(signature),
        });

        credentials.signature(
          xdr.ScVal.scvVec([xdr.ScVal.scvMap([sigEntry, sigEntrySignature])])
        );

        signedAuthEntries.push(entry);
      }

      // Get fresh account
      sourceAccount = await this.rpc.getAccount(tempKeypair.publicKey());

      // Get the invoke host function from simulation
      const invokeHostFn = simulationTx.operations[0] as Operation.InvokeHostFunction;

      // Build transaction with signed auth entries
      const txWithAuth = new TransactionBuilder(sourceAccount, {
        fee: BASE_FEE,
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(
          Operation.invokeHostFunction({
            func: invokeHostFn.func,
            auth: signedAuthEntries,
          })
        )
        .setTimeout(30)
        .build();

      // Convert to XDR and back to normalize the Transaction type
      // This is needed because bundlers (Vite) may create multiple SDK instances
      const txWithAuthXdr = txWithAuth.toXDR();
      const normalizedTxWithAuth = TransactionBuilder.fromXDR(txWithAuthXdr, this.networkPassphrase);

      // Use SDK's assembleTransaction to apply fees and soroban data
      const preparedTx = assembleTransaction(normalizedTxWithAuth as Transaction, simResult).build();

      // Sign with temp keypair if not using Launchtube, or if tx has source_account auth
      // (source_account auth requires envelope signature; Address auth has signature in entry)
      const submissionOpts = { skipLaunchtube: options?.skipLaunchtube };
      if (!this.shouldUseLaunchtube(submissionOpts) || this.hasSourceAccountAuth(preparedTx)) {
        preparedTx.sign(tempKeypair);
      }

      // Submit and poll for confirmation
      const txResult = await this.sendAndPoll(preparedTx, submissionOpts);

      return {
        ...txResult,
        amount: txResult.success ? transferAmount : undefined,
      };
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  /**
   * Transfer tokens from the smart wallet to a recipient
   *
   * This handles the full flow: build transaction, simulate, sign auth entries
   * with passkey, re-simulate for accurate resources, and submit.
   *
   * The deployer keypair is used as the fee payer (transaction source).
   *
   * @param tokenContract - Token contract address (SAC address for native assets)
   * @param recipient - Recipient address (G... or C...)
   * @param amount - Amount to transfer (in token units, e.g., 10 for 10 XLM)
   * @param options - Transfer options
   * @returns Transfer result
   */
  async transfer(
    tokenContract: string,
    recipient: string,
    amount: number,
    options?: {
      /** Credential ID to use for signing (defaults to connected credential) */
      credentialId?: string;
      /** Skip Launchtube and submit directly via RPC (default: false) */
      skipLaunchtube?: boolean;
    }
  ): Promise<TransactionResult> {
    if (!this._contractId) {
      return { success: false, hash: "", error: "Not connected to a wallet" };
    }

    // Validate inputs
    try {
      validateAddress(tokenContract, "tokenContract");
      validateAddress(recipient, "recipient");
      validateAmount(amount, "amount");
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Validation failed",
      };
    }

    // Prevent self-transfer
    if (recipient === this._contractId) {
      return {
        success: false,
        hash: "",
        error: "Cannot transfer to self",
      };
    }

    try {
      // Convert amount to stroops (7 decimal places for XLM/SAC tokens)
      const amountInStroops = xlmToStroops(amount);

      // Build the transfer host function
      const tokenAddress = Address.fromString(tokenContract);
      const fromAddress = Address.fromString(this._contractId);
      const toAddress = Address.fromString(recipient);

      const hostFunc = xdr.HostFunction.hostFunctionTypeInvokeContract(
        new xdr.InvokeContractArgs({
          contractAddress: tokenAddress.toScAddress(),
          functionName: "transfer",
          args: [
            xdr.ScVal.scvAddress(fromAddress.toScAddress()),
            xdr.ScVal.scvAddress(toAddress.toScAddress()),
            xdr.ScVal.scvI128(
              new xdr.Int128Parts({
                lo: xdr.Uint64.fromString((amountInStroops & BigInt("0xFFFFFFFFFFFFFFFF")).toString()),
                hi: xdr.Int64.fromString((amountInStroops >> BigInt(64)).toString()),
              })
            ),
          ],
        })
      );

      // Initial simulation to get auth entries
      const { authEntries } = await this.simulateHostFunction(hostFunc);

      // Sign, re-simulate, and prepare the transaction
      const preparedTx = await this.signResimulateAndPrepare(
        hostFunc,
        authEntries,
        { credentialId: options?.credentialId }
      );

      // Sign with deployer keypair if not using Launchtube, or if tx has source_account auth
      // (source_account auth requires envelope signature; Address auth has signature in entry)
      const submissionOpts = { skipLaunchtube: options?.skipLaunchtube };
      if (!this.shouldUseLaunchtube(submissionOpts) || this.hasSourceAccountAuth(preparedTx)) {
        preparedTx.sign(this.deployerKeypair);
      }

      // Submit and poll for confirmation
      return this.sendAndPoll(preparedTx, submissionOpts);
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  // ==========================================================================
  // Private Helpers
  // ==========================================================================

  /**
   * Check if a transaction has any auth entries using source_account credentials.
   *
   * When auth uses source_account credentials, the authorization comes from the
   * transaction envelope signature, so we MUST sign even when using Launchtube.
   * For Address credentials, the authorization is in the auth entry itself.
   *
   * @param transaction - The transaction to check
   * @returns true if any auth entry uses source_account credentials
   * @internal
   */
  private hasSourceAccountAuth(transaction: Transaction): boolean {
    for (const op of transaction.operations) {
      if (op.type !== "invokeHostFunction") continue;

      const invokeOp = op as Operation.InvokeHostFunction;
      if (!invokeOp.auth) continue;

      for (const entry of invokeOp.auth) {
        if (entry.credentials().switch().name === "sorobanCredentialsSourceAccount") {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Find the full key_data for an External signer by matching credential ID suffix.
   *
   * This method looks up on-chain context rules to find a signer whose key_data
   * ends with the given credential ID. The key_data format is:
   * pubkey (65 bytes) + credentialId (variable bytes)
   *
   * @param credentialId - The credential ID to search for
   * @returns The full key_data buffer (pubkey + credentialId)
   * @throws If no matching signer is found
   * @internal
   */
  private async findKeyDataByCredentialId(credentialId: Buffer): Promise<Buffer> {
    const { wallet } = this.requireWallet();

    // Get default context rules (most common case for primary signers)
    const rulesResult = await wallet.get_context_rules({
      context_rule_type: { tag: "Default", values: undefined },
    });
    const rules = rulesResult.result;

    // Iterate through all rules and signers to find matching credential ID suffix
    for (const rule of rules) {
      for (const signer of rule.signers) {
        if (signer.tag === "External") {
          // External signer has 2 values: [verifierAddress, keyData]
          const keyData = signer.values[1] as Buffer;
          if (keyData.length > SECP256R1_PUBLIC_KEY_SIZE) {
            // key_data format: pubkey (65 bytes) + credentialId (variable bytes)
            const suffix = keyData.slice(SECP256R1_PUBLIC_KEY_SIZE);
            if (suffix.equals(credentialId)) {
              return keyData;
            }
          }
        }
      }
    }

    throw new Error(
      `No signer found for credential ID: ${credentialId.toString("base64")}`
    );
  }

  /**
   * Simulate a host function to get auth entries
   */
  private async simulateHostFunction(
    hostFunc: xdr.HostFunction
  ): Promise<{ authEntries: xdr.SorobanAuthorizationEntry[] }> {
    const sourceAccount = await this.rpc.getAccount(this.deployerKeypair.publicKey());

    const simulationTx = new TransactionBuilder(sourceAccount, {
      fee: BASE_FEE,
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(
        Operation.invokeHostFunction({
          func: hostFunc,
          auth: [],
        })
      )
      .setTimeout(this.timeoutInSeconds)
      .build();

    const simResult = await this.rpc.simulateTransaction(simulationTx);

    if ("error" in simResult) {
      throw new Error(`Simulation failed: ${simResult.error}`);
    }

    return {
      authEntries: simResult.result?.auth || [],
    };
  }

  /**
   * Sign auth entries with WebAuthn, re-simulate, and prepare transaction for submission.
   *
   * This is the core helper that handles the WebAuthn-specific flow:
   * 1. Sign each auth entry with the passkey
   * 2. Rebuild transaction with signed auth
   * 3. Re-simulate to get accurate resource costs (WebAuthn signatures are large)
   * 4. Assemble transaction with correct fees and soroban data
   *
   * @returns Prepared transaction ready for fee payer signature and submission
   */
  private async signResimulateAndPrepare(
    hostFunc: xdr.HostFunction,
    authEntries: xdr.SorobanAuthorizationEntry[],
    options?: {
      credentialId?: string;
      expiration?: number;
    }
  ): Promise<Transaction> {
    // Sign all auth entries with passkey
    const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];
    for (const authEntry of authEntries) {
      const signedEntry = await this.signAuthEntry(authEntry, {
        credentialId: options?.credentialId,
        expiration: options?.expiration,
      });
      signedAuthEntries.push(signedEntry);
    }

    // Re-simulate with signed auth entries to get accurate resource requirements
    // WebAuthn signatures include authenticator_data, client_data, and signature
    // which are much larger than the empty placeholders from initial simulation
    const sourceAccount = await this.rpc.getAccount(this.deployerKeypair.publicKey());

    const resimTx = new TransactionBuilder(sourceAccount, {
      fee: BASE_FEE,
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(
        Operation.invokeHostFunction({
          func: hostFunc,
          auth: signedAuthEntries,
        })
      )
      .setTimeout(this.timeoutInSeconds)
      .build();

    const resimResult = await this.rpc.simulateTransaction(resimTx);

    if ("error" in resimResult) {
      throw new Error(`Re-simulation failed: ${resimResult.error}`);
    }

    // Convert to XDR and back to normalize the Transaction type
    // This is needed because bundlers (Vite) may create multiple SDK instances
    const resimTxXdr = resimTx.toXDR();
    const normalizedTx = TransactionBuilder.fromXDR(resimTxXdr, this.networkPassphrase);

    // Use SDK's assembleTransaction to apply fees and soroban data
    const assembled = assembleTransaction(normalizedTx as Transaction, resimResult);
    return assembled.build() as Transaction;
  }

  /**
   * Check if Launchtube should be used for this submission.
   * Launchtube is used by default when configured, unless explicitly skipped.
   */
  private shouldUseLaunchtube(options?: SubmissionOptions): boolean {
    if (!this.launchtube) return false;
    if (options?.skipLaunchtube) return false;
    return true;
  }

  /**
   * Send a transaction and poll for confirmation.
   * Uses Launchtube for fee sponsoring if configured (default), otherwise submits directly via RPC.
   * @param transaction - The transaction to submit
   * @param options - Submission options (use skipLaunchtube to bypass Launchtube)
   */
  private async sendAndPoll(
    transaction: Transaction,
    options?: SubmissionOptions
  ): Promise<TransactionResult> {
    let hash: string;

    // Use Launchtube if configured and not explicitly skipped
    if (this.shouldUseLaunchtube(options)) {
      const launchtubeResult = await this.launchtube!.send(transaction);

      if (!launchtubeResult.success) {
        return {
          success: false,
          hash: "",
          error: launchtubeResult.error ?? "Launchtube submission failed",
        };
      }

      hash = launchtubeResult.hash ?? "";
    } else {
      // Submit directly via RPC
      const sendResult = await this.rpc.sendTransaction(transaction);

      if (sendResult.status === "ERROR") {
        return {
          success: false,
          hash: sendResult.hash,
          error: sendResult.errorResult?.toXDR("base64") ?? "Transaction submission failed",
        };
      }

      hash = sendResult.hash;
    }

    // Use SDK's built-in pollTransaction with linear backoff
    const txResult = await this.rpc.pollTransaction(hash, {
      attempts: 10,
    });

    if (txResult.status === "SUCCESS") {
      return {
        success: true,
        hash,
        ledger: txResult.ledger,
      };
    }

    if (txResult.status === "FAILED") {
      return {
        success: false,
        hash,
        error: "Transaction failed on-chain",
      };
    }

    // Still NOT_FOUND after polling
    return {
      success: false,
      hash,
      error: "Transaction confirmation timed out",
    };
  }

  /**
   * Build a deployment transaction for the smart account contract
   * Returns an AssembledTransaction that can be signed and sent
   */
  private async buildDeployTransaction(
    contractId: string,
    credentialId: Buffer,
    publicKey: Uint8Array
  ) {
    // Build the signer for the contract
    // External signer: (verifier_address, key_data)
    // key_data = pubkey (65 bytes) + credentialId (variable bytes)
    const keyData = buildKeyData(publicKey, credentialId);
    const signer: ContractSigner = {
      tag: "External",
      values: [
        this.webauthnVerifierAddress, // verifier address
        keyData, // key_data (65-byte public key + credential ID)
      ],
    };

    // Deploy the contract using the generated bindings
    return SmartAccountClient.deploy(
      {
        signers: [signer],
        policies: new Map(), // No default policies
      },
      {
        networkPassphrase: this.networkPassphrase,
        rpcUrl: this.rpcUrl,
        wasmHash: this.accountWasmHash,
        publicKey: this.deployerKeypair.publicKey(),
        salt: hash(credentialId), // Deterministic salt from credential ID
        timeoutInSeconds: this.timeoutInSeconds,
      }
    );
  }

  /**
   * Build a signature map entry for the contract
   *
   * Encodes a SignerId and WebAuthn signature data into an XDR ScMapEntry
   * that can be added to the authorization signature map.
   */
  private buildSignatureMapEntry(
    signerId: ContractSignerId,
    sigData: WebAuthnSigData
  ): xdr.ScMapEntry {
    // Encode the SignerId as the key
    let keyVal: xdr.ScVal;
    if (signerId.tag === "Delegated") {
      // Delegated(Address)
      keyVal = xdr.ScVal.scvVec([
        xdr.ScVal.scvSymbol("Delegated"),
        xdr.ScVal.scvAddress(Address.fromString(signerId.values[0]).toScAddress()),
      ]);
    } else {
      // External(Address, Bytes) = (verifier, key_data)
      // key_data = pubkey (65 bytes) + credentialId (variable bytes)
      keyVal = xdr.ScVal.scvVec([
        xdr.ScVal.scvSymbol("External"),
        xdr.ScVal.scvAddress(Address.fromString(signerId.values[0]).toScAddress()),
        xdr.ScVal.scvBytes(signerId.values[1]),
      ]);
    }

    // Encode the WebAuthnSigData struct as XDR bytes.
    // The verifier contract expects sig_data as Bytes containing XDR-encoded WebAuthnSigData.
    // Soroban structs are encoded as ScVal::Map with alphabetically sorted symbol keys.
    const sigDataScVal = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("authenticator_data"),
        val: xdr.ScVal.scvBytes(sigData.authenticator_data),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("client_data"),
        val: xdr.ScVal.scvBytes(sigData.client_data),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("signature"),
        val: xdr.ScVal.scvBytes(sigData.signature),
      }),
    ]);

    // XDR-encode the ScVal and wrap in scvBytes for the signature map value
    const sigDataXdrBytes = sigDataScVal.toXDR();
    const sigVal = xdr.ScVal.scvBytes(sigDataXdrBytes);

    return new xdr.ScMapEntry({
      key: keyVal,
      val: sigVal,
    });
  }

  // ==========================================================================
  // Multi-Signer Operations (private - access via kit.multiSigners.*)
  // ==========================================================================

  /**
   * Execute a transfer with multiple signers.
   * @internal Access via kit.multiSigners.transfer()
   */
  private async multiSignersTransfer(
    tokenContract: string,
    recipient: string,
    amount: number,
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions & { skipLaunchtube?: boolean }
  ): Promise<TransactionResult> {
    const onLog = options?.onLog ?? (() => {});

    if (!this._contractId) {
      return { success: false, hash: "", error: "Not connected to a wallet" };
    }

    // Separate passkey and wallet signers
    const passkeySigners = selectedSigners.filter((s) => s.type === "passkey");
    const walletSigners = selectedSigners.filter((s) => s.type === "wallet");

    onLog(`Signing with ${passkeySigners.length} passkey(s) and ${walletSigners.length} wallet(s)`);

    // Validate that we can sign for all required wallet addresses
    for (const walletSigner of walletSigners) {
      if (!walletSigner.walletAddress) continue;
      if (!this.externalSigners.canSignFor(walletSigner.walletAddress)) {
        return {
          success: false,
          hash: "",
          error: `No signer available for address: ${walletSigner.walletAddress}. ` +
            `Use kit.externalSigners.addFromSecret() or kit.externalSigners.addFromWallet() to add a signer.`,
        };
      }
    }

    try {
      // Convert amount to stroops (7 decimal places)
      const amountInStroops = BigInt(Math.round(amount * 10_000_000));

      // Build the transfer host function
      const tokenAddress = Address.fromString(tokenContract);
      const fromAddress = Address.fromString(this._contractId);
      const toAddress = Address.fromString(recipient);

      const hostFunc = xdr.HostFunction.hostFunctionTypeInvokeContract(
        new xdr.InvokeContractArgs({
          contractAddress: tokenAddress.toScAddress(),
          functionName: "transfer",
          args: [
            xdr.ScVal.scvAddress(fromAddress.toScAddress()),
            xdr.ScVal.scvAddress(toAddress.toScAddress()),
            xdr.ScVal.scvI128(
              new xdr.Int128Parts({
                lo: xdr.Uint64.fromString(
                  (amountInStroops & BigInt("0xFFFFFFFFFFFFFFFF")).toString()
                ),
                hi: xdr.Int64.fromString((amountInStroops >> BigInt(64)).toString()),
              })
            ),
          ],
        })
      );

      // Initial simulation
      onLog("Simulating transaction...");
      const sourceAccount = await this.rpc.getAccount(this.deployerPublicKey);

      const simulationTx = new TransactionBuilder(sourceAccount, {
        fee: BASE_FEE,
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(
          Operation.invokeHostFunction({
            func: hostFunc,
            auth: [],
          })
        )
        .setTimeout(this.timeoutInSeconds)
        .build();

      const simResult = await this.rpc.simulateTransaction(simulationTx);

      if ("error" in simResult) {
        return { success: false, hash: "", error: `Simulation failed: ${simResult.error}` };
      }

      const authEntries = simResult.result?.auth || [];
      onLog(`Found ${authEntries.length} auth entries to sign`);

      // Process each auth entry
      const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];
      const { sequence } = await this.rpc.getLatestLedger();
      const expiration = sequence + 100;

      for (const entry of authEntries) {
        // Check if this is for the smart account or a delegated signer
        const credentials = entry.credentials();

        if (credentials.switch().name !== "sorobanCredentialsAddress") {
          // Not an address credential, pass through
          signedAuthEntries.push(entry);
          continue;
        }

        const addressCreds = credentials.address();
        const authAddress = Address.fromScAddress(addressCreds.address()).toString();

        if (authAddress === this._contractId) {
          // This is the smart account's auth entry - sign with ALL selected signers
          let signedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
          signedEntry.credentials().address().signatureExpirationLedger(expiration);

          // Sign with ALL selected passkeys
          for (let i = 0; i < passkeySigners.length; i++) {
            const passkeySigner = passkeySigners[i];
            onLog(`Signing smart account auth entry with passkey ${i + 1}/${passkeySigners.length}...`);
            const credentialId = passkeySigner?.credentialId;
            signedEntry = await this.signAuthEntry(signedEntry, { credentialId, expiration });
          }

          // Add the delegated signers to the smart account's signature map
          for (const walletSigner of walletSigners) {
            if (!walletSigner.walletAddress) continue;

            const delegatedSignerKey = xdr.ScVal.scvVec([
              xdr.ScVal.scvSymbol("Delegated"),
              xdr.ScVal.scvAddress(Address.fromString(walletSigner.walletAddress).toScAddress()),
            ]);

            const ourSig = signedEntry.credentials().address().signature();
            const emptyBytes = xdr.ScVal.scvBytes(Buffer.alloc(0));

            if (ourSig.switch().name === "scvVoid") {
              signedEntry.credentials().address().signature(
                xdr.ScVal.scvVec([
                  xdr.ScVal.scvMap([
                    new xdr.ScMapEntry({ key: delegatedSignerKey, val: emptyBytes }),
                  ]),
                ])
              );
            } else {
              const sigMap = ourSig.vec()?.[0].map();
              if (sigMap) {
                sigMap.push(new xdr.ScMapEntry({ key: delegatedSignerKey, val: emptyBytes }));
                sigMap.sort((a, b) => a.key().toXDR("hex").localeCompare(b.key().toXDR("hex")));
              }
            }
          }

          signedAuthEntries.push(signedEntry);

          // Create SEPARATE auth entries for each delegated signer
          const smartAccountPreimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
            new xdr.HashIdPreimageSorobanAuthorization({
              networkId: hash(Buffer.from(this.networkPassphrase)),
              nonce: signedEntry.credentials().address().nonce(),
              signatureExpirationLedger: expiration,
              invocation: signedEntry.rootInvocation(),
            })
          );
          const signaturePayload = hash(smartAccountPreimage.toXDR());

          for (const walletSigner of walletSigners) {
            if (!walletSigner.walletAddress) continue;

            onLog(`Getting delegated auth from ${walletSigner.walletAddress.slice(0, 8)}...`);

            const delegatedNonce = xdr.Int64.fromString(Date.now().toString());

            const delegatedInvocation = new xdr.SorobanAuthorizedInvocation({
              function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
                new xdr.InvokeContractArgs({
                  contractAddress: Address.fromString(this._contractId!).toScAddress(),
                  functionName: "__check_auth",
                  args: [xdr.ScVal.scvBytes(signaturePayload)],
                })
              ),
              subInvocations: [],
            });

            const delegatedPreimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
              new xdr.HashIdPreimageSorobanAuthorization({
                networkId: hash(Buffer.from(this.networkPassphrase)),
                nonce: delegatedNonce,
                signatureExpirationLedger: expiration,
                invocation: delegatedInvocation,
              })
            );
            const delegatedPreimageXdr = delegatedPreimage.toXDR("base64");

            // Sign with the internal external signer manager
            const { signedAuthEntry: walletSignatureBase64 } = await this.externalSigners.signAuthEntry(
              delegatedPreimageXdr,
              walletSigner.walletAddress!
            );

            const signatureBytes = Buffer.from(walletSignatureBase64, "base64");
            const walletPublicKeyBytes = Address.fromString(walletSigner.walletAddress)
              .toScAddress()
              .accountId()
              .ed25519();

            const signatureScVal = xdr.ScVal.scvVec([
              xdr.ScVal.scvMap([
                new xdr.ScMapEntry({
                  key: xdr.ScVal.scvSymbol("public_key"),
                  val: xdr.ScVal.scvBytes(walletPublicKeyBytes),
                }),
                new xdr.ScMapEntry({
                  key: xdr.ScVal.scvSymbol("signature"),
                  val: xdr.ScVal.scvBytes(signatureBytes),
                }),
              ]),
            ]);

            const walletSignedEntry = new xdr.SorobanAuthorizationEntry({
              credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
                new xdr.SorobanAddressCredentials({
                  address: Address.fromString(walletSigner.walletAddress).toScAddress(),
                  nonce: delegatedNonce,
                  signatureExpirationLedger: expiration,
                  signature: signatureScVal,
                })
              ),
              rootInvocation: delegatedInvocation,
            });
            signedAuthEntries.push(walletSignedEntry);
          }
        } else {
          // This auth entry is for an address OTHER than the smart account
          const walletSigner = walletSigners.find(
            (s) => s.walletAddress === authAddress
          );

          if (walletSigner && this.externalSigners.canSignFor(authAddress)) {
            onLog(`Signing separate auth entry for ${authAddress.slice(0, 8)}...`);

            const entryClone = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
            entryClone.credentials().address().signatureExpirationLedger(expiration);

            const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
              new xdr.HashIdPreimageSorobanAuthorization({
                networkId: hash(Buffer.from(this.networkPassphrase)),
                nonce: entryClone.credentials().address().nonce(),
                signatureExpirationLedger: expiration,
                invocation: entryClone.rootInvocation(),
              })
            );
            const preimageXdr = preimage.toXDR("base64");

            const { signedAuthEntry: signatureBase64 } = await this.externalSigners.signAuthEntry(
              preimageXdr,
              authAddress
            );

            const signatureBytes = Buffer.from(signatureBase64, "base64");
            const publicKeyBytes = Address.fromString(authAddress)
              .toScAddress()
              .accountId()
              .ed25519();

            const signatureScVal = xdr.ScVal.scvVec([
              xdr.ScVal.scvMap([
                new xdr.ScMapEntry({
                  key: xdr.ScVal.scvSymbol("public_key"),
                  val: xdr.ScVal.scvBytes(publicKeyBytes),
                }),
                new xdr.ScMapEntry({
                  key: xdr.ScVal.scvSymbol("signature"),
                  val: xdr.ScVal.scvBytes(signatureBytes),
                }),
              ]),
            ]);

            entryClone.credentials().address().signature(signatureScVal);
            signedAuthEntries.push(entryClone);
          } else {
            onLog(`Warning: Unknown auth entry for ${authAddress}`, "error");
            signedAuthEntries.push(entry);
          }
        }
      }

      // Re-simulate with signed auth entries
      onLog("Re-simulating with signatures...");
      const freshSourceAccount = await this.rpc.getAccount(this.deployerPublicKey);

      const resimTx = new TransactionBuilder(freshSourceAccount, {
        fee: BASE_FEE,
        networkPassphrase: this.networkPassphrase,
      })
        .addOperation(
          Operation.invokeHostFunction({
            func: hostFunc,
            auth: signedAuthEntries,
          })
        )
        .setTimeout(this.timeoutInSeconds)
        .build();

      const resimResult = await this.rpc.simulateTransaction(resimTx);

      if ("error" in resimResult) {
        return { success: false, hash: "", error: `Re-simulation failed: ${resimResult.error}` };
      }

      // Assemble and prepare the transaction
      const resimTxXdr = resimTx.toXDR();
      const normalizedTx = TransactionBuilder.fromXDR(resimTxXdr, this.networkPassphrase);
      const assembled = assembleTransaction(normalizedTx as Transaction, resimResult);
      const preparedTx = assembled.build() as Transaction;

      // Sign with deployer keypair if not using Launchtube, or if tx has source_account auth
      // (source_account auth requires envelope signature; Address auth has signature in entry)
      const submissionOpts = { skipLaunchtube: options?.skipLaunchtube };
      if (!this.shouldUseLaunchtube(submissionOpts) || this.hasSourceAccountAuth(preparedTx)) {
        preparedTx.sign(this.deployerKeypair);
      }

      // Submit
      onLog("Submitting transaction...");
      return this.sendAndPoll(preparedTx, submissionOpts);
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  // ==========================================================================
  // Utility Methods
  // ==========================================================================

  /**
   * Convert policy parameters to ScVal format for on-chain submission.
   *
   * When adding policies via `kit.policies.add()`, the install parameters need
   * to be in ScVal format. This method converts native JavaScript objects to
   * the proper ScVal format based on the policy type.
   *
   * @param policyType - The type of policy: "threshold", "spending_limit", or "weighted_threshold"
   * @param params - The policy parameters as a native JavaScript object
   * @returns The parameters converted to ScVal format, or the original params if conversion fails
   *
   * @example
   * ```typescript
   * // Convert threshold policy params
   * const thresholdParams = kit.convertPolicyParams("threshold", { threshold: 2 });
   *
   * // Convert spending limit params
   * const spendingParams = kit.convertPolicyParams("spending_limit", {
   *   token: "CDLZFC3...",
   *   limit: 1000000000n,
   *   period: 8640, // ~1 day in ledgers
   * });
   *
   * // Use with policies.add()
   * const tx = await kit.policies.add(ruleId, policyAddress, thresholdParams);
   * ```
   */
  public convertPolicyParams(
    policyType: "threshold" | "spending_limit" | "weighted_threshold",
    params: unknown
  ): unknown {
    if (!this.wallet) {
      // No wallet connected - return params as-is
      return params;
    }

    // Map policy types to their UDT names in the contract spec
    const udtNames: Record<string, string> = {
      threshold: "SimpleThresholdAccountParams",
      spending_limit: "SpendingLimitAccountParams",
      weighted_threshold: "WeightedThresholdAccountParams",
    };

    const udtName = udtNames[policyType];
    if (!udtName) {
      return params;
    }

    try {
      // Create UDT type definition
      const udtType = xdr.ScSpecTypeDef.scSpecTypeUdt(
        new xdr.ScSpecTypeUdt({ name: udtName })
      );

      // Use the contract spec to convert native JS object to ScVal
      // The spec is accessible on the ContractClient as an internal property
      const walletObj = this.wallet as unknown as Record<string, unknown>;
      const spec = walletObj.spec as { nativeToScVal?: (val: unknown, type: xdr.ScSpecTypeDef) => xdr.ScVal } | undefined;
      if (spec && typeof spec.nativeToScVal === "function") {
        const scVal = spec.nativeToScVal(params, udtType);
        // Ensure ScMap entries are sorted by key (Soroban requirement)
        if (scVal.switch().name === "scvMap" && scVal.map()) {
          scVal.map()?.sort((a, b) => {
            // Sort by symbol name (for struct fields)
            const aKey = a.key().switch().name === "scvSymbol" ? a.key().sym().toString() : a.key().toXDR("hex");
            const bKey = b.key().switch().name === "scvSymbol" ? b.key().sym().toString() : b.key().toXDR("hex");
            return aKey.localeCompare(bKey);
          });
        }
        return scVal;
      }
      // Spec not available, fall back to raw params
      return params;
    } catch (error) {
      // Fall back to raw params if conversion fails
      console.warn("[SmartAccountKit] Failed to convert policy params to ScVal:", error);
      return params;
    }
  }

  /**
   * Build a sorted policies Map as ScVal for on-chain submission.
   *
   * Soroban requires ScMap keys to be sorted. This method converts a JavaScript
   * Map of policy addresses to params into a properly sorted ScVal.
   *
   * @param policies - Map of policy addresses (C...) to their params
   * @param policyTypes - Map of policy addresses to their types (for conversion)
   * @returns ScVal representing the sorted policies map
   */
  public buildPoliciesScVal(
    policies: Map<string, unknown>,
    policyTypes: Map<string, "threshold" | "spending_limit" | "weighted_threshold" | "custom">
  ): xdr.ScVal {
    if (!this.wallet) {
      throw new Error("Wallet not connected");
    }

    // Convert each policy to ScMapEntry
    const entries: xdr.ScMapEntry[] = [];

    for (const [address, params] of policies) {
      // Convert address to ScAddress
      const scAddress = new Address(address).toScVal();

      // Convert params to ScVal
      const policyType = policyTypes.get(address);
      let scParams: xdr.ScVal;

      if (policyType && policyType !== "custom") {
        const converted = this.convertPolicyParams(policyType, params);
        scParams = converted instanceof xdr.ScVal ? converted : xdr.ScVal.scvVoid();
      } else {
        // For custom policies, try to use nativeToScVal directly
        const walletObj = this.wallet as unknown as Record<string, unknown>;
        const spec = walletObj.spec as { nativeToScVal?: (val: unknown, type: xdr.ScSpecTypeDef) => xdr.ScVal } | undefined;
        if (spec && typeof spec.nativeToScVal === "function") {
          try {
            scParams = spec.nativeToScVal(params, xdr.ScSpecTypeDef.scSpecTypeVal());
          } catch {
            scParams = xdr.ScVal.scvVoid();
          }
        } else {
          scParams = xdr.ScVal.scvVoid();
        }
      }

      entries.push(new xdr.ScMapEntry({
        key: scAddress,
        val: scParams,
      }));
    }

    // Sort entries by key (ScAddress XDR comparison)
    entries.sort((a, b) => {
      const aXdr = a.key().toXDR("hex");
      const bXdr = b.key().toXDR("hex");
      return aXdr.localeCompare(bXdr);
    });

    return xdr.ScVal.scvMap(entries);
  }
}
