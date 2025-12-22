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
} from "@simplewebauthn/browser";
import {
  hash,
  xdr,
  Keypair,
  TransactionBuilder,
  Transaction,
  rpc,
  contract,
} from "@stellar/stellar-sdk";

const { Server: RpcServer } = rpc;
const { AssembledTransaction } = contract;

import type {
  SmartAccountConfig,
  StorageAdapter,
  CreateWalletResult,
  ConnectWalletResult,
  TransactionResult,
  SubmissionOptions,
  SubmissionMethod,
  ExternalWalletAdapter,
  SelectedSigner,
} from "./types";
import { MemoryStorage } from "./storage/memory";
import {
  Client as SmartAccountClient,
} from "smart-account-kit-bindings";

// Constants
import { DEFAULT_SESSION_EXPIRY_MS } from "./constants";

// Error classes
import {
  ValidationError,
  SmartAccountErrorCode,
} from "./errors";

// Utility functions
import { deriveContractAddress } from "./utils";

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

// Relayer client for fee-sponsored transactions via proxy
import { RelayerClient } from "./relayer";

// Manager classes
import {
  SignerManager as SignerManagerClass,
  ContextRuleManager as ContextRuleManagerClass,
  PolicyManager as PolicyManagerClass,
  CredentialManager as CredentialManagerClass,
  MultiSignerManager as MultiSignerManagerClass,
} from "./managers";

import type { MultiSignerOptions } from "./kit/public-types";
export type {
  SignerManager,
  ContextRuleManager,
  PolicyManager,
  CredentialManager,
  MultiSignerManager,
  MultiSignerOptions,
} from "./kit/public-types";

import {
  discoverContractsByCredential,
  discoverContractsByAddress,
  getContractDetailsFromIndexer,
} from "./kit/indexer-ops";
import {
  createPasskey,
  authenticatePasskey,
  signAuthEntry,
} from "./kit/webauthn-ops";
import {
  createWallet,
  connectWallet,
  connectWithCredentials,
  disconnect,
} from "./kit/wallet-ops";
import {
  buildDeployTransaction,
  submitDeploymentTx,
} from "./kit/deploy-ops";
import {
  sign,
  signAndSubmit,
  fundWallet,
  transfer,
  hasSourceAccountAuth,
  simulateHostFunction,
  signResimulateAndPrepare,
  getSubmissionMethod,
  shouldUseFeeSponsoring,
  sendAndPoll,
} from "./kit/tx-ops";
import { multiSignersTransfer } from "./kit/multi-signer-ops";
import { convertPolicyParams, buildPoliciesScVal } from "./kit/policies-ops";


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
   * Optional Relayer client for fee-sponsored transaction submission.
   *
   * When configured, allows submitting transactions without paying fees -
   * the fees are sponsored by the Relayer proxy service.
   *
   * The Relayer uses channel accounts for parallel transaction submission with
   * automatic fee bumping, eliminating sequence number conflicts.
   *
   * @example
   * ```typescript
   * // Configure Relayer in the kit
   * const kit = new SmartAccountKit({
   *   // ... other config
   *   relayerUrl: 'https://my-relayer-proxy.example.com/submit',
   * });
   *
   * // Submit a transaction via Relayer
   * if (kit.relayer) {
   *   const result = await kit.relayer.send(signedTransaction);
   *   console.log('Hash:', result.hash);
   * }
   * ```
   */
  public readonly relayer: RelayerClient | null;

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

    // Relayer client for fee-sponsored transactions via proxy (optional)
    // Only initialize if url is provided
    this.relayer = config.relayerUrl
      ? new RelayerClient(config.relayerUrl)
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
        buildDeployTransaction: (credentialIdBuffer, publicKey) =>
          this.buildDeployTransaction(credentialIdBuffer, publicKey),
      signWithDeployer: (tx) => this.signWithDeployer(tx as contract.AssembledTransaction<null>),
      submitDeploymentTx: (tx, credentialId, options) =>
        this.submitDeploymentTx(tx as contract.AssembledTransaction<null>, credentialId, options),
      deriveContractAddress: (credentialIdBuffer) =>
        deriveContractAddress(credentialIdBuffer, this.deployerKeypair.publicKey(), this.networkPassphrase),
      shouldUseFeeSponsoring: (options) => this.shouldUseFeeSponsoring(options),
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
      shouldUseFeeSponsoring: (options) => this.shouldUseFeeSponsoring(options),
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
    return discoverContractsByCredential(this.indexer, credentialId);
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
    return discoverContractsByAddress(this.indexer, address);
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
    return getContractDetailsFromIndexer(this.indexer, contractId);
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
   * Update connection state and initialize wallet client.
   * @internal
   */
  private setConnectedState(contractId: string, credentialId: string): void {
    this._contractId = contractId;
    this._credentialId = credentialId;
    this.initializeWallet(contractId);
  }

  /**
   * Clear connection state.
   * @internal
   */
  private clearConnectedState(): void {
    this._contractId = undefined;
    this._credentialId = undefined;
    this.wallet = undefined;
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
   *
   * Deployment uses source_account auth (envelope signature). When using Relayer,
   * the signed XDR is submitted for fee-bumping. The inner tx signature is preserved.
   *
   * @internal
   */
  private async submitDeploymentTx<T>(
    tx: contract.AssembledTransaction<T>,
    credentialId: string,
    options?: SubmissionOptions
  ): Promise<TransactionResult> {
    return submitDeploymentTx(
      { storage: this.storage, rpc: this.rpc, relayer: this.relayer },
      tx,
      credentialId,
      options
    );
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
      /** Force a specific submission method (relayer or rpc) */
      forceMethod?: SubmissionMethod;
    }
  ): Promise<CreateWalletResult & { submitResult?: TransactionResult; fundResult?: TransactionResult & { amount?: number } }> {
    return createWallet(
      {
        storage: this.storage,
        events: this.events,
        deployerKeypair: this.deployerKeypair,
        networkPassphrase: this.networkPassphrase,
        sessionExpiryMs: this.sessionExpiryMs,
        createPasskey: (name, user, selection) => this.createPasskey(name, user, selection),
        buildDeployTransaction: (credentialIdBuffer, publicKey) =>
          this.buildDeployTransaction(credentialIdBuffer, publicKey),
        signWithDeployer: (tx) => this.signWithDeployer(tx),
        submitDeploymentTx: (tx, credentialId, submissionOptions) =>
          this.submitDeploymentTx(tx, credentialId, submissionOptions),
        fundWallet: (nativeTokenContract, fundOptions) =>
          this.fundWallet(nativeTokenContract, fundOptions),
        setConnectedState: (contractId, credentialId) =>
          this.setConnectedState(contractId, credentialId),
      },
      appName,
      userName,
      options
    );
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
    return createPasskey(
      {
        rpId: this.rpId,
        rpName: this.rpName,
        webAuthn: this.webAuthn,
      },
      appName,
      userName,
      authenticatorSelection
    );
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
    return authenticatePasskey({
      rpId: this.rpId,
      rpName: this.rpName,
      webAuthn: this.webAuthn,
    });
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
    return connectWallet(
      {
        storage: this.storage,
        events: this.events,
        rpId: this.rpId,
        webAuthn: this.webAuthn,
        connectWithCredentials: (credentialId, contractId) =>
          this.connectWithCredentials(credentialId, contractId),
      },
      options
    );
  }

  /**
   * Internal helper to connect with known credentials
   */
  private async connectWithCredentials(
    credentialId?: string,
    contractId?: string
  ): Promise<ConnectWalletResult> {
    return connectWithCredentials(
      {
        storage: this.storage,
        rpc: this.rpc,
        deployerKeypair: this.deployerKeypair,
        networkPassphrase: this.networkPassphrase,
        sessionExpiryMs: this.sessionExpiryMs,
        events: this.events,
        setConnectedState: (nextContractId, nextCredentialId) =>
          this.setConnectedState(nextContractId, nextCredentialId),
      },
      credentialId,
      contractId
    );
  }

  /**
   * Disconnect from the current wallet and clear stored session
   */
  async disconnect(): Promise<void> {
    return disconnect({
      storage: this.storage,
      events: this.events,
      clearConnectedState: () => this.clearConnectedState(),
      getContractId: () => this._contractId,
    });
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
    const signed = await sign(
      {
        getContractId: () => this._contractId,
        getCredentialId: () => this._credentialId,
        calculateExpiration: () => this.calculateExpiration(),
        signAuthEntry: (entry, signOptions) => this.signAuthEntry(entry, signOptions),
      },
      transaction,
      options
    );

    return signed as contract.AssembledTransaction<T>;
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
      /** Force a specific submission method (relayer or rpc) */
      forceMethod?: SubmissionMethod;
    }
  ): Promise<TransactionResult> {
    return signAndSubmit(
      {
        getContractId: () => this._contractId,
        signResimulateAndPrepare: (hostFunc, authEntries, signOptions) =>
          this.signResimulateAndPrepare(hostFunc, authEntries, signOptions),
        shouldUseFeeSponsoring: (submissionOptions) =>
          this.shouldUseFeeSponsoring(submissionOptions),
        hasSourceAccountAuth: (preparedTx) => this.hasSourceAccountAuth(preparedTx),
        sendAndPoll: (preparedTx, submissionOptions) =>
          this.sendAndPoll(preparedTx, submissionOptions),
        deployerKeypair: this.deployerKeypair,
      },
      transaction,
      options
    );
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
    return signAuthEntry(
      {
        rpId: this.rpId,
        rpName: this.rpName,
        webAuthn: this.webAuthn,
        networkPassphrase: this.networkPassphrase,
        storage: this.storage,
        webauthnVerifierAddress: this.webauthnVerifierAddress,
        calculateExpiration: () => this.calculateExpiration(),
        getCredentialId: () => this._credentialId,
        requireWallet: () => this.requireWallet(),
      },
      entry,
      options
    );
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
      /** Force a specific submission method (relayer or rpc) */
      forceMethod?: SubmissionMethod;
    }
  ): Promise<TransactionResult & { amount?: number }> {
    return fundWallet(
      {
        getContractId: () => this._contractId,
        rpc: this.rpc,
        networkPassphrase: this.networkPassphrase,
        timeoutInSeconds: this.timeoutInSeconds,
        shouldUseFeeSponsoring: (submissionOptions) =>
          this.shouldUseFeeSponsoring(submissionOptions),
        hasSourceAccountAuth: (preparedTx) => this.hasSourceAccountAuth(preparedTx),
        sendAndPoll: (preparedTx, submissionOptions) =>
          this.sendAndPoll(preparedTx, submissionOptions),
      },
      nativeTokenContract,
      options
    );
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
      /** Force a specific submission method (relayer or rpc) */
      forceMethod?: SubmissionMethod;
    }
  ): Promise<TransactionResult> {
    return transfer(
      {
        getContractId: () => this._contractId,
        rpc: this.rpc,
        networkPassphrase: this.networkPassphrase,
        timeoutInSeconds: this.timeoutInSeconds,
        deployerKeypair: this.deployerKeypair,
        shouldUseFeeSponsoring: (submissionOptions) =>
          this.shouldUseFeeSponsoring(submissionOptions),
        hasSourceAccountAuth: (preparedTx) => this.hasSourceAccountAuth(preparedTx),
        sendAndPoll: (preparedTx, submissionOptions) =>
          this.sendAndPoll(preparedTx, submissionOptions),
        signResimulateAndPrepare: (hostFunc, authEntries, signOptions) =>
          this.signResimulateAndPrepare(hostFunc, authEntries, signOptions),
      },
      tokenContract,
      recipient,
      amount,
      options
    );
  }

  // ==========================================================================
  // Private Helpers
  // ==========================================================================

  /**
   * Check if a transaction has any auth entries using source_account credentials.
   *
   * When auth uses source_account credentials, the authorization comes from the
   * transaction envelope signature, so we MUST sign even when using fee sponsoring.
   * For Address credentials, the authorization is in the auth entry itself.
   *
   * @param transaction - The transaction to check
   * @returns true if any auth entry uses source_account credentials
   * @internal
   */
  private hasSourceAccountAuth(transaction: Transaction): boolean {
    return hasSourceAccountAuth(transaction);
  }

  /**
   * Simulate a host function to get auth entries
   */
  private async simulateHostFunction(
    hostFunc: xdr.HostFunction
  ): Promise<{ authEntries: xdr.SorobanAuthorizationEntry[] }> {
    return simulateHostFunction(
      {
        rpc: this.rpc,
        networkPassphrase: this.networkPassphrase,
        timeoutInSeconds: this.timeoutInSeconds,
        deployerKeypair: this.deployerKeypair,
      },
      hostFunc
    );
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
    return signResimulateAndPrepare(
      {
        rpc: this.rpc,
        networkPassphrase: this.networkPassphrase,
        timeoutInSeconds: this.timeoutInSeconds,
        deployerKeypair: this.deployerKeypair,
        signAuthEntry: (entry, signOptions) => this.signAuthEntry(entry, signOptions),
      },
      hostFunc,
      authEntries,
      options
    );
  }

  /**
   * Determine which submission method to use based on configuration and options.
   *
   * Priority order (when not forced):
   * 1. Relayer (if configured)
   * 2. RPC (always available)
   *
   * @param options - Submission options
   * @returns The submission method to use
   */
  private getSubmissionMethod(options?: SubmissionOptions): SubmissionMethod {
    return getSubmissionMethod(this.relayer, options);
  }

  /**
   * Check if fee sponsoring service (Relayer) should be used.
   * When using fee sponsoring, transactions are wrapped in a fee-bump, so the
   * envelope signature is generally not required (unless source_account auth is present).
   */
  private shouldUseFeeSponsoring(options?: SubmissionOptions): boolean {
    return shouldUseFeeSponsoring(this.relayer, options);
  }

  /**
   * Send a transaction and poll for confirmation.
   *
   * Uses the following priority for submission (unless overridden):
   * 1. Relayer (if configured) - submits func + auth entries
   * 2. RPC (direct submission) - submits full transaction XDR
   *
   * @param transaction - The transaction to submit
   * @param options - Submission options
   * @returns Transaction result with hash and status
   */
  private async sendAndPoll(
    transaction: Transaction,
    options?: SubmissionOptions
  ): Promise<TransactionResult> {
    return sendAndPoll(
      { rpc: this.rpc, relayer: this.relayer },
      transaction,
      options
    );
  }

  /**
   * Build a deployment transaction for the smart account contract
   * Returns an AssembledTransaction that can be signed and sent
   */
  private async buildDeployTransaction(
    credentialId: Buffer,
    publicKey: Uint8Array
  ) {
    return buildDeployTransaction(
      {
        accountWasmHash: this.accountWasmHash,
        webauthnVerifierAddress: this.webauthnVerifierAddress,
        networkPassphrase: this.networkPassphrase,
        rpcUrl: this.rpcUrl,
        deployerKeypair: this.deployerKeypair,
        timeoutInSeconds: this.timeoutInSeconds,
      },
      credentialId,
      publicKey
    );
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
    options?: MultiSignerOptions & { forceMethod?: SubmissionMethod }
  ): Promise<TransactionResult> {
    return multiSignersTransfer(
      {
        getContractId: () => this._contractId,
        externalSigners: this.externalSigners,
        rpc: this.rpc,
        networkPassphrase: this.networkPassphrase,
        timeoutInSeconds: this.timeoutInSeconds,
        deployerKeypair: this.deployerKeypair,
        deployerPublicKey: this.deployerPublicKey,
        signAuthEntry: (entry, signOptions) => this.signAuthEntry(entry, signOptions),
        shouldUseFeeSponsoring: (submissionOptions) =>
          this.shouldUseFeeSponsoring(submissionOptions),
        hasSourceAccountAuth: (preparedTx) => this.hasSourceAccountAuth(preparedTx),
        sendAndPoll: (preparedTx, submissionOptions) =>
          this.sendAndPoll(preparedTx, submissionOptions),
      },
      tokenContract,
      recipient,
      amount,
      selectedSigners,
      options
    );
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
    return convertPolicyParams(this.wallet, policyType, params);
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
    return buildPoliciesScVal(this.wallet, policies, policyTypes);
  }
}
