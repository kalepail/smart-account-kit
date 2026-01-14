/**
 * Smart Account Kit Type Definitions
 *
 * This module defines the core types used throughout the SDK for managing
 * smart accounts with WebAuthn passkey authentication.
 */

import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

// ============================================================================
// Credential Storage Types
// ============================================================================

/**
 * Deployment status for a stored credential.
 * Note: Successfully deployed credentials are deleted from storage,
 * so only "pending" and "failed" credentials remain stored.
 */
export type CredentialDeploymentStatus = "pending" | "failed";

/**
 * Stored session data for auto-reconnect functionality.
 * Tracks the most recently connected wallet.
 */
export interface StoredSession {
  /** Smart account contract address */
  contractId: string;

  /** Base64URL encoded credential ID (for passkey wallets) */
  credentialId: string;

  /** Unix timestamp when the session was created */
  connectedAt: number;

  /** Unix timestamp when the session expires (optional) */
  expiresAt?: number;
}

/**
 * Represents a stored WebAuthn credential with associated smart account data.
 *
 * The credential ID (rawId) is essential for identifying which passkey to use
 * during authentication. Without it, the passkey cannot be used again.
 */
export interface StoredCredential {
  /** Base64URL encoded credential ID (rawId) - unique identifier for the passkey */
  credentialId: string;

  /** 65-byte secp256r1 uncompressed public key (0x04 prefix + x + y coordinates) */
  publicKey: Uint8Array;

  /** Smart account contract address this credential is associated with */
  contractId: string;

  /** User-friendly name for this passkey */
  nickname?: string;

  /** Unix timestamp when the credential was created */
  createdAt: number;

  /** Unix timestamp when the credential was last used */
  lastUsedAt?: number;

  /** Authenticator transports (how the browser can communicate with the authenticator) */
  transports?: AuthenticatorTransportFuture[];

  /** Device type: 'singleDevice' (security key) or 'multiDevice' (synced passkey) */
  deviceType?: "singleDevice" | "multiDevice";

  /** Whether the passkey is backed up/synced */
  backedUp?: boolean;

  /** Which context rule ID this signer belongs to (if any) */
  contextRuleId?: number;

  /** Whether this was the primary passkey used to deploy the wallet */
  isPrimary?: boolean;

  /**
   * Deployment status:
   * - "pending": Credential created locally, deployment not yet attempted or in progress
   * - "failed": Deployment was attempted but failed
   * Note: Successfully deployed credentials are deleted from storage.
   */
  deploymentStatus?: CredentialDeploymentStatus;

  /** Error message if deployment failed */
  deploymentError?: string;
}

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * Configuration for the SmartAccountKit client
 */
export interface SmartAccountConfig {
  /** Stellar RPC URL */
  rpcUrl: string;

  /** Network passphrase (e.g., 'Test SDF Network ; September 2015') */
  networkPassphrase: string;

  /** Smart account WASM hash for deployment */
  accountWasmHash: string;

  /** Deployed WebAuthn verifier contract address */
  webauthnVerifierAddress: string;

  /** Default policy contract addresses (optional) */
  defaultPolicies?: PolicyConfig[];

  /** Transaction timeout in seconds (default: 30) */
  timeoutInSeconds?: number;

  /** Signature expiration in ledgers from current ledger (default: 720 = ~1 hour) */
  signatureExpirationLedgers?: number;

  /** Custom storage adapter for credential persistence */
  storage?: StorageAdapter;

  /** WebAuthn Relying Party ID (domain) - defaults to current domain */
  rpId?: string;

  /** WebAuthn Relying Party name (displayed to user) */
  rpName?: string;

  /** Custom WebAuthn implementation (for testing) */
  webAuthn?: {
    startRegistration: (options: {
      optionsJSON: PublicKeyCredentialCreationOptionsJSON;
      useAutoRegister?: boolean;
    }) => Promise<RegistrationResponseJSON>;
    startAuthentication: (options: {
      optionsJSON: PublicKeyCredentialRequestOptionsJSON;
      useBrowserAutofill?: boolean;
      verifyBrowserAutofillInput?: boolean;
    }) => Promise<AuthenticationResponseJSON>;
  };

  /** Session expiration time in milliseconds (default: 7 days) */
  sessionExpiryMs?: number;

  /**
   * Optional external wallet adapter for multi-signer support.
   * Use this to integrate external wallets (Freighter, Lobstr, etc.)
   * for delegated signer operations.
   *
   * @example
   * ```typescript
   * import { StellarWalletsKit } from '@creit-tech/stellar-wallets-kit';
   *
   * const kit = new SmartAccountKit({
   *   // ... other config
   *   externalWallet: {
   *     connect: () => StellarWalletsKit.authModal(),
   *     disconnect: () => StellarWalletsKit.disconnect(),
   *     signAuthEntry: (xdr, opts) => StellarWalletsKit.signAuthEntry(xdr, opts),
   *     getConnectedWallets: () => myConnectedWallets,
   *     canSignFor: (addr) => myConnectedWallets.some(w => w.address === addr),
   *   },
   * });
   * ```
   */
  externalWallet?: ExternalWalletAdapter;

  /**
   * Optional indexer URL for contract discovery.
   * The indexer enables reverse lookups from signer credentials to contracts.
   *
   * If not provided, a default URL will be used for known networks (testnet).
   * Set to `false` to disable indexer integration entirely.
   *
   * @example
   * ```typescript
   * const kit = new SmartAccountKit({
   *   // ... other config
   *   indexerUrl: 'https://smart-account-indexer.sdf-ecosystem.workers.dev',
   * });
   *
   * // Discover all contracts for a credential ID
   * const contracts = await kit.discoverContractsByCredential(credentialId);
   * ```
   */
  indexerUrl?: string | false;

  /**
   * Optional Relayer proxy URL for fee-sponsored transaction submission.
   * When configured, the SDK posts `{ func, auth }` for invokeHostFunction
   * flows and `{ xdr }` for signed transactions, enabling gasless submissions.
   *
   * @example
   * ```typescript
   * const kit = new SmartAccountKit({
   *   // ... other config
   *   relayerUrl: 'https://my-relayer-proxy.example.com',
   * });
   *
   * // Transactions will automatically use the Relayer if configured
   * const result = await kit.signAndSubmit(transaction);
   * ```
   */
  relayerUrl?: string;
}


/**
 * Configuration for policy contracts to include when creating wallets
 */
export interface PolicyConfig {
  /** Policy contract address */
  address: string;

  /** Installation parameters for the policy */
  installParams: unknown;
}

// ============================================================================
// Storage Adapter Interface
// ============================================================================

/**
 * Interface for credential storage adapters.
 *
 * Implementations can store credentials in various backends:
 * - IndexedDB (recommended for web apps)
 * - localStorage (simple fallback)
 * - Server/database (for cross-device sync)
 * - Memory (for testing)
 */
export interface StorageAdapter {
  /** Save a new credential or update existing */
  save(credential: StoredCredential): Promise<void>;

  /** Get a credential by its ID */
  get(credentialId: string): Promise<StoredCredential | null>;

  /** Get all credentials for a specific contract */
  getByContract(contractId: string): Promise<StoredCredential[]>;

  /** Get all stored credentials */
  getAll(): Promise<StoredCredential[]>;

  /** Delete a credential by its ID */
  delete(credentialId: string): Promise<void>;

  /** Update credential metadata */
  update(
    credentialId: string,
    updates: Partial<Omit<StoredCredential, "credentialId" | "publicKey">>
  ): Promise<void>;

  /** Clear all stored credentials */
  clear(): Promise<void>;

  // Session management

  /** Save the current session (last connected wallet) */
  saveSession(session: StoredSession): Promise<void>;

  /** Get the stored session (if any) */
  getSession(): Promise<StoredSession | null>;

  /** Clear the stored session */
  clearSession(): Promise<void>;
}

// ============================================================================
// Result Types
// ============================================================================

/**
 * Result of creating a new wallet
 */
export interface CreateWalletResult {
  /** The raw WebAuthn registration response */
  rawResponse: RegistrationResponseJSON;

  /** Base64URL encoded credential ID */
  credentialId: string;

  /** 65-byte secp256r1 public key */
  publicKey: Uint8Array;

  /** Smart account contract address */
  contractId: string;

  /** Signed deployment transaction (ready to submit) */
  signedTransaction: string;
}

/**
 * Result of connecting to an existing wallet
 */
export interface ConnectWalletResult {
  /** Raw WebAuthn authentication response (if authentication was performed) */
  rawResponse?: AuthenticationResponseJSON;

  /** Base64URL encoded credential ID */
  credentialId: string;

  /** Smart account contract address */
  contractId: string;

  /** Stored credential data (if found in storage) */
  credential?: StoredCredential;
}

/**
 * Result of a transaction operation
 */
export interface TransactionResult {
  /** Whether the transaction succeeded */
  success: boolean;

  /** Transaction hash */
  hash: string;

  /** Error message (if failed) */
  error?: string;

  /** Ledger the transaction was included in (if successful) */
  ledger?: number;
}

/**
 * Submission method for transactions
 */
export type SubmissionMethod = "relayer" | "rpc";

/**
 * Options for transaction submission.
 *
 * By default, transactions are submitted via Relayer if configured,
 * otherwise directly via RPC.
 */
export interface SubmissionOptions {
  /**
   * Force a specific submission method, bypassing the default.
   *
   * - "relayer": Use Relayer proxy (fails if not configured)
   * - "rpc": Submit directly via RPC (always available)
   *
   * When not specified, uses Relayer if configured, otherwise RPC.
   */
  forceMethod?: SubmissionMethod;
}

// ============================================================================
// External Wallet Adapter Types
// ============================================================================

/**
 * Info about a connected external wallet (e.g., Freighter, Lobstr)
 */
export interface ConnectedWallet {
  /** Stellar G-address of the connected wallet */
  address: string;
  /** Wallet identifier (e.g., 'freighter', 'lobstr') */
  walletId: string;
  /** Human-readable wallet name */
  walletName: string;
}

/**
 * Interface for external wallet adapters.
 *
 * Implementations can integrate with various Stellar wallet extensions:
 * - Stellar Wallets Kit (SWK) - recommended
 * - Freighter directly
 * - Custom wallet integrations
 *
 * @example
 * ```typescript
 * // Using with Stellar Wallets Kit
 * const walletAdapter: ExternalWalletAdapter = {
 *   connect: () => StellarWalletsKit.authModal(),
 *   disconnect: () => StellarWalletsKit.disconnect(),
 *   signAuthEntry: (authEntryXdr, opts) =>
 *     StellarWalletsKit.signAuthEntry(authEntryXdr, opts),
 *   getConnectedWallets: () => connectedWallets,
 *   canSignFor: (address) => connectedWallets.some(w => w.address === address),
 * };
 * ```
 */
export interface ExternalWalletAdapter {
  /**
   * Connect an external wallet (typically shows a modal).
   * @returns The connected wallet info, or null if cancelled
   */
  connect(): Promise<ConnectedWallet | null>;

  /**
   * Disconnect all external wallets
   */
  disconnect(): Promise<void>;

  /**
   * Sign an authorization entry with an external wallet.
   *
   * The auth entry is an XDR-encoded HashIdPreimage that the wallet
   * should sign with Ed25519.
   *
   * @param authEntryXdr - Base64 encoded HashIdPreimage XDR
   * @param opts - Signing options
   * @returns The raw Ed25519 signature as base64
   */
  signAuthEntry(
    authEntryXdr: string,
    opts?: {
      /** Network passphrase for signing */
      networkPassphrase?: string;
      /** Specific address to sign with (if multiple wallets connected) */
      address?: string;
    }
  ): Promise<{ signedAuthEntry: string; signerAddress?: string }>;

  /**
   * Get all currently connected wallets
   */
  getConnectedWallets(): ConnectedWallet[];

  /**
   * Check if a specific address has a connected wallet that can sign for it
   */
  canSignFor(address: string): boolean;

  /**
   * Get wallet info for a specific address
   */
  getWalletForAddress?(address: string): ConnectedWallet | undefined;

  /**
   * Reconnect to a previously connected wallet by ID.
   * Used for restoring connections on page reload.
   * @param walletId - The wallet ID to reconnect to (e.g., 'freighter', 'lobstr')
   * @returns Connected wallet info, or null if reconnection failed
   */
  reconnect?(walletId: string): Promise<ConnectedWallet | null>;
}

// ============================================================================
// Multi-Signer Types
// ============================================================================

/**
 * Represents a signer selected for a multi-signature operation
 */
export interface SelectedSigner {
  /** Signer type: 'passkey' for WebAuthn, 'wallet' for external wallet */
  type: "passkey" | "wallet";
  /** Credential ID for passkey signers (base64url encoded) */
  credentialId?: string;
  /** G-address for wallet signers */
  walletAddress?: string;
  /** Human-readable label for display (optional) */
  label?: string;
  /** The original contract Signer object (optional, for advanced use cases) */
  signer?: unknown;
}
