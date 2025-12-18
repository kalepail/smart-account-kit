/**
 * External Wallet Adapter Implementations
 *
 * This module provides concrete adapter implementations for integrating
 * external Stellar wallets with the Smart Account Kit.
 *
 * @remarks
 * To use the StellarWalletsKitAdapter, you must install the peer dependency:
 * ```bash
 * pnpm add @creit-tech/stellar-wallets-kit
 * ```
 */

import type { ExternalWalletAdapter, ConnectedWallet } from "./types";
import type { Networks } from "@stellar/stellar-sdk";

// Import types from StellarWalletsKit (peer dependency)
// These are type-only imports so they don't require the package at runtime
// unless you actually use the adapter
import type {
  StellarWalletsKit as SWKType,
  ISupportedWallet,
} from "@creit-tech/stellar-wallets-kit";

/**
 * Configuration options for StellarWalletsKitAdapter
 */
export interface StellarWalletsKitAdapterConfig {
  /**
   * Network to use (e.g., Networks.TESTNET, Networks.PUBLIC)
   * @default Networks.TESTNET
   */
  network?: Networks | string;

  /**
   * Optional callback when connection status changes
   */
  onConnectionChange?: (connected: boolean, wallet?: ConnectedWallet) => void;
}

/**
 * Adapter for StellarWalletsKit
 *
 * This adapter integrates the @creit-tech/stellar-wallets-kit library
 * with the Smart Account Kit, providing a unified interface for
 * connecting to and signing with external Stellar wallets like
 * Freighter, Lobstr, xBull, and others.
 *
 * @remarks
 * Requires `@creit-tech/stellar-wallets-kit` to be installed as a peer dependency.
 *
 * @example
 * ```typescript
 * import { StellarWalletsKitAdapter, SmartAccountKit } from "smart-account-kit";
 * import { Networks } from "@stellar/stellar-sdk";
 *
 * // Create and initialize the adapter
 * const walletAdapter = new StellarWalletsKitAdapter({
 *   network: Networks.TESTNET
 * });
 * await walletAdapter.init();
 *
 * // Use with SmartAccountKit
 * const kit = new SmartAccountKit({
 *   rpcUrl: "https://soroban-testnet.stellar.org",
 *   networkPassphrase: Networks.TESTNET,
 *   externalWallet: walletAdapter,
 * });
 *
 * // Connect a wallet
 * const wallet = await walletAdapter.connect();
 * if (wallet) {
 *   console.log(`Connected: ${wallet.walletName} (${wallet.address})`);
 * }
 * ```
 */
export class StellarWalletsKitAdapter implements ExternalWalletAdapter {
  private network: Networks | string;
  private connectedWallets: Map<string, ConnectedWallet> = new Map();
  private onConnectionChange?: (connected: boolean, wallet?: ConnectedWallet) => void;
  private StellarWalletsKit: typeof SWKType | null = null;
  private initialized = false;

  constructor(config: StellarWalletsKitAdapterConfig = {}) {
    // Default to testnet if not specified
    this.network = config.network || "Test SDF Network ; September 2015";
    this.onConnectionChange = config.onConnectionChange;
  }

  /**
   * Initialize the adapter
   *
   * Must be called before using connect() or signAuthEntry().
   * This method imports StellarWalletsKit and initializes it with
   * all SEP-43 compatible wallet modules.
   *
   * @throws Error if @creit-tech/stellar-wallets-kit is not installed
   */
  async init(): Promise<void> {
    if (this.initialized) return;

    try {
      // Dynamic imports - will fail if peer dependency not installed
      const { StellarWalletsKit } = await import("@creit-tech/stellar-wallets-kit");
      const { sep43Modules } = await import("@creit-tech/stellar-wallets-kit/modules/utils");

      // Initialize StellarWalletsKit with all SEP-43 compatible modules
      StellarWalletsKit.init({
        modules: sep43Modules(),
        network: this.network as Networks,
      });

      this.StellarWalletsKit = StellarWalletsKit;
      this.initialized = true;
    } catch (error) {
      throw new Error(
        `Failed to initialize StellarWalletsKitAdapter. ` +
        `Make sure @creit-tech/stellar-wallets-kit is installed: pnpm add @creit-tech/stellar-wallets-kit`
      );
    }
  }

  /**
   * Ensure the adapter is initialized and return the StellarWalletsKit instance
   * @internal
   */
  private ensureInitialized(): typeof SWKType {
    if (!this.initialized || !this.StellarWalletsKit) {
      throw new Error("StellarWalletsKitAdapter not initialized. Call init() first.");
    }
    return this.StellarWalletsKit;
  }

  /**
   * Get list of available/installed wallet extensions
   *
   * @returns Array of wallet info with availability status
   */
  async getAvailableWallets(): Promise<ISupportedWallet[]> {
    const kit = this.ensureInitialized();
    return kit.refreshSupportedWallets();
  }

  /**
   * Connect to a wallet using the built-in modal
   *
   * Shows a modal allowing the user to select and connect their preferred wallet.
   * The connected wallet is tracked internally for signing operations.
   *
   * @returns Connected wallet info, or null if user cancelled
   */
  async connect(): Promise<ConnectedWallet | null> {
    const kit = this.ensureInitialized();

    try {
      const result = await kit.authModal();

      if (result?.address) {
        const selectedModule = kit.selectedModule;
        const wallet: ConnectedWallet = {
          address: result.address,
          walletId: selectedModule?.productId ?? "unknown",
          walletName: selectedModule?.productName ?? "Unknown Wallet",
        };

        // Track connected wallet
        this.connectedWallets.set(wallet.address, wallet);

        // Notify listeners
        this.onConnectionChange?.(true, wallet);

        return wallet;
      }

      return null;
    } catch {
      // Connection failed - return null to indicate failure
      // Callers can handle this gracefully
      return null;
    }
  }

  /**
   * Reconnect to a previously connected wallet by ID
   *
   * Attempts to reconnect to a specific wallet type without showing the modal.
   * This is used for restoring connections on page reload.
   *
   * If the wallet extension remembers the site authorization, this will
   * succeed silently. Otherwise, it may prompt the user for authorization.
   *
   * @param walletId - The wallet ID to reconnect to (e.g., 'freighter', 'lobstr')
   * @returns Connected wallet info, or null if reconnection failed
   */
  async reconnect(walletId: string): Promise<ConnectedWallet | null> {
    const kit = this.ensureInitialized();

    try {
      // Set the wallet module to use
      kit.setWallet(walletId);

      // Try to get the address - this will work if the wallet remembers the site
      const result = await kit.getAddress();

      if (result?.address) {
        const selectedModule = kit.selectedModule;
        const wallet: ConnectedWallet = {
          address: result.address,
          walletId: selectedModule?.productId ?? walletId,
          walletName: selectedModule?.productName ?? walletId,
        };

        // Track connected wallet
        this.connectedWallets.set(wallet.address, wallet);

        // Notify listeners
        this.onConnectionChange?.(true, wallet);

        return wallet;
      }

      return null;
    } catch {
      // Reconnection failed - wallet may not be installed or not authorized
      return null;
    }
  }

  /**
   * Disconnect all wallets
   */
  async disconnect(): Promise<void> {
    const kit = this.ensureInitialized();

    await kit.disconnect();
    this.connectedWallets.clear();
    this.onConnectionChange?.(false);
  }

  /**
   * Disconnect a specific wallet by address
   *
   * @param address - The Stellar address to disconnect
   */
  disconnectByAddress(address: string): void {
    this.connectedWallets.delete(address);
    if (this.connectedWallets.size === 0) {
      this.onConnectionChange?.(false);
    }
  }

  /**
   * Sign an auth entry with the wallet
   *
   * @param authEntryXdr - The auth entry to sign, as XDR string
   * @param opts - Optional signing options
   * @returns The signed auth entry
   * @throws Error if no wallet is connected or requested address not found
   */
  async signAuthEntry(
    authEntryXdr: string,
    opts?: { networkPassphrase?: string; address?: string }
  ): Promise<{ signedAuthEntry: string; signerAddress?: string }> {
    const kit = this.ensureInitialized();

    const targetAddress = opts?.address;

    // Validate we can sign for the requested address
    if (targetAddress && !this.connectedWallets.has(targetAddress)) {
      throw new Error(`No wallet connected for address ${targetAddress}`);
    }

    if (!targetAddress && this.connectedWallets.size === 0) {
      throw new Error("No wallet connected");
    }

    // Use the target address or first connected wallet
    const signingAddress = targetAddress || [...this.connectedWallets.keys()][0];

    return kit.signAuthEntry(authEntryXdr, {
      networkPassphrase: opts?.networkPassphrase || (this.network as string),
      address: signingAddress,
    });
  }

  /**
   * Check if we can sign for a specific address
   *
   * @param address - The Stellar address to check
   * @returns True if a wallet is connected for this address
   */
  canSignFor(address: string): boolean {
    return this.connectedWallets.has(address);
  }

  /**
   * Get wallet info for a specific address
   *
   * @param address - The Stellar address to look up
   * @returns Wallet info if connected, undefined otherwise
   */
  getWalletForAddress(address: string): ConnectedWallet | undefined {
    return this.connectedWallets.get(address);
  }

  /**
   * Get all connected wallets
   *
   * @returns Array of connected wallet info
   */
  getConnectedWallets(): ConnectedWallet[] {
    return [...this.connectedWallets.values()];
  }

  /**
   * Check if any wallet is connected
   */
  get isConnected(): boolean {
    return this.connectedWallets.size > 0;
  }
}
