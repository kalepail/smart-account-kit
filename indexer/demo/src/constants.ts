/**
 * Constants for Indexer Demo
 */

// ============================================================================
// Network Configuration
// ============================================================================

/** Default hosted indexer URL for the checked-in demo (testnet). Override via env or UI for mainnet. */
export const DEFAULT_INDEXER_URL = "https://smart-account-indexer.sdf-ecosystem.workers.dev";

/** Default RPC URL for the checked-in demo (testnet). Override via env or UI for mainnet. */
export const DEFAULT_RPC_URL = "https://soroban-testnet.stellar.org";

/** Default Stellar network passphrase for the checked-in demo (testnet). */
export const DEFAULT_NETWORK_PASSPHRASE = "Test SDF Network ; September 2015";

/** Default smart-account WASM hash used by the checked-in demo. */
export const DEFAULT_ACCOUNT_WASM_HASH =
  "1b5f4534a76322da2ad7c745f6900857a6802b0ca79850c35a03561df997785a";

/** Default WebAuthn verifier used by the checked-in demo. */
export const DEFAULT_WEBAUTHN_VERIFIER_ADDRESS =
  "CC7EKIHQP3TN4CARQDND6CEOY2UXLWWC2X5GHTD5NLAT7BG5GPZIOM3F";

// ============================================================================
// Ledger Constants
// ============================================================================

/** Approximate number of ledgers per day (~5 seconds per ledger) */
export const LEDGERS_PER_DAY = 17280;

/** Number of stroops (smallest unit) per XLM */
export const STROOPS_PER_XLM = 10_000_000;

// ============================================================================
// Display Constants
// ============================================================================

/** Number of characters to show at start of truncated address */
export const TRUNCATE_START_CHARS = 8;

/** Number of characters to show at end of truncated address */
export const TRUNCATE_END_CHARS = 8;

/**
 * Truncate a contract ID or address for display
 */
export function truncateAddress(address: string, startChars = TRUNCATE_START_CHARS, endChars = TRUNCATE_END_CHARS): string {
  if (address.length <= startChars + endChars + 3) {
    return address;
  }
  return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
}
