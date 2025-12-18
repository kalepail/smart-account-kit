/**
 * Constants used throughout the Smart Account Kit SDK.
 *
 * @packageDocumentation
 */

// ============================================================================
// WebAuthn Configuration
// ============================================================================

/** Default timeout for WebAuthn operations in milliseconds */
export const WEBAUTHN_TIMEOUT_MS = 60000;

// ============================================================================
// Stellar/Soroban Configuration
// ============================================================================

/** Default base fee for Stellar transactions (in stroops) */
export const BASE_FEE = "100";

/** Number of stroops per XLM (1 XLM = 10,000,000 stroops) */
export const STROOPS_PER_XLM = 10_000_000;

/** Reserve XLM amount to keep when funding via Friendbot */
export const FRIENDBOT_RESERVE_XLM = 5;

// ============================================================================
// Cryptographic Constants
// ============================================================================

/** Size of an uncompressed secp256r1 (P-256) public key in bytes */
export const SECP256R1_PUBLIC_KEY_SIZE = 65;

/** First byte of an uncompressed secp256r1 public key (0x04) */
export const UNCOMPRESSED_PUBKEY_PREFIX = 0x04;

// ============================================================================
// Storage Configuration
// ============================================================================

/** Default IndexedDB database name */
export const DB_NAME = "smart-account-kit";

/** Current IndexedDB schema version */
export const DB_VERSION = 2;

/** LocalStorage key for credentials */
export const LOCALSTORAGE_CREDENTIALS_KEY = "smart-account-kit:credentials";

/** LocalStorage key for session */
export const LOCALSTORAGE_SESSION_KEY = "smart-account-kit:session";

// ============================================================================
// Session Configuration
// ============================================================================

/** Default session expiration time in milliseconds (7 days) */
export const DEFAULT_SESSION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
