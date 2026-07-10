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
// Stellar smart contract configuration
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

// ============================================================================
// Ledger Configuration
// ============================================================================

/** Approximate number of ledgers per hour (~5 seconds per ledger) */
export const LEDGERS_PER_HOUR = 720;

/** Approximate number of ledgers per day */
export const LEDGERS_PER_DAY = 17280;

/** Approximate number of ledgers per week */
export const LEDGERS_PER_WEEK = 120960;

/** Buffer ledgers for auth entry expiration to ensure they don't expire during signing */
export const AUTH_ENTRY_EXPIRATION_BUFFER = 100;

// ============================================================================
// Network URLs
// ============================================================================

/** Stellar Friendbot URL for testnet funding */
export const FRIENDBOT_URL = "https://friendbot.stellar.org";

// ============================================================================
// Indexer Configuration
// ============================================================================

/** Default timeout for indexer requests in milliseconds */
export const DEFAULT_INDEXER_TIMEOUT_MS = 10000;

/** Default timeout for relayer requests in milliseconds (6 minutes for testnet retries) */
export const DEFAULT_RELAYER_TIMEOUT_MS = 360000;

// ============================================================================
// IndexedDB Configuration
// ============================================================================

/** IndexedDB store name for credentials */
export const IDB_STORE_CREDENTIALS = "credentials";

/** IndexedDB store name for session data */
export const IDB_STORE_SESSION = "session";

/** IndexedDB key for current session */
export const IDB_SESSION_KEY = "current";

/** IndexedDB index name for contract ID lookups */
export const IDB_INDEX_CONTRACT_ID = "contractId";

/** IndexedDB index name for creation date sorting */
export const IDB_INDEX_CREATED_AT = "createdAt";

/** IndexedDB index name for primary credential filtering */
export const IDB_INDEX_IS_PRIMARY = "isPrimary";

// ============================================================================
// API Paths
// ============================================================================

/** Indexer API path for credential lookup */
export const API_PATH_LOOKUP = "/api/lookup";

/** Indexer API path for address lookup */
export const API_PATH_LOOKUP_ADDRESS = "/api/lookup/address";

/** Indexer API path for contract details */
export const API_PATH_CONTRACT = "/api/contract";

/** Indexer API path for stats */
export const API_PATH_STATS = "/api/stats";
