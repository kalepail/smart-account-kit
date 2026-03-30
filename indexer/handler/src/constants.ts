/**
 * Constants for Smart Account Indexer
 */

// ============================================================================
// Service Metadata
// ============================================================================

/** Service name for health checks */
export const SERVICE_NAME = "smart-account-indexer";

// ============================================================================
// Pagination
// ============================================================================

/** Default pagination limit for list endpoints */
export const DEFAULT_PAGINATION_LIMIT = 100;

// ============================================================================
// HTTP Status Codes
// ============================================================================

export const HTTP_STATUS = {
  OK: 200,
  BAD_REQUEST: 400,
  NOT_FOUND: 404,
  INTERNAL_ERROR: 500,
} as const;

// ============================================================================
// Error Messages
// ============================================================================

export const ERROR_MESSAGES = {
  DATABASE_QUERY_FAILED: "Database query failed",
  CONTRACT_NOT_FOUND: "Contract not found",
} as const;

// ============================================================================
// Event Types
// ============================================================================

export const EVENT_TYPES = {
  CONTEXT_RULE_ADDED: "context_rule_added",
  CONTEXT_RULE_META_UPDATED: "context_rule_meta_updated",
  CONTEXT_RULE_REMOVED: "context_rule_removed",
  SIGNER_ADDED: "signer_added",
  SIGNER_REMOVED: "signer_removed",
  SIGNER_REGISTERED: "signer_registered",
  SIGNER_DEREGISTERED: "signer_deregistered",
  POLICY_ADDED: "policy_added",
  POLICY_REGISTERED: "policy_registered",
  POLICY_REMOVED: "policy_removed",
  POLICY_DEREGISTERED: "policy_deregistered",
} as const;
