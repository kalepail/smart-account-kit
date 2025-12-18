/**
 * Builder utilities for Smart Account Kit
 *
 * Type-safe constructors for creating signers, context rule types, and policy parameters.
 * These helpers ensure correct data structures are created for smart account operations.
 *
 * @packageDocumentation
 */

import { Address } from "@stellar/stellar-sdk";
import type {
  Signer,
  ContextRuleType,
  SimpleThresholdAccountParams,
  WeightedThresholdAccountParams,
  SpendingLimitAccountParams,
} from "smart-account-kit-bindings";
import { buildKeyData } from "./utils";
import { ValidationError, SmartAccountErrorCode } from "./errors";
import { SECP256R1_PUBLIC_KEY_SIZE } from "./constants";

// ============================================================================
// Signer Builders
// ============================================================================

/**
 * Create a Delegated signer (native Stellar account).
 *
 * Delegated signers use Stellar's native `require_auth()` mechanism.
 * No external verifier contract is needed.
 *
 * @param publicKey - Stellar account public key (G...)
 * @returns Signer object for use in context rules
 *
 * @example
 * ```typescript
 * const signer = createDelegatedSigner("G...");
 * ```
 */
export function createDelegatedSigner(publicKey: string): Signer {
  // Validate the address format
  if (!publicKey.startsWith("G") || publicKey.length !== 56) {
    throw new ValidationError(
      "Invalid Stellar account address. Must start with 'G' and be 56 characters.",
      SmartAccountErrorCode.INVALID_ADDRESS,
      { publicKey }
    );
  }
  return {
    tag: "Delegated",
    values: [publicKey],
  };
}

/**
 * Create an External signer (custom verifier contract).
 *
 * External signers use a verifier contract to validate signatures.
 * Used for WebAuthn passkeys, Ed25519 with custom logic, etc.
 *
 * @param verifierAddress - Verifier contract address (C...)
 * @param keyData - Key data for the verifier (format depends on verifier)
 * @returns Signer object for use in context rules
 *
 * @example
 * ```typescript
 * // WebAuthn signer (keyData = 65-byte pubkey + credentialId)
 * const webauthnSigner = createExternalSigner(
 *   "C...", // WebAuthn verifier address
 *   buildKeyData(publicKey, credentialId)
 * );
 *
 * // Ed25519 signer (keyData = 32-byte public key)
 * const ed25519Signer = createExternalSigner(
 *   "C...", // Ed25519 verifier address
 *   ed25519PublicKey
 * );
 * ```
 */
export function createExternalSigner(
  verifierAddress: string,
  keyData: Buffer | Uint8Array
): Signer {
  // Validate the address format
  if (!verifierAddress.startsWith("C") || verifierAddress.length !== 56) {
    throw new ValidationError(
      "Invalid contract address. Must start with 'C' and be 56 characters.",
      SmartAccountErrorCode.INVALID_ADDRESS,
      { verifierAddress }
    );
  }
  return {
    tag: "External",
    values: [verifierAddress, Buffer.from(keyData)],
  };
}

/**
 * Create a WebAuthn passkey signer.
 *
 * Convenience wrapper around createExternalSigner that handles
 * the key_data format for WebAuthn (pubkey + credentialId).
 *
 * @param webauthnVerifierAddress - WebAuthn verifier contract address
 * @param publicKey - 65-byte secp256r1 uncompressed public key
 * @param credentialId - Base64URL credential ID or Buffer
 * @returns Signer object for use in context rules
 *
 * @example
 * ```typescript
 * const signer = createWebAuthnSigner(
 *   "C...",
 *   publicKey,
 *   credentialId
 * );
 * ```
 */
export function createWebAuthnSigner(
  webauthnVerifierAddress: string,
  publicKey: Uint8Array,
  credentialId: string | Buffer
): Signer {
  const keyData = buildKeyData(publicKey, credentialId);
  return createExternalSigner(webauthnVerifierAddress, keyData);
}

/**
 * Create an Ed25519 signer (with external verifier).
 *
 * For Ed25519 keys that need custom verification logic via a verifier contract.
 * The key data is the 32-byte Ed25519 public key.
 *
 * @param ed25519VerifierAddress - Ed25519 verifier contract address
 * @param publicKey - 32-byte Ed25519 public key
 * @returns Signer object for use in context rules
 *
 * @example
 * ```typescript
 * const signer = createEd25519Signer(
 *   "C...", // Ed25519 verifier address
 *   Keypair.fromPublicKey("G...").rawPublicKey()
 * );
 * ```
 */
export function createEd25519Signer(
  ed25519VerifierAddress: string,
  publicKey: Buffer | Uint8Array
): Signer {
  if (publicKey.length !== 32) {
    throw new ValidationError(
      "Ed25519 public key must be 32 bytes",
      SmartAccountErrorCode.INVALID_INPUT,
      { actualLength: publicKey.length }
    );
  }
  return createExternalSigner(ed25519VerifierAddress, publicKey);
}

// ============================================================================
// Context Rule Type Builders
// ============================================================================

/**
 * Create a Default context rule type.
 *
 * Default rules apply to any operation that doesn't match
 * a more specific CallContract or CreateContract rule.
 *
 * @returns ContextRuleType for default authorization
 *
 * @example
 * ```typescript
 * const contextType = createDefaultContext();
 * await kit.rules.add(contextType, "Primary Signers", signers, policies);
 * ```
 */
export function createDefaultContext(): ContextRuleType {
  return { tag: "Default", values: undefined };
}

/**
 * Create a CallContract context rule type.
 *
 * CallContract rules apply only when calling a specific contract.
 * Useful for restricting signers to specific dApps or operations.
 *
 * @param contractAddress - The contract address this rule applies to
 * @returns ContextRuleType for contract-specific authorization
 *
 * @example
 * ```typescript
 * const contextType = createCallContractContext("C...");
 * await kit.rules.add(contextType, "DEX Trading", signers, policies);
 * ```
 */
export function createCallContractContext(contractAddress: string): ContextRuleType {
  // Validate the address format
  if (!contractAddress.startsWith("C") || contractAddress.length !== 56) {
    throw new ValidationError(
      "Invalid contract address. Must start with 'C' and be 56 characters.",
      SmartAccountErrorCode.INVALID_ADDRESS,
      { contractAddress }
    );
  }
  return {
    tag: "CallContract",
    values: [contractAddress],
  };
}

/**
 * Create a CreateContract context rule type.
 *
 * CreateContract rules apply only when deploying contracts
 * with a specific WASM hash.
 *
 * @param wasmHash - The WASM hash (32 bytes or 64-char hex string)
 * @returns ContextRuleType for contract creation authorization
 *
 * @example
 * ```typescript
 * const contextType = createCreateContractContext("abc123...");
 * await kit.rules.add(contextType, "Deploy Factory", signers, policies);
 * ```
 */
export function createCreateContractContext(wasmHash: string | Buffer): ContextRuleType {
  let hashBuffer: Buffer;
  if (typeof wasmHash === "string") {
    // Remove 0x prefix if present
    const cleanHash = wasmHash.startsWith("0x") ? wasmHash.slice(2) : wasmHash;
    if (cleanHash.length !== 64) {
      throw new ValidationError(
        "WASM hash must be 32 bytes (64 hex characters)",
        SmartAccountErrorCode.INVALID_INPUT,
        { actualLength: cleanHash.length }
      );
    }
    hashBuffer = Buffer.from(cleanHash, "hex");
  } else {
    if (wasmHash.length !== 32) {
      throw new ValidationError(
        "WASM hash must be 32 bytes",
        SmartAccountErrorCode.INVALID_INPUT,
        { actualLength: wasmHash.length }
      );
    }
    hashBuffer = Buffer.from(wasmHash);
  }
  return {
    tag: "CreateContract",
    values: [hashBuffer],
  };
}

// ============================================================================
// Policy Parameter Builders
// ============================================================================

/**
 * Create Simple Threshold policy parameters.
 *
 * Simple threshold requires M-of-N signers where M = threshold
 * and N = total number of signers on the context rule.
 *
 * @param threshold - Minimum number of signers required
 * @returns Policy parameters for simple threshold
 *
 * @example
 * ```typescript
 * // 2-of-3 multisig
 * const params = createThresholdParams(2);
 * await kit.policies.add(ruleId, thresholdPolicyAddress, params);
 * ```
 */
export function createThresholdParams(threshold: number): SimpleThresholdAccountParams {
  if (threshold < 1) {
    throw new ValidationError(
      "Threshold must be at least 1",
      SmartAccountErrorCode.INVALID_INPUT,
      { threshold }
    );
  }
  if (!Number.isInteger(threshold)) {
    throw new ValidationError(
      "Threshold must be an integer",
      SmartAccountErrorCode.INVALID_INPUT,
      { threshold }
    );
  }
  return { threshold };
}

/**
 * Create Weighted Threshold policy parameters.
 *
 * Weighted threshold assigns different weights to different signers.
 * Authorization succeeds when the sum of weights of authenticated
 * signers meets or exceeds the threshold.
 *
 * @param threshold - Total weight required for authorization
 * @param signerWeights - Map of signers to their weights
 * @returns Policy parameters for weighted threshold
 *
 * @example
 * ```typescript
 * const weights = new Map<Signer, number>();
 * weights.set(adminSigner, 100);
 * weights.set(userSigner, 50);
 * const params = createWeightedThresholdParams(100, weights);
 * ```
 */
export function createWeightedThresholdParams(
  threshold: number,
  signerWeights: Map<Signer, number>
): WeightedThresholdAccountParams {
  if (threshold < 1) {
    throw new ValidationError(
      "Threshold must be at least 1",
      SmartAccountErrorCode.INVALID_INPUT,
      { threshold }
    );
  }
  if (!Number.isInteger(threshold)) {
    throw new ValidationError(
      "Threshold must be an integer",
      SmartAccountErrorCode.INVALID_INPUT,
      { threshold }
    );
  }
  if (signerWeights.size === 0) {
    throw new ValidationError(
      "At least one signer weight must be provided",
      SmartAccountErrorCode.INVALID_INPUT
    );
  }

  // Validate all weights are positive integers and calculate sum
  let totalWeight = 0;
  for (const [, weight] of signerWeights) {
    if (weight < 1 || !Number.isInteger(weight)) {
      throw new ValidationError(
        "All weights must be positive integers",
        SmartAccountErrorCode.INVALID_INPUT,
        { weight }
      );
    }
    totalWeight += weight;
  }

  // Validate that threshold is achievable
  if (totalWeight < threshold) {
    throw new ValidationError(
      `Sum of weights (${totalWeight}) must be >= threshold (${threshold})`,
      SmartAccountErrorCode.INVALID_INPUT,
      { threshold, totalWeight }
    );
  }

  // Fields must be in alphabetical order for Soroban ScMap serialization
  return {
    signer_weights: signerWeights,
    threshold,
  };
}

/**
 * Create Spending Limit policy parameters.
 *
 * Spending limit restricts how much can be transferred within
 * a given time period. Useful for rate limiting or daily limits.
 *
 * @param spendingLimit - Maximum amount allowed in the period (in stroops)
 * @param periodLedgers - Number of ledgers in the period (~5 seconds per ledger)
 * @returns Policy parameters for spending limit
 *
 * @example
 * ```typescript
 * // 100 XLM per day (~17280 ledgers at 5 seconds per ledger)
 * const params = createSpendingLimitParams(1000000000n, 17280);
 * await kit.policies.add(ruleId, spendingLimitPolicyAddress, params);
 * ```
 */
export function createSpendingLimitParams(
  spendingLimit: bigint | number,
  periodLedgers: number
): SpendingLimitAccountParams {
  if (periodLedgers < 1) {
    throw new ValidationError(
      "Period must be at least 1 ledger",
      SmartAccountErrorCode.INVALID_INPUT,
      { periodLedgers }
    );
  }
  if (!Number.isInteger(periodLedgers)) {
    throw new ValidationError(
      "Period must be an integer number of ledgers",
      SmartAccountErrorCode.INVALID_INPUT,
      { periodLedgers }
    );
  }

  const limitBigInt = typeof spendingLimit === "bigint" ? spendingLimit : BigInt(spendingLimit);
  if (limitBigInt < 1n) {
    throw new ValidationError(
      "Spending limit must be positive",
      SmartAccountErrorCode.INVALID_AMOUNT,
      { spendingLimit: limitBigInt.toString() }
    );
  }

  // Fields must be in alphabetical order for Soroban ScMap serialization
  return {
    period_ledgers: periodLedgers,
    spending_limit: limitBigInt,
  };
}

// ============================================================================
// Utility Constants for Spending Limit
// ============================================================================

/** Approximate number of ledgers per hour (~5 seconds per ledger) */
export const LEDGERS_PER_HOUR = 720;

/** Approximate number of ledgers per day */
export const LEDGERS_PER_DAY = 17280;

/** Approximate number of ledgers per week */
export const LEDGERS_PER_WEEK = 120960;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Parse a signer from various input formats.
 *
 * Accepts:
 * - Stellar account address (G...) → Delegated signer
 * - Full Signer object → returned as-is
 *
 * @param input - Signer input to parse
 * @returns Parsed Signer object
 */
export function parseSigner(input: string | Signer): Signer {
  if (typeof input === "string") {
    // Check if it's a Stellar account address
    if (input.startsWith("G") && input.length === 56) {
      return createDelegatedSigner(input);
    }
    throw new ValidationError(
      "Invalid signer input. Use a Stellar address (G...) or a Signer object.",
      SmartAccountErrorCode.INVALID_INPUT,
      { input }
    );
  }
  return input;
}

/**
 * Extract credential ID from a WebAuthn signer's key_data.
 *
 * @param signer - External signer with WebAuthn key_data
 * @returns Base64URL encoded credential ID
 */
export function getCredentialIdFromSigner(signer: Signer): string | null {
  if (signer.tag !== "External") {
    return null;
  }
  const keyData = signer.values[1] as Buffer;
  if (keyData.length <= SECP256R1_PUBLIC_KEY_SIZE) {
    return null; // Not a WebAuthn signer (no credential ID suffix)
  }
  const credentialId = keyData.slice(SECP256R1_PUBLIC_KEY_SIZE);
  // Convert to base64url
  return credentialId
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Check if a signer is a Delegated signer (native Stellar account).
 */
export function isDelegatedSigner(signer: Signer): signer is { tag: "Delegated"; values: [string] } {
  return signer.tag === "Delegated";
}

/**
 * Check if a signer is an External signer (verifier contract).
 */
export function isExternalSigner(signer: Signer): signer is { tag: "External"; values: [string, Buffer] } {
  return signer.tag === "External";
}

/**
 * Get a human-readable description of a signer.
 *
 * @param signer - The signer to describe
 * @returns Human-readable string
 */
export function describeSignerType(signer: Signer): string {
  if (signer.tag === "Delegated") {
    return "Stellar Account";
  }

  const keyData = signer.values[1] as Buffer;

  // WebAuthn signers have 65-byte pubkey + credential ID
  if (keyData.length > 65) {
    return "Passkey (WebAuthn)";
  }

  // Ed25519 signers have 32-byte public key
  if (keyData.length === 32) {
    return "Ed25519";
  }

  return "External Verifier";
}

/**
 * Truncate an address for display.
 *
 * @param address - Full address
 * @param chars - Number of characters to show on each end (default: 4)
 * @returns Truncated address like "GABC...WXYZ"
 */
export function truncateAddress(address: string, chars: number = 4): string {
  if (address.length <= chars * 2 + 3) {
    return address;
  }
  return `${address.slice(0, chars)}...${address.slice(-chars)}`;
}

/**
 * Check if a signer matches a given credential ID.
 *
 * Useful for finding a specific passkey signer among a list of signers.
 *
 * @param signer - The signer to check
 * @param credentialId - The credential ID to match (base64url encoded)
 * @returns True if the signer's credential ID matches
 *
 * @example
 * ```ts
 * const signers = await kit.multiSigners.getAvailableSigners();
 * const matchingSigner = signers.find(s => signerMatchesCredential(s, myCredentialId));
 * ```
 */
export function signerMatchesCredential(signer: Signer, credentialId: string): boolean {
  const signerCredId = getCredentialIdFromSigner(signer);
  return signerCredId === credentialId;
}

/**
 * Check if a signer matches a given Stellar address.
 *
 * Useful for finding a specific delegated signer among a list of signers.
 *
 * @param signer - The signer to check
 * @param address - The Stellar address to match (G...)
 * @returns True if the signer is a Delegated signer with the matching address
 *
 * @example
 * ```ts
 * const signers = await kit.multiSigners.getAvailableSigners();
 * const matchingSigner = signers.find(s => signerMatchesAddress(s, walletAddress));
 * ```
 */
export function signerMatchesAddress(signer: Signer, address: string): boolean {
  if (signer.tag !== "Delegated") {
    return false;
  }
  return signer.values[0] === address;
}

/**
 * Format a signer for display, returning both type and identifier.
 *
 * @param signer - The signer to format
 * @returns Object with type label and display identifier
 *
 * @example
 * ```ts
 * const { type, display } = formatSignerForDisplay(signer);
 * // type: "Passkey" or "G-Address"
 * // display: "cred:abc123..." or "GABC...WXYZ"
 * ```
 */
export function formatSignerForDisplay(signer: Signer): { type: string; display: string } {
  if (signer.tag === "Delegated") {
    return {
      type: "G-Address",
      display: truncateAddress(signer.values[0] as string, 6),
    };
  }

  const credentialId = getCredentialIdFromSigner(signer);
  if (credentialId) {
    return {
      type: "Passkey",
      display: `cred:${credentialId.slice(0, 8)}...`,
    };
  }

  const keyData = signer.values[1] as Buffer;
  if (keyData.length === 32) {
    return {
      type: "Ed25519",
      display: `key:${keyData.toString("hex").slice(0, 8)}...`,
    };
  }

  return {
    type: "External",
    display: truncateAddress(signer.values[0] as string, 4),
  };
}

/**
 * Check if two signers are equal.
 *
 * Compares signers by their tag and values. For Delegated signers,
 * compares the address. For External signers, compares verifier address
 * and key_data bytes.
 *
 * @param a - First signer
 * @param b - Second signer
 * @returns True if signers are equal
 *
 * @example
 * ```ts
 * const isSame = signersEqual(signer1, signer2);
 * const newSigners = currentSigners.filter(s => !originalSigners.some(o => signersEqual(s, o)));
 * ```
 */
export function signersEqual(a: Signer, b: Signer): boolean {
  if (a.tag !== b.tag) return false;

  if (a.tag === "Delegated" && b.tag === "Delegated") {
    return a.values[0] === b.values[0];
  }

  if (a.tag === "External" && b.tag === "External") {
    const aVerifier = a.values[0] as string;
    const bVerifier = b.values[0] as string;
    const aKey = a.values[1] as Buffer;
    const bKey = b.values[1] as Buffer;
    return aVerifier === bVerifier && aKey.equals(bKey);
  }

  return false;
}

/**
 * Get a unique key for a signer suitable for Map/Set operations.
 *
 * @param signer - The signer to get a key for
 * @returns A unique string key identifying this signer
 *
 * @example
 * ```ts
 * const signerMap = new Map<string, Signer>();
 * for (const signer of signers) {
 *   const key = getSignerKey(signer);
 *   if (!signerMap.has(key)) {
 *     signerMap.set(key, signer);
 *   }
 * }
 * ```
 */
export function getSignerKey(signer: Signer): string {
  if (signer.tag === "Delegated") {
    return `delegated:${signer.values[0]}`;
  }
  const keyData = signer.values[1] as Buffer;
  return `external:${signer.values[0]}:${keyData.toString("hex")}`;
}

/**
 * Collect unique signers from an array, removing duplicates.
 *
 * Uses `getSignerKey()` to determine uniqueness.
 *
 * @param signers - Array of signers (may contain duplicates)
 * @returns Array of unique signers
 *
 * @example
 * ```ts
 * const allSigners = rules.flatMap(r => r.signers);
 * const uniqueSigners = collectUniqueSigners(allSigners);
 * ```
 */
export function collectUniqueSigners(signers: Signer[]): Signer[] {
  const signerMap = new Map<string, Signer>();
  for (const signer of signers) {
    const key = getSignerKey(signer);
    if (!signerMap.has(key)) {
      signerMap.set(key, signer);
    }
  }
  return Array.from(signerMap.values());
}

/**
 * Format a context rule type for display.
 *
 * @param contextType - The context rule type to format
 * @returns Human-readable description
 *
 * @example
 * ```ts
 * const label = formatContextType(rule.context_type);
 * // "Default (Any Operation)"
 * // "Call Contract: CABC...WXYZ"
 * // "Create Contract: abc123..."
 * ```
 */
export function formatContextType(contextType: ContextRuleType): string {
  if (contextType.tag === "Default") {
    return "Default (Any Operation)";
  }

  if (contextType.tag === "CallContract") {
    return `Call Contract: ${truncateAddress(contextType.values[0] as string)}`;
  }

  if (contextType.tag === "CreateContract") {
    const hashBytes = contextType.values[0] as Buffer;
    const hashHex = hashBytes.toString("hex");
    return `Create Contract: ${hashHex.slice(0, 8)}...`;
  }

  return "Unknown";
}
