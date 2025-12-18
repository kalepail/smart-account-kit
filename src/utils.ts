/**
 * Utility functions for the Smart Account Kit SDK.
 *
 * Contains cryptographic helpers, validation functions, and common operations.
 *
 * @packageDocumentation
 */

import { StrKey, hash, xdr, Address } from "@stellar/stellar-sdk";
import type { RegistrationResponseJSON } from "@simplewebauthn/browser";
import base64url from "base64url";

import {
  SECP256R1_PUBLIC_KEY_SIZE,
  UNCOMPRESSED_PUBKEY_PREFIX,
  STROOPS_PER_XLM,
} from "./constants";
import {
  ValidationError,
  SmartAccountErrorCode,
} from "./errors";

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Validate that a string is a valid Stellar address (G... or C...).
 *
 * Uses stellar-sdk's StrKey methods for proper checksum validation.
 *
 * @param address - The address to validate
 * @param fieldName - Name of the field for error messages
 * @throws {ValidationError} If the address is invalid
 */
export function validateAddress(address: string, fieldName: string = "address"): void {
  if (!address || typeof address !== "string") {
    throw new ValidationError(
      `${fieldName} is required`,
      SmartAccountErrorCode.INVALID_ADDRESS,
      { field: fieldName }
    );
  }

  const isValidAccount = StrKey.isValidEd25519PublicKey(address);
  const isValidContract = StrKey.isValidContract(address);

  if (!isValidAccount && !isValidContract) {
    throw new ValidationError(
      `Invalid ${fieldName}: must be a valid Stellar account (G...) or contract (C...) address`,
      SmartAccountErrorCode.INVALID_ADDRESS,
      { field: fieldName, value: address.slice(0, 10) + "..." }
    );
  }
}

/**
 * Validate that an amount is a positive number.
 *
 * @param amount - The amount to validate
 * @param fieldName - Name of the field for error messages
 * @throws {ValidationError} If the amount is invalid
 */
export function validateAmount(amount: number, fieldName: string = "amount"): void {
  if (typeof amount !== "number" || isNaN(amount)) {
    throw new ValidationError(
      `${fieldName} must be a number`,
      SmartAccountErrorCode.INVALID_AMOUNT,
      { field: fieldName }
    );
  }

  if (amount <= 0) {
    throw new ValidationError(
      `${fieldName} must be positive`,
      SmartAccountErrorCode.INVALID_AMOUNT,
      { field: fieldName, value: amount }
    );
  }
}

/**
 * Validate that a string is not empty.
 *
 * @param value - The value to validate
 * @param fieldName - Name of the field for error messages
 * @throws {ValidationError} If the value is empty
 */
export function validateNotEmpty(value: string | undefined | null, fieldName: string): void {
  if (!value || typeof value !== "string" || value.trim().length === 0) {
    throw new ValidationError(
      `${fieldName} is required`,
      SmartAccountErrorCode.INVALID_INPUT,
      { field: fieldName }
    );
  }
}

// ============================================================================
// Encoding Helpers
// ============================================================================

/**
 * Convert bytes to a base64url-encoded string.
 *
 * This is a browser-compatible implementation that doesn't require Node.js Buffer.
 * Useful for encoding credential IDs, public keys, and other binary data for display
 * or transmission.
 *
 * @param bytes - The bytes to encode
 * @returns Base64url-encoded string (URL-safe, no padding)
 *
 * @example
 * ```ts
 * const credentialId = new Uint8Array([1, 2, 3, 4]);
 * const encoded = toBase64Url(credentialId); // "AQIDBA"
 * ```
 */
export function toBase64Url(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Decode a base64url-encoded string to bytes.
 *
 * This is a browser-compatible implementation that doesn't require Node.js Buffer.
 *
 * @param str - The base64url-encoded string
 * @returns Decoded bytes as Uint8Array
 *
 * @example
 * ```ts
 * const decoded = fromBase64Url("AQIDBA"); // Uint8Array([1, 2, 3, 4])
 * ```
 */
export function fromBase64Url(str: string): Uint8Array {
  // Add padding if needed
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ============================================================================
// Conversion Helpers
// ============================================================================

/**
 * Convert XLM amount to stroops.
 *
 * @param xlm - Amount in XLM
 * @returns Amount in stroops as BigInt
 */
export function xlmToStroops(xlm: number): bigint {
  return BigInt(Math.floor(xlm * STROOPS_PER_XLM));
}

/**
 * Convert stroops to XLM amount.
 *
 * @param stroops - Amount in stroops
 * @returns Amount in XLM
 */
export function stroopsToXlm(stroops: bigint | number): number {
  return Number(stroops) / STROOPS_PER_XLM;
}

// ============================================================================
// Key Data Helpers
// ============================================================================

/**
 * Build key_data by concatenating public key and credential ID.
 *
 * The key_data format is: pubkey (65 bytes) + credentialId (variable bytes)
 *
 * @param publicKey - The 65-byte uncompressed secp256r1 public key
 * @param credentialId - The credential ID (as base64url string or Buffer)
 * @returns Concatenated key_data as Buffer
 */
export function buildKeyData(
  publicKey: Uint8Array,
  credentialId: string | Buffer
): Buffer {
  const credentialIdBuffer =
    typeof credentialId === "string"
      ? base64url.toBuffer(credentialId)
      : credentialId;

  return Buffer.concat([Buffer.from(publicKey), credentialIdBuffer]);
}

/**
 * Extract the public key from key_data.
 *
 * @param keyData - The full key_data (pubkey + credentialId)
 * @returns The 65-byte public key
 */
export function extractPubkeyFromKeyData(keyData: Buffer): Buffer {
  return keyData.slice(0, SECP256R1_PUBLIC_KEY_SIZE);
}

/**
 * Extract the credential ID from key_data.
 *
 * @param keyData - The full key_data (pubkey + credentialId)
 * @returns The credential ID portion
 */
export function extractCredentialIdFromKeyData(keyData: Buffer): Buffer {
  return keyData.slice(SECP256R1_PUBLIC_KEY_SIZE);
}

// ============================================================================
// Cryptographic Helpers
// ============================================================================

/**
 * Derive a contract address from a credential ID.
 *
 * Uses the Stellar contract ID preimage to deterministically derive
 * the contract address from the deployer and credential ID.
 *
 * @param credentialId - The credential ID buffer
 * @param deployerPublicKey - The deployer's public key string
 * @param networkPassphrase - The network passphrase
 * @returns The derived contract address (C...)
 */
export function deriveContractAddress(
  credentialId: Buffer,
  deployerPublicKey: string,
  networkPassphrase: string
): string {
  const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
    new xdr.HashIdPreimageContractId({
      networkId: hash(Buffer.from(networkPassphrase)),
      contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
        new xdr.ContractIdPreimageFromAddress({
          address: Address.fromString(deployerPublicKey).toScAddress(),
          salt: hash(credentialId),
        })
      ),
    })
  );

  return StrKey.encodeContract(hash(preimage.toXDR()));
}

/**
 * Extract the public key from a WebAuthn attestation response.
 *
 * Tries multiple methods to extract the public key:
 * 1. From response.publicKey directly (if provided)
 * 2. From authenticatorData (parsing CBOR structure)
 * 3. From attestationObject (parsing CBOR structure)
 *
 * @param response - The WebAuthn registration response
 * @returns The 65-byte uncompressed secp256r1 public key
 * @throws {Error} If public key cannot be extracted
 */
export async function extractPublicKeyFromAttestation(
  response: RegistrationResponseJSON["response"]
): Promise<Uint8Array> {
  let publicKey: Buffer | undefined;

  // Try to get the public key from the response directly
  if (response.publicKey) {
    publicKey = base64url.toBuffer(response.publicKey);
    publicKey = publicKey.slice(publicKey.length - SECP256R1_PUBLIC_KEY_SIZE);
  }

  // Validate it's a proper uncompressed EC point
  if (
    !publicKey ||
    publicKey[0] !== UNCOMPRESSED_PUBKEY_PREFIX ||
    publicKey.length !== SECP256R1_PUBLIC_KEY_SIZE
  ) {
    // Fall back to extracting from authenticatorData or attestationObject
    let x: Buffer;
    let y: Buffer;

    if (response.authenticatorData) {
      const authenticatorData = base64url.toBuffer(response.authenticatorData);
      const credentialIdLength =
        (authenticatorData[53] << 8) | authenticatorData[54];

      x = authenticatorData.slice(
        65 + credentialIdLength,
        97 + credentialIdLength
      );
      y = authenticatorData.slice(
        100 + credentialIdLength,
        132 + credentialIdLength
      );
    } else if (response.attestationObject) {
      const attestationObject = base64url.toBuffer(response.attestationObject);

      // COSE key structure prefix for ES256 (P-256)
      const publicKeyPrefixSlice = Buffer.from([
        0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
      ]);
      let startIndex = attestationObject.indexOf(publicKeyPrefixSlice);
      startIndex = startIndex + publicKeyPrefixSlice.length;

      x = attestationObject.slice(startIndex, 32 + startIndex);
      y = attestationObject.slice(35 + startIndex, 67 + startIndex);
    } else {
      throw new Error(
        "Could not extract public key from attestation response"
      );
    }

    publicKey = Buffer.from([
      UNCOMPRESSED_PUBKEY_PREFIX, // 0x04 - Uncompressed EC point prefix
      ...x,
      ...y,
    ]);
  }

  return new Uint8Array(publicKey);
}

/**
 * Convert a DER-encoded ECDSA signature to compact format with low-S.
 *
 * Stellar requires signatures in compact (r || s) format with low-S values.
 * This function:
 * 1. Decodes the DER structure
 * 2. Ensures S is in low-S form (S <= n/2)
 * 3. Returns 64-byte compact signature
 *
 * @param derSignature - The DER-encoded signature
 * @returns 64-byte compact signature (r || s)
 */
export function compactSignature(derSignature: Buffer): Uint8Array {
  // Decode DER signature: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
  let offset = 2; // Skip 0x30 and total length

  const rLength = derSignature[offset + 1];
  const r = derSignature.slice(offset + 2, offset + 2 + rLength);

  offset += 2 + rLength;

  const sLength = derSignature[offset + 1];
  const s = derSignature.slice(offset + 2, offset + 2 + sLength);

  // Convert to BigInt for low-S calculation
  const rBigInt = BigInt("0x" + r.toString("hex"));
  let sBigInt = BigInt("0x" + s.toString("hex"));

  // Ensure low-S form (required by Stellar)
  // n is the order of the secp256r1 curve
  const n = BigInt(
    "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
  );
  const halfN = n / 2n;

  if (sBigInt > halfN) {
    sBigInt = n - sBigInt;
  }

  // Convert back to 32-byte buffers (padded)
  const rPadded = Buffer.from(rBigInt.toString(16).padStart(64, "0"), "hex");
  const sLowS = Buffer.from(sBigInt.toString(16).padStart(64, "0"), "hex");

  return new Uint8Array(Buffer.concat([rPadded, sLowS]));
}

// ============================================================================
// WebAuthn Helpers
// ============================================================================

/**
 * Generate a random challenge for WebAuthn operations.
 *
 * @returns A base64url-encoded random challenge
 */
export function generateChallenge(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}
