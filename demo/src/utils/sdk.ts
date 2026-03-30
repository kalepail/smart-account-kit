import type { Signer, ContextRuleType } from "smart-account-kit-bindings";
import { ValidationError, SmartAccountErrorCode, getCredentialIdFromSigner } from "smart-account-kit";

export function validateAddress(address: string, fieldName: string = "address"): void {
  if (!address || typeof address !== "string") {
    throw new ValidationError(
      `${fieldName} is required`,
      SmartAccountErrorCode.INVALID_ADDRESS,
      { field: fieldName }
    );
  }

  const isAccount = address.startsWith("G") && address.length === 56;
  const isContract = address.startsWith("C") && address.length === 56;

  if (!isAccount && !isContract) {
    throw new ValidationError(
      `Invalid ${fieldName}: must be a valid Stellar account (G...) or contract (C...) address`,
      SmartAccountErrorCode.INVALID_ADDRESS,
      { field: fieldName, value: `${address.slice(0, 10)}...` }
    );
  }
}

export function validateAmount(amount: number, fieldName: string = "amount"): void {
  if (typeof amount !== "number" || !Number.isFinite(amount)) {
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

export function truncateAddress(address: string, chars: number = 4): string {
  if (address.length <= chars * 2 + 3) {
    return address;
  }

  return `${address.slice(0, chars)}...${address.slice(-chars)}`;
}

export function describeSignerType(signer: Signer): string {
  if (signer.tag === "Delegated") {
    return "Stellar Account";
  }

  const keyData = signer.values[1] as Buffer;
  if (getCredentialIdFromSigner(signer)) {
    return "Passkey (WebAuthn)";
  }
  if (keyData.length === 32) {
    return "Ed25519";
  }

  return "External Verifier";
}

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

export function formatContextType(contextType: ContextRuleType): string {
  if (contextType.tag === "Default") {
    return "Default (Any Operation)";
  }

  if (contextType.tag === "CallContract") {
    return `Call Contract: ${truncateAddress(contextType.values[0] as string)}`;
  }

  if (contextType.tag === "CreateContract") {
    const hashBytes = contextType.values[0] as Buffer;
    return `Create Contract: ${hashBytes.toString("hex").slice(0, 8)}...`;
  }

  return "Unknown";
}
