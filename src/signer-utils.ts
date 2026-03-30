import type { Signer } from "smart-account-kit-bindings";
import { SECP256R1_PUBLIC_KEY_SIZE } from "./constants";

export function getCredentialIdFromSigner(signer: Signer): string | null {
  if (signer.tag !== "External") {
    return null;
  }

  const keyData = signer.values[1] as Buffer;
  if (keyData.length <= SECP256R1_PUBLIC_KEY_SIZE) {
    return null;
  }

  const credentialId = keyData.slice(SECP256R1_PUBLIC_KEY_SIZE);
  return credentialId.toString("base64url");
}

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

export function getSignerKey(signer: Signer): string {
  if (signer.tag === "Delegated") {
    return `delegated:${signer.values[0]}`;
  }

  const keyData = signer.values[1] as Buffer;
  return `external:${signer.values[0]}:${keyData.toString("hex")}`;
}

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
