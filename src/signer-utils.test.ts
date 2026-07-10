import { describe, expect, it } from "vitest";
import base64url from "base64url";
import type { Signer } from "smart-account-kit-bindings";
import {
  collectUniqueSigners,
  getCredentialIdFromSigner,
  getSignerKey,
  signersEqual,
} from "./signer-utils";

const VERIFIER = "CVERIFIER";

function passkey(pubkeyByte: number, credByte: number): Signer {
  const pubkey = Buffer.alloc(65, pubkeyByte);
  const cred = Buffer.alloc(20, credByte);
  return { tag: "External", values: [VERIFIER, Buffer.concat([pubkey, cred])] };
}

function ed25519(keyByte: number): Signer {
  return { tag: "External", values: [VERIFIER, Buffer.alloc(32, keyByte)] };
}

function delegated(addr: string): Signer {
  return { tag: "Delegated", values: [addr] };
}

describe("getCredentialIdFromSigner", () => {
  it("extracts the credential id suffix from a passkey External signer", () => {
    const cred = Buffer.alloc(20, 7);
    const signer = passkey(1, 7);
    expect(getCredentialIdFromSigner(signer)).toBe(base64url.encode(cred));
  });

  it("returns null for Delegated signers", () => {
    expect(getCredentialIdFromSigner(delegated("G".padEnd(56, "A")))).toBeNull();
  });

  it("returns null for External signers with no credential suffix (ed25519)", () => {
    expect(getCredentialIdFromSigner(ed25519(1))).toBeNull();
  });
});

describe("signersEqual", () => {
  it("is true for identical Delegated signers", () => {
    expect(signersEqual(delegated("GABC"), delegated("GABC"))).toBe(true);
  });

  it("is false for different tags", () => {
    expect(signersEqual(delegated("GABC"), ed25519(1))).toBe(false);
  });

  it("compares External verifier + key bytes", () => {
    expect(signersEqual(ed25519(1), ed25519(1))).toBe(true);
    expect(signersEqual(ed25519(1), ed25519(2))).toBe(false);
  });
});

describe("getSignerKey", () => {
  it("produces distinct keys per signer identity", () => {
    expect(getSignerKey(delegated("GABC"))).toBe("delegated:GABC");
    expect(getSignerKey(ed25519(1))).toContain("external:CVERIFIER:");
    expect(getSignerKey(ed25519(1))).not.toBe(getSignerKey(ed25519(2)));
  });
});

describe("collectUniqueSigners", () => {
  it("deduplicates by signer identity, keeping first occurrence", () => {
    const a = ed25519(1);
    const b = ed25519(1);
    const c = delegated("GABC");
    const unique = collectUniqueSigners([a, b, c, c]);
    expect(unique).toHaveLength(2);
    expect(unique[0]).toBe(a);
    expect(unique[1]).toBe(c);
  });
});
