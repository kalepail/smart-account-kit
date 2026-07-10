import { describe, expect, it } from "vitest";
import { Keypair, hash, xdr } from "@stellar/stellar-sdk";
import { buildAuthDigest } from "./kit/auth-payload";
import { Ed25519Signer, computeEntryAuthDigest } from "./signers";
import { ValidationError } from "./errors";
import { makeAddressAuthEntry, makeContract } from "./managers/test-utils";

const TESTNET = "Test SDF Network ; September 2015";

/** Independent re-implementation of the documented auth-digest formula. */
function referenceAuthDigest(signaturePayload: Buffer, contextRuleIds: number[]): Buffer {
  const idsXdr = xdr.ScVal
    .scvVec(contextRuleIds.map((id) => xdr.ScVal.scvU32(id)))
    .toXDR();
  return hash(Buffer.concat([signaturePayload, idsXdr]));
}

describe("buildAuthDigest", () => {
  it("matches the documented sha256(payload ++ scvVec(ids).toXDR()) formula", () => {
    const payload = Buffer.alloc(32, 7);
    const ids = [0, 5, 42];
    expect(buildAuthDigest(payload, ids)).toEqual(referenceAuthDigest(payload, ids));
  });

  it("pins golden digest vectors (regression guard for the Rust formula)", () => {
    const payload = Buffer.alloc(32, 7);
    expect(buildAuthDigest(payload, [0, 5, 42]).toString("hex")).toBe(
      "5c00edbcad5ec543c2f3b7ad37ccf4878342d8e59c560fbe9256eba049668706"
    );
    expect(buildAuthDigest(payload, []).toString("hex")).toBe(
      "0f0b7265fdbecfcb83f0ed792c9bfd1a03439eb289cd39767128e845e9437c6d"
    );
  });

  it("binds the context rule ids: different ids produce different digests", () => {
    const payload = Buffer.alloc(32, 1);
    expect(buildAuthDigest(payload, [1]).toString("hex")).not.toBe(
      buildAuthDigest(payload, [2]).toString("hex")
    );
    expect(buildAuthDigest(payload, [1, 2]).toString("hex")).not.toBe(
      buildAuthDigest(payload, [2, 1]).toString("hex")
    );
  });

  it("always produces a 32-byte digest", () => {
    expect(buildAuthDigest(Buffer.alloc(32, 9), [3])).toHaveLength(32);
  });
});

describe("computeEntryAuthDigest", () => {
  it("returns a 32-byte digest consistent with buildAuthDigest", () => {
    const contractId = makeContract(1);
    const entry = makeAddressAuthEntry(contractId);
    const ids = [0, 3];

    const { signaturePayload, authDigest } = computeEntryAuthDigest(
      TESTNET,
      entry,
      100,
      ids
    );

    expect(authDigest).toHaveLength(32);
    expect(signaturePayload).toHaveLength(32);
    expect(authDigest).toEqual(buildAuthDigest(signaturePayload, ids));
  });

  it("writes the expiration onto the entry as a side effect", () => {
    const entry = makeAddressAuthEntry(makeContract(2));
    computeEntryAuthDigest(TESTNET, entry, 12345, [1]);
    expect(entry.credentials().address().signatureExpirationLedger()).toBe(12345);
  });

  it("changes the digest when expiration changes", () => {
    const entry = makeAddressAuthEntry(makeContract(3));
    const a = computeEntryAuthDigest(TESTNET, entry, 100, [1]).authDigest.toString("hex");
    const b = computeEntryAuthDigest(TESTNET, entry, 200, [1]).authDigest.toString("hex");
    expect(a).not.toBe(b);
  });
});

describe("Ed25519Signer", () => {
  const verifier = makeContract(9);
  const keypair = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 11));

  it("exposes an External(verifier, 32-byte pubkey) signer identity", () => {
    const signer = new Ed25519Signer(keypair, verifier);
    expect(signer.signer.tag).toBe("External");
    expect(signer.signer.values[0]).toBe(verifier);
    const keyData = signer.signer.values[1] as Buffer;
    expect(keyData).toHaveLength(32);
    expect(Buffer.from(keyData)).toEqual(Buffer.from(keypair.rawPublicKey()));
    expect(signer.publicKey).toEqual(Buffer.from(keypair.rawPublicKey()));
    expect(signer.address).toBe(keypair.publicKey());
    expect(signer.verifier).toBe(verifier);
  });

  it("signs the auth digest, producing a verifiable 64-byte signature", () => {
    const signer = new Ed25519Signer(keypair, verifier);
    const authDigest = Buffer.alloc(32, 3);

    const signature = signer.signAuthDigest(authDigest);

    expect(signature).toHaveLength(64);
    // The deployed ed25519 verifier checks the raw 32-byte digest against the key.
    expect(keypair.verify(authDigest, signature)).toBe(true);
    // A different digest must not verify against this signature.
    expect(keypair.verify(Buffer.alloc(32, 4), signature)).toBe(false);
  });

  it("builds from a secret key", () => {
    const signer = Ed25519Signer.fromSecret(keypair.secret(), verifier);
    expect(signer.address).toBe(keypair.publicKey());
  });

  it("rejects an invalid secret key with a ValidationError", () => {
    expect(() => Ed25519Signer.fromSecret("not-a-secret", verifier)).toThrow(
      ValidationError
    );
  });
});
