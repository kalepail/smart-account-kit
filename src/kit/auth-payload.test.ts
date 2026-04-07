import { Keypair, hash, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import type { AuthPayload, Signer } from "smart-account-kit-bindings";
import {
  buildAuthDigest,
  buildAddressSignatureScVal,
  readAuthPayload,
  upsertAuthPayloadSigner,
  writeAuthPayload,
} from "./auth-payload";

function makeDelegatedSigner(address: string): Signer {
  return {
    tag: "Delegated",
    values: [address],
  };
}

function makeAccount(seedByte: number): string {
  return Keypair.fromRawEd25519Seed(Buffer.alloc(32, seedByte)).publicKey();
}

describe("auth-payload", () => {
  it("round-trips AuthPayload with signer map and context rule ids", () => {
    const signer = makeDelegatedSigner(
      makeAccount(1)
    );
    const payload: AuthPayload = {
      context_rule_ids: [3, 9],
      signers: new Map([[signer, Buffer.from("deadbeef", "hex")]]),
    };

    const encoded = writeAuthPayload(payload);
    const decoded = readAuthPayload(encoded);

    expect(decoded.context_rule_ids).toEqual([3, 9]);
    expect(decoded.signers.size).toBe(1);

    const [decodedSigner, decodedSignature] = Array.from(decoded.signers.entries())[0];
    expect(decodedSigner).toEqual(signer);
    expect(decodedSignature).toEqual(Buffer.from("deadbeef", "hex"));
  });

  it("replaces an existing signer entry instead of duplicating it", () => {
    const signer = makeDelegatedSigner(
      makeAccount(2)
    );
    const payload: AuthPayload = {
      context_rule_ids: [],
      signers: new Map([[signer, Buffer.from("aa", "hex")]]),
    };

    upsertAuthPayloadSigner(payload, signer, Buffer.from("bb", "hex"));

    expect(payload.signers.size).toBe(1);
    expect(Array.from(payload.signers.values())[0]).toEqual(Buffer.from("bb", "hex"));
  });

  it("binds context rule ids into the auth digest", () => {
    const signaturePayload = hash(Buffer.from("payload"));

    const digestA = buildAuthDigest(signaturePayload, [1]);
    const digestB = buildAuthDigest(signaturePayload, [2]);

    expect(digestA.equals(digestB)).toBe(false);

    const expected = hash(
      Buffer.concat([
        signaturePayload,
        xdr.ScVal.scvVec([xdr.ScVal.scvU32(1)]).toXDR(),
      ])
    );
    expect(digestA).toEqual(expected);
  });

  it("builds a canonical address-signature ScVal envelope", () => {
    const publicKey = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 3)).rawPublicKey();
    const signature = Buffer.from("deadbeef", "hex");

    const scVal = buildAddressSignatureScVal(publicKey, signature);
    const items = scVal.vec();
    expect(items).toHaveLength(1);

    const entries = items?.[0].map();
    expect(entries).toHaveLength(2);
    expect(entries?.[0].key().sym().toString()).toBe("public_key");
    expect(Buffer.from(entries?.[0].val().bytes() ?? [])).toEqual(Buffer.from(publicKey));
    expect(entries?.[1].key().sym().toString()).toBe("signature");
    expect(Buffer.from(entries?.[1].val().bytes() ?? [])).toEqual(signature);
  });
});
