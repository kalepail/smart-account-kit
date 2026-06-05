import { Address, Keypair, hash, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import type { AuthPayload, Signer } from "smart-account-kit-bindings";
import {
  buildAuthDigest,
  buildAddressSignatureScVal,
  buildSignaturePayload,
  createAddressCredentials,
  getAddressCredentials,
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

function makeAuthEntry(address: string): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: createAddressCredentials(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(address).toScAddress(),
        nonce: xdr.Int64.fromString("7"),
        signatureExpirationLedger: 1,
        signature: xdr.ScVal.scvVoid(),
      })
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: xdr.ScAddress.scAddressTypeContract(
            hash(Buffer.from("contract"))
          ),
          functionName: "do_it",
          args: [],
        })
      ),
      subInvocations: [],
    }),
  });
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

  it("unwraps address credentials through the shared helper", () => {
    const account = makeAccount(4);
    const entry = makeAuthEntry(account);
    const credentials = getAddressCredentials(entry.credentials());

    expect(entry.credentials().switch().name).toBe("sorobanCredentialsAddress");
    expect(credentials.nonce().toString()).toBe("7");
    expect(Address.fromScAddress(credentials.address()).toString()).toBe(account);
  });

  it("requires explicit opt-in for ADDRESS_V2 credentials", () => {
    const credentials = getAddressCredentials(makeAuthEntry(makeAccount(5)).credentials());

    expect(() => createAddressCredentials(credentials, { version: "address_v2" })).toThrow(
      "ADDRESS_V2 credentials require an SDK with Protocol 27 credential support"
    );
  });

  it("rejects unsupported address credential versions", () => {
    const credentials = getAddressCredentials(makeAuthEntry(makeAccount(6)).credentials());

    expect(() =>
      createAddressCredentials(credentials, { version: "bogus" as never })
    ).toThrow("Unsupported Soroban address credential version: bogus");
  });

  it("does not sign address-bound credentials without P27 preimage support", () => {
    const credentials = getAddressCredentials(makeAuthEntry(makeAccount(7)).credentials());
    const fakeAddressV2Entry = {
      credentials: () => ({
        switch: () => ({ name: "sorobanCredentialsAddressV2" }),
        addressV2: () => credentials,
      }),
      rootInvocation: () => makeAuthEntry(makeAccount(8)).rootInvocation(),
    } as unknown as xdr.SorobanAuthorizationEntry;

    expect(() =>
      buildSignaturePayload("Test SDF Network ; September 2015", fakeAddressV2Entry, 123)
    ).toThrow(
      "Address-bound Soroban auth credentials require an SDK with Protocol 27 auth preimage support"
    );
    expect(credentials.signatureExpirationLedger()).toBe(1);
  });

  it("keeps the submitted expiration in sync with the signed payload", () => {
    const entry = makeAuthEntry(makeAccount(9));
    const payload = buildSignaturePayload("Test SDF Network ; September 2015", entry, 123);

    expect(payload).toHaveLength(32);
    expect(getAddressCredentials(entry.credentials()).signatureExpirationLedger()).toBe(123);
  });

  it("rounds fractional signature expirations up before XDR serialization", () => {
    const entry = makeAuthEntry(makeAccount(10));
    const payload = buildSignaturePayload("Test SDF Network ; September 2015", entry, 123.2);

    expect(payload).toHaveLength(32);
    expect(getAddressCredentials(entry.credentials()).signatureExpirationLedger()).toBe(124);
  });

  it("rejects non-finite signature expirations without mutating the entry", () => {
    const entry = makeAuthEntry(makeAccount(11));

    expect(() =>
      buildSignaturePayload("Test SDF Network ; September 2015", entry, Number.NaN)
    ).toThrow("Signature expiration ledger must be a finite number");
    expect(getAddressCredentials(entry.credentials()).signatureExpirationLedger()).toBe(1);
  });

  it("rejects out-of-range signature expirations without mutating the entry", () => {
    const negativeEntry = makeAuthEntry(makeAccount(12));
    const oversizedEntry = makeAuthEntry(makeAccount(13));

    expect(() =>
      buildSignaturePayload("Test SDF Network ; September 2015", negativeEntry, -1)
    ).toThrow("Signature expiration ledger must fit in u32");
    expect(getAddressCredentials(negativeEntry.credentials()).signatureExpirationLedger()).toBe(1);

    expect(() =>
      buildSignaturePayload("Test SDF Network ; September 2015", oversizedEntry, 0x1_0000_0000)
    ).toThrow("Signature expiration ledger must fit in u32");
    expect(getAddressCredentials(oversizedEntry.credentials()).signatureExpirationLedger()).toBe(1);
  });
});
