import {
  Address,
  Keypair,
  buildAuthorizationEntryPreimage,
  buildWithDelegatesEntry,
  hash,
  xdr,
} from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import type { AuthPayload, Signer } from "smart-account-kit-bindings";
import {
  buildAuthDigest,
  buildAddressSignatureScVal,
  buildSignaturePreimage,
  buildSignaturePayload,
  buildWebAuthnSignatureBytes,
  createAddressCredentials,
  getAddressCredentials,
  readAuthPayload,
  upsertAuthPayloadSigner,
  writeAuthPayload,
} from "./auth-payload";

describe("buildWebAuthnSignatureBytes", () => {
  it("encodes WebAuthnSigData to the pinned ScVal XDR (sorted authenticator_data/client_data/signature)", () => {
    const bytes = buildWebAuthnSignatureBytes({
      authenticator_data: Buffer.alloc(4, 1),
      client_data: Buffer.alloc(4, 2),
      signature: Buffer.alloc(64, 3),
    });
    expect(bytes.toString("hex")).toBe(
      "0000001100000001000000030000000f0000001261757468656e74696361746f725f6461746100000000000d00000004010101010000000f0000000b636c69656e745f64617461000000000d00000004020202020000000f000000097369676e61747572650000000000000d0000004003030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303"
    );
  });
});

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

  it("creates ADDRESS_V2 credentials only with explicit opt-in", () => {
    const credentials = getAddressCredentials(makeAuthEntry(makeAccount(5)).credentials());
    const legacyCredentials = createAddressCredentials(credentials);
    const addressV2Credentials = createAddressCredentials(credentials, {
      version: "address_v2",
    });

    expect(legacyCredentials.switch().name).toBe("sorobanCredentialsAddress");
    expect(addressV2Credentials.switch().name).toBe("sorobanCredentialsAddressV2");
    expect(getAddressCredentials(addressV2Credentials).nonce().toString()).toBe("7");
  });

  it("rejects unsupported address credential versions", () => {
    const credentials = getAddressCredentials(makeAuthEntry(makeAccount(6)).credentials());

    expect(() =>
      createAddressCredentials(credentials, { version: "bogus" as never })
    ).toThrow("Unsupported Soroban address credential version: bogus");
  });

  it("matches the SDK auth preimage helper for legacy ADDRESS credentials", () => {
    const networkPassphrase = "Test SDF Network ; September 2015";
    const entry = makeAuthEntry(makeAccount(7));
    const expectedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
    const preimage = buildSignaturePreimage(networkPassphrase, entry, 123);
    const expected = buildAuthorizationEntryPreimage(expectedEntry, 123, networkPassphrase);

    expect(preimage.toXDR()).toEqual(expected.toXDR());
    expect(preimage.switch().name).toBe("envelopeTypeSorobanAuthorization");
    expect(getAddressCredentials(entry.credentials()).signatureExpirationLedger()).toBe(123);
  });

  it("matches the SDK auth preimage helper for ADDRESS_V2 credentials", () => {
    const networkPassphrase = "Test SDF Network ; September 2015";
    const baseEntry = makeAuthEntry(makeAccount(8));
    const entry = new xdr.SorobanAuthorizationEntry({
      credentials: createAddressCredentials(getAddressCredentials(baseEntry.credentials()), {
        version: "address_v2",
      }),
      rootInvocation: baseEntry.rootInvocation(),
    });
    const expectedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
    const preimage = buildSignaturePreimage(networkPassphrase, entry, 123);
    const expected = buildAuthorizationEntryPreimage(expectedEntry, 123, networkPassphrase);

    expect(preimage.toXDR()).toEqual(expected.toXDR());
    expect(preimage.switch().name).toBe("envelopeTypeSorobanAuthorizationWithAddress");
    expect(buildSignaturePayload(networkPassphrase, entry, 123)).toHaveLength(32);
    expect(getAddressCredentials(entry.credentials()).signatureExpirationLedger()).toBe(123);
  });

  it("matches the SDK auth preimage helper for ADDRESS_WITH_DELEGATES credentials", () => {
    const networkPassphrase = "Test SDF Network ; September 2015";
    const delegatedEntry = buildWithDelegatesEntry({
      entry: makeAuthEntry(makeAccount(14)),
      validUntilLedgerSeq: 123,
      delegates: [{ address: makeAccount(15) }],
    });
    const expectedEntry = xdr.SorobanAuthorizationEntry.fromXDR(delegatedEntry.toXDR());
    const preimage = buildSignaturePreimage(networkPassphrase, delegatedEntry, 123);
    const expected = buildAuthorizationEntryPreimage(expectedEntry, 123, networkPassphrase);

    expect(delegatedEntry.credentials().switch().name).toBe(
      "sorobanCredentialsAddressWithDelegates"
    );
    expect(preimage.toXDR()).toEqual(expected.toXDR());
    expect(preimage.switch().name).toBe("envelopeTypeSorobanAuthorizationWithAddress");
  });

  it("keeps the submitted expiration in sync with the signed payload", () => {
    const entry = makeAuthEntry(makeAccount(16));
    const payload = buildSignaturePayload("Test SDF Network ; September 2015", entry, 123);

    expect(payload).toHaveLength(32);
    expect(getAddressCredentials(entry.credentials()).signatureExpirationLedger()).toBe(123);
  });

  it("rounds fractional signature expirations up before XDR serialization", () => {
    const entry = makeAuthEntry(makeAccount(17));
    const payload = buildSignaturePayload("Test SDF Network ; September 2015", entry, 123.2);

    expect(payload).toHaveLength(32);
    expect(getAddressCredentials(entry.credentials()).signatureExpirationLedger()).toBe(124);
  });

  it("rejects non-finite signature expirations without mutating the entry", () => {
    const entry = makeAuthEntry(makeAccount(18));

    expect(() =>
      buildSignaturePayload("Test SDF Network ; September 2015", entry, Number.NaN)
    ).toThrow("Signature expiration ledger must be a finite number");
    expect(getAddressCredentials(entry.credentials()).signatureExpirationLedger()).toBe(1);
  });

  it("rejects out-of-range signature expirations without mutating the entry", () => {
    const negativeEntry = makeAuthEntry(makeAccount(19));
    const negativeFractionEntry = makeAuthEntry(makeAccount(21));
    const oversizedEntry = makeAuthEntry(makeAccount(20));

    expect(() =>
      buildSignaturePayload("Test SDF Network ; September 2015", negativeEntry, -1)
    ).toThrow("Signature expiration ledger must fit in u32");
    expect(getAddressCredentials(negativeEntry.credentials()).signatureExpirationLedger()).toBe(1);

    expect(() =>
      buildSignaturePayload("Test SDF Network ; September 2015", negativeFractionEntry, -0.5)
    ).toThrow("Signature expiration ledger must fit in u32");
    expect(
      getAddressCredentials(negativeFractionEntry.credentials()).signatureExpirationLedger()
    ).toBe(1);

    expect(() =>
      buildSignaturePayload("Test SDF Network ; September 2015", oversizedEntry, 0x1_0000_0000)
    ).toThrow("Signature expiration ledger must fit in u32");
    expect(getAddressCredentials(oversizedEntry.credentials()).signatureExpirationLedger()).toBe(1);
  });
});
