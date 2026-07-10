import { describe, expect, it } from "vitest";
import { Keypair, StrKey, hash } from "@stellar/stellar-sdk";
import { ExternalSignerManager } from "./external-signers";
import { Ed25519Signer } from "./signers";
import { ValidationError } from "./errors";

const NETWORK = "Test SDF Network ; September 2015";
const VERIFIER = StrKey.encodeContract(hash(Buffer.from("ed25519-verifier")));

function keypair(seed: number): Keypair {
  return Keypair.fromRawEd25519Seed(Buffer.alloc(32, seed));
}

describe("ExternalSignerManager — Ed25519 signers", () => {
  it("adds an ed25519 signer with an explicit verifier address", () => {
    const mgr = new ExternalSignerManager(NETWORK);
    const kp = keypair(1);

    const { address, publicKey } = mgr.addEd25519FromSecret(kp.secret(), VERIFIER);

    expect(address).toBe(kp.publicKey());
    expect(publicKey).toBe(Buffer.from(kp.rawPublicKey()).toString("hex"));
    expect(mgr.canSignEd25519(kp.rawPublicKey())).toBe(true);
    expect(mgr.hasSigners).toBe(true);
  });

  it("uses the SDK-configured verifier address by default", () => {
    const mgr = new ExternalSignerManager(NETWORK, undefined, undefined, VERIFIER);
    const kp = keypair(2);

    mgr.addEd25519FromSecret(kp.secret());

    const signer = mgr.getEd25519Signer(kp.rawPublicKey());
    expect(signer?.verifier).toBe(VERIFIER);
  });

  it("throws when no verifier address is available", () => {
    const mgr = new ExternalSignerManager(NETWORK);
    expect(() => mgr.addEd25519FromSecret(keypair(3).secret())).toThrow(
      ValidationError
    );
  });

  it("signs an auth digest identically to a standalone Ed25519Signer", () => {
    const mgr = new ExternalSignerManager(NETWORK, undefined, undefined, VERIFIER);
    const kp = keypair(4);
    mgr.addEd25519FromSecret(kp.secret());

    const authDigest = Buffer.alloc(32, 5);
    const fromManager = mgr.signEd25519Digest(kp.rawPublicKey(), authDigest);
    const fromSigner = new Ed25519Signer(kp, VERIFIER).signAuthDigest(authDigest);

    expect(fromManager).toEqual(fromSigner);
    expect(kp.verify(authDigest, fromManager)).toBe(true);
  });

  it("throws when signing for an unknown ed25519 key", () => {
    const mgr = new ExternalSignerManager(NETWORK, undefined, undefined, VERIFIER);
    expect(() =>
      mgr.signEd25519Digest(keypair(6).rawPublicKey(), Buffer.alloc(32, 1))
    ).toThrow();
  });

  it("lists ed25519 signers via getAll", () => {
    const mgr = new ExternalSignerManager(NETWORK, undefined, undefined, VERIFIER);
    const kp = keypair(7);
    mgr.addEd25519FromSecret(kp.secret());

    const listed = mgr.getAll().find((s) => s.type === "ed25519");
    expect(listed).toMatchObject({
      address: kp.publicKey(),
      type: "ed25519",
      verifierAddress: VERIFIER,
      publicKey: Buffer.from(kp.rawPublicKey()).toString("hex"),
    });
  });

  it("removes an ed25519 signer by G-address", () => {
    const mgr = new ExternalSignerManager(NETWORK, undefined, undefined, VERIFIER);
    const kp = keypair(8);
    mgr.addEd25519FromSecret(kp.secret());

    mgr.remove(kp.publicKey());
    expect(mgr.canSignEd25519(kp.rawPublicKey())).toBe(false);
    expect(mgr.hasSigners).toBe(false);
  });

  it("clears ed25519 signers via removeAll", async () => {
    const mgr = new ExternalSignerManager(NETWORK, undefined, undefined, VERIFIER);
    mgr.addEd25519FromSecret(keypair(9).secret());

    await mgr.removeAll();
    expect(mgr.hasSigners).toBe(false);
  });
});

describe("ExternalSignerManager — keypair (Delegated) signers", () => {
  it("adds a keypair from a secret and reports it can sign", () => {
    const mgr = new ExternalSignerManager(NETWORK);
    const kp = keypair(20);
    const { address } = mgr.addFromSecret(kp.secret());
    expect(address).toBe(kp.publicKey());
    expect(mgr.canSignFor(kp.publicKey())).toBe(true);
    expect(mgr.hasSigners).toBe(true);
  });

  it("rejects an invalid secret", () => {
    const mgr = new ExternalSignerManager(NETWORK);
    expect(() => mgr.addFromSecret("not-a-secret")).toThrow(ValidationError);
  });

  it("lists keypair signers and removes them", () => {
    const mgr = new ExternalSignerManager(NETWORK);
    const kp = keypair(21);
    mgr.addFromSecret(kp.secret());
    expect(mgr.getAll().find((s) => s.type === "keypair")?.address).toBe(kp.publicKey());
    mgr.remove(kp.publicKey());
    expect(mgr.canSignFor(kp.publicKey())).toBe(false);
  });

  it("keeps keypair and ed25519 signers independent", () => {
    const mgr = new ExternalSignerManager(NETWORK, undefined, undefined, VERIFIER);
    const kp = keypair(22);
    mgr.addFromSecret(kp.secret());
    mgr.addEd25519FromSecret(keypair(23).secret());
    expect(mgr.getAll().filter((s) => s.type === "keypair")).toHaveLength(1);
    expect(mgr.getAll().filter((s) => s.type === "ed25519")).toHaveLength(1);
  });

  it("throws from addFromWallet with no adapter configured", async () => {
    const mgr = new ExternalSignerManager(NETWORK);
    await expect(mgr.addFromWallet()).rejects.toThrow();
  });

  it("signAuthEntry throws SignerNotFoundError for an unknown address", async () => {
    const mgr = new ExternalSignerManager(NETWORK);
    await expect(
      mgr.signAuthEntry("AAAA", keypair(24).publicKey())
    ).rejects.toThrow();
  });
});
