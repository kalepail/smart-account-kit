import { describe, expect, it } from "vitest";
import base64url from "base64url";
import { extractPublicKeyFromAttestation } from "./utils";

describe("utils.extractPublicKeyFromAttestation", () => {
  it("normalizes SPKI public keys from WebAuthn registration responses", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );

    const spki = Buffer.from(
      new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey))
    );
    const raw = Buffer.from(
      new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey))
    );

    const extracted = await extractPublicKeyFromAttestation({
      clientDataJSON: "",
      attestationObject: "",
      publicKey: base64url.encode(spki),
    });

    expect(Buffer.from(extracted)).toEqual(raw);
    expect(extracted).toHaveLength(65);
    expect(extracted[0]).toBe(0x04);
  });
});
