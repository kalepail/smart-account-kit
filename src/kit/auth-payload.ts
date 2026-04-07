import { Address, hash, xdr } from "@stellar/stellar-sdk";
import type {
  AuthPayload,
  Signer as ContractSigner,
} from "smart-account-kit-bindings";
import { signersEqual } from "../signer-utils";
import type { WebAuthnSigData } from "../contract-types";

export function buildSignaturePayload(
  networkPassphrase: string,
  entry: xdr.SorobanAuthorizationEntry,
  expiration: number
): Buffer {
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: hash(Buffer.from(networkPassphrase)),
      nonce: entry.credentials().address().nonce(),
      signatureExpirationLedger: expiration,
      invocation: entry.rootInvocation(),
    })
  );

  return hash(preimage.toXDR());
}

export function buildAuthDigest(
  signaturePayload: Buffer,
  contextRuleIds: number[]
): Buffer {
  const ruleIdsXdr = xdr.ScVal.scvVec(
    contextRuleIds.map((contextRuleId) => xdr.ScVal.scvU32(contextRuleId))
  ).toXDR();

  return hash(Buffer.concat([signaturePayload, ruleIdsXdr]));
}

export function buildWebAuthnSignatureBytes(sigData: WebAuthnSigData): Buffer {
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("authenticator_data"),
      val: xdr.ScVal.scvBytes(sigData.authenticator_data),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("client_data"),
      val: xdr.ScVal.scvBytes(sigData.client_data),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("signature"),
      val: xdr.ScVal.scvBytes(sigData.signature),
    }),
  ]).toXDR();
}

export function buildAddressSignatureScVal(
  publicKeyBytes: Uint8Array | Buffer,
  signatureBytes: Uint8Array | Buffer
): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("public_key"),
        val: xdr.ScVal.scvBytes(Buffer.from(publicKeyBytes)),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("signature"),
        val: xdr.ScVal.scvBytes(Buffer.from(signatureBytes)),
      }),
    ]),
  ]);
}

export function emptyAuthPayload(): AuthPayload {
  return {
    context_rule_ids: [],
    signers: new Map(),
  };
}

export function readAuthPayload(signature: xdr.ScVal): AuthPayload {
  if (signature.switch().name === "scvVoid") {
    return emptyAuthPayload();
  }

  if (signature.switch().name !== "scvMap") {
    throw new Error("Smart account auth signature is not encoded as AuthPayload");
  }

  const payload = emptyAuthPayload();

  for (const entry of signature.map() ?? []) {
    const key = entry.key();
    if (key.switch().name !== "scvSymbol") {
      continue;
    }

    const field = key.sym().toString();
    if (field === "context_rule_ids") {
      const value = entry.val();
      if (value.switch().name !== "scvVec") {
        throw new Error("AuthPayload.context_rule_ids is not a vector");
      }

      payload.context_rule_ids = (value.vec() ?? []).map((item) => {
        if (item.switch().name !== "scvU32") {
          throw new Error("AuthPayload.context_rule_ids contains a non-u32 value");
        }
        return item.u32();
      });
    }

    if (field === "signers") {
      const value = entry.val();
      if (value.switch().name !== "scvMap") {
        throw new Error("AuthPayload.signers is not a map");
      }

      for (const signerEntry of value.map() ?? []) {
        const signer = parseSignerScVal(signerEntry.key());
        const signerValue = signerEntry.val();
        if (signerValue.switch().name !== "scvBytes") {
          throw new Error("AuthPayload.signers contains a non-bytes signature value");
        }

        payload.signers.set(signer, Buffer.from(signerValue.bytes()));
      }
    }
  }

  return payload;
}

export function writeAuthPayload(payload: AuthPayload): xdr.ScVal {
  const signerEntries = Array.from(payload.signers.entries()).map(
    ([signer, signatureBytes]) =>
      new xdr.ScMapEntry({
        key: signerToScVal(signer),
        val: xdr.ScVal.scvBytes(signatureBytes),
      })
  );

  signerEntries.sort((a, b) => a.key().toXDR("hex").localeCompare(b.key().toXDR("hex")));

  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("context_rule_ids"),
      val: xdr.ScVal.scvVec(
        payload.context_rule_ids.map((contextRuleId) => xdr.ScVal.scvU32(contextRuleId))
      ),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("signers"),
      val: xdr.ScVal.scvMap(signerEntries),
    }),
  ]);
}

export function upsertAuthPayloadSigner(
  payload: AuthPayload,
  signer: ContractSigner,
  signatureBytes: Buffer
): void {
  for (const existingSigner of payload.signers.keys()) {
    if (signersEqual(existingSigner, signer)) {
      payload.signers.delete(existingSigner);
      break;
    }
  }

  payload.signers.set(signer, signatureBytes);
}

function signerToScVal(signer: ContractSigner): xdr.ScVal {
  if (signer.tag === "Delegated") {
    return xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("Delegated"),
      xdr.ScVal.scvAddress(Address.fromString(signer.values[0]).toScAddress()),
    ]);
  }

  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("External"),
    xdr.ScVal.scvAddress(Address.fromString(signer.values[0]).toScAddress()),
    xdr.ScVal.scvBytes(signer.values[1]),
  ]);
}

function parseSignerScVal(value: xdr.ScVal): ContractSigner {
  if (value.switch().name !== "scvVec") {
    throw new Error("Signer key is not encoded as a vector");
  }

  const items = value.vec() ?? [];
  if (items.length < 2 || items[0].switch().name !== "scvSymbol") {
    throw new Error("Signer key is not a valid enum encoding");
  }

  const variant = items[0].sym().toString();
  if (variant === "Delegated") {
    if (items[1].switch().name !== "scvAddress") {
      throw new Error("Delegated signer is missing an address");
    }

    return {
      tag: "Delegated",
      values: [Address.fromScAddress(items[1].address()).toString()],
    };
  }

  if (variant === "External") {
    if (
      items.length < 3 ||
      items[1].switch().name !== "scvAddress" ||
      items[2].switch().name !== "scvBytes"
    ) {
      throw new Error("External signer is missing required verifier or key data");
    }

    return {
      tag: "External",
      values: [
        Address.fromScAddress(items[1].address()).toString(),
        Buffer.from(items[2].bytes()),
      ],
    };
  }

  throw new Error(`Unknown signer variant: ${variant}`);
}
