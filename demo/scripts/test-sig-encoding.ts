#!/usr/bin/env bun
/**
 * Test script to verify the signature XDR encoding matches what the contract expects
 * Uses the debug data from a previous browser session to test encoding
 */

import {
  hash,
  Networks,
  xdr,
  Address,
} from "@stellar/stellar-sdk";

// === DEBUG DATA FROM BROWSER CONSOLE ===
const DEBUG_DATA = {
  "challenge": "CAF1a7EI85H59YdHwNYZDeNQKNkySxrUgF2wzLsnXKk",
  "challengeHex": "0801756bb108f391f9f58747c0d6190de35028d9324b1ad4805db0ccbb275ca9",
  "credentialId": "pFsj0RA3CJdwUjYHMu4hwWLJ4ME",
  "credentialIdHex": "a45b23d1103708977052360732ee21c162c9e0c1",
  "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQ0FGMWE3RUk4NUg1OVlkSHdOWVpEZU5RS05reVN4clVnRjJ3ekxzblhLayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
  "signature": "MEUCIQCvgBGrMEoHjQObyPRIUmhlqsedBPOb4q4s6DH35ZGU1gIgKpECyyVcbdKuMzZyl35n9A9W21Qz_2-CXWwiMfoZ7nw",
  "authenticatorDataHex": "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
  "clientDataJSONDecoded": "{\"type\":\"webauthn.get\",\"challenge\":\"CAF1a7EI85H59YdHwNYZDeNQKNkySxrUgF2wzLsnXKk\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false,\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\"}",
  "signatureHex": "3045022100af8011ab304a078d039bc8f448526865aac79d04f39be2ae2ce831f7e59194d602202a9102cb255c6dd2ae333672977e67f40f56db5433ff6f825d6c2231fa19ee7c",
  "signatureCompactedHex": "af8011ab304a078d039bc8f448526865aac79d04f39be2ae2ce831f7e59194d62a9102cb255c6dd2ae333672977e67f40f56db5433ff6f825d6c2231fa19ee7c",
  "webauthnVerifierAddress": "CCIYFQ4FCK3WJ3YYUQPDEZZUVB63ZKMGBGOKGI5ZGT6HXUGHHAEHS2RE",
  "smartAccountContractId": "CDANWYENKH6PTTY6GDTMDAMYRHMU4SBRPX5NUDYDMTYVOIF32ASZFU4Y",
  "networkPassphrase": "Test SDF Network ; September 2015"
};

// Types matching the kit
interface WebAuthnSigData {
  authenticator_data: Buffer;
  client_data: Buffer;
  signature: Buffer;
}

interface ContractSignerId {
  tag: "Delegated" | "External";
  values: [string] | [string, Buffer];
}

/**
 * Build a signature map entry - same logic as kit.ts buildSignatureMapEntry
 */
function buildSignatureMapEntry(
  signerId: ContractSignerId,
  sigData: WebAuthnSigData
): xdr.ScMapEntry {
  // Encode the SignerId as the key
  let keyVal: xdr.ScVal;
  if (signerId.tag === "Delegated") {
    // Delegated(Address)
    keyVal = xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("Delegated"),
      xdr.ScVal.scvAddress(Address.fromString(signerId.values[0]).toScAddress()),
    ]);
  } else {
    // External(Address, Bytes) = (verifier, key_id)
    keyVal = xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("External"),
      xdr.ScVal.scvAddress(Address.fromString(signerId.values[0]).toScAddress()),
      xdr.ScVal.scvBytes(signerId.values[1]),
    ]);
  }

  // Encode the WebAuthnSigData struct as XDR bytes.
  // The verifier contract expects sig_data as Bytes containing XDR-encoded WebAuthnSigData.
  // Soroban structs are encoded as ScVal::Map with alphabetically sorted symbol keys.
  const sigDataScVal = xdr.ScVal.scvMap([
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
  ]);

  // XDR-encode the ScVal and wrap in scvBytes for the signature map value
  const sigDataXdrBytes = sigDataScVal.toXDR();
  const sigVal = xdr.ScVal.scvBytes(sigDataXdrBytes);

  return new xdr.ScMapEntry({
    key: keyVal,
    val: sigVal,
  });
}

async function testSignatureEncoding() {
  console.log("=== Testing Signature XDR Encoding ===\n");

  // Prepare the data
  const authenticatorData = Buffer.from(DEBUG_DATA.authenticatorDataHex, "hex");
  const clientDataJSON = Buffer.from(DEBUG_DATA.clientDataJSON, "base64");
  const compactSignature = Buffer.from(DEBUG_DATA.signatureCompactedHex, "hex");
  const credentialId = Buffer.from(DEBUG_DATA.credentialIdHex, "hex");

  console.log("1. Input Data:");
  console.log("   Authenticator Data:", authenticatorData.length, "bytes");
  console.log("   Client Data JSON:", clientDataJSON.length, "bytes");
  console.log("   Compact Signature:", compactSignature.length, "bytes");
  console.log("   Credential ID:", credentialId.length, "bytes");

  // Build the SignerId
  const signerId: ContractSignerId = {
    tag: "External",
    values: [
      DEBUG_DATA.webauthnVerifierAddress,
      credentialId,
    ],
  };

  // Build the WebAuthnSigData
  const webAuthnSigData: WebAuthnSigData = {
    authenticator_data: authenticatorData,
    client_data: clientDataJSON,
    signature: compactSignature,
  };

  console.log("\n2. Building Signature Map Entry...");
  const scMapEntry = buildSignatureMapEntry(signerId, webAuthnSigData);

  // Inspect the key
  console.log("\n3. Key (SignerId) Analysis:");
  const keyXdr = scMapEntry.key().toXDR("hex");
  console.log("   Key XDR (hex):", keyXdr);
  console.log("   Key XDR length:", keyXdr.length / 2, "bytes");

  // Inspect the value
  console.log("\n4. Value (Signature Data) Analysis:");
  const valXdr = scMapEntry.val().toXDR("hex");
  console.log("   Value XDR (hex):", valXdr);
  console.log("   Value XDR length:", valXdr.length / 2, "bytes");

  // Decode the inner value to verify structure
  const valBytes = scMapEntry.val().bytes();
  console.log("\n5. Inner Value (WebAuthnSigData XDR):");
  console.log("   Inner bytes length:", valBytes.length, "bytes");
  console.log("   Inner bytes (hex):", Buffer.from(valBytes).toString("hex"));

  // Try to decode as ScVal to verify structure
  try {
    const innerScVal = xdr.ScVal.fromXDR(Buffer.from(valBytes));
    console.log("\n6. Decoded Inner ScVal:");
    console.log("   Type:", innerScVal.switch().name);

    if (innerScVal.switch().name === "scvMap") {
      const map = innerScVal.map();
      console.log("   Map entries:", map?.length);
      map?.forEach((entry, i) => {
        const key = entry.key();
        const val = entry.val();
        console.log(`   [${i}] Key: ${key.switch().name === "scvSymbol" ? key.sym().toString() : key.switch().name}`);
        console.log(`       Val: ${val.switch().name}, length: ${val.switch().name === "scvBytes" ? val.bytes().length : "N/A"}`);
      });
    }
  } catch (e) {
    console.log("\n6. Failed to decode inner ScVal:", e);
  }

  // Build a complete signature map
  console.log("\n7. Complete Signature Map:");
  const sigMap = xdr.ScVal.scvMap([scMapEntry]);
  const sigMapXdr = sigMap.toXDR("hex");
  console.log("   Signature Map XDR length:", sigMapXdr.length / 2, "bytes");

  // Build the credentials signature structure: Vec<Map<SignerId, Bytes>>
  const credentialsSig = xdr.ScVal.scvVec([sigMap]);
  const credentialsSigXdr = credentialsSig.toXDR("hex");
  console.log("   Credentials Signature XDR length:", credentialsSigXdr.length / 2, "bytes");

  console.log("\n=== Encoding Test Complete ===");

  // Now let's compare with what brozorec/smart-account-sign does
  console.log("\n\n=== Comparing with brozorec/smart-account-sign format ===\n");

  // Their format: ScMap::sorted_from with the struct fields directly
  // Then XDR encode and wrap in ScVal::Bytes

  // Their sig_obj equivalent
  const sigObjMap = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("authenticator_data"),
      val: xdr.ScVal.scvBytes(authenticatorData),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("client_data"),
      val: xdr.ScVal.scvBytes(clientDataJSON),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("signature"),
      val: xdr.ScVal.scvBytes(compactSignature),
    }),
  ]);

  // Sort the map entries (should already be sorted alphabetically)
  const sortedEntries = sigObjMap.map()!.sort((a, b) => {
    const aKey = a.key().sym().toString();
    const bKey = b.key().sym().toString();
    return aKey.localeCompare(bKey);
  });

  const sortedSigObjMap = xdr.ScVal.scvMap(sortedEntries);
  console.log("8. Sorted Sig Object Map:");
  sortedSigObjMap.map()?.forEach((entry, i) => {
    const key = entry.key().sym().toString();
    const val = entry.val();
    console.log(`   [${i}] ${key}: ${val.bytes().length} bytes`);
  });

  // XDR encode
  const sigObjXdr = sortedSigObjMap.toXDR();
  console.log("\n9. Sig Object XDR:");
  console.log("   Length:", sigObjXdr.length, "bytes");
  console.log("   Hex:", sigObjXdr.toString("hex"));

  // Wrap in Bytes
  const sigObjAsBytes = xdr.ScVal.scvBytes(sigObjXdr);
  console.log("\n10. Wrapped as ScVal::Bytes:");
  console.log("   Final XDR length:", sigObjAsBytes.toXDR().length, "bytes");

  // Compare with our encoding
  const ourInnerBytes = Buffer.from(scMapEntry.val().bytes());
  console.log("\n11. Comparison:");
  console.log("   Our inner XDR matches brozorec format:", ourInnerBytes.equals(sigObjXdr) ? "YES ✓" : "NO ✗");
  if (!ourInnerBytes.equals(sigObjXdr)) {
    console.log("   Our inner XDR:", ourInnerBytes.toString("hex"));
    console.log("   brozorec XDR:", sigObjXdr.toString("hex"));
  }
}

testSignatureEncoding().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
