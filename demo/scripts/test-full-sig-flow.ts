#!/usr/bin/env bun
/**
 * Test the complete signature flow including:
 * 1. Building the Signatures tuple struct
 * 2. Verifying it can be decoded as Map<SignerId, Bytes>
 * 3. Verifying the inner Bytes can be decoded as WebAuthnSigData
 */

import {
  xdr,
  Address,
} from "@stellar/stellar-sdk";

// === DEBUG DATA FROM BROWSER CONSOLE ===
const DEBUG_DATA = {
  "credentialIdHex": "a45b23d1103708977052360732ee21c162c9e0c1",
  "authenticatorDataHex": "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQ0FGMWE3RUk4NUg1OVlkSHdOWVpEZU5RS05reVN4clVnRjJ3ekxzblhLayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
  "signatureCompactedHex": "af8011ab304a078d039bc8f448526865aac79d04f39be2ae2ce831f7e59194d62a9102cb255c6dd2ae333672977e67f40f56db5433ff6f825d6c2231fa19ee7c",
  "webauthnVerifierAddress": "CCIYFQ4FCK3WJ3YYUQPDEZZUVB63ZKMGBGOKGI5ZGT6HXUGHHAEHS2RE",
};

async function testFullSignatureFlow() {
  console.log("=== Testing Full Signature Flow ===\n");

  // Prepare the data
  const authenticatorData = Buffer.from(DEBUG_DATA.authenticatorDataHex, "hex");
  const clientDataJSON = Buffer.from(DEBUG_DATA.clientDataJSON, "base64");
  const compactSignature = Buffer.from(DEBUG_DATA.signatureCompactedHex, "hex");
  const credentialId = Buffer.from(DEBUG_DATA.credentialIdHex, "hex");

  console.log("1. Input Data Sizes:");
  console.log("   Authenticator Data:", authenticatorData.length, "bytes");
  console.log("   Client Data JSON:", clientDataJSON.length, "bytes");
  console.log("   Compact Signature:", compactSignature.length, "bytes");
  console.log("   Credential ID:", credentialId.length, "bytes");

  // ==========================================
  // Step 1: Build SignerId (External variant)
  // ==========================================
  console.log("\n2. Building SignerId::External(Address, Bytes)...");

  // SignerId::External(verifier_address, key_id)
  // Encoded as: Vec[Symbol("External"), Address, Bytes]
  const signerIdScVal = xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("External"),
    xdr.ScVal.scvAddress(Address.fromString(DEBUG_DATA.webauthnVerifierAddress).toScAddress()),
    xdr.ScVal.scvBytes(credentialId),
  ]);

  console.log("   SignerId XDR length:", signerIdScVal.toXDR().length, "bytes");

  // ==========================================
  // Step 2: Build WebAuthnSigData struct
  // ==========================================
  console.log("\n3. Building WebAuthnSigData struct...");

  // WebAuthnSigData is a named-field struct:
  // pub struct WebAuthnSigData {
  //     pub signature: BytesN<64>,
  //     pub authenticator_data: Bytes,
  //     pub client_data: Bytes,
  // }
  // Encoded as: Map with symbol keys sorted alphabetically
  const sigDataMap = xdr.ScVal.scvMap([
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

  console.log("   WebAuthnSigData as ScVal::Map");
  sigDataMap.map()?.forEach((entry, i) => {
    const key = entry.key().sym().toString();
    const val = entry.val();
    console.log(`   [${i}] ${key}: ${val.bytes().length} bytes`);
  });

  // XDR encode the struct (this is what from_xdr expects)
  const sigDataXdr = sigDataMap.toXDR();
  console.log("   WebAuthnSigData XDR length:", sigDataXdr.length, "bytes");

  // ==========================================
  // Step 3: Build Bytes value containing XDR
  // ==========================================
  console.log("\n4. Wrapping in ScVal::Bytes...");

  // The signature value in Map<SignerId, Bytes> is Bytes containing XDR
  const sigDataAsBytes = xdr.ScVal.scvBytes(sigDataXdr);
  console.log("   Bytes wrapper XDR length:", sigDataAsBytes.toXDR().length, "bytes");

  // ==========================================
  // Step 4: Build Map<SignerId, Bytes>
  // ==========================================
  console.log("\n5. Building Map<SignerId, Bytes>...");

  const signaturesMap = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: signerIdScVal,
      val: sigDataAsBytes,
    }),
  ]);
  console.log("   Map XDR length:", signaturesMap.toXDR().length, "bytes");

  // ==========================================
  // Step 5: Build Signatures tuple struct
  // ==========================================
  console.log("\n6. Building Signatures tuple struct (Vec wrapper)...");

  // Signatures is: pub struct Signatures(pub Map<SignerId, Bytes>)
  // Tuple structs are encoded as: Vec[field0, field1, ...]
  // So Signatures(Map) becomes Vec[Map]
  const signaturesStruct = xdr.ScVal.scvVec([signaturesMap]);
  const finalXdr = signaturesStruct.toXDR();
  console.log("   Signatures struct XDR length:", finalXdr.length, "bytes");
  console.log("   Signatures struct XDR (hex):", finalXdr.toString("hex"));

  // ==========================================
  // Step 6: Verify decoding
  // ==========================================
  console.log("\n7. Verifying decoding...");

  // Decode as Signatures (Vec[Map])
  const decodedSignatures = xdr.ScVal.fromXDR(finalXdr);
  console.log("   Decoded type:", decodedSignatures.switch().name);

  if (decodedSignatures.switch().name === "scvVec") {
    const vec = decodedSignatures.vec();
    console.log("   Vec length:", vec?.length);

    if (vec && vec.length > 0) {
      const innerMap = vec[0];
      console.log("   Inner element type:", innerMap.switch().name);

      if (innerMap.switch().name === "scvMap") {
        const mapEntries = innerMap.map();
        console.log("   Map entries:", mapEntries?.length);

        if (mapEntries && mapEntries.length > 0) {
          const entry = mapEntries[0];
          console.log("\n   Entry key type:", entry.key().switch().name);
          console.log("   Entry val type:", entry.val().switch().name);

          // Decode the key as SignerId
          if (entry.key().switch().name === "scvVec") {
            const keyVec = entry.key().vec();
            console.log("\n   SignerId variant:", keyVec?.[0].sym().toString());
            console.log("   SignerId address:", keyVec?.[1].address());
            console.log("   SignerId key_id length:", keyVec?.[2].bytes().length, "bytes");
          }

          // Decode the value as Bytes containing WebAuthnSigData XDR
          if (entry.val().switch().name === "scvBytes") {
            const sigDataBytes = Buffer.from(entry.val().bytes());
            console.log("\n   Signature data bytes length:", sigDataBytes.length);

            // Try to decode as WebAuthnSigData
            try {
              const innerSigData = xdr.ScVal.fromXDR(sigDataBytes);
              console.log("   Inner decode type:", innerSigData.switch().name);

              if (innerSigData.switch().name === "scvMap") {
                console.log("\n   WebAuthnSigData fields:");
                innerSigData.map()?.forEach((e, i) => {
                  const k = e.key().sym().toString();
                  const v = e.val();
                  console.log(`     [${i}] ${k}: ${v.bytes().length} bytes`);
                });
                console.log("\n   ✓ Successfully decoded WebAuthnSigData!");
              }
            } catch (e) {
              console.log("   ✗ Failed to decode inner sig data:", e);
            }
          }
        }
      }
    }
  }

  console.log("\n=== Test Complete ===");
}

testFullSignatureFlow().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
