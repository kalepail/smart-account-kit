#!/usr/bin/env bun
/**
 * Test script to debug WebAuthn signature verification
 * Paste the debug data from the browser console here to test signature format
 */

import {
  hash,
  Networks,
  xdr,
  StrKey,
} from "@stellar/stellar-sdk";

// === PASTE DEBUG DATA FROM BROWSER CONSOLE HERE ===
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
// === END PASTE SECTION ===

async function testWebAuthnSignature() {
  console.log("=== Testing WebAuthn Signature Format ===\n");

  if (!DEBUG_DATA.challengeHex) {
    console.log("No debug data pasted. Please paste the JSON from browser console.");
    console.log("Look for '=== WEBAUTHN AUTH RESPONSE DEBUG ===' in the console output.");
    process.exit(1);
  }

  // Parse the data
  const payload = Buffer.from(DEBUG_DATA.challengeHex, "hex");
  const authenticatorData = Buffer.from(DEBUG_DATA.authenticatorDataHex, "hex");
  const clientDataJSON = DEBUG_DATA.clientDataJSONDecoded;
  const rawSignature = Buffer.from(DEBUG_DATA.signatureHex, "hex");
  const compactSignature = Buffer.from(DEBUG_DATA.signatureCompactedHex, "hex");
  const credentialId = Buffer.from(DEBUG_DATA.credentialIdHex, "hex");

  console.log("1. Payload (challenge) that was signed:");
  console.log("   Hex:", DEBUG_DATA.challengeHex);
  console.log("   Length:", payload.length, "bytes");

  console.log("\n2. Authenticator Data:");
  console.log("   Hex:", DEBUG_DATA.authenticatorDataHex);
  console.log("   Length:", authenticatorData.length, "bytes");

  // Parse authenticator data structure
  // https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
  const rpIdHash = authenticatorData.subarray(0, 32);
  const flags = authenticatorData[32];
  const signCount = authenticatorData.readUInt32BE(33);
  console.log("   RP ID Hash:", rpIdHash.toString("hex"));
  console.log("   Flags:", flags.toString(2).padStart(8, "0"), `(0x${flags.toString(16)})`);
  console.log("   Sign Count:", signCount);

  // Flags breakdown
  console.log("   - User Present (UP):", !!(flags & 0x01));
  console.log("   - User Verified (UV):", !!(flags & 0x04));
  console.log("   - Attested Credential Data (AT):", !!(flags & 0x40));
  console.log("   - Extension Data (ED):", !!(flags & 0x80));

  console.log("\n3. Client Data JSON:");
  console.log("   Parsed:", clientDataJSON);

  // Parse as JSON to see individual fields
  try {
    const clientData = JSON.parse(clientDataJSON);
    console.log("   type:", clientData.type);
    console.log("   challenge:", clientData.challenge);
    console.log("   origin:", clientData.origin);
    console.log("   crossOrigin:", clientData.crossOrigin);
  } catch (e) {
    console.log("   Failed to parse:", e);
  }

  console.log("\n4. Signature:");
  console.log("   Raw (DER) Hex:", DEBUG_DATA.signatureHex);
  console.log("   Raw Length:", rawSignature.length, "bytes");
  console.log("   Compact Hex:", DEBUG_DATA.signatureCompactedHex);
  console.log("   Compact Length:", compactSignature.length, "bytes");

  // Verify signature is correct length (64 bytes for P-256)
  if (compactSignature.length !== 64) {
    console.log("   WARNING: Compact signature should be 64 bytes!");
  }

  console.log("\n5. Credential ID:");
  console.log("   Base64url:", DEBUG_DATA.credentialId);
  console.log("   Hex:", DEBUG_DATA.credentialIdHex);
  console.log("   Length:", credentialId.length, "bytes");

  console.log("\n6. Contract Info:");
  console.log("   WebAuthn Verifier:", DEBUG_DATA.webauthnVerifierAddress);
  console.log("   Smart Account:", DEBUG_DATA.smartAccountContractId);
  console.log("   Network:", DEBUG_DATA.networkPassphrase);

  // Now let's verify what the contract expects
  console.log("\n=== Verifying Signature Format ===\n");

  // The WebAuthn signature verification typically works as:
  // 1. Hash the clientDataJSON
  // 2. Concatenate authenticatorData + SHA256(clientDataJSON)
  // 3. Verify signature over this concatenated data

  const clientDataHash = hash(Buffer.from(clientDataJSON));
  console.log("7. Client Data Hash (SHA256):");
  console.log("   Hex:", clientDataHash.toString("hex"));

  const signedData = Buffer.concat([authenticatorData, clientDataHash]);
  console.log("\n8. Signed Data (authenticatorData || hash(clientDataJSON)):");
  console.log("   Hex:", signedData.toString("hex"));
  console.log("   Length:", signedData.length, "bytes");

  // The challenge in clientDataJSON should match our payload
  console.log("\n9. Challenge Verification:");
  try {
    const clientData = JSON.parse(clientDataJSON);
    // The challenge is base64url encoded in clientDataJSON
    // We need to decode it and compare to our payload
    const challengeFromClient = Buffer.from(clientData.challenge, "base64url");
    console.log("   Challenge from clientData:", challengeFromClient.toString("hex"));
    console.log("   Original payload:", payload.toString("hex"));
    console.log("   Match:", challengeFromClient.equals(payload) ? "YES ✓" : "NO ✗");
  } catch (e) {
    console.log("   Failed to verify:", e);
  }

  // Check signature structure
  console.log("\n10. Signature Structure Analysis:");
  if (rawSignature[0] === 0x30) {
    console.log("   Raw signature is DER encoded (starts with 0x30)");
    // Parse DER structure
    const totalLen = rawSignature[1];
    console.log("   DER total length:", totalLen);

    // Find r value
    let offset = 2;
    if (rawSignature[offset] === 0x02) {
      const rLen = rawSignature[offset + 1];
      const r = rawSignature.subarray(offset + 2, offset + 2 + rLen);
      console.log("   r length:", rLen, "value:", r.toString("hex"));
      offset += 2 + rLen;

      // Find s value
      if (rawSignature[offset] === 0x02) {
        const sLen = rawSignature[offset + 1];
        const s = rawSignature.subarray(offset + 2, offset + 2 + sLen);
        console.log("   s length:", sLen, "value:", s.toString("hex"));
      }
    }
  } else {
    console.log("   Raw signature is NOT DER encoded (first byte:", rawSignature[0].toString(16), ")");
  }

  // Check compact signature (should be r || s, each 32 bytes)
  console.log("\n11. Compact Signature Analysis:");
  if (compactSignature.length === 64) {
    const r = compactSignature.subarray(0, 32);
    const s = compactSignature.subarray(32, 64);
    console.log("   r (32 bytes):", r.toString("hex"));
    console.log("   s (32 bytes):", s.toString("hex"));

    // Check if r or s have leading zeros (they should be padded to 32 bytes)
    if (r[0] === 0) {
      console.log("   NOTE: r has leading zero padding");
    }
    if (s[0] === 0) {
      console.log("   NOTE: s has leading zero padding");
    }
  }

  console.log("\n=== Test Complete ===");
}

testWebAuthnSignature().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
