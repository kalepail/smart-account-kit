#!/usr/bin/env bun
/**
 * Test script to debug auth entry signing for smart account transfers
 * This tests the XDR handling of auth entries outside of Vite
 */

import {
  Contract,
  Networks,
  nativeToScVal,
  Keypair,
  hash,
  TransactionBuilder,
  BASE_FEE,
  xdr,
  Operation,
  rpc,
} from "@stellar/stellar-sdk";

const { Server } = rpc;

const CONFIG = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: Networks.TESTNET,
  nativeTokenContract: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
};

// Derive the same deployer keypair used by the SDK
const DEPLOYER_KEYPAIR = Keypair.fromRawEd25519Seed(
  hash(Buffer.from("openzeppelin-smart-account-kit"))
);

// The smart wallet contract (already deployed)
const SMART_WALLET = "CDANWYENKH6PTTY6GDTMDAMYRHMU4SBRPX5NUDYDMTYVOIF32ASZFU4Y";

// A recipient address
const RECIPIENT = "CCIYFQ4FCK3WJ3YYUQPDEZZUVB63ZKMGBGOKGI5ZGT6HXUGHHAEHS2RE";

async function testAuthEntry() {
  console.log("=== Testing Auth Entry Signing ===\n");

  const server = new Server(CONFIG.rpcUrl);
  const tokenContract = new Contract(CONFIG.nativeTokenContract);

  console.log("Deployer public key:", DEPLOYER_KEYPAIR.publicKey());
  console.log("Smart wallet:", SMART_WALLET);
  console.log("Recipient:", RECIPIENT);

  // Get the deployer account (fee payer)
  console.log("\n1. Getting deployer account...");
  let sourceAccount = await server.getAccount(DEPLOYER_KEYPAIR.publicKey());
  console.log("   Sequence:", sourceAccount.sequenceNumber());

  // Build a transfer from the smart wallet
  const amount = BigInt(10 * 10_000_000); // 10 XLM in stroops

  console.log("\n2. Building simulation transaction...");
  const simulationTx = new TransactionBuilder(sourceAccount, {
    fee: BASE_FEE,
    networkPassphrase: CONFIG.networkPassphrase,
  })
    .addOperation(
      tokenContract.call(
        "transfer",
        nativeToScVal(SMART_WALLET, { type: "address" }), // from: smart wallet
        nativeToScVal(RECIPIENT, { type: "address" }), // to: recipient
        nativeToScVal(amount, { type: "i128" })
      )
    )
    .setTimeout(30)
    .build();

  console.log("   Transaction built");

  console.log("\n3. Simulating transaction...");
  const simResult = await server.simulateTransaction(simulationTx);

  if ("error" in simResult) {
    console.error("   Simulation failed:", simResult.error);
    process.exit(1);
  }

  console.log("   Simulation successful");
  console.log("   Latest ledger:", simResult.latestLedger);
  console.log("   Min resource fee:", simResult.minResourceFee);

  // Inspect the auth entries
  console.log("\n4. Inspecting auth entries...");
  const authEntries = simResult.result?.auth || [];
  console.log("   Found", authEntries.length, "auth entries");

  if (authEntries.length === 0) {
    console.log("   No auth entries to sign!");
    process.exit(0);
  }

  for (let i = 0; i < authEntries.length; i++) {
    const entry = authEntries[i];
    console.log(`\n   --- Auth Entry ${i} ---`);
    console.log("   Entry XDR (base64):", entry.toXDR("base64"));
    console.log("   Credentials type:", entry.credentials().switch().name);

    if (entry.credentials().switch().name === "sorobanCredentialsAddress") {
      const credentials = entry.credentials().address();
      console.log("   Address credentials found");

      // Inspect the nonce
      const nonce = credentials.nonce();
      console.log("   Nonce type:", typeof nonce);
      console.log("   Nonce value:", nonce);
      console.log("   Nonce toString:", nonce.toString());

      // Check signature expiration ledger
      const expLedger = credentials.signatureExpirationLedger();
      console.log("   Signature expiration ledger:", expLedger);

      // Try to build the preimage manually
      console.log("\n5. Building HashIdPreimageSorobanAuthorization with FULL SDK...");
      try {
        const networkId = hash(Buffer.from(CONFIG.networkPassphrase));
        console.log("   Network ID:", networkId.toString("hex"));

        // The nonce might already be an xdr.Int64 object
        // Let's check what methods it has
        console.log("   Nonce constructor name:", nonce.constructor?.name);
        console.log("   Nonce keys:", Object.keys(nonce));

        // Try creating the preimage with full SDK
        const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
          new xdr.HashIdPreimageSorobanAuthorization({
            networkId: networkId,
            nonce: nonce, // Pass as-is first
            signatureExpirationLedger: expLedger,
            invocation: entry.rootInvocation(),
          })
        );
        console.log("   Preimage created successfully with FULL SDK!");

        const payload = hash(preimage.toXDR());
        console.log("   Payload hash:", payload.toString("hex"));
      } catch (err) {
        console.error("   Error creating preimage with FULL SDK:", err);
      }

    }
  }

  console.log("\n=== Test Complete ===");
}

testAuthEntry().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
