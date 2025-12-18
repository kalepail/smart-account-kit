#!/usr/bin/env bun
/**
 * Test script for verifying Stellar transaction submission works correctly
 * Used for debugging bundler issues - this script runs outside of Vite
 * Run with: bun run scripts/test-fund.ts
 */

import {
  Contract,
  Networks,
  nativeToScVal,
  Keypair,
  TransactionBuilder,
  BASE_FEE,
  rpc,
} from "@stellar/stellar-sdk";

const { Server } = rpc;

const CONFIG = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: Networks.TESTNET,
  // Native XLM token contract on testnet
  nativeTokenContract: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
};

// Use a test destination - this is just a random contract address for testing
const TEST_DESTINATION = "CCIYFQ4FCK3WJ3YYUQPDEZZUVB63ZKMGBGOKGI5ZGT6HXUGHHAEHS2RE";

async function main() {
  console.log("=== Stellar Transaction Test ===\n");

  // 1. Create a random keypair
  const tempKeypair = Keypair.random();
  console.log(`1. Created temp account: ${tempKeypair.publicKey()}`);

  // 2. Fund it with Friendbot
  console.log("\n2. Requesting XLM from Friendbot...");
  const friendbotResponse = await fetch(
    `https://friendbot.stellar.org?addr=${tempKeypair.publicKey()}`
  );
  if (!friendbotResponse.ok) {
    throw new Error(`Friendbot request failed: ${friendbotResponse.status}`);
  }
  console.log("   Received 10,000 XLM from Friendbot");

  // 3. Setup server and contract
  const server = new Server(CONFIG.rpcUrl);
  const tokenContract = new Contract(CONFIG.nativeTokenContract);

  // 4. Get the source account
  console.log("\n3. Fetching source account...");
  const sourceAccount = await server.getAccount(tempKeypair.publicKey());
  console.log(`   Sequence: ${sourceAccount.sequenceNumber()}`);

  // 5. Build the transaction
  console.log("\n4. Building transaction...");
  const amount = BigInt(100 * 10_000_000); // 100 XLM in stroops

  const transaction = new TransactionBuilder(sourceAccount, {
    fee: BASE_FEE,
    networkPassphrase: CONFIG.networkPassphrase,
  })
    .addOperation(
      tokenContract.call(
        "transfer",
        nativeToScVal(tempKeypair.publicKey(), { type: "address" }),
        nativeToScVal(TEST_DESTINATION, { type: "address" }),
        nativeToScVal(amount, { type: "i128" })
      )
    )
    .setTimeout(30)
    .build();

  console.log(`   Transaction built, hash: ${transaction.hash().toString("hex").slice(0, 20)}...`);
  console.log(`   Transaction type: ${transaction.constructor.name}`);

  // 6. Prepare (simulate) the transaction
  console.log("\n5. Preparing transaction (simulation)...");
  const preparedTx = await server.prepareTransaction(transaction);
  console.log(`   Prepared transaction type: ${preparedTx.constructor.name}`);
  console.log(`   Has toXDR: ${typeof preparedTx.toXDR}`);
  console.log(`   Has sign: ${typeof preparedTx.sign}`);

  // 7. Sign the transaction
  console.log("\n6. Signing transaction...");
  preparedTx.sign(tempKeypair);
  console.log("   Transaction signed");

  // 8. Check what we're sending
  console.log("\n7. Inspecting transaction before send...");
  const xdr = preparedTx.toXDR();
  console.log(`   XDR length: ${xdr.length}`);
  console.log(`   XDR preview: ${xdr.slice(0, 100)}...`);

  // 9. Send the transaction
  console.log("\n8. Sending transaction...");
  try {
    const result = await server.sendTransaction(preparedTx);
    console.log(`   Status: ${result.status}`);
    console.log(`   Hash: ${result.hash}`);

    if (result.status === "PENDING") {
      console.log("\n9. Waiting for confirmation...");
      let txResult = await server.getTransaction(result.hash);
      let attempts = 0;
      while (txResult.status === "NOT_FOUND" && attempts < 30) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        txResult = await server.getTransaction(result.hash);
        attempts++;
        process.stdout.write(".");
      }
      console.log("");

      if (txResult.status === "SUCCESS") {
        console.log(`   SUCCESS! Transaction confirmed.`);
        console.log(`   Transaction hash: ${result.hash}`);

        // 10. Verify the balance was transferred
        console.log("\n10. Verifying balance...");
        console.log(`   Checking destination balance: ${TEST_DESTINATION}`);

        // Query the balance using the token contract
        const balanceTx = new TransactionBuilder(sourceAccount, {
          fee: BASE_FEE,
          networkPassphrase: CONFIG.networkPassphrase,
        })
          .addOperation(
            tokenContract.call(
              "balance",
              nativeToScVal(TEST_DESTINATION, { type: "address" })
            )
          )
          .setTimeout(30)
          .build();

        const simResult = await server.simulateTransaction(balanceTx);
        if ("result" in simResult && simResult.result) {
          console.log(`   Balance result: ${JSON.stringify(simResult.result)}`);
        }
      } else {
        console.log(`   Final status: ${txResult.status}`);
        if ("resultXdr" in txResult) {
          console.log(`   Result XDR: ${txResult.resultXdr}`);
        }
      }
    } else {
      console.log(`   Unexpected status: ${result.status}`);
      if ("errorResult" in result) {
        console.log(`   Error: ${JSON.stringify(result.errorResult)}`);
      }
    }
  } catch (error) {
    console.error("\n   SEND FAILED:");
    console.error(`   Error: ${error}`);
    if (error instanceof Error) {
      console.error(`   Stack: ${error.stack}`);
    }
  }

  console.log("\n=== Test Complete ===");
}

main().catch(console.error);
