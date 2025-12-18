#!/usr/bin/env bun
/**
 * Test script that mimics the frontend transaction flow
 * Used to verify transaction logic works correctly outside of Vite bundler
 * This helped debug instanceof issues with Vite module duplication
 */

// Import exactly as the frontend does
import {
  Contract,
  Networks,
  nativeToScVal,
  Keypair,
  hash,
  TransactionBuilder,
  BASE_FEE,
  rpc,
} from "@stellar/stellar-sdk";

const { Server } = rpc;

const CONFIG = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: Networks.TESTNET,
  nativeTokenContract: "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
};

// Derive the same deployer keypair used by the SDK (not used here, but matches frontend)
const DEPLOYER_KEYPAIR = Keypair.fromRawEd25519Seed(
  hash(Buffer.from("openzeppelin-smart-account-kit"))
);

// Test destination
const TEST_DESTINATION = "CCIYFQ4FCK3WJ3YYUQPDEZZUVB63ZKMGBGOKGI5ZGT6HXUGHHAEHS2RE";

async function testFrontendFlow() {
  console.log("=== Testing Frontend Flow ===\n");

  const contractId = TEST_DESTINATION; // Simulating we already have a wallet

  try {
    // 1. Create a random keypair (same as frontend handleFundWallet)
    const tempKeypair = Keypair.random();
    console.log(`1. Created temp account: ${tempKeypair.publicKey()}`);

    // 2. Fund it with Friendbot (same as frontend)
    console.log("\n2. Requesting XLM from Friendbot...");
    const friendbotResponse = await fetch(
      `https://friendbot.stellar.org?addr=${tempKeypair.publicKey()}`
    );
    if (!friendbotResponse.ok) {
      throw new Error("Friendbot request failed");
    }
    console.log("   Received 10,000 XLM from Friendbot");

    // 3. Transfer XLM to the smart wallet using the native token SAC (same as frontend)
    const server = new Server(CONFIG.rpcUrl);
    const tokenContract = new Contract(CONFIG.nativeTokenContract);

    console.log("\n3. Getting source account...");
    const sourceAccount = await server.getAccount(tempKeypair.publicKey());

    // Transfer 100 XLM to the smart wallet (same as frontend)
    const amount = BigInt(100 * 10_000_000); // 100 XLM in stroops

    console.log("\n4. Building transaction...");
    const transaction = new TransactionBuilder(sourceAccount, {
      fee: BASE_FEE,
      networkPassphrase: CONFIG.networkPassphrase,
    })
      .addOperation(
        tokenContract.call(
          "transfer",
          nativeToScVal(tempKeypair.publicKey(), { type: "address" }), // from: temp account
          nativeToScVal(contractId, { type: "address" }), // to: smart wallet
          nativeToScVal(amount, { type: "i128" })
        )
      )
      .setTimeout(30)
      .build();

    console.log("   Transaction built");
    console.log(`   Transaction type: ${transaction.constructor.name}`);
    console.log(`   Transaction has toXDR: ${typeof transaction.toXDR === 'function'}`);

    console.log("\n5. Preparing transaction...");

    // Use prepareTransaction which handles simulation and assembly in one step
    // and returns a Transaction ready to sign and submit (same as frontend)
    let preparedTx;
    try {
      preparedTx = await server.prepareTransaction(transaction);
      console.log(`   Prepared tx type: ${preparedTx.constructor.name}`);
      console.log(`   Prepared tx has toXDR: ${typeof preparedTx.toXDR === 'function'}`);
      console.log(`   Prepared tx has sign: ${typeof preparedTx.sign === 'function'}`);

      // Check instanceof
      const { Transaction } = await import("@stellar/stellar-sdk");
      console.log(`   preparedTx instanceof Transaction: ${preparedTx instanceof Transaction}`);
    } catch (err) {
      console.error(`   Prepare failed: ${err}`);
      throw err;
    }

    // Sign with the temp keypair (same as frontend)
    console.log("\n6. Signing transaction...");
    try {
      preparedTx.sign(tempKeypair);
      console.log("   Transaction signed");
    } catch (err) {
      console.error(`   Sign failed: ${err}`);
      throw err;
    }

    console.log("\n7. Submitting transaction...");
    let result;
    try {
      result = await server.sendTransaction(preparedTx);
      console.log(`   Send result: ${result.status}, hash: ${result.hash}`);
    } catch (err) {
      console.error(`   sendTransaction failed: ${err}`);
      if (err instanceof Error) {
        console.error(`   Stack: ${err.stack}`);
      }
      throw err;
    }

    if (result.status === "PENDING") {
      // Wait for confirmation (same as frontend)
      console.log("\n8. Transaction pending, waiting for confirmation...");
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
        console.log(`   Funded smart wallet with 100 XLM!`);
        console.log(`   Transaction: ${result.hash.slice(0, 20)}...`);
      } else {
        throw new Error(`Transaction failed: ${txResult.status}`);
      }
    } else {
      // DUPLICATE, TRY_AGAIN_LATER, or ERROR
      throw new Error(`Transaction submission failed: ${result.status}`);
    }
  } catch (error) {
    console.error(`\nFunding failed: ${error}`);
    if (error instanceof Error) {
      console.error(`Stack: ${error.stack}`);
    }
    process.exit(1);
  }

  console.log("\n=== Success! ===");
}

testFrontendFlow();
