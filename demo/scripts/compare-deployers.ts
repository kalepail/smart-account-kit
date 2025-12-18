import { Keypair, hash } from "@stellar/stellar-sdk";

// passkey-kit entropy
const passkeyKitKeypair = Keypair.fromRawEd25519Seed(
  hash(Buffer.from("kalepail"))
);

// smart-account-kit entropy
const smartAccountKitKeypair = Keypair.fromRawEd25519Seed(
  hash(Buffer.from("openzeppelin-smart-account-kit"))
);

console.log("=== Deployer Account Comparison ===\n");

console.log("passkey-kit (entropy: 'kalepail'):");
console.log("  Public Key:", passkeyKitKeypair.publicKey());
console.log("");

console.log("smart-account-kit (entropy: 'openzeppelin-smart-account-kit'):");
console.log("  Public Key:", smartAccountKitKeypair.publicKey());
console.log("");

console.log("=== Fund the account you want to use ===");
