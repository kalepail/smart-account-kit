#!/usr/bin/env node
/**
 * Node native-ESM import smoke test.
 *
 * Regression gate for a real 0.4.0 bug: `tsc` with `moduleResolution: "bundler"`
 * emitted extensionless relative imports (`from "./kit"`), which Node's native
 * ESM loader rejects (`ERR_UNSUPPORTED_DIR_IMPORT`). The published package then
 * imported fine under a bundler (Vite/webpack) but crashed for any plain Node
 * consumer — a gap the Vite-based demo e2e never exercised.
 *
 * This script imports the built package the way a Node consumer would (by name,
 * via self-reference through package `exports`) and asserts key exports resolve.
 * It runs as part of `pnpm build`, so a regression fails the build (and release).
 */
const failures = [];

async function check(specifier, expectedExports) {
  try {
    const mod = await import(specifier);
    for (const name of expectedExports) {
      if (!(name in mod)) {
        failures.push(`${specifier}: missing export "${name}"`);
      }
    }
    console.log(`  ok  ${specifier} (${expectedExports.join(", ")})`);
  } catch (err) {
    failures.push(`${specifier}: ${err.code ?? ""} ${String(err.message).split("\n")[0]}`);
    console.log(`  FAIL ${specifier}: ${err.code ?? ""} ${String(err.message).split("\n")[0]}`);
  }
}

console.log("Node ESM import smoke test:");
await check("smart-account-kit", ["SmartAccountKit", "RelayerClient", "Ed25519Signer"]);
await check("smart-account-kit/storage", ["MemoryStorage", "IndexedDBStorage"]);

if (failures.length) {
  console.error("\nESM import smoke test FAILED:");
  for (const f of failures) console.error("  - " + f);
  console.error(
    "\nThe built package cannot be imported by a Node ESM consumer. This usually\n" +
      "means a relative import is missing its explicit .js extension (NodeNext)."
  );
  process.exit(1);
}
console.log("\nESM import smoke test passed.");
