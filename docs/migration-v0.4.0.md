# Migrating to `smart-account-kit` v0.4.0

This release is an OpenZeppelin-parity overhaul of the SDK. It has **no backwards-compatibility layer** — every breaking change below is a clean cut from `0.3.0`. The public API is realigned around a unified error model, a unified signing pipeline (with end-to-end Ed25519 support), typed policy clients, full contract parity, and client-side validation.

The deployed contract surface is unchanged from `0.3.0` (the bindings were regenerated from the same canonical Protocol 27 testnet WASM hash `1b5f4534…785a` and differ only in JSDoc/description bytes). All the changes below are on the SDK side.

## Contents

- [Results & error handling](#results--error-handling)
- [Errors](#errors)
- [Signers & Ed25519](#signers--ed25519)
- [Configuration](#configuration)
- [Policy clients](#policy-clients)
- [Client-side validation](#client-side-validation)
- [Kit methods](#kit-methods)
- [Removed exports](#removed-exports)
- [Bindings & build pipeline](#bindings--build-pipeline)

---

## Results & error handling

**`TransactionResult` is now a discriminated union on `success`.** This is the highest-impact change: narrow on `result.success` before reading `.error` or `.hash`.

```ts
// Before (0.3.0): { success: boolean; hash: string; error?: string; ledger? }
const result = await kit.transfer(token, to, 100);
if (result.success) {
  console.log(result.hash);
} else {
  console.error(result.error); // string
}

// After (0.4.0)
const result = await kit.transfer(token, to, 100);
if (result.success) {
  // TransactionSuccess: { success: true; hash: string; ledger? }
  console.log(result.hash, result.ledger);
} else {
  // TransactionFailure: { success: false; error: SmartAccountError; code; hash? }
  console.error(`[${result.code}] ${result.error.message}`);
}
```

Key differences:

- `error` is now a **typed `SmartAccountError`** (a `ContractError` when an on-chain code was decoded), not a string.
- Success results have **no** `error` field.
- Failures gain a `code` field (mirrors `error.code`) for quick branching.
- `hash` is now **optional on failure** (present only when one was assigned before the failure).
- New type exports: `TransactionSuccess`, `TransactionFailure`.

**Which methods return this vs. throw.** Every submission method — `transfer`, `signAndSubmit`, `executeAndSubmit`, `fundWallet`, `createWallet`'s deploy step, `multiSigners.*`, and credential deployment — returns a `TransactionResult`. **Everything else now throws typed errors** instead of returning failure objects or plain `Error`s.

## Errors

New error classes and behaviors:

- **`ContractError`** (extends `SmartAccountError`) — carries `contractCode` (e.g. `3010`), `contractErrorName` (e.g. `"TooManySigners"`), and `family`.
- **`PolicyNotFoundError`** — thrown when a policy is not found on a context rule.
- **New decoding API:** `decodeContractError(diagnostic)`, `contractErrorFromCode(code)`, `CONTRACT_ERROR_REGISTRY`, and types `ContractErrorFamily` / `ContractErrorInfo`. Covers SmartAccount `3000–3016`, WebAuthn `3110–3119`, SimpleThreshold `3200–3203`, WeightedThreshold `3210–3214`, and SpendingLimit `3220–3227`.
- **`SmartAccountErrorCode`** gains `CONTRACT_ERROR` (`10000`) and `POLICY_NOT_FOUND` (`6003`).
- **`ValidationError`** code union widened to include `INVALID_CONFIG` / `MISSING_CONFIG`.
- **`SignerNotFoundError`** constructor gained an optional 2nd `hint` argument.

**Behavior changes — methods that used to return failures or plain `Error`s now throw typed errors:**

| Situation | Now throws |
|---|---|
| Operation requires a connected wallet | `WalletNotConnectedError` |
| Invalid secret key | `ValidationError` |
| Missing signer | `SignerNotFoundError` |
| Missing policy | `PolicyNotFoundError` |
| Required-config validation | `ValidationError` |
| Bad policy params (`convertPolicyParams`) | `ValidationError` (was `console.warn` + returning unconverted params) |

`StellarWalletsKitAdapter.connect()` now throws on a genuine failure (it still returns `null` on user-cancel/dismiss).

## Signers & Ed25519

Ed25519 external signers are now supported end-to-end (builders, signing, multi-signer submission).

New exports:

- `Ed25519Signer`, `computeEntryAuthDigest`, and the `AuthDigestSigner` type.
- Constants `ED25519_PUBLIC_KEY_SIZE` (32) and `ED25519_SIGNATURE_SIZE` (64).

Widened types:

- `SelectedSigner.type` is now `"passkey" | "wallet" | "ed25519"` (added `ed25519`), with a new `ed25519PublicKey` field.
- `ExternalSigner` (from `getAll()`) gains `type: "ed25519"` plus `verifierAddress` / `publicKey` fields.

`ExternalSignerManager`:

- Constructor gained a 4th argument (`ed25519VerifierAddress`).
- New methods: `addEd25519FromSecret(secret, verifier?)`, `canSignEd25519`, `getEd25519Signer`, `signEd25519Digest`.

Also newly exported for advanced flows: `signerToScVal` / `parseSignerScVal` (auth-payload), and `buildI128ScVal`, `signFeePayer`, `resimulateAndAssemble` (tx-ops).

> Ed25519 signing goes through `kit.multiSigners` (build a `SelectedSigner` of type `"ed25519"` via `buildSelectedSigners`). `kit.transfer`'s single-signer convenience path stays passkey-only by design.

See the [Ed25519 & External Signers](../README.md#ed25519--external-signers) section of the README for the full flow.

## Configuration

`SmartAccountConfig` gains several fields:

- **`ed25519VerifierAddress?: string`** — needed for Ed25519 external signers.
- **`deployerSecret?: string`** — custom fee payer. The default is a deterministic keypair derived from a fixed well-known seed. **Overriding it changes the derived contract addresses** (documented tradeoff — the default makes addresses reproducible from a credential ID alone).
- **`externalSignerStorage?: WalletStorage`** — external-signer persistence store (default: `localStorage`). Separate from the credential `StorageAdapter`.

Behavior:

- **`defaultPolicies` is now honored.** It was previously silently ignored/dead. It is now applied to the new wallet's default context rule via the contract `__constructor`.
- **`PolicyConfig` gains an optional `type`** (`"threshold" | "spending_limit" | "weighted_threshold" | "custom"`), required so install params can be encoded. `"custom"` policies must supply an `xdr.ScVal`.
- **`createWallet` gains `options.policies`** — a per-call override of `defaultPolicies`.

## Policy clients

New typed clients for the three example policies, via `kit.policyClients`:

```ts
kit.policyClients.threshold(address);      // SimpleThresholdPolicyClient
kit.policyClients.weighted(address);       // WeightedThresholdPolicyClient
kit.policyClients.spendingLimit(address);  // SpendingLimitPolicyClient
```

New exports: `SimpleThresholdPolicyClient`, `WeightedThresholdPolicyClient`, `SpendingLimitPolicyClient`, and the `PolicyClientDeps` type; plus contract types `SpendingLimitData` / `SpendingEntry`.

- **Getters** (`getThreshold`, `getSignerWeights`, `getSpendingLimitData`) read on-chain state via simulation.
- **Setters** (`setThreshold`, `setSignerWeight`, `setSpendingLimit`) return an `AssembledTransaction` routed through the smart account's `execute()`, and take the **full `ContextRule` struct** (not just the id).

> ⚠️ **Signer-set divergence caveat.** Threshold policies are **not** auto-notified when a rule's signer set changes. Call `setThreshold` / `setSignerWeight` around add/remove-signer operations, or authorization may break.

## Client-side validation

New module validating deployed-contract limits before submission (throwing `ValidationError` instead of letting an opaque on-chain failure surface).

- Constants: `MAX_SIGNERS` (15), `MAX_POLICIES` (5), `MAX_NAME_SIZE` (20 UTF-8 **bytes**), `MAX_EXTERNAL_KEY_SIZE` (256).
- Functions: `validateContextRule`, `validateContextRuleName`, `validateSigner`, `validateSigners`, `validatePolicyCount`, `validateExternalKeySize`, `validateValidUntil`.

`kit.rules.add`, `kit.signers.add*`, and `kit.signers.addBatch` now throw `ValidationError` **before** submitting on a limit violation (name > 20 bytes, > 15 signers, > 5 policies, past `valid_until`, or a rule with no signers and no policies).

## Kit methods

Full contract parity — every entry point is now wrapped. **The README's "intentionally unwrapped raw methods" section is gone** because there are no longer any intentionally-unwrapped methods. `kit.wallet` remains available as a raw escape hatch.

New methods:

| New wrapper | Contract entry point |
|---|---|
| `kit.upgrade(newWasmHash)` | `upgrade` (32-byte hash; the contract ignores the `operator` arg) |
| `kit.rules.count()` | `get_context_rules_count` |
| `kit.signers.addBatch(ruleId, signers)` | `batch_add_signer` |
| `kit.signers.idOf(signer)` | `get_signer_id` |
| `kit.policies.idOf(address)` | `get_policy_id` |

Shared option types are now used across `sign` / `signAndSubmit` / `executeAndSubmit` / `transfer` / `fundWallet`: new exports `SignOptions`, `SubmitOptions`, `SignAndSubmitOptions`, and `ResolveContextRuleIds`.

`convertPolicyParams` signature is `(policyType, params)` and returns an `xdr.ScVal`; `buildPoliciesScVal` is `(policies, policyTypes)`. Both now throw `ValidationError` on bad input rather than silently returning unconverted params.

## Removed exports

The following were removed in this release (they were dead or never meant to be public):

- `validateNotEmpty`
- `signerMatchesCredential`
- `signerMatchesAddress`

(`extractPubkeyFromKeyData`, `extractCredentialIdFromKeyData`, `simulateHostFunction`, and `decodeContextRuleResultXdr` were never part of the public API.)

## Bindings & build pipeline

- **`packages/smart-account-kit-bindings/src/index.ts` was regenerated** from the canonical deployed testnet WASM hash (`1b5f4534…785a`). The diff versus the prior checked-in copy was **documentation-only** (JSDoc + spec description bytes for `get_context_rules_count` / `__check_auth`); function names, args, return types, and ScVal encoding are byte-identical.
- **New `pnpm verify:bindings`** (`scripts/bindings/verify.sh`) regenerates from the canonical WASM hash, diffs against the checked-in bindings, and exits nonzero on drift.
- `build.sh` no longer silently sources local `demo/.env`. It prefers explicit env/args, falls back to `demo/.env.example`, and prints the source and hash it binds against.

### Two implementation notes worth knowing

1. **`get_context_rule` id hydration.** The deployed contract's `get_context_rule` omits the aligned `signer_ids`/`policy_ids` fields, so the generated bindings spec cannot decode them directly. The SDK injects empty id vectors and hydrates the real ids via `get_signer_id`/`get_policy_id`. Reading a rule with populated ids therefore depends on those getters being reachable; a read-only client without them yields empty `signer_ids`/`policy_ids`.
2. **Do not hand-edit bindings.** They are regenerated from the canonical WASM. If richer descriptions are wanted, fix them on the contract side (redeploy) and regenerate — hand-editing re-introduces drift that `pnpm verify:bindings` will flag.

---

See the [README](../README.md) for the full v0.4.0 API reference, and [`deployments-protocol-27-2026-07-09.md`](deployments-protocol-27-2026-07-09.md) for the deployed contract IDs and WASM hashes.
