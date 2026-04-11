---
name: manage-signers
description: "Add, remove, and manage signers and context rules on a Stellar smart account using smart-account-kit. Use when a developer wants to add a passkey signer, add a G-address signer, remove a signer, create context rules, update rules, or manage who can authorize transactions on a smart account."
license: Apache-2.0
compatibility: Designed for Claude Code. Requires a connected SmartAccountKit instance with indexer access for list operations.
metadata:
  author: kalepail
  version: "0.3.0"
allowed-tools: Read Write Edit
---

# Manage Signers and Context Rules

Add and remove signers, and manage context rules that define authorization requirements for a smart account.

## Prerequisites

- `SmartAccountKit` initialized and connected
- For `list()` and `getAll()`: indexer access (auto-configured for testnet/mainnet)

## Context Rules

Context rules define what signers and policies are required for different operations. Every smart account needs at least one context rule.

### Create a Context Rule

```typescript
import {
  createDefaultContext,
  createCallContractContext,
  createWebAuthnSigner,
} from 'smart-account-kit';

// Default context - matches any operation
const context = createDefaultContext();

// Or: only match calls to a specific contract
const context = createCallContractContext('CTARGET_CONTRACT...');

// Create the rule with an initial signer
const signer = createWebAuthnSigner(
  verifierAddress,
  publicKey,
  credentialId
);

await kit.rules.add(context, 'My Rule', [signer], []);
```

### Read Rules

```typescript
// Read a specific rule directly from chain (by ID)
const rule = (await kit.rules.get(0)).result;

// List all active rules (indexer-backed)
const rules = await kit.rules.list();

// All rules of a specific context type (indexer-backed)
const callRules = await kit.rules.getAll(createCallContractContext('C...'));
```

> `get()` reads from chain directly. `list()` and `getAll()` are indexer-backed because the contract does not expose an active-rule iterator after deletions.

### Update a Rule

```typescript
await kit.rules.updateName(0, 'New Name');
await kit.rules.updateExpiration(0, expirationLedger);
```

### Remove a Rule

```typescript
await kit.rules.remove(0);
```

## Signers

### Add a Passkey Signer

Registers a new WebAuthn passkey and adds it to a context rule:

```typescript
const { credentialId } = await kit.signers.addPasskey(
  0,             // context rule ID
  'My App',      // app name shown during passkey creation
  'Recovery Key', // label for this passkey
  { nickname: 'Backup YubiKey' }  // optional local nickname
);
```

### Add a G-Address (Delegated) Signer

Adds a Stellar G-address (hardware wallet, co-signer service, etc.):

```typescript
await kit.signers.addDelegated(
  0,           // context rule ID
  'GABC...'    // Stellar address
);
```

### Remove a Signer

Pass the signer value directly - the SDK resolves the on-chain signer ID internally:

```typescript
// Get the signer object first
const rule = (await kit.rules.get(0)).result;
const signer = rule.signers[0];

await kit.signers.remove(0, signer);
```

### Batch Add Signers

For adding multiple signers in one transaction, use the raw contract client:

```typescript
// kit.wallet is available after connectWallet()
await kit.wallet?.batch_add_signer({ signers: [signer1, signer2] });
```

## Signer Types

| Builder | Signer Type |
|---------|-------------|
| `createWebAuthnSigner(verifier, pubKey, credId)` | Passkey (secp256r1) |
| `createDelegatedSigner(address, ed25519Verifier)` | G-address |
| `createEd25519Signer(verifier, pubKey)` | Ed25519 key |
| `createExternalSigner(verifier, pubKey)` | Custom verifier |

## Context Rule Types

| Builder | Matches |
|---------|---------|
| `createDefaultContext()` | Any operation |
| `createCallContractContext(contractId)` | Calls to a specific contract |
| `createCreateContractContext()` | Contract deployments |

## Credential Lifecycle

Local credential state is managed separately from on-chain signers:

```typescript
// Get all stored credentials
const all = await kit.credentials.getAll();

// Get credentials for the current wallet
const mine = await kit.credentials.getForWallet();

// Sync local state against on-chain
await kit.credentials.syncAll();

// Delete a pending (never-deployed) credential
await kit.credentials.delete(credentialId);
```

> `credentials.delete()` only removes the local record. Use `kit.signers.remove()` to remove an on-chain signer.
