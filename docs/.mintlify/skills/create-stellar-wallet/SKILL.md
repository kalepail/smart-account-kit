---
name: create-stellar-wallet
description: "Create and deploy a WebAuthn passkey-secured smart account wallet on Stellar using smart-account-kit. Use when a user wants to create a new wallet, register a passkey, deploy a smart account, or set up a new account on Stellar/Soroban."
license: Apache-2.0
compatibility: Designed for Claude Code. Requires a browser environment for WebAuthn.
metadata:
  author: kalepail
  version: "0.3.0"
allowed-tools: Read Write Edit
---

# Create a Stellar Smart Wallet

Creates a WebAuthn passkey and deploys a smart account contract on Stellar/Soroban.

## Prerequisites

- `SmartAccountKit` initialized with `accountWasmHash` and `webauthnVerifierAddress`
- Browser environment (WebAuthn requires `window.navigator.credentials`)
- Testnet: a funded account or `autoFund: true`

## Basic Creation

```typescript
const { contractId, credentialId } = await kit.createWallet(
  'My App',          // relying party name shown during passkey creation
  'user@example.com', // username label for the passkey
  {
    autoSubmit: true,  // deploy immediately (recommended)
    autoFund: true,    // fund via Friendbot - testnet only
    nativeTokenContract: process.env.VITE_NATIVE_TOKEN_CONTRACT!,
  }
);

console.log('Wallet deployed at:', contractId);
console.log('Credential ID:', credentialId);
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `autoSubmit` | false | Deploy the contract immediately after passkey creation |
| `autoFund` | false | Fund via Friendbot (testnet only, requires `nativeTokenContract`) |
| `nativeTokenContract` | - | Native XLM SAC contract ID, required for `autoFund` |

## Step-by-Step (Manual)

For custom flows where you need control between creation and deployment:

```typescript
// 1. Create credential (registers passkey locally, no chain interaction)
const credential = await kit.credentials.create();

// 2. Save to storage
await kit.credentials.save(credential);

// 3. Deploy when ready
const result = await kit.credentials.deploy(credential.credentialId, {
  autoSubmit: true,
});
```

## Post-Creation

After `createWallet()` the kit is automatically connected. You can immediately:

```typescript
// Transfer tokens
await kit.transfer(tokenContract, recipient, amount);

// Sign arbitrary transactions
await kit.signAndSubmit(tx);

// Access the connected contract ID
console.log(kit.contractId);
```

## Connecting on Return Visits

On page reload, restore without showing the passkey prompt:

```typescript
// Silent restore from stored session
const result = await kit.connectWallet();

if (!result) {
  // No session - show create/connect UI
}
```

To always prompt:

```typescript
await kit.connectWallet({ prompt: true });  // always show passkey picker
await kit.connectWallet({ fresh: true });   // ignore session, always prompt
```

## Common Issues

**User cancels passkey prompt**
`WebAuthnError` is thrown. Catch it and stay on the create screen - this is expected behaviour, not a bug.

```typescript
try {
  await kit.createWallet(appName, userName, { autoSubmit: true });
} catch (err) {
  if (err instanceof WebAuthnError) return; // user cancelled
  throw err;
}
```

**Wallet not funded (mainnet)**
On mainnet, remove `autoFund` and ensure the deploying account has enough XLM to cover the transaction fee before calling `createWallet()`.

**Duplicate passkey names**
The `userName` parameter is a display label only - it does not need to be unique. However, using a meaningful label (e.g. the user's email) helps users identify the correct passkey in their device's credential picker.
