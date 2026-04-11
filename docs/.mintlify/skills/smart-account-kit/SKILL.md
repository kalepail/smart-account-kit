---
name: smart-account-kit
description: "Initialize, configure, and use the smart-account-kit TypeScript SDK for deploying WebAuthn passkey-secured smart accounts on Stellar/Soroban. Use when a developer asks about smart-account-kit, passkey wallets on Stellar, or smart account integration."
license: Apache-2.0
compatibility: Designed for Claude Code. Requires Node.js >= 22 and pnpm >= 10.
metadata:
  author: kalepail
  version: "0.3.0"
allowed-tools: Bash(pnpm:*) Read Write Edit
---

# Smart Account Kit

TypeScript SDK for deploying and managing OpenZeppelin Smart Account contracts on Stellar/Soroban with WebAuthn passkey authentication.

## Installation

```bash
pnpm add smart-account-kit
```

## SDK Initialization

Always initialize `SmartAccountKit` before any wallet operations:

```typescript
import { SmartAccountKit, IndexedDBStorage } from 'smart-account-kit';

const kit = new SmartAccountKit({
  rpcUrl: 'https://soroban-testnet.stellar.org',
  networkPassphrase: 'Test SDF Network ; September 2015',
  accountWasmHash: process.env.VITE_ACCOUNT_WASM_HASH!,
  webauthnVerifierAddress: process.env.VITE_WEBAUTHN_VERIFIER_ADDRESS!,
  storage: new IndexedDBStorage(),
  // Optional:
  relayerUrl: process.env.VITE_RELAYER_URL,   // fee sponsoring
  timeoutInSeconds: 30,
});
```

## Required Config Fields

| Field | Description |
|-------|-------------|
| `rpcUrl` | Stellar RPC endpoint |
| `networkPassphrase` | Network passphrase (`Networks.TESTNET` or `Networks.PUBLIC`) |
| `accountWasmHash` | WASM hash of uploaded smart account contract |
| `webauthnVerifierAddress` | Deployed WebAuthn verifier contract ID |

Testnet defaults are in `demo/.env.example`.

## Sub-Managers

After initialization, all sub-managers are available as properties:

| Property | Purpose |
|----------|---------|
| `kit.signers` | Add/remove signers on context rules |
| `kit.rules` | CRUD context rules |
| `kit.policies` | Attach/detach policies |
| `kit.credentials` | Local credential lifecycle |
| `kit.multiSigners` | Multi-signer transaction flows |
| `kit.externalSigners` | G-address / wallet signers |
| `kit.indexer` | Contract discovery by credential or address |
| `kit.relayer` | Fee-sponsored submission |
| `kit.events` | Lifecycle event subscriptions |
| `kit.wallet` | Raw contract client (available after connect) |

## Key Workflows

- **Create wallet** - see [create-stellar-wallet](../create-stellar-wallet/SKILL.md)
- **Sign and submit transactions** - see [sign-stellar-transactions](../sign-stellar-transactions/SKILL.md)
- **Add/remove signers and rules** - see [manage-signers](../manage-signers/SKILL.md)
- **Set up multisig policies** - see [setup-policies](../setup-policies/SKILL.md)

## On-Page Load Pattern

```typescript
// 1. Try silent session restore
const session = await kit.connectWallet();

if (session) {
  // Already connected - proceed
  console.log('Restored:', session.contractId);
} else {
  // Show connect/create UI
}
```

## Environment Variables (Vite)

```bash
VITE_RPC_URL=https://soroban-testnet.stellar.org
VITE_NETWORK_PASSPHRASE=Test SDF Network ; September 2015
VITE_ACCOUNT_WASM_HASH=<hash>
VITE_WEBAUTHN_VERIFIER_ADDRESS=<contract_id>
VITE_RELAYER_URL=https://my-relayer.example.com  # optional
```

## Error Handling

All SDK operations throw typed errors:

```typescript
import {
  WalletNotConnectedError,
  WebAuthnError,
  SimulationError,
  SubmissionError,
} from 'smart-account-kit';

try {
  await kit.transfer(token, recipient, amount);
} catch (err) {
  if (err instanceof WebAuthnError) {
    // User cancelled passkey prompt - expected, not a bug
  } else if (err instanceof WalletNotConnectedError) {
    // Need to connect first
  } else if (err instanceof SimulationError) {
    // Contract simulation rejected the tx
  }
}
```
