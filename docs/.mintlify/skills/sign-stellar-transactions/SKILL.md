---
name: sign-stellar-transactions
description: "Sign and submit Stellar transactions using a smart account passkey via smart-account-kit. Use when a developer needs to sign transactions, submit operations, execute contract calls, or transfer tokens on Stellar/Soroban using a connected smart account."
license: Apache-2.0
compatibility: Designed for Claude Code. Requires a connected SmartAccountKit instance.
metadata:
  author: kalepail
  version: "0.3.0"
allowed-tools: Read Write Edit
---

# Sign and Submit Stellar Transactions

Sign and submit transactions through a connected smart account using WebAuthn passkey authentication.

## Prerequisites

- `SmartAccountKit` initialized and connected (`kit.connectWallet()` returned a result)
- A wallet contract deployed on the target network

## Token Transfer (Shortcut)

For simple token transfers, use `kit.transfer()`:

```typescript
const result = await kit.transfer(
  'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC', // token contract
  'GRECIPIENT...',
  100
);

if (result.success) {
  console.log('Hash:', result.hash);
}
```

To bypass the relayer for a specific call:
```typescript
await kit.transfer(token, recipient, amount, { forceMethod: 'rpc' });
```

## Arbitrary Contract Calls

For calling any Soroban contract through the smart account:

```typescript
// Build + sign + submit in one step (preferred)
const result = await kit.executeAndSubmit(
  'CTARGET_CONTRACT...',  // contract to call
  'function_name',         // function
  [arg1, arg2]             // xdr.ScVal[] arguments
);
```

To inspect the assembled transaction before submitting:
```typescript
const tx = await kit.execute('CTARGET...', 'function_name', [arg1, arg2]);
// tx is an AssembledTransaction - inspect, modify, then:
const result = await kit.signAndSubmit(tx.toXDR());
```

## Sign a Pre-built Transaction

When you already have a `Transaction` object:

```typescript
import { TransactionBuilder, Networks, Operation, Asset } from '@stellar/stellar-sdk';

const tx = new TransactionBuilder(sourceAccount, {
  fee: BASE_FEE,
  networkPassphrase: Networks.TESTNET,
})
  .addOperation(Operation.payment({
    destination: 'GRECIPIENT...',
    asset: Asset.native(),
    amount: '10',
  }))
  .setTimeout(30)
  .build();

const result = await kit.signAndSubmit(tx);
```

## Sign Auth Entries Only

When you need the signed auth entries without submitting:

```typescript
// Sign all auth entries on a transaction
const signedTx = await kit.sign(tx);

// Sign a single auth entry
const signedEntry = await kit.signAuthEntry(authEntry);
```

## Transaction Result

All submission methods return `TransactionResult`:

```typescript
interface TransactionResult {
  success: boolean;
  hash?: string;
  error?: string;
}

const result = await kit.transfer(token, recipient, amount);
if (result.success) {
  console.log('Confirmed:', result.hash);
} else {
  console.error('Failed:', result.error);
}
```

## Fee Sponsoring

If a `relayerUrl` was configured during initialization, all submissions are automatically routed through the relayer:

```typescript
const kit = new SmartAccountKit({
  // ...
  relayerUrl: 'https://my-relayer.example.com',
});

// Uses relayer automatically - user pays no fees
await kit.transfer(token, recipient, amount);
```

Access the relayer client directly for custom flows:
```typescript
if (kit.relayer) {
  const result = await kit.relayer.sendXdr(signedXdr);
}
```

## Choosing the Right Method

| Scenario | Method |
|----------|--------|
| Token transfer | `kit.transfer()` |
| Arbitrary contract call | `kit.executeAndSubmit()` |
| Pre-built transaction | `kit.signAndSubmit()` |
| Need signed tx, not submit | `kit.sign()` |
| Single auth entry | `kit.signAuthEntry()` |
| Multi-signer required | `kit.multiSigners.transfer()` or `kit.multiSigners.operation()` |
