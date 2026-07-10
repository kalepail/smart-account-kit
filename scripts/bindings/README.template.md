# smart-account-kit-bindings

Generated TypeScript client and contract types for the OpenZeppelin smart account contract on Stellar.

Most applications should install [`smart-account-kit`](https://www.npmjs.com/package/smart-account-kit), which wraps these bindings with passkey, signer, policy, discovery, and transaction workflows. Use this package directly when you need the generated contract client or exact contract types.

## Install

```bash
pnpm add smart-account-kit-bindings @stellar/stellar-sdk
```

## Use the generated client

```typescript
import { Client } from 'smart-account-kit-bindings';

const client = new Client({
  contractId: 'C...',
  networkPassphrase: 'Test SDF Network ; September 2015',
  rpcUrl: 'https://soroban-testnet.stellar.org',
});

const transaction = await client.get_context_rule({ context_rule_id: 0 });
console.log(transaction.result);
```

Contract calls return `AssembledTransaction` values from `@stellar/stellar-sdk/contract`. Read-only simulations expose their decoded return value on `.result`; state-changing calls can be signed and submitted through the assembled-transaction API.

## Regenerate in this repository

The repository wrapper preserves package metadata, formatting, and this README after invoking Stellar CLI:

```bash
ACCOUNT_WASM=/path/to/multisig_account_example.wasm \
BINDINGS_VERSION=0.2.0 \
pnpm build:bindings
```

You can also configure a deployed WASM hash or contract ID in `demo/.env`. See the repository's [release guide](https://github.com/kalepail/smart-account-kit/blob/main/docs/releasing.md) for the optimized contract build and publish sequence.

The underlying Stellar CLI command is `stellar contract bindings typescript`; the older `soroban contract bindings ts` spelling is no longer used.
