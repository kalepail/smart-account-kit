# Smart Account Indexer

Indexes smart account signer events from Stellar to enable reverse lookups from passkey credentials to contract IDs and to support indexer-backed rule discovery for the SDK.

## Overview

When a user authenticates with a passkey, the indexer enables discovering all smart account contracts they have access to. The SDK also relies on this indexer surface for active context-rule discovery after removals. This is essential because:

1. A single passkey can be a signer on multiple smart accounts
2. Passkeys added as secondary signers don't have a deterministic contract address
3. Users need to discover their accounts without knowing contract IDs upfront
4. The contract exposes individual rule lookups, but not a stable iterator over currently active rule IDs

## Architecture

```
Stellar Network → Goldsky Pipeline → PostgreSQL → Cloudflare Worker API → SDK
```

### Components

- **`goldsky/`** - Goldsky pipeline configuration for ingesting Stellar events
- **`handler/`** - Cloudflare Worker API for queries
- **`relayer-proxy/`** - Cloudflare Worker proxy for OpenZeppelin Relayer Channels
- **`demo/`** - Standalone demo for testing the indexer

## Deployment

### Prerequisites

- Wrangler CLI (`pnpm add -g wrangler`)
- Goldsky CLI
- Goldsky Turbo CLI extension
- PostgreSQL database (e.g., Neon, Supabase, or self-hosted)

### Configuration

```bash
# Optional shared config record for Goldsky/database values
cp .env.example .env.dev  # For testnet notes
cp .env.example .env.prod # For mainnet notes

# Local handler secrets for `wrangler dev`
cp handler/.dev.vars.example handler/.dev.vars

# Demo UI defaults
cp demo/.env.example demo/.env
```

Use the files for these purposes:

- `indexer/.env.example`: shared record of database and Goldsky settings; not loaded automatically by Wrangler.
- `indexer/handler/.dev.vars.example`: local Worker secrets for `wrangler dev`.
- `indexer/relayer-proxy/.dev.vars.example`: optional local overrides for relayer Worker vars during `wrangler dev`.
- `indexer/demo/.env.example`: Vite env defaults for the standalone indexer demo.

### Cloudflare Worker

```bash
cd handler
pnpm install
cp .dev.vars.example .dev.vars    # for local `wrangler dev`
wrangler secret put DATABASE_URL  # PostgreSQL connection string for deployed testnet worker
wrangler deploy

# Mainnet
wrangler secret put DATABASE_URL --env production
wrangler deploy --env production
```

### Goldsky Pipelines

```bash
cd goldsky

# Install Turbo extension if needed
goldsky turbo

# Testnet: Turbo on stellar_testnet.events v1.2.0, start_at earliest
goldsky turbo apply ./pipeline-testnet.yaml

# Mainnet: Turbo on stellar_mainnet.events v1.2.0, start_at 60343871
goldsky turbo apply ./pipeline-mainnet.yaml
```

## API Endpoints

**Testnet URL**: `https://smart-account-indexer.sdf-ecosystem.workers.dev`

**Mainnet URL**: `https://smart-account-indexer-mainnet.sdf-ecosystem.workers.dev`

### Health Check
```
GET /
```

### Lookup by Credential ID
```
GET /api/lookup/:credentialId
```
Find all contracts associated with a passkey credential.

### Lookup by Address
```
GET /api/lookup/address/:address
```
Find contracts by G-address (delegated signer) or C-address (verifier).

### Contract Details
```
GET /api/contract/:contractId
```
Get full contract details including active signers and policies per context rule.
This is the endpoint the SDK uses to rebuild active rule state for `rules.list()` and `rules.getAll()`.

### Stats
```
GET /api/stats
```
Get indexer statistics (event counts, unique contracts, etc.).

## Events Indexed

| Event | Description |
|-------|-------------|
| `context_rule_added` | New context rule with signers and policies |
| `context_rule_meta_updated` | Context rule metadata updated |
| `context_rule_removed` | Context rule deleted |
| `signer_added` | Signer added to existing rule |
| `signer_removed` | Signer removed from rule |
| `signer_registered` | Signer registered in the global registry |
| `signer_deregistered` | Signer deregistered from the global registry |
| `policy_added` | Policy added to existing rule |
| `policy_removed` | Policy removed from rule |
| `policy_registered` | Policy registered in the global registry |
| `policy_deregistered` | Policy deregistered from the global registry |

## SDK Integration

The indexer client is integrated into the Smart Account Kit SDK and can be used in two ways:
1. Via `kit.indexer` property (auto-configured for known networks)
2. Via direct `IndexerClient` import for standalone use

The contract-detail API is the important bit for wallet flows: it turns the raw event stream into current active rule state so the SDK can resolve rule IDs without guessing after deletions.

For this project, testnet intentionally uses `start_at: earliest` so it replays all events still available in the current testnet history, including events from before the pipeline was first deployed.

```typescript
import { SmartAccountKit, IndexedDBStorage } from 'smart-account-kit';

const kit = new SmartAccountKit({
  rpcUrl: 'https://soroban-testnet.stellar.org',
  networkPassphrase: 'Test SDF Network ; September 2015',
  accountWasmHash: '...',
  webauthnVerifierAddress: 'C...',
  storage: new IndexedDBStorage(),
  // Indexer auto-configured for testnet/mainnet
});

// Step 1: Authenticate with passkey (prompts user to select)
const { credentialId } = await kit.authenticatePasskey();

// Step 2: Discover contracts via indexer
const contracts = await kit.discoverContractsByCredential(credentialId);

// Step 3: Connect to selected contract
if (contracts && contracts.length > 0) {
  await kit.connectWallet({
    contractId: contracts[0].contract_id,
    credentialId,
  });
}

// You can also use the indexer client directly:
if (kit.indexer) {
  const { contracts } = await kit.indexer.lookupByCredentialId(credentialIdHex);
  const details = await kit.indexer.getContractDetails('CABC...');
}
```

## Development

### Run Demo Locally

```bash
cd demo
pnpm install
pnpm dev
```

### Test API

```bash
# Health check
curl https://smart-account-indexer.sdf-ecosystem.workers.dev/

# Get stats
curl https://smart-account-indexer.sdf-ecosystem.workers.dev/api/stats

# Lookup credential
curl https://smart-account-indexer.sdf-ecosystem.workers.dev/api/lookup/<credential-id-hex>

# Mainnet health check
curl https://smart-account-indexer-mainnet.sdf-ecosystem.workers.dev/
```

## Relayer Proxy

The `relayer-proxy/` directory contains a Cloudflare Worker that proxies requests to the OpenZeppelin Relayer Channels service. This allows frontend applications to submit fee-sponsored transactions without exposing API keys.

### Features

- Automatic API key generation per IP address (one key per IP, persisted indefinitely)
- Relayer's usage limits reset every 24 hours on their side - no need to regenerate keys
- Rate limiting via Relayer's built-in fair use policy
- Support for both testnet and mainnet

### Deployment

```bash
cd relayer-proxy
pnpm install

# Create KV namespace
wrangler kv namespace create API_KEYS

# Update wrangler.toml with your KV namespace ID

# Deploy (testnet)
wrangler deploy

# For mainnet production:
wrangler kv namespace create API_KEYS --env production
# Update wrangler.toml with production KV namespace ID
wrangler deploy --env production
```

The relayer proxy keeps its non-secret runtime config in `wrangler.toml` (`NETWORK`
and `RELAYER_BASE_URL`). The checked-in `.dev.vars.example` is only for optional
local overrides.

### Relayer Proxy API Endpoints

**Health Check**
```
GET /
```

**Submit Transaction**
```
POST /
Body: { "func": "base64-encoded-func", "auth": ["base64-auth-entry", ...] }
Body: { "xdr": "base64-encoded-xdr" }
```

### SDK Integration

Configure the Smart Account Kit to use the relayer proxy:

```typescript
const kit = new SmartAccountKit({
  rpcUrl: 'https://soroban-testnet.stellar.org',
  networkPassphrase: 'Test SDF Network ; September 2015',
  accountWasmHash: '...',
  webauthnVerifierAddress: 'C...',
  // Use Relayer via proxy
  relayerUrl: 'https://smart-account-relayer-proxy.your-domain.workers.dev',
});

// Transactions will automatically use Relayer if configured
const result = await kit.signAndSubmit(transaction);

// Or force a specific submission method
const result = await kit.signAndSubmit(transaction, { forceMethod: 'relayer' });
```
