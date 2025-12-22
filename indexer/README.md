# Smart Account Indexer

Indexes smart account signer events from Stellar to enable reverse lookups from passkey credentials to contract IDs.

## Overview

When a user authenticates with a passkey, the indexer enables discovering all smart account contracts they have access to. This is essential because:

1. A single passkey can be a signer on multiple smart accounts
2. Passkeys added as secondary signers don't have a deterministic contract address
3. Users need to discover their accounts without knowing contract IDs upfront

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
- Goldsky CLI (for mainnet pipeline management)
- PostgreSQL database (e.g., Neon, Supabase, or self-hosted)

### Configuration

```bash
# Copy the example environment file
cp .env.example .env.dev  # For testnet
cp .env.example .env.prod # For mainnet

# Edit with your database credentials and Goldsky API key
```

### Cloudflare Worker

```bash
cd handler
pnpm install
wrangler secret put DATABASE_URL  # PostgreSQL connection string
wrangler deploy
```

### Goldsky Pipeline (Mainnet)

```bash
cd goldsky
goldsky pipeline create smart-account-signers --definition-path ./pipeline.yaml
goldsky pipeline start smart-account-signers
```

## API Endpoints

**Base URL**: `https://smart-account-indexer.sdf-ecosystem.workers.dev`

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
Get full contract details including signers and policies per context rule.

### Stats
```
GET /api/stats
```
Get indexer statistics (event counts, unique contracts, etc.).

### Manual Poll (Testnet)
```
POST /api/poll
```
Trigger immediate polling of testnet events.

## Events Indexed

| Event | Description |
|-------|-------------|
| `context_rule_added` | New context rule with signers and policies |
| `context_rule_removed` | Context rule deleted |
| `signer_added` | Signer added to existing rule |
| `signer_removed` | Signer removed from rule |
| `policy_added` | Policy added to existing rule |
| `policy_removed` | Policy removed from rule |

## SDK Integration

The indexer client is integrated into the Smart Account Kit SDK and can be used in two ways:
1. Via `kit.indexer` property (auto-configured for known networks)
2. Via direct `IndexerClient` import for standalone use

```typescript
import { SmartAccountKit, IndexedDBStorage } from 'smart-account-kit';

const kit = new SmartAccountKit({
  rpcUrl: 'https://soroban-testnet.stellar.org',
  networkPassphrase: 'Test SDF Network ; September 2015',
  accountWasmHash: '...',
  webauthnVerifierAddress: 'C...',
  storage: new IndexedDBStorage(),
  // Indexer auto-configured for testnet
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
