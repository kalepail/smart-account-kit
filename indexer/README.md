# Smart Account Indexer

Reference indexer stack for smart account events on Stellar. It enables reverse lookups from passkey credentials to contract IDs and supplies active rule IDs to the SDK's best-effort discovery flow.

## Overview

When a user authenticates with a passkey, an indexer can discover all smart account contracts they have access to. It is also the reliable source for active context-rule IDs after removals or when IDs become sparse. The SDK has a bounded low-ID on-chain fallback for fresh wallets and temporary indexer lag, but it cannot reconstruct arbitrary active IDs because:

1. A single passkey can be a signer on multiple smart accounts
2. Passkeys added as secondary signers don't have a deterministic contract address
3. Users need to discover their accounts without knowing contract IDs upfront
4. The contract exposes individual rule lookups, but not a stable iterator over currently active rule IDs

## Architecture

```
Stellar Network → Goldsky Pipeline → PostgreSQL → Cloudflare Worker API → SDK
```

This directory implements the Goldsky/PostgreSQL/Cloudflare reference stack. The SDK only depends on the REST contract, so it can also point at a wire-compatible provider such as Mercury.

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

# Testnet: Turbo on stellar_testnet.events v1.2.0, start_at 1799808 (~2026-04-01)
goldsky turbo apply ./pipeline-testnet.yaml

# Mainnet: Turbo on stellar_mainnet.events v1.2.0, start_at 60343871 (~2026-01-01)
goldsky turbo apply ./pipeline-mainnet.yaml
```

## API Endpoints

| Provider | Testnet | Mainnet |
|----------|---------|---------|
| Reference Cloudflare Workers (SDK defaults) | `https://smart-account-indexer.sdf-ecosystem.workers.dev` | `https://smart-account-indexer-mainnet.sdf-ecosystem.workers.dev` |
| Mercury-compatible REST API | `https://testnet.mercurydata.app/rest/smart-account-indexer` | `https://mainnet.mercurydata.app/rest/smart-account-indexer` |

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
This is the primary endpoint the SDK uses to rebuild active rule state for `rules.list()` and `rules.getAll()`.

### Contract Signers
```
GET /api/contract/:contractId/signers
```
Get the active signers associated with a contract.

### Credential IDs
```
GET /api/credentials
```
List indexed credential IDs. This is an admin/debug endpoint. In the reference handler it is **never** publicly reachable: it returns `403` unless `INDEXER_AUTH_TOKEN` is configured and presented as a bearer token (see [Authentication](#authentication)).

### Stats
```
GET /api/stats
```
Get indexer statistics (event counts, unique contracts, etc.).

## Authentication

The reference Cloudflare handler is a **public reference implementation** by
default. Access control is governed by the optional `INDEXER_AUTH_TOKEN` secret
on the handler (see [`handler/README.md`](./handler/README.md#authentication)):

| `INDEXER_AUTH_TOKEN` | `GET /` | `/api/*` (except credentials) | `/api/credentials` |
|----------------------|---------|-------------------------------|--------------------|
| unset (default) | public | public | `403 Forbidden` |
| set | public | require `Authorization: Bearer <token>` | require the same bearer token |

The SDK sends its configured `indexerAuthToken` as `Authorization: Bearer <token>`
on every request, so the same client works against the open reference handler, a
token-gated private deployment, or a Mercury-compatible provider without code
changes. CORS is intentionally left wide open (read-only data API); when access
must be restricted, use the bearer token rather than origin allow-lists.

Browser applications should only embed public or tightly scoped indexer tokens.
Keep catch-up, admin, and other privileged credentials in server-side tooling.

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

The contract-detail API turns the raw event stream into current active rule state so the SDK can resolve rule IDs without guessing after deletions. If it is unavailable, the SDK probes a bounded low-ID range on-chain by default; sparse or higher-numbered rules still need an indexer.

For this project, testnet pins `start_at: 1799808` (the first ledger at or after 2026-04-01 UTC) rather than replaying the full testnet epoch, so the pipeline catches up quickly after a reset. See [`goldsky/README.md`](./goldsky/README.md) for the rationale.

```typescript
import { SmartAccountKit, IndexedDBStorage } from 'smart-account-kit';

const kit = new SmartAccountKit({
  rpcUrl: 'https://soroban-testnet.stellar.org',
  networkPassphrase: 'Test SDF Network ; September 2015',
  accountWasmHash: '...',
  webauthnVerifierAddress: 'C...',
  storage: new IndexedDBStorage(),
  // Optional wire-compatible provider override:
  indexerUrl: 'https://testnet.mercurydata.app/rest/smart-account-indexer',
  // Optional API key or JWT, sent as Authorization: Bearer <token>
  indexerAuthToken: 'public-or-scoped-token',
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
INDEXER_URL=https://testnet.mercurydata.app/rest/smart-account-indexer

# Health check
curl "$INDEXER_URL/"

# Get stats
curl "$INDEXER_URL/api/stats"

# Lookup credential
curl "$INDEXER_URL/api/lookup/<credential-id-hex>"

# Add bearer auth when required by the selected provider (see Authentication)
curl -H "Authorization: Bearer $INDEXER_TOKEN" \
  "$INDEXER_URL/api/stats"
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
Provide **either** `func` + `auth` (Relayer builds and signs with channel
accounts — used for Address-credential operations like transfers) **or** `xdr`
(Relayer fee-bumps an already-signed transaction — used for source-account auth
like deployment). Supplying both, or neither, returns `400`. On testnet, if a
channel account is missing after a network reset, the proxy funds it via
Friendbot and retries for up to 5 minutes.

**Fee Usage**
```
GET /fee-usage
```
Report whether the caller's IP has a minted Relayer API key and when it was
created. Detailed fee accounting is not exposed by the managed Relayer service.

**Status**
```
GET /status
```
Return the resolved client IP, network, and whether an API key has been minted
for that IP.

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
