# Smart Account Indexer Handler

Cloudflare Worker that serves REST API endpoints for querying indexed smart account signer data.

## Overview

This worker queries a PostgreSQL database populated by the Goldsky indexing pipeline. It enables reverse lookups from credential IDs and addresses to smart account contracts and provides the active-rule views used by the SDK's primary discovery path.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Health check |
| `GET /api/lookup/:credentialId` | Find contracts by passkey credential ID |
| `GET /api/lookup/address/:address` | Find contracts by G-address or C-address |
| `GET /api/contract/:contractId` | Get contract details with active signers and policies |
| `GET /api/contract/:contractId/signers` | Get all signers for a contract |
| `GET /api/credentials` | List all credential IDs (admin/debug — see Authentication) |
| `GET /api/stats` | Get indexer statistics |

## Authentication

The handler ships as a **public reference implementation**: with no secret
configured, every route except `/api/credentials` is open (CORS is wide open so
browser SDK clients can call it cross-origin). The health check `GET /` is
always public.

Set the optional `INDEXER_AUTH_TOKEN` secret to run a **private deployment**:

| `INDEXER_AUTH_TOKEN` | `/api/*` routes | `/api/credentials` |
|----------------------|-----------------|--------------------|
| unset (default) | public | `403 Forbidden` (no token can authorize it) |
| set | require `Authorization: Bearer <token>`, else `401` | requires the same bearer token |

The `/api/credentials` route enumerates every indexed credential ID, so it is
treated as admin/debug: it is never reachable without a configured-and-presented
token. This matches the SDK client, which already sends configured tokens as
`Authorization: Bearer <token>` (`indexerAuthToken`), and preserves wire
compatibility with Mercury-style providers that gate the same REST surface.

```bash
wrangler secret put INDEXER_AUTH_TOKEN            # testnet
wrangler secret put INDEXER_AUTH_TOKEN --env production
```

## Deployment

### Prerequisites

- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- PostgreSQL database with the Goldsky-populated `smart_account_signer_events` table

### Setup

```bash
# Install dependencies
pnpm install

# Local dev secret file for `wrangler dev`
cp .dev.vars.example .dev.vars

# Set deployed database connection string
wrangler secret put DATABASE_URL

# Deploy to Cloudflare (testnet)
wrangler deploy

# Deploy to production (mainnet)
wrangler secret put DATABASE_URL --env production
wrangler deploy --env production
```

### Database Setup

Run `schema.sql` against your PostgreSQL database to create the required views:

```bash
psql $DATABASE_URL -f schema.sql
```

This creates:
- `processed_signers` - View that parses signer data from raw events
- `processed_policies` - View that parses policy data from raw events
- `contract_summary` - Aggregated statistics per contract and active context-rule ids

The SDK uses the contract-detail endpoint and summary view to resolve active rule IDs without relying on contract iteration after deletions. A bounded on-chain probe covers fresh low-numbered rules when the indexer is unavailable, but it is not a replacement for complete indexed state.
Those views are intentionally the compatibility layer between Goldsky dataset evolution and the SDK's stable indexer API.

## Local Development

```bash
# Start local dev server
wrangler dev

# Test endpoints
curl http://localhost:8787/
curl http://localhost:8787/api/stats
```

## Configuration

See `wrangler.toml` for environment configuration:

- Default environment: Testnet
- `production` environment: Mainnet

## Related

- [Indexer Overview](../README.md)
- [Goldsky Pipeline](../goldsky/README.md)
