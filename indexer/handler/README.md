# Smart Account Indexer Handler

Cloudflare Worker that serves REST API endpoints for querying indexed smart account signer data.

## Overview

This worker queries a PostgreSQL database populated by the Goldsky indexing pipeline. It enables reverse lookups from credential IDs and addresses to smart account contracts.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Health check |
| `GET /api/lookup/:credentialId` | Find contracts by passkey credential ID |
| `GET /api/lookup/address/:address` | Find contracts by G-address or C-address |
| `GET /api/contract/:contractId` | Get contract details with signers and policies |
| `GET /api/contract/:contractId/signers` | Get all signers for a contract |
| `GET /api/credentials` | List all credential IDs (debugging) |
| `GET /api/stats` | Get indexer statistics |

## Deployment

### Prerequisites

- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- PostgreSQL database with the Goldsky-populated `smart_account_signer_events` table

### Setup

```bash
# Install dependencies
pnpm install

# Set database connection string
wrangler secret put DATABASE_URL

# Deploy to Cloudflare (testnet)
wrangler deploy

# Deploy to production (mainnet)
wrangler deploy --env production
wrangler secret put DATABASE_URL --env production
```

### Database Setup

Run `schema.sql` against your PostgreSQL database to create the required views:

```bash
psql $DATABASE_URL -f schema.sql
```

This creates:
- `processed_signers` - View that parses signer data from raw events
- `processed_policies` - View that parses policy data from raw events
- `contract_summary` - Aggregated statistics per contract

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
