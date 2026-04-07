# Goldsky Pipeline Configuration

[Goldsky](https://goldsky.com/) pipeline configurations for indexing smart account events from Stellar.

## Overview

These pipelines filter Stellar contract events for smart account operations and sink them to PostgreSQL. The indexed data enables reverse lookups from signer credentials to contract IDs and preserves the registry lifecycle events needed to reconstruct current active signer and policy state.

## Files

| File | Network | Description |
|------|---------|-------------|
| `pipeline-testnet.yaml` | Testnet | Turbo pipeline on `stellar_testnet.events` v1.2.0 with `start_at: earliest` |
| `pipeline-mainnet.yaml` | Mainnet | Turbo pipeline on `stellar_mainnet.events` v1.2.0 starting from ledger `60343871` (approx. 2026-01-01 UTC) |
| `schema-inspect.yaml` | Mainnet | Blackhole inspection pipeline for validating current Stellar dataset schemas |

## Events Indexed

| Event | Description |
|-------|-------------|
| `context_rule_added` | New context rule created with signers and policies |
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

The SDK and handler depend on these events being present together. The rule views only stay correct when Goldsky retains both the context-rule lifecycle and the global signer/policy registry lifecycle.

## Deployment

### Prerequisites

- [Goldsky CLI](https://docs.goldsky.com/get-started/cli)
- Goldsky Turbo CLI extension (`goldsky turbo`)
- Goldsky account with Stellar dataset access
- PostgreSQL database

### Deploy Pipeline

```bash
# Login to Goldsky
goldsky login

# Deploy testnet pipeline
goldsky turbo apply ./pipeline-testnet.yaml

# Deploy mainnet pipeline
goldsky turbo apply ./pipeline-mainnet.yaml
```

### Manage Pipeline

```bash
# Check pipeline status
goldsky turbo list

# View pipeline logs
goldsky turbo logs smart-account-signers-testnet
goldsky turbo logs smart-account-signers-mainnet

# Pause pipeline
goldsky turbo pause smart-account-signers-testnet
goldsky turbo pause smart-account-signers-mainnet

# Delete pipeline
goldsky turbo delete smart-account-signers-testnet
goldsky turbo delete smart-account-signers-mainnet
```

## Database

The pipeline creates and populates the `smart_account_signer_events` table. Run the schema from `../handler/schema.sql` to create the required views for querying.

## Notes

- Goldsky now supports Turbo for both `stellar_mainnet.*` and `stellar_testnet.*` datasets.
- Mainnet uses a ledger-sequence `start_at` so backfill starts around January 1, 2026 UTC instead of replaying full history.
- Testnet intentionally uses `start_at: earliest` so it captures all events still available in the current testnet epoch, including events from before the pipeline was deployed.
- Stellar testnet still resets frequently, so `earliest` only covers the current reset window rather than all historical testnet activity.

## Related

- [Indexer Overview](../README.md)
- [Handler API](../handler/README.md)
- [Goldsky Documentation](https://docs.goldsky.com/)
