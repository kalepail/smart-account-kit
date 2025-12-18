# Goldsky Pipeline Configuration

[Goldsky](https://goldsky.com/) pipeline configurations for indexing smart account events from Stellar.

## Overview

These pipelines filter Stellar contract events for smart account operations and sink them to PostgreSQL. The indexed data enables reverse lookups from signer credentials to contract IDs.

## Files

| File | Network | Description |
|------|---------|-------------|
| `pipeline.yaml` | Testnet | Indexes from `stellar_testnet.events` |
| `pipeline-mainnet.yaml` | Mainnet | Indexes from `stellar_mainnet.events` |

## Events Indexed

| Event | Description |
|-------|-------------|
| `context_rule_added` | New context rule created with signers and policies |
| `context_rule_updated` | Context rule metadata updated |
| `context_rule_removed` | Context rule deleted |
| `signer_added` | Signer added to existing rule |
| `signer_removed` | Signer removed from rule |
| `policy_added` | Policy added to existing rule |
| `policy_removed` | Policy removed from rule |

## Deployment

### Prerequisites

- [Goldsky CLI](https://docs.goldsky.com/get-started/cli)
- Goldsky account with Stellar dataset access
- PostgreSQL database

### Deploy Pipeline

```bash
# Login to Goldsky
goldsky login

# Deploy testnet pipeline
goldsky pipeline apply ./pipeline.yaml --status ACTIVE

# Deploy mainnet pipeline
goldsky pipeline apply ./pipeline-mainnet.yaml --status ACTIVE
```

### Manage Pipeline

```bash
# Check pipeline status
goldsky pipeline list

# View pipeline logs
goldsky pipeline logs smart-account-signers

# Pause pipeline
goldsky pipeline update smart-account-signers --status PAUSED

# Delete pipeline
goldsky pipeline delete smart-account-signers
```

## Database

The pipeline creates and populates the `smart_account_signer_events` table. Run the schema from `../handler/schema.sql` to create the required views for querying.

## Related

- [Indexer Overview](../README.md)
- [Handler API](../handler/README.md)
- [Goldsky Documentation](https://docs.goldsky.com/)
