# Goldsky Turbo Stellar Mainnet Dataset Schemas

> **Version:** 1.1.0
> **Last Verified:** 2025-12-23
> **Source:** Extracted directly from Goldsky internal SQL transforms via `goldsky turbo logs`

All datasets are derived from `stellar_mainnet_raw_ledgers` (Kafka topic: `stellar-pubnet.ledgers.v4`) via internal SQL transforms.

---

## stellar_mainnet.ledgers

Simple ledger metadata with transaction counts.

**Primary Key:** `ledger_sequence`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `ledger_sequence` | integer | Ledger sequence number |
| 2 | `ledger_hash` | string | Ledger hash |
| 3 | `ledger_closed_at` | timestamp | Ledger close time |
| 4 | `ledger_signature` | string | Ledger signature |
| 5 | `transaction_count` | integer | Number of transactions in ledger |
| 6 | `_gs_op` | string | CDC operation type ('i' = insert) |

**Internal SQL:**
```sql
SELECT
  l.sequence AS ledger_sequence,
  l.ledger_hash,
  l.closed_at AS ledger_closed_at,
  l.signature AS ledger_signature,
  CARDINALITY(l.transactions) AS transaction_count,
  'i' AS _gs_op
FROM stellar_mainnet_raw_ledgers__1_1_0__go6d6vq AS l
```

---

## stellar_mainnet.transactions

All transactions on the network with full metadata.

**Primary Key:** `transaction_hash`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `transaction_hash` | string | Unique transaction hash |
| 2 | `account` | string | Source account |
| 3 | `account_muxed` | string | Muxed source account |
| 4 | `account_sequence` | bigint | Account sequence number |
| 5 | `max_fee` | bigint | Maximum fee willing to pay |
| 6 | `fee_charged` | bigint | Actual fee charged |
| 7 | `fee_account` | string | Fee source account |
| 8 | `fee_account_muxed` | string | Muxed fee account |
| 9 | `inner_transaction_hash` | string | Inner tx hash (fee bump txs) |
| 10 | `new_max_fee` | bigint | New max fee (fee bump txs) |
| 11 | `memo_type` | string | Memo type (none/text/id/hash/return) |
| 12 | `memo` | string | Memo content |
| 13 | `time_bounds_lower` | bigint | Time bounds lower limit |
| 14 | `time_bounds_upper` | bigint | Time bounds upper limit |
| 15 | `successful` | boolean | Transaction success status |
| 16 | `transaction_result_code` | string | Result code |
| 17 | `operation_count` | integer | Number of operations |
| 18 | `event_count` | integer | Number of events |
| 19 | `diagnostic_event_count` | integer | Number of diagnostic events |
| 20 | `inclusion_fee_bid` | bigint | Soroban inclusion fee bid |
| 21 | `resource_fee` | bigint | Soroban resource fee |
| 22 | `soroban_resources_instructions` | bigint | Soroban CPU instructions |
| 23 | `soroban_resources_read_bytes` | bigint | Soroban read bytes |
| 24 | `soroban_resources_write_bytes` | bigint | Soroban write bytes |
| 25 | `non_refundable_resource_fee_charged` | bigint | Non-refundable fee |
| 26 | `refundable_resource_fee_charged` | bigint | Refundable fee |
| 27 | `rent_fee_charged` | bigint | Storage rent fee |
| 28 | `tx_signers` | array | Transaction signers |
| 29 | `ledger_sequence` | integer | Ledger sequence number |
| 30 | `ledger_hash` | string | Ledger hash |
| 31 | `ledger_closed_at` | timestamp | Ledger close time |
| 32 | `ledger_signature` | string | Ledger signature |
| 33 | `_gs_op` | string | CDC operation type |

---

## stellar_mainnet.events

All contract events (transaction-level and operation-level).

**Primary Key:** `id`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `id` | string | Event ID |
| 2 | `type` | string | Event type |
| 3 | `contract_id` | string | Contract address |
| 4 | `topics` | json | Event topics array |
| 5 | `data` | json | Event data payload |
| 6 | `in_successful_contract_call` | boolean | In successful call |
| 7 | `transaction_hash` | string | Parent transaction hash |
| 8 | `transaction_account` | string | Transaction source account |
| 9 | `transaction_fee_account` | string | Transaction fee account |
| 10 | `transaction_successful` | boolean | Transaction success status |
| 11 | `transaction_index` | integer | Transaction index in ledger |
| 12 | `operation_body` | string | Operation body (NULL for tx events) |
| 13 | `operation_result_code` | string | Operation result code (NULL for tx events) |
| 14 | `operation_type` | string | Operation type (NULL for tx events) |
| 15 | `ledger_sequence` | integer | Ledger sequence number |
| 16 | `ledger_hash` | string | Ledger hash |
| 17 | `ledger_closed_at` | timestamp | Ledger close time |
| 18 | `ledger_signature` | string | Ledger signature |
| 19 | `_gs_op` | string | CDC operation type |

**Note:** This is a UNION of transaction-level events and operation-level events. For transaction events, operation_* fields are NULL.

---

## stellar_mainnet.operations

All operations performed within transactions.

**Primary Key:** `id`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `body` | json | Operation body/parameters |
| 2 | `event_count` | integer | Number of events |
| 3 | `id` | string | Operation ID |
| 4 | `ledger_entry_changes_count` | integer | Number of ledger entry changes |
| 5 | `result_code` | string | Operation result code |
| 6 | `source_account` | string | Operation source account |
| 7 | `source_account_muxed` | string | Muxed source account |
| 8 | `type` | string | Operation type |
| 9 | `transaction_hash` | string | Parent transaction hash |
| 10 | `transaction_account` | string | Transaction source account |
| 11 | `transaction_fee_account` | string | Transaction fee account |
| 12 | `transaction_successful` | boolean | Transaction success status |
| 13 | `transaction_index` | integer | Transaction index in ledger |
| 14 | `ledger_sequence` | integer | Ledger sequence number |
| 15 | `ledger_hash` | string | Ledger hash |
| 16 | `ledger_closed_at` | timestamp | Ledger close time |
| 17 | `ledger_signature` | string | Ledger signature |
| 18 | `_gs_op` | string | CDC operation type |

---

## stellar_mainnet.ledger_entries

Individual ledger entry changes (accounts, trustlines, offers, etc.).

**Primary Key:** `ledger_sequence` (Note: per Goldsky config)

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `id` | string | Entry change ID |
| 2 | `change_type` | string | created/updated/removed/restored |
| 3 | `ledger_entry_type` | string | account/trustline/offer/data/claimable_balance/liquidity_pool/contract_data/contract_code/config_setting/ttl |
| 4 | `entry_data` | json | Full entry data |
| 5 | `key_data` | json | Entry key data |
| 6 | `last_modified_ledger_sequence` | integer | Last modified ledger |
| 7 | `operation_id` | string | Parent operation ID |
| 8 | `operation_type` | string | Operation type |
| 9 | `operation_result_code` | string | Operation result code |
| 10 | `operation_source_account` | string | Operation source account |
| 11 | `operation_source_account_muxed` | string | Muxed operation source |
| 12 | `operation_body` | json | Operation body |
| 13 | `transaction_hash` | string | Parent transaction hash |
| 14 | `transaction_account` | string | Transaction source account |
| 15 | `transaction_fee_account` | string | Transaction fee account |
| 16 | `transaction_successful` | boolean | Transaction success status |
| 17 | `transaction_index` | integer | Transaction index in ledger |
| 18 | `ledger_sequence` | integer | Ledger sequence number |
| 19 | `ledger_hash` | string | Ledger hash |
| 20 | `ledger_closed_at` | timestamp | Ledger close time |
| 21 | `ledger_signature` | string | Ledger signature |
| 22 | `_gs_op` | string | CDC operation type |

---

## stellar_mainnet.transfers

Parsed transfer events (burn, claim, clawback, donate, fee, mint, transfer).

**Primary Key:** `id`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `id` | string | Transfer event ID |
| 2 | `transfer_type` | string | burn/claim/clawback/donate/fee/mint/transfer |
| 3 | `sender` | string | Sender address (from topics[1]) |
| 4 | `recipient` | string | Recipient address (from topics[2]) |
| 5 | `asset_raw` | string | Raw asset string (native or code:issuer) |
| 6 | `asset_code` | string | Asset code (XLM for native) |
| 7 | `asset_issuer` | string | Asset issuer (NULL for native) |
| 8 | `amount` | decimal(38,0) | Transfer amount (i128 from data) |
| 9 | `to_muxed_id` | string | Recipient muxed ID (if present) |
| 10 | `contract_id` | string | Contract address |
| 11 | `topics` | json | Event topics array |
| 12 | `data` | json | Event data payload |
| 13 | `in_successful_contract_call` | boolean | In successful call |
| 14 | `transaction_hash` | string | Parent transaction hash |
| 15 | `transaction_account` | string | Transaction source account |
| 16 | `transaction_fee_account` | string | Transaction fee account |
| 17 | `transaction_successful` | boolean | Transaction success status |
| 18 | `transaction_index` | integer | Transaction index in ledger |
| 19 | `operation_body` | string | Operation body (NULL for tx events) |
| 20 | `operation_result_code` | string | Operation result code |
| 21 | `operation_type` | string | Operation type |
| 22 | `ledger_sequence` | integer | Ledger sequence number |
| 23 | `ledger_hash` | string | Ledger hash |
| 24 | `ledger_closed_at` | timestamp | Ledger close time |
| 25 | `ledger_signature` | string | Ledger signature |
| 26 | `_gs_op` | string | CDC operation type |

**Note:** Only includes events where `topics[0].symbol` is one of: burn, claim, clawback, donate, fee, mint, transfer

---

## stellar_mainnet.balances

Account balances over time (XLM, trustlines, liquidity pools).

**Primary Key:** `account_id, asset_code` (composite)

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `account_id` | string | Account address |
| 2 | `asset_code` | string | Asset code (XLM for native) |
| 3 | `asset_type` | string | native/credit_alphanum4/credit_alphanum12 |
| 4 | `asset_issuer` | string | Asset issuer (NULL for native) |
| 5 | `liquidity_pool_id` | string | Liquidity pool ID (if applicable) |
| 6 | `balance` | decimal | Balance in human units (stroops / 10^7) |
| 7 | `balance_key` | string | `account_id|asset_code|asset_issuer` |
| 8 | `last_modified_ledger_sequence` | integer | Last modified ledger |
| 9 | `change_type` | string | created/updated/removed/restored |
| 10 | `ledger_entry_type` | string | account/trustline/liquidity_pool |
| 11 | `ingested_at` | timestamp | Ingestion timestamp (now()) |

**Note:** Derived from ledger entry changes of type 'account', 'trustline', or 'liquidity_pool'.

---

## How to Discover/Verify Schemas

### Method 1: Inspect pipeline logs
```bash
# Deploy a blackhole pipeline
goldsky turbo apply schema-inspect.yaml

# View internal SQL transforms with full schema definitions
goldsky turbo logs <pipeline-name>
```

### Method 2: Inspect live data
```bash
# See actual data samples flowing through
goldsky turbo inspect <pipeline-name>
```

### Example schema inspection pipeline
```yaml
name: schema-inspect
resource_size: s

sources:
  stellar_events:
    type: dataset
    dataset_name: stellar_mainnet.events
    version: 1.1.0
    start_at: latest

transforms:
  passthrough:
    type: sql
    primary_key: id
    sql: SELECT * FROM stellar_events

sinks:
  dev_sink:
    type: blackhole
    from: passthrough
```

---

## SQL Transform Notes

- **Engine:** Apache DataFusion
- **Supported:** SELECT, WHERE, CASE, LIKE, CAST, COALESCE, JSON_VALUE, REGEXP_EXTRACT, CARDINALITY, CONCAT
- **NOT Supported:** JOIN, CROSS JOIN (handled internally by Goldsky for dataset derivation)
- **Primary Keys:** Required for deduplication; latest row wins

## Useful SQL Patterns

```sql
-- Filter events by topic keyword
WHERE topics LIKE '%transfer%'

-- Extract from JSON topics array
JSON_VALUE(topics, '$[0].symbol')

-- Case-based event typing
CASE
  WHEN topics LIKE '%mint%' THEN 'mint'
  WHEN topics LIKE '%burn%' THEN 'burn'
  ELSE 'other'
END AS event_type

-- Filter by contract
WHERE contract_id = 'CXXX...'

-- Extract nested JSON values
JSON_VALUE(data, '$.i128') AS amount
```
