-- Smart Account Indexer Database Schema
--
-- This schema defines:
-- 1. Indexes on the raw Goldsky table (smart_account_signer_events)
-- 2. Live views for querying processed data (always fresh, no staleness)
--
-- The raw table `smart_account_signer_events` is created and managed by Goldsky.
-- We only add indexes and create views on top of it.

-- ============================================================================
-- STEP 1: Indexes on raw Goldsky table
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_events_contract
ON smart_account_signer_events(contract_id);

CREATE INDEX IF NOT EXISTS idx_events_type
ON smart_account_signer_events(event_type);

CREATE INDEX IF NOT EXISTS idx_events_contract_type
ON smart_account_signer_events(contract_id, event_type);

CREATE INDEX IF NOT EXISTS idx_events_ledger
ON smart_account_signer_events(ledger_sequence);

-- ============================================================================
-- STEP 2: Live view for processed signers
-- Parses JSON and extracts signer data from events
-- ============================================================================

CREATE OR REPLACE VIEW processed_signers AS
WITH parsed_events AS (
  SELECT
    e.id,
    e.contract_id,
    e.ledger_sequence,
    e.transaction_hash,
    e.event_type,
    e.topics::jsonb as topics_json,
    e.data::jsonb as data_json
  FROM smart_account_signer_events e
),
-- Signers from context_rule_added events (inline signers array)
context_rule_signers AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.transaction_hash,
    pe.event_type,
    (pe.topics_json->1->'u32')::int as context_rule_id,
    signer_elem->'vec' as signer_vec
  FROM parsed_events pe,
  LATERAL (
    SELECT elem->'val'->'vec' as signers_vec
    FROM jsonb_array_elements(pe.data_json->'map') elem
    WHERE elem->'key'->>'symbol' = 'signers'
  ) signers,
  jsonb_array_elements(signers.signers_vec) as signer_elem
  WHERE pe.event_type = 'context_rule_added'
),
-- Signers from signer_added/signer_removed events (single signer)
single_signer_events AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.transaction_hash,
    pe.event_type,
    (pe.topics_json->1->'u32')::int as context_rule_id,
    (SELECT elem->'val'->'vec' FROM jsonb_array_elements(pe.data_json->'map') elem WHERE elem->'key'->>'symbol' = 'signer') as signer_vec
  FROM parsed_events pe
  WHERE pe.event_type IN ('signer_added', 'signer_removed')
),
-- Combine both sources
all_signers AS (
  SELECT * FROM context_rule_signers
  UNION ALL
  SELECT * FROM single_signer_events
)
SELECT
  id,
  contract_id,
  ledger_sequence,
  transaction_hash,
  event_type,
  context_rule_id,
  signer_vec->0->>'symbol' as signer_type,
  signer_vec->1->>'address' as signer_address,
  signer_vec->2->>'bytes' as raw_bytes,
  -- For External signers with passkeys (> 65 bytes), extract just credential_id
  -- For Delegated signers (32 bytes ed25519), keep as-is
  CASE
    WHEN LENGTH(signer_vec->2->>'bytes') > 130
    THEN SUBSTRING(signer_vec->2->>'bytes' FROM 131)  -- Skip first 65 bytes (130 hex chars)
    ELSE signer_vec->2->>'bytes'
  END as credential_id
FROM all_signers;

-- ============================================================================
-- STEP 3: Live view for processed policies
-- ============================================================================

CREATE OR REPLACE VIEW processed_policies AS
-- Policies from policy_added/policy_removed events
SELECT
  e.id,
  e.contract_id,
  e.ledger_sequence,
  e.transaction_hash,
  e.event_type,
  (e.topics::jsonb->1->>'u32')::int as context_rule_id,
  (SELECT elem->'val'->>'address' FROM jsonb_array_elements(e.data::jsonb->'map') elem WHERE elem->'key'->>'symbol' = 'policy') as policy_address,
  (SELECT elem->'val' FROM jsonb_array_elements(e.data::jsonb->'map') elem WHERE elem->'key'->>'symbol' = 'install_param') as install_params
FROM smart_account_signer_events e
WHERE e.event_type IN ('policy_added', 'policy_removed')

UNION ALL

-- Inline policies from context_rule_added events
SELECT
  e.id,
  e.contract_id,
  e.ledger_sequence,
  e.transaction_hash,
  'context_rule_added' as event_type,
  (e.topics::jsonb->1->>'u32')::int as context_rule_id,
  policy_elem->>'address' as policy_address,
  NULL::jsonb as install_params
FROM smart_account_signer_events e,
LATERAL (
  SELECT elem->'val'->'vec' as policies_vec
  FROM jsonb_array_elements(e.data::jsonb->'map') elem
  WHERE elem->'key'->>'symbol' = 'policies'
) policies,
jsonb_array_elements(policies.policies_vec) as policy_elem
WHERE e.event_type = 'context_rule_added'
  AND policies.policies_vec IS NOT NULL
  AND jsonb_array_length(policies.policies_vec) > 0;

-- ============================================================================
-- STEP 4: Live view for contract summary
-- Pre-aggregated statistics per contract
-- ============================================================================

CREATE OR REPLACE VIEW contract_summary AS
SELECT
  contract_id,
  COUNT(DISTINCT context_rule_id) as context_rule_count,
  COUNT(*) FILTER (WHERE signer_type = 'External' AND event_type != 'signer_removed') as external_signer_count,
  COUNT(*) FILTER (WHERE signer_type = 'Delegated' AND event_type != 'signer_removed') as delegated_signer_count,
  COUNT(*) FILTER (WHERE signer_type = 'Native' AND event_type != 'signer_removed') as native_signer_count,
  MIN(ledger_sequence) as first_seen_ledger,
  MAX(ledger_sequence) as last_seen_ledger,
  array_agg(DISTINCT context_rule_id ORDER BY context_rule_id) as context_rule_ids
FROM processed_signers
GROUP BY contract_id;
