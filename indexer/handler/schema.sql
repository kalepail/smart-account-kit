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
-- Latest signer registry rows keyed by signer_id.
-- Current contracts emit signer references by ID, then publish the signer
-- payload separately via signer_registered events.
signer_registry_events AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.event_type,
    (pe.topics_json->1->>'u32')::int as signer_id,
    (
      SELECT elem->'val'->'vec'
      FROM jsonb_array_elements(pe.data_json->'map') elem
      WHERE elem->'key'->>'symbol' = 'signer'
    ) as signer_vec
  FROM parsed_events pe
  WHERE pe.event_type IN ('signer_registered', 'signer_deregistered')
),
latest_signer_registry AS (
  SELECT DISTINCT ON (contract_id, signer_id)
    contract_id,
    signer_id,
    event_type,
    signer_vec,
    ledger_sequence
  FROM signer_registry_events
  ORDER BY contract_id, signer_id, ledger_sequence DESC
),
registered_signers AS (
  SELECT
    contract_id,
    signer_id,
    signer_vec
  FROM latest_signer_registry
  WHERE event_type = 'signer_registered'
),
-- Legacy context_rule_added shape with inline signers array.
context_rule_inline_signers AS (
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
-- Current context_rule_added shape with signer_ids references.
context_rule_signer_ids AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.transaction_hash,
    pe.event_type,
    (pe.topics_json->1->'u32')::int as context_rule_id,
    (signer_id_elem->>'u32')::int as signer_id
  FROM parsed_events pe,
  LATERAL (
    SELECT elem->'val'->'vec' as signer_ids_vec
    FROM jsonb_array_elements(pe.data_json->'map') elem
    WHERE elem->'key'->>'symbol' = 'signer_ids'
  ) signer_ids,
  jsonb_array_elements(signer_ids.signer_ids_vec) as signer_id_elem
  WHERE pe.event_type = 'context_rule_added'
),
-- Legacy signer_added/signer_removed shape with inline signer payload.
single_inline_signer_events AS (
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
-- Current signer_added/signer_removed shape with signer_id in the payload.
single_signer_id_events AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.transaction_hash,
    pe.event_type,
    (pe.topics_json->1->'u32')::int as context_rule_id,
    (
      SELECT (elem->'val'->>'u32')::int
      FROM jsonb_array_elements(pe.data_json->'map') elem
      WHERE elem->'key'->>'symbol' = 'signer_id'
    ) as signer_id
  FROM parsed_events pe
  WHERE pe.event_type IN ('signer_added', 'signer_removed')
),
inline_signers AS (
  SELECT * FROM context_rule_inline_signers
  UNION ALL
  SELECT * FROM single_inline_signer_events
),
id_based_signers AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.transaction_hash,
    pe.event_type,
    pe.context_rule_id,
    rs.signer_vec
  FROM (
    SELECT * FROM context_rule_signer_ids
    UNION ALL
    SELECT * FROM single_signer_id_events
  ) pe
  JOIN registered_signers rs
    ON rs.contract_id = pe.contract_id
   AND rs.signer_id = pe.signer_id
  WHERE pe.signer_id IS NOT NULL
),
all_signers AS (
  SELECT * FROM inline_signers
  UNION ALL
  SELECT * FROM id_based_signers
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
policy_registry_events AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.event_type,
    (pe.topics_json->1->>'u32')::int as policy_id,
    (
      SELECT elem->'val'->>'address'
      FROM jsonb_array_elements(pe.data_json->'map') elem
      WHERE elem->'key'->>'symbol' = 'policy'
    ) as policy_address
  FROM parsed_events pe
  WHERE pe.event_type IN ('policy_registered', 'policy_deregistered')
),
latest_policy_registry AS (
  SELECT DISTINCT ON (contract_id, policy_id)
    contract_id,
    policy_id,
    event_type,
    policy_address,
    ledger_sequence
  FROM policy_registry_events
  ORDER BY contract_id, policy_id, ledger_sequence DESC
),
registered_policies AS (
  SELECT
    contract_id,
    policy_id,
    policy_address
  FROM latest_policy_registry
  WHERE event_type = 'policy_registered'
),
-- Current policy_added/policy_removed shape keyed by policy_id.
policy_id_events AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.transaction_hash,
    pe.event_type,
    (pe.topics_json->1->>'u32')::int as context_rule_id,
    (
      SELECT (elem->'val'->>'u32')::int
      FROM jsonb_array_elements(pe.data_json->'map') elem
      WHERE elem->'key'->>'symbol' = 'policy_id'
    ) as policy_id,
    (
      SELECT elem->'val'
      FROM jsonb_array_elements(pe.data_json->'map') elem
      WHERE elem->'key'->>'symbol' = 'install_param'
    ) as install_params
  FROM parsed_events pe
  WHERE pe.event_type IN ('policy_added', 'policy_removed')
),
legacy_inline_policies AS (
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
    AND jsonb_array_length(policies.policies_vec) > 0
),
context_rule_policy_ids AS (
  SELECT
    pe.id,
    pe.contract_id,
    pe.ledger_sequence,
    pe.transaction_hash,
    pe.event_type,
    (pe.topics_json->1->>'u32')::int as context_rule_id,
    (policy_id_elem->>'u32')::int as policy_id,
    NULL::jsonb as install_params
  FROM parsed_events pe,
  LATERAL (
    SELECT elem->'val'->'vec' as policy_ids_vec
    FROM jsonb_array_elements(pe.data_json->'map') elem
    WHERE elem->'key'->>'symbol' = 'policy_ids'
  ) policy_ids,
  jsonb_array_elements(policy_ids.policy_ids_vec) as policy_id_elem
  WHERE pe.event_type = 'context_rule_added'
),
resolved_policy_ids AS (
  SELECT
    e.id,
    e.contract_id,
    e.ledger_sequence,
    e.transaction_hash,
    e.event_type,
    e.context_rule_id,
    rp.policy_address,
    e.install_params
  FROM (
    SELECT * FROM policy_id_events
    UNION ALL
    SELECT * FROM context_rule_policy_ids
  ) e
  JOIN registered_policies rp
    ON rp.contract_id = e.contract_id
   AND rp.policy_id = e.policy_id
  WHERE e.policy_id IS NOT NULL
)
-- Policies from current and legacy shapes
SELECT
  id,
  contract_id,
  ledger_sequence,
  transaction_hash,
  event_type,
  context_rule_id,
  policy_address,
  install_params
FROM resolved_policy_ids

UNION ALL

SELECT
  id,
  contract_id,
  ledger_sequence,
  transaction_hash,
  event_type,
  context_rule_id,
  policy_address,
  install_params
FROM legacy_inline_policies;

-- ============================================================================
-- STEP 4: Live view for contract summary
-- Pre-aggregated statistics per contract
-- ============================================================================

CREATE OR REPLACE VIEW contract_summary AS
WITH latest_context_rule_events AS (
  SELECT DISTINCT ON (contract_id, (topics::jsonb->1->>'u32'))
    contract_id,
    (topics::jsonb->1->>'u32')::int as context_rule_id,
    event_type,
    ledger_sequence
  FROM smart_account_signer_events
  WHERE event_type IN ('context_rule_added', 'context_rule_removed')
  ORDER BY contract_id, (topics::jsonb->1->>'u32'), ledger_sequence DESC
),
active_context_rules AS (
  SELECT
    contract_id,
    context_rule_id
  FROM latest_context_rule_events
  WHERE event_type != 'context_rule_removed'
),
latest_signer_events AS (
  SELECT DISTINCT ON (
    ps.contract_id,
    ps.context_rule_id,
    ps.signer_type,
    COALESCE(ps.signer_address, ''),
    COALESCE(ps.credential_id, '')
  )
    ps.contract_id,
    ps.context_rule_id,
    ps.signer_type,
    ps.signer_address,
    ps.credential_id,
    ps.event_type,
    ps.ledger_sequence
  FROM processed_signers ps
  JOIN active_context_rules acr
    ON acr.contract_id = ps.contract_id
   AND acr.context_rule_id = ps.context_rule_id
  ORDER BY
    ps.contract_id,
    ps.context_rule_id,
    ps.signer_type,
    COALESCE(ps.signer_address, ''),
    COALESCE(ps.credential_id, ''),
    ps.ledger_sequence DESC
),
active_signers AS (
  SELECT *
  FROM latest_signer_events
  WHERE event_type IN ('context_rule_added', 'signer_added')
),
contract_ledgers AS (
  SELECT
    contract_id,
    MIN(ledger_sequence) as first_seen_ledger,
    MAX(ledger_sequence) as last_seen_ledger
  FROM smart_account_signer_events
  GROUP BY contract_id
)
SELECT
  cl.contract_id,
  COUNT(DISTINCT acr.context_rule_id) as context_rule_count,
  COUNT(*) FILTER (WHERE asg.signer_type = 'External') as external_signer_count,
  COUNT(*) FILTER (WHERE asg.signer_type = 'Delegated') as delegated_signer_count,
  COUNT(*) FILTER (WHERE asg.signer_type = 'Native') as native_signer_count,
  cl.first_seen_ledger,
  cl.last_seen_ledger,
  COALESCE(array_agg(DISTINCT acr.context_rule_id ORDER BY acr.context_rule_id), ARRAY[]::int[]) as context_rule_ids
FROM contract_ledgers cl
LEFT JOIN active_context_rules acr
  ON acr.contract_id = cl.contract_id
LEFT JOIN active_signers asg
  ON asg.contract_id = cl.contract_id
 AND asg.context_rule_id = acr.context_rule_id
GROUP BY cl.contract_id, cl.first_seen_ledger, cl.last_seen_ledger;
