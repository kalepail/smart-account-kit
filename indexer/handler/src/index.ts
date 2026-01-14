/**
 * Smart Account Indexer - Cloudflare Worker
 *
 * This worker provides API endpoints to query signer data indexed by Goldsky.
 * It enables reverse lookups from credential IDs to contract IDs.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import postgres from "postgres";

// Extend the generated Env interface with secrets (not in wrangler.toml)
declare global {
  interface Env {
    DATABASE_URL: string;
  }
}

interface ContractSummary {
  contract_id: string;
  context_rule_count: number;
  external_signer_count: number;
  delegated_signer_count: number;
  native_signer_count: number;
  first_seen_ledger: number;
  last_seen_ledger: number;
  context_rule_ids: number[];
}

// Hono app
const app = new Hono<{ Bindings: Env }>();

// Enable CORS
app.use("*", cors());

// Health check
app.get("/", (c) => {
  return c.json({ status: "ok", service: "smart-account-indexer" });
});

// ============================================================================
// API Endpoints for querying indexed data
// ============================================================================

/**
 * Reverse lookup: Find all contracts associated with a credential ID
 * The credential_id is the hex-encoded bytes from the signer data
 * Returns aggregated contract summaries (one row per contract)
 */
app.get("/api/lookup/:credentialId", async (c) => {
  const credentialId = c.req.param("credentialId").toLowerCase();
  const sql = postgres(c.env.DATABASE_URL);

  try {
    // Find unique contracts for this credential, then join with summary
    const results = await sql<ContractSummary[]>`
      SELECT DISTINCT ON (cs.contract_id)
        cs.contract_id,
        cs.context_rule_count,
        cs.external_signer_count,
        cs.delegated_signer_count,
        cs.native_signer_count,
        cs.first_seen_ledger,
        cs.last_seen_ledger,
        cs.context_rule_ids
      FROM processed_signers ps
      JOIN contract_summary cs ON ps.contract_id = cs.contract_id
      WHERE ps.credential_id = ${credentialId}
      ORDER BY cs.contract_id, cs.last_seen_ledger DESC
    `;

    return c.json({
      credentialId,
      contracts: results,
      count: results.length,
    });
  } catch (error) {
    console.error("Lookup error:", error);
    return c.json({ error: "Database query failed" }, 500);
  } finally {
    c.executionCtx.waitUntil(sql.end());
  }
});

/**
 * Reverse lookup: Find all contracts associated with a signer address (G-address or C-address)
 */
app.get("/api/lookup/address/:signerAddress", async (c) => {
  const signerAddress = c.req.param("signerAddress");
  const sql = postgres(c.env.DATABASE_URL);

  try {
    const results = await sql<ContractSummary[]>`
      SELECT DISTINCT ON (cs.contract_id)
        cs.contract_id,
        cs.context_rule_count,
        cs.external_signer_count,
        cs.delegated_signer_count,
        cs.native_signer_count,
        cs.first_seen_ledger,
        cs.last_seen_ledger,
        cs.context_rule_ids
      FROM processed_signers ps
      JOIN contract_summary cs ON ps.contract_id = cs.contract_id
      WHERE ps.signer_address = ${signerAddress}
      ORDER BY cs.contract_id, cs.last_seen_ledger DESC
    `;

    return c.json({
      signerAddress,
      contracts: results,
      count: results.length,
    });
  } catch (error) {
    console.error("Address lookup error:", error);
    return c.json({ error: "Database query failed" }, 500);
  } finally {
    c.executionCtx.waitUntil(sql.end());
  }
});

/**
 * Get detailed contract information including all context rules and signers
 * Returns structured data grouped by context rule
 */
app.get("/api/contract/:contractId", async (c) => {
  const contractId = c.req.param("contractId");
  const sql = postgres(c.env.DATABASE_URL);

  try {
    // Get contract summary from live view
    const [summary] = await sql<ContractSummary[]>`
      SELECT * FROM contract_summary WHERE contract_id = ${contractId}
    `;

    if (!summary) {
      return c.json({ error: "Contract not found" }, 404);
    }

    // First, find which context rules have been removed
    // Query the raw events table since context_rule_removed events don't have signers
    const removedRules = await sql<{ context_rule_id: number }[]>`
      WITH context_rule_events AS (
        SELECT DISTINCT ON ((topics::jsonb->1->>'u32')::int)
          (topics::jsonb->1->>'u32')::int as context_rule_id,
          event_type,
          ledger_sequence
        FROM smart_account_signer_events
        WHERE contract_id = ${contractId}
          AND event_type IN ('context_rule_added', 'context_rule_removed')
        ORDER BY (topics::jsonb->1->>'u32')::int, ledger_sequence DESC
      )
      SELECT context_rule_id FROM context_rule_events
      WHERE event_type = 'context_rule_removed'
    `;
    const removedRuleIds = new Set(removedRules.map(r => r.context_rule_id));

    // Get active signers (where most recent event is an 'add' type, not 'removed')
    const signers = await sql`
      WITH latest_signer_events AS (
        SELECT DISTINCT ON (context_rule_id, signer_type, COALESCE(signer_address, ''), COALESCE(credential_id, ''))
          context_rule_id,
          signer_type,
          signer_address,
          credential_id,
          event_type,
          ledger_sequence
        FROM processed_signers
        WHERE contract_id = ${contractId}
        ORDER BY context_rule_id, signer_type, COALESCE(signer_address, ''), COALESCE(credential_id, ''), ledger_sequence DESC
      )
      SELECT * FROM latest_signer_events
      WHERE event_type IN ('context_rule_added', 'signer_added')
      ORDER BY context_rule_id, signer_type, ledger_sequence
    `;

    // Get active policies (where most recent event is an add, not 'policy_removed')
    const policies = await sql`
      WITH latest_policy_events AS (
        SELECT DISTINCT ON (context_rule_id, policy_address)
          context_rule_id,
          policy_address,
          install_params,
          event_type,
          ledger_sequence
        FROM processed_policies
        WHERE contract_id = ${contractId}
        ORDER BY context_rule_id, policy_address, ledger_sequence DESC
      )
      SELECT * FROM latest_policy_events
      WHERE event_type IN ('policy_added', 'context_rule_added')
      ORDER BY context_rule_id, ledger_sequence
    `;

    // Group signers and policies by context rule, excluding removed rules
    const contextRules: Record<number, any> = {};

    for (const signer of signers) {
      const ruleId = signer.context_rule_id;
      // Skip signers from removed context rules
      if (removedRuleIds.has(ruleId)) continue;

      if (!contextRules[ruleId]) {
        contextRules[ruleId] = {
          context_rule_id: ruleId,
          signers: [],
          policies: [],
        };
      }
      contextRules[ruleId].signers.push({
        signer_type: signer.signer_type,
        signer_address: signer.signer_address,
        credential_id: signer.credential_id,
      });
    }

    for (const policy of policies) {
      const ruleId = policy.context_rule_id;
      // Skip policies from removed context rules
      if (removedRuleIds.has(ruleId)) continue;

      if (!contextRules[ruleId]) {
        contextRules[ruleId] = {
          context_rule_id: ruleId,
          signers: [],
          policies: [],
        };
      }
      contextRules[ruleId].policies.push({
        policy_address: policy.policy_address,
        install_params: policy.install_params,
      });
    }

    return c.json({
      contractId,
      summary,
      contextRules: Object.values(contextRules).sort((a, b) => a.context_rule_id - b.context_rule_id),
    });
  } catch (error) {
    console.error("Contract details error:", error);
    return c.json({ error: "Database query failed" }, 500);
  } finally {
    c.executionCtx.waitUntil(sql.end());
  }
});

/**
 * Get all signers for a specific contract (simpler flat list)
 */
app.get("/api/contract/:contractId/signers", async (c) => {
  const contractId = c.req.param("contractId");
  const sql = postgres(c.env.DATABASE_URL);

  try {
    const results = await sql`
      SELECT
        signer_type,
        signer_address,
        credential_id,
        context_rule_id,
        ledger_sequence
      FROM processed_signers
      WHERE contract_id = ${contractId}
      ORDER BY context_rule_id, ledger_sequence
    `;

    return c.json({
      contractId,
      signers: results,
      count: results.length,
    });
  } catch (error) {
    console.error("Contract signers error:", error);
    return c.json({ error: "Database query failed" }, 500);
  } finally {
    c.executionCtx.waitUntil(sql.end());
  }
});

/**
 * List all unique credential IDs (for debugging/testing)
 */
app.get("/api/credentials", async (c) => {
  const limit = parseInt(c.req.query("limit") || "100");
  const sql = postgres(c.env.DATABASE_URL);

  try {
    const results = await sql`
      SELECT
        credential_id,
        COUNT(DISTINCT contract_id) as contract_count,
        array_agg(DISTINCT signer_type) as signer_types
      FROM processed_signers
      WHERE credential_id IS NOT NULL
      GROUP BY credential_id
      ORDER BY contract_count DESC
      LIMIT ${limit}
    `;

    return c.json({
      credentials: results,
      count: results.length,
    });
  } catch (error) {
    console.error("Credentials error:", error);
    return c.json({ error: "Database query failed" }, 500);
  } finally {
    c.executionCtx.waitUntil(sql.end());
  }
});

/**
 * Get indexer stats
 */
app.get("/api/stats", async (c) => {
  const sql = postgres(c.env.DATABASE_URL);

  try {
    const [eventStats] = await sql`
      SELECT
        COUNT(*) as total_events,
        COUNT(DISTINCT contract_id) as unique_contracts,
        COUNT(DISTINCT credential_id) as unique_credentials,
        MIN(ledger_sequence) as first_ledger,
        MAX(ledger_sequence) as last_ledger
      FROM processed_signers
    `;

    const eventTypeStats = await sql`
      SELECT
        event_type,
        COUNT(*) as count
      FROM processed_signers
      GROUP BY event_type
    `;

    return c.json({
      stats: {
        ...eventStats,
        eventTypes: eventTypeStats,
      },
    });
  } catch (error) {
    console.error("Stats error:", error);
    return c.json({ error: "Database query failed" }, 500);
  } finally {
    c.executionCtx.waitUntil(sql.end());
  }
});

// ============================================================================
// Worker Export
// ============================================================================

export default {
  fetch: app.fetch,
};
