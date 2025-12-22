/**
 * Smart Account Relayer Proxy - Cloudflare Worker
 *
 * This worker provides a proxy for OpenZeppelin Relayer Channels service.
 * It manages API keys per client IP, allowing the frontend to submit transactions
 * without exposing the backend API key.
 *
 * Uses the official @openzeppelin/relayer-plugin-channels SDK.
 *
 * Features:
 * - Automatic API key generation per IP address (persisted indefinitely)
 * - One API key per IP - Relayer's usage limits reset every 24 hours on their side
 * - Rate limiting via Relayer's built-in fair use policy
 * - Separate deployments for testnet and mainnet
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  ChannelsClient,
  PluginExecutionError,
  PluginTransportError,
} from "@openzeppelin/relayer-plugin-channels";

interface StoredApiKey {
  apiKey: string;
  createdAt: number;
}

// Hono app
const app = new Hono<{ Bindings: Env }>();

// Enable CORS
app.use("*", cors());

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get client IP from request
 */
function getClientIP(request: Request): string {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    request.headers.get("X-Real-IP") ||
    "unknown"
  );
}

/**
 * Generate a unique key for KV storage
 */
function getKVKey(ip: string): string {
  return `api-key:${ip}`;
}

/**
 * Get or generate an API key for the given IP.
 * Keys are stored indefinitely - one key per IP address.
 * The Relayer's usage limits reset every 24 hours on their side.
 */
async function getOrCreateApiKey(
  env: Env,
  ip: string
): Promise<{ apiKey: string; isNew: boolean } | null> {
  const kvKey = getKVKey(ip);

  // Check if we already have an API key for this IP
  const cached = (await env.API_KEYS.get(kvKey, "json")) as StoredApiKey | null;
  if (cached) {
    return { apiKey: cached.apiKey, isNew: false };
  }

  // No existing key - generate a new one from Relayer's /gen endpoint
  const newApiKey = await generateApiKey(env);
  if (!newApiKey) {
    return null;
  }

  // Store the new API key (no expiration - persists indefinitely)
  const storedKey: StoredApiKey = {
    apiKey: newApiKey,
    createdAt: Date.now(),
  };

  // Store without expiration TTL - key persists until manually deleted
  await env.API_KEYS.put(kvKey, JSON.stringify(storedKey));

  return { apiKey: newApiKey, isNew: true };
}

/**
 * Generate a new API key from the Relayer service.
 * Calls the /gen endpoint which requires no authentication.
 * @see https://docs.openzeppelin.com/relayer/1.3.x/guides/stellar-channels-guide
 */
async function generateApiKey(env: Env): Promise<string | null> {
  try {
    // The /gen endpoint generates a new API key - no auth required (GET request)
    const response = await fetch(`${env.RELAYER_BASE_URL}/gen`, {
      method: "GET",
    });

    const text = await response.text();

    if (response.ok) {
      try {
        const data = JSON.parse(text) as Record<string, unknown>;
        // Try various possible key names
        const apiKey = data.apiKey || data.api_key || data.key || data.token;
        if (typeof apiKey === "string") {
          return apiKey;
        }
        console.error("API key not found in response:", data);
        return null;
      } catch {
        // Response might be plain text API key
        if (text && text.length > 10 && text.length < 200) {
          return text.trim();
        }
        console.error("Could not parse API key response:", text);
        return null;
      }
    }

    console.error("Failed to generate API key:", response.status, text);
    return null;
  } catch (error) {
    console.error("Error generating API key:", error);
    return null;
  }
}

/**
 * Create a ChannelsClient for the configured network
 */
function createClient(env: Env, apiKey: string): ChannelsClient {
  return new ChannelsClient({
    baseUrl: env.RELAYER_BASE_URL,
    apiKey,
  });
}

/**
 * Extract account address from "Account not found" error message
 */
function extractMissingAccount(errorMessage: string): string | null {
  // Pattern: "Account not found: GXXXX..."
  const match = errorMessage.match(/Account not found:\s*(G[A-Z0-9]{55})/);
  return match ? match[1] : null;
}

/**
 * Fund an account via Friendbot (testnet only)
 */
async function fundWithFriendbot(account: string): Promise<boolean> {
  try {
    const response = await fetch(
      `https://friendbot.stellar.org?addr=${encodeURIComponent(account)}`
    );
    return response.ok;
  } catch (error) {
    console.error("Friendbot funding failed:", error);
    return false;
  }
}

// ============================================================================
// API Endpoints
// ============================================================================

// Health check
app.get("/", (c) => {
  return c.json({
    status: "ok",
    service: "smart-account-relayer-proxy",
    network: c.env.NETWORK,
  });
});

/**
 * Submit a transaction via Relayer
 * POST /
 *
 * Two modes:
 * 1. { func: string, auth: string[] } - Relayer builds tx with channel accounts
 * 2. { xdr: string } - Relayer fee-bumps a signed transaction
 *
 * Use func+auth for Address credentials (transfers, wallet operations).
 * Use xdr for source_account auth (deployment) - tx must be signed.
 *
 * On testnet, if channel accounts are missing (after testnet reset),
 * we'll fund them via friendbot and retry for up to 5 minutes.
 */
app.post("/", async (c) => {
  const ip = getClientIP(c.req.raw);
  const apiKeyResult = await getOrCreateApiKey(c.env, ip);

  if (!apiKeyResult) {
    return c.json(
      {
        success: false,
        error: "Could not obtain API key. Service may be misconfigured.",
      },
      500
    );
  }

  try {
    const body = await c.req.json<{
      func?: string;
      auth?: string[];
      xdr?: string;
    }>();

    // Validate: must have either xdr OR (func AND auth)
    const hasXdr = !!body.xdr;
    const hasFuncAuth = !!body.func && !!body.auth;

    if (!hasXdr && !hasFuncAuth) {
      return c.json(
        { success: false, error: "Request must include 'xdr' OR ('func' and 'auth')" },
        400
      );
    }

    if (hasXdr && hasFuncAuth) {
      return c.json(
        { success: false, error: "Request must include 'xdr' OR ('func' and 'auth'), not both" },
        400
      );
    }

    const client = createClient(c.env, apiKeyResult.apiKey);
    const isTestnet = c.env.NETWORK === "testnet";

    // On testnet, retry for up to 5 minutes to handle channel accounts needing funding
    // On mainnet, only try once (no friendbot available)
    const TESTNET_RETRY_DURATION_MS = 5 * 60 * 1000; // 5 minutes
    const deadline = isTestnet ? Date.now() + TESTNET_RETRY_DURATION_MS : 0;
    const fundedAccounts = new Set<string>(); // Track accounts we've already funded

    // Submit with retry logic for missing accounts (testnet only)
    while (true) {
      try {
        if (hasXdr) {
          // Fee-bump a signed transaction
          const result = await client.submitTransaction({ xdr: body.xdr! });
          return c.json({
            success: true,
            data: {
              transactionId: result.transactionId,
              hash: result.hash,
              status: result.status,
            },
          });
        } else {
          // Build tx with channel accounts
          const result = await client.submitSorobanTransaction({
            func: body.func!,
            auth: body.auth!,
          });
          return c.json({
            success: true,
            data: {
              transactionId: result.transactionId,
              hash: result.hash,
              status: result.status,
            },
          });
        }
      } catch (submitError) {
        const errorMessage = submitError instanceof Error ? submitError.message : String(submitError);

        // Check if this is a "missing account" error (testnet reset scenario)
        const missingAccount = extractMissingAccount(errorMessage);
        const timeRemaining = deadline - Date.now();

        if (missingAccount && isTestnet && timeRemaining > 0) {
          // Only fund each account once per request
          if (!fundedAccounts.has(missingAccount)) {
            console.log(`Account ${missingAccount} not found. Funding via friendbot (${Math.round(timeRemaining / 1000)}s remaining)...`);

            const funded = await fundWithFriendbot(missingAccount);
            if (funded) {
              console.log(`Successfully funded ${missingAccount}. Retrying submission...`);
              fundedAccounts.add(missingAccount);
            } else {
              console.error(`Failed to fund ${missingAccount}`);
            }
          } else {
            console.log(`Account ${missingAccount} already funded, retrying...`);
          }

          continue; // Retry immediately
        }

        // Not a recoverable error or deadline exceeded - throw to outer handler
        throw submitError;
      }
    }
  } catch (error) {
    console.error("Relayer submission error:", error);

    if (error instanceof PluginExecutionError) {
      return c.json(
        {
          success: false,
          error: error.message,
          data: {
            code: error.errorDetails?.code,
            details: error.errorDetails?.details,
          },
        },
        400
      );
    }

    if (error instanceof PluginTransportError) {
      const status = error.statusCode || 500;
      return c.json(
        {
          success: false,
          error: error.message,
        },
        status as 400 | 401 | 403 | 404 | 500 | 502 | 503
      );
    }

    return c.json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Relayer request failed",
      },
      500
    );
  }
});

/**
 * Get fee usage for the current IP
 * GET /fee-usage
 */
app.get("/fee-usage", async (c) => {
  const ip = getClientIP(c.req.raw);
  const kvKey = getKVKey(ip);

  // Check if we have an API key for this IP
  const cached = (await c.env.API_KEYS.get(kvKey, "json")) as StoredApiKey | null;

  if (!cached) {
    return c.json({
      success: true,
      data: {
        hasKey: false,
        message: "No API key assigned yet. Submit a transaction to get one.",
      },
    });
  }

  // Fee usage query requires admin access which we don't have for the managed service
  // Just return key info
  return c.json({
    success: true,
    data: {
      hasKey: true,
      keyCreatedAt: cached.createdAt,
      network: c.env.NETWORK,
      message: "Fee usage details not available for managed service.",
    },
  });
});

/**
 * Get proxy status and client info
 * GET /status
 */
app.get("/status", async (c) => {
  const ip = getClientIP(c.req.raw);
  const kvKey = getKVKey(ip);

  const apiKey = (await c.env.API_KEYS.get(kvKey, "json")) as StoredApiKey | null;

  return c.json({
    success: true,
    data: {
      clientIP: ip,
      network: c.env.NETWORK,
      hasKey: !!apiKey,
      keyCreatedAt: apiKey?.createdAt,
    },
  });
});

// ============================================================================
// Worker Export
// ============================================================================

export default {
  fetch: app.fetch,
};
