/**
 * Optional bearer-token auth gate for the indexer handler.
 *
 * The handler is a public reference implementation by default. When the
 * `INDEXER_AUTH_TOKEN` secret is configured, it becomes a private deployment:
 * every `/api/*` route then requires `Authorization: Bearer <token>`.
 */

import type { MiddlewareHandler } from "hono";
import { ERROR_MESSAGES } from "./constants";

/** Admin/debug route that must never be publicly reachable. */
export const ADMIN_ONLY_PATH = "/api/credentials";

/**
 * Extract the token from an `Authorization: Bearer <token>` header.
 * Returns null when the header is absent or not a well-formed bearer header.
 * The scheme match is case-insensitive and surrounding whitespace is ignored.
 */
export function extractBearerToken(
  header: string | null | undefined
): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

/**
 * Constant-time string comparison so a caller cannot recover the configured
 * token character-by-character from response timing. Every position is
 * compared regardless of where the first mismatch occurs, and unequal-length
 * inputs never compare equal.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const length = Math.max(a.length, b.length);
  // Seed with the length difference so differing lengths always mismatch.
  let mismatch = a.length ^ b.length;
  for (let i = 0; i < length; i++) {
    mismatch |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return mismatch === 0;
}

/**
 * Bearer-token auth gate for `/api/*` routes.
 *
 * Posture (documented in indexer/README.md → Authentication):
 * - `INDEXER_AUTH_TOKEN` unset: public reference-implementation behavior,
 *   EXCEPT the admin/debug `/api/credentials` route, which stays locked (403)
 *   because no token exists that could authorize it.
 * - `INDEXER_AUTH_TOKEN` set: every `/api/*` route requires a matching
 *   `Authorization: Bearer <token>` and returns 401 otherwise.
 *
 * The health check (`GET /`) is intentionally left outside this gate so
 * uptime probes keep working regardless of configuration.
 */
export function apiAuth(): MiddlewareHandler<{ Bindings: Env }> {
  return async (c, next) => {
    const configuredToken = c.env.INDEXER_AUTH_TOKEN?.trim();
    const isAdminOnly = c.req.path === ADMIN_ONLY_PATH;

    if (!configuredToken) {
      if (isAdminOnly) {
        return c.json({ error: ERROR_MESSAGES.FORBIDDEN }, 403);
      }
      return next();
    }

    const provided = extractBearerToken(c.req.header("Authorization"));
    if (!provided || !timingSafeEqual(provided, configuredToken)) {
      return c.json({ error: ERROR_MESSAGES.UNAUTHORIZED }, 401);
    }

    return next();
  };
}
