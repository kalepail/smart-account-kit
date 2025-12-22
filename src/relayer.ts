/**
 * Relayer Client
 *
 * Client for submitting transactions via a Relayer proxy service.
 * The proxy handles communication with OpenZeppelin Relayer Channels,
 * managing API keys and providing CORS support for browser clients.
 *
 * Two submission modes:
 * 1. `send(func, auth)` - For Address credentials. Relayer builds the tx envelope.
 * 2. `sendXdr(xdr)` - For signed transactions. Relayer fee-bumps the signed tx.
 *
 * @see https://docs.openzeppelin.com/relayer/1.3.x/plugins/channels
 */

import type { Transaction } from "@stellar/stellar-sdk";

// Package version for client identification
const CLIENT_NAME = "smart-account-kit";
const CLIENT_VERSION = "0.2.5";

/**
 * Response from Relayer transaction submission
 */
export interface RelayerResponse {
  /** Whether the submission was successful */
  success: boolean;

  /** Transaction ID from relayer (if successful) */
  transactionId?: string;

  /** Transaction hash (if successful) */
  hash?: string;

  /** Transaction status */
  status?: string;

  /** Error message (if failed) */
  error?: string;

  /** Error code from Relayer */
  errorCode?: string;

  /** Error details from Relayer */
  details?: unknown;
}

/**
 * Options for sending a transaction via Relayer
 */
export interface RelayerSendOptions {
  /**
   * Request timeout in milliseconds.
   * Default: 30000 (30 seconds)
   */
  timeout?: number;
}

/**
 * Error codes from Relayer service
 */
export const RelayerErrorCodes = {
  INVALID_PARAMS: "INVALID_PARAMS",
  INVALID_XDR: "INVALID_XDR",
  POOL_CAPACITY: "POOL_CAPACITY",
  SIMULATION_FAILED: "SIMULATION_FAILED",
  ONCHAIN_FAILED: "ONCHAIN_FAILED",
  INVALID_TIME_BOUNDS: "INVALID_TIME_BOUNDS",
  FEE_LIMIT_EXCEEDED: "FEE_LIMIT_EXCEEDED",
  UNAUTHORIZED: "UNAUTHORIZED",
} as const;

export type RelayerErrorCode = (typeof RelayerErrorCodes)[keyof typeof RelayerErrorCodes];

/**
 * Relayer client for fee-sponsored transaction submission via proxy.
 *
 * POSTs func + auth entries to the configured URL. The proxy handles
 * communication with OpenZeppelin Relayer Channels, managing API keys and CORS.
 *
 * @example
 * ```typescript
 * const relayer = new RelayerClient(
 *   'https://my-relayer-proxy.example.com'
 * );
 *
 * // Submit a transaction with func and auth entries
 * const result = await relayer.send(funcXdr, authXdrArray);
 * if (result.success) {
 *   console.log('Transaction hash:', result.hash);
 * }
 * ```
 */
export class RelayerClient {
  private readonly url: string;
  private readonly timeout: number;

  // Default timeout of 6 minutes to accommodate testnet retries (up to 5 min)
  // when Relayer channel accounts need funding after testnet reset.
  // Mainnet requests return quickly; this only affects max wait time.
  constructor(url: string, timeout = 360000) {
    if (!url) {
      throw new Error("Relayer URL is required");
    }

    this.url = url.replace(/\/+$/, "");
    this.timeout = timeout;
  }

  /**
   * Check if the client is properly configured
   */
  get isConfigured(): boolean {
    return !!this.url;
  }

  /**
   * Submit a transaction via Relayer for fee sponsoring.
   *
   * The Relayer builds the transaction envelope using channel accounts and pays the fees.
   * Transactions are submitted in parallel using a pool of channel accounts.
   *
   * @param func - Base64 encoded Soroban host function XDR
   * @param auth - Array of base64 encoded authorization entry XDRs
   * @param options - Optional submission options
   * @returns The submission result
   *
   * @example
   * ```typescript
   * // Extract func and auth from a prepared transaction
   * const funcXdr = hostFunc.toXDR('base64');
   * const authXdrs = authEntries.map(e => e.toXDR('base64'));
   *
   * const result = await relayer.send(funcXdr, authXdrs);
   *
   * if (result.success) {
   *   console.log('Hash:', result.hash);
   * } else {
   *   console.error('Error:', result.error, result.errorCode);
   * }
   * ```
   */
  async send(
    func: string,
    auth: string[],
    options?: RelayerSendOptions
  ): Promise<RelayerResponse> {
    // Build headers
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Client-Name": CLIENT_NAME,
      "X-Client-Version": CLIENT_VERSION,
    };

    // Build request body - always use func + auth, never xdr
    const body = JSON.stringify({ func, auth });

    try {
      // Create abort controller for timeout
      const controller = new AbortController();
      const timeout = options?.timeout ?? this.timeout;
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(this.url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const responseData = await response.json();

      // Handle successful response
      if (response.ok && responseData.success) {
        const data = responseData.data ?? responseData;
        return {
          success: true,
          transactionId: data.transactionId ?? undefined,
          hash: data.hash ?? undefined,
          status: data.status ?? undefined,
        };
      }

      // Handle error response
      const errorMessage = responseData.error ?? responseData.message ?? `Relayer request failed with status ${response.status}`;
      const errorCode = this.extractErrorCode(responseData);

      return {
        success: false,
        error: errorMessage,
        errorCode,
        details: responseData.data ?? responseData,
      };
    } catch (err) {
      // Handle network errors and timeouts
      if (err instanceof Error && err.name === "AbortError") {
        return {
          success: false,
          error: "Relayer request timed out",
          errorCode: "TIMEOUT",
        };
      }

      return {
        success: false,
        error: err instanceof Error ? err.message : "Relayer request failed",
        details: err,
      };
    }
  }

  /**
   * Submit a signed transaction for fee-bumping.
   *
   * Use this for transactions that require source_account auth (e.g., deployment).
   * The Relayer will fee-bump the signed transaction, preserving the inner signature.
   *
   * @param transaction - Signed transaction (Transaction object or XDR string)
   * @param options - Optional submission options
   * @returns The submission result
   *
   * @example
   * ```typescript
   * // Sign the deployment transaction
   * deployTx.sign(deployerKeypair);
   *
   * // Submit for fee-bumping
   * const result = await relayer.sendXdr(deployTx);
   * ```
   */
  async sendXdr(
    transaction: Transaction | string,
    options?: RelayerSendOptions
  ): Promise<RelayerResponse> {
    // Convert to XDR string
    const xdr = typeof transaction === "string"
      ? transaction
      : transaction.toXDR();

    // Build headers
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Client-Name": CLIENT_NAME,
      "X-Client-Version": CLIENT_VERSION,
    };

    // Build request body
    const body = JSON.stringify({ xdr });

    try {
      // Create abort controller for timeout
      const controller = new AbortController();
      const timeout = options?.timeout ?? this.timeout;
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(this.url, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const responseData = await response.json();

      // Handle successful response
      if (response.ok && responseData.success) {
        const data = responseData.data ?? responseData;
        return {
          success: true,
          transactionId: data.transactionId ?? undefined,
          hash: data.hash ?? undefined,
          status: data.status ?? undefined,
        };
      }

      // Handle error response
      const errorMessage = responseData.error ?? responseData.message ?? `Relayer request failed with status ${response.status}`;
      const errorCode = this.extractErrorCode(responseData);

      return {
        success: false,
        error: errorMessage,
        errorCode,
        details: responseData.data ?? responseData,
      };
    } catch (err) {
      // Handle network errors and timeouts
      if (err instanceof Error && err.name === "AbortError") {
        return {
          success: false,
          error: "Relayer request timed out",
          errorCode: "TIMEOUT",
        };
      }

      return {
        success: false,
        error: err instanceof Error ? err.message : "Relayer request failed",
        details: err,
      };
    }
  }

  /**
   * Extract error code from Relayer response
   */
  private extractErrorCode(responseData: unknown): RelayerErrorCode | string | undefined {
    if (!responseData || typeof responseData !== "object") {
      return undefined;
    }

    const data = responseData as Record<string, unknown>;

    // Check common error code locations
    if (typeof data.code === "string") {
      return data.code;
    }
    if (typeof data.errorCode === "string") {
      return data.errorCode;
    }
    if (data.data && typeof data.data === "object") {
      const nestedData = data.data as Record<string, unknown>;
      if (typeof nestedData.code === "string") {
        return nestedData.code;
      }
    }

    return undefined;
  }
}
