/**
 * Launchtube Client
 *
 * Client for submitting transactions via Launchtube fee sponsoring service.
 * Launchtube allows users to submit Soroban transactions without paying fees
 * themselves - the fees are sponsored by the service.
 *
 * @see https://github.com/stellar/launchtube
 */

import type { Transaction } from "@stellar/stellar-sdk";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import type { LaunchtubeConfig } from "./types";

// Package version for client identification
const CLIENT_NAME = "smart-account-kit";
const CLIENT_VERSION = "0.2.1";

/**
 * Response from Launchtube transaction submission
 */
export interface LaunchtubeResponse {
  /** Whether the submission was successful */
  success: boolean;

  /** Transaction hash (if successful) */
  hash?: string;

  /** Fee-bump transaction XDR (if successful) */
  feeBumpTxXdr?: string;

  /** Error message (if failed) */
  error?: string;

  /** Error details from Launchtube */
  details?: unknown;
}

/**
 * Options for sending a transaction via Launchtube
 */
export interface LaunchtubeSendOptions {
  /**
   * Maximum fee to pay in stroops.
   * If not specified, Launchtube will determine the fee.
   */
  fee?: number;

  /**
   * Whether to let Launchtube handle simulation.
   * Default: true
   */
  simulate?: boolean;
}

/**
 * Launchtube client for fee-sponsored transaction submission.
 *
 * @example
 * ```typescript
 * const launchtube = new LaunchtubeClient({
 *   url: 'https://launchtube.xyz',
 *   jwt: 'your-jwt-token',
 * });
 *
 * // Submit a signed transaction
 * const result = await launchtube.send(signedTransaction);
 * if (result.success) {
 *   console.log('Transaction hash:', result.hash);
 * }
 * ```
 */
export class LaunchtubeClient {
  private readonly url: string;
  private readonly jwt?: string;
  private readonly headers: Record<string, string>;

  constructor(config: LaunchtubeConfig) {
    if (!config.url) {
      throw new Error("Launchtube URL is required");
    }

    // Use URL as provided, just remove trailing slashes
    this.url = config.url.replace(/\/+$/, "");
    this.jwt = config.jwt;
    this.headers = config.headers ?? {};
  }

  /**
   * Check if the client is properly configured
   */
  get isConfigured(): boolean {
    return !!this.url;
  }

  /**
   * Submit a transaction via Launchtube for fee sponsoring (v2 API).
   *
   * Launchtube wraps the transaction in a fee-bump and pays the fees.
   *
   * Signing requirements depend on the auth type:
   * - Address credentials: Only signed auth entries needed (no envelope signature)
   * - source_account credentials: Envelope signature required (preserved in fee bump)
   *
   * @param transaction - The transaction to submit
   * @param options - Optional submission options
   * @returns The submission result
   *
   * @example
   * ```typescript
   * // Submit a transaction with signed auth entries
   * const result = await launchtube.send(preparedTx);
   *
   * // Submit with custom fee limit
   * const result = await launchtube.send(preparedTx, { fee: 1000000 });
   * ```
   */
  async send(
    transaction: AssembledTransaction<unknown> | Transaction | string,
    options?: LaunchtubeSendOptions
  ): Promise<LaunchtubeResponse> {
    // Convert transaction to XDR string
    let xdr: string;

    if (typeof transaction === "string") {
      xdr = transaction;
    } else if ("built" in transaction && transaction.built) {
      // AssembledTransaction
      xdr = transaction.built.toXDR();
    } else if ("toXDR" in transaction) {
      // Transaction
      xdr = transaction.toXDR();
    } else {
      throw new Error("Invalid transaction format");
    }

    // Build form data for the request
    const formData = new FormData();
    formData.set("xdr", xdr);

    if (options?.fee !== undefined) {
      formData.set("fee", options.fee.toString());
    }

    if (options?.simulate === false) {
      formData.set("sim", "false");
    }

    // Build headers
    const headers: Record<string, string> = {
      "X-Client-Name": CLIENT_NAME,
      "X-Client-Version": CLIENT_VERSION,
      ...this.headers,
    };

    // Add JWT authorization if configured
    if (this.jwt) {
      headers["Authorization"] = `Bearer ${this.jwt}`;
    }

    try {
      const response = await fetch(this.url, {
        method: "POST",
        headers,
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        return {
          success: true,
          hash: data.hash,
          feeBumpTxXdr: data.tx,
        };
      }

      // Handle error response
      const errorData = await response.json().catch(() => ({}));
      return {
        success: false,
        error: errorData.message ?? `Launchtube request failed with status ${response.status}`,
        details: errorData,
      };
    } catch (err) {
      return {
        success: false,
        error: err instanceof Error ? err.message : "Launchtube request failed",
        details: err,
      };
    }
  }

  /**
   * Get the remaining credit balance for the configured JWT token.
   *
   * @returns Credit info or null if not available
   */
  async getInfo(): Promise<{ credits?: number } | null> {
    if (!this.jwt) {
      return null;
    }

    const headers: Record<string, string> = {
      "X-Client-Name": CLIENT_NAME,
      "X-Client-Version": CLIENT_VERSION,
      ...this.headers,
      Authorization: `Bearer ${this.jwt}`,
    };

    try {
      const response = await fetch(`${this.url}/info`, {
        method: "GET",
        headers,
      });

      if (response.ok) {
        return await response.json();
      }

      return null;
    } catch {
      return null;
    }
  }
}
