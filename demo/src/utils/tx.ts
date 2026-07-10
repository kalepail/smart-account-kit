import type { TransactionResult } from "smart-account-kit";

/**
 * The demo's simplified submission result. The SDK returns a discriminated
 * {@link TransactionResult} union where the failure member carries a typed
 * {@link SmartAccountError}; the UI only ever needs a boolean + a message.
 */
export interface SimpleTxResult {
  success: boolean;
  error?: string;
}

/**
 * Human-readable message for a failed {@link TransactionResult}. Returns an
 * empty string for successful results.
 */
export function txErrorMessage(
  result: TransactionResult,
  fallback = "Transaction failed"
): string {
  return result.success ? "" : result.error?.message ?? fallback;
}

/**
 * Normalize an SDK {@link TransactionResult} into the demo's simple shape so UI
 * code can branch on `success` and surface `error` as a string.
 */
export function toSimpleResult(result: TransactionResult): SimpleTxResult {
  return result.success
    ? { success: true }
    : { success: false, error: result.error?.message };
}
