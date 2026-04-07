import { LEDGERS_PER_DAY } from "smart-account-kit";

export const DEFAULT_EXPIRATION_DAYS = 30;
export const DEFAULT_EXPIRATION_LEDGER_DELTA = DEFAULT_EXPIRATION_DAYS * LEDGERS_PER_DAY;

export function expirationDaysToLedgerDelta(days: number): number {
  const normalizedDays = Math.max(1, Math.trunc(days) || 1);
  return normalizedDays * LEDGERS_PER_DAY;
}

export function expirationLedgerDeltaToDays(ledgerDelta: number): number {
  return Math.max(1, Math.ceil(ledgerDelta / LEDGERS_PER_DAY));
}

export function absoluteValidUntilToLedgerDelta(validUntil: number, currentLedger: number): number {
  return Math.max(LEDGERS_PER_DAY, validUntil - currentLedger);
}
