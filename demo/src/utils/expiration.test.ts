import { describe, expect, it } from "vitest";
import { LEDGERS_PER_DAY } from "smart-account-kit";
import {
  absoluteValidUntilToLedgerDelta,
  DEFAULT_EXPIRATION_DAYS,
  DEFAULT_EXPIRATION_LEDGER_DELTA,
  expirationDaysToLedgerDelta,
  expirationLedgerDeltaToDays,
} from "./expiration";

describe("expiration helpers", () => {
  it("converts days to a positive ledger delta", () => {
    expect(expirationDaysToLedgerDelta(2)).toBe(2 * LEDGERS_PER_DAY);
    expect(expirationDaysToLedgerDelta(0)).toBe(LEDGERS_PER_DAY);
  });

  it("converts ledger deltas back to whole-day values", () => {
    expect(expirationLedgerDeltaToDays(LEDGERS_PER_DAY)).toBe(1);
    expect(expirationLedgerDeltaToDays((2 * LEDGERS_PER_DAY) - 1)).toBe(2);
  });

  it("normalizes absolute valid_until values against the current ledger", () => {
    expect(absoluteValidUntilToLedgerDelta(2_000_000, 1_900_000)).toBe(100_000);
    expect(absoluteValidUntilToLedgerDelta(1_800_000, 1_900_000)).toBe(LEDGERS_PER_DAY);
  });

  it("keeps the default expiration aligned with the default day count", () => {
    expect(DEFAULT_EXPIRATION_LEDGER_DELTA).toBe(DEFAULT_EXPIRATION_DAYS * LEDGERS_PER_DAY);
  });
});
