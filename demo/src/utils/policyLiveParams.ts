/**
 * Shared readers for live on-chain policy params via the SDK's typed policy
 * clients (`kit.policyClients.*`).
 *
 * PolicyInspector (manage panel) and the rule-builder's readRulePolicyParams
 * previously each hand-rolled the same per-policy-type reads + unit conversions
 * (stroops→XLM, ledgers→days). This module is the single source of that logic so
 * the two views can't drift.
 */
import type { SmartAccountKit } from "smart-account-kit";
import { LEDGERS_PER_DAY } from "smart-account-kit";
import type { ContextRule, Signer } from "smart-account-kit-bindings";
import { STROOPS_PER_XLM } from "../constants";

/** Read a simple-threshold policy's required threshold for a rule. */
export function readThresholdValue(
  kit: SmartAccountKit,
  policyAddress: string,
  ruleId: number
): Promise<number> {
  return kit.policyClients.threshold(policyAddress).getThreshold(ruleId);
}

/** Read a weighted-threshold policy's required total weight for a rule. */
export function readWeightedThresholdValue(
  kit: SmartAccountKit,
  policyAddress: string,
  ruleId: number
): Promise<number> {
  return kit.policyClients.weighted(policyAddress).getThreshold(ruleId);
}

/** Live per-signer weight read from a weighted-threshold policy. */
export interface LiveSignerWeight {
  signer: Signer;
  weight: number;
}

/** Read a weighted-threshold policy's per-signer weights for a rule. */
export async function readWeightedSignerWeights(
  kit: SmartAccountKit,
  policyAddress: string,
  rule: ContextRule
): Promise<LiveSignerWeight[]> {
  const weightMap = await kit.policyClients.weighted(policyAddress).getSignerWeights(rule);
  return [...weightMap.entries()].map(([signer, weight]) => ({ signer, weight }));
}

/** Live spending-limit params, converted to display units (XLM / days). */
export interface LiveSpendingLimit {
  spendingLimitXlm: number;
  periodDays: number;
  totalSpentXlm: number;
}

/**
 * Read a spending-limit policy's data for a rule and convert it to display
 * units: stroops → XLM and period ledgers → whole days (min 1).
 */
export async function readSpendingLimitParams(
  kit: SmartAccountKit,
  policyAddress: string,
  ruleId: number
): Promise<LiveSpendingLimit> {
  const data = await kit.policyClients.spendingLimit(policyAddress).getSpendingLimitData(ruleId);
  return {
    spendingLimitXlm: Number(data.spending_limit) / STROOPS_PER_XLM,
    periodDays: Math.round(Number(data.period_ledgers) / LEDGERS_PER_DAY) || 1,
    totalSpentXlm: Number(data.cached_total_spent) / STROOPS_PER_XLM,
  };
}
