/**
 * Policy parameter helpers for the rule builder.
 *
 * - {@link signerEntryToContractSigner} / {@link encodePolicyInstallParam}
 *   dedupe the install-param construction that previously lived twice inside
 *   ContextRuleBuilder.executeSubmit.
 * - {@link readRulePolicyParams} reads live on-chain policy params via the SDK's
 *   typed policy clients (kit.policyClients.*), replacing the old hand-rolled
 *   getLedgerEntries + ScVal decoding.
 */
import type { SmartAccountKit } from "smart-account-kit";
import {
  createDelegatedSigner,
  createWebAuthnSigner,
  createEd25519Signer,
  createThresholdParams,
  createSpendingLimitParams,
  createWeightedThresholdParams,
  LEDGERS_PER_DAY,
} from "smart-account-kit";
import type { ContextRule, Signer } from "smart-account-kit-bindings";
import { STROOPS_PER_XLM } from "../../constants";
import type { KnownPolicy } from "../../config";
import {
  readSpendingLimitParams,
  readThresholdValue,
  readWeightedThresholdValue,
} from "../../utils/policyLiveParams";
import type { SelectedPolicy, SignerEntry } from "./types";

/**
 * Build the contract {@link Signer} object for a staged rule-builder entry.
 * Reuses the on-chain signer object when the entry already exists.
 */
export function signerEntryToContractSigner(
  entry: SignerEntry,
  webauthnVerifierAddress: string,
  ed25519VerifierAddress: string
): Signer | null {
  if (entry.signer) {
    return entry.signer;
  }
  if (entry.type === "delegated" && entry.address) {
    return createDelegatedSigner(entry.address);
  }
  if (entry.type === "passkey" && entry.publicKey && entry.credentialId) {
    return createWebAuthnSigner(
      webauthnVerifierAddress,
      entry.publicKey,
      entry.credentialId
    );
  }
  if (entry.type === "ed25519" && entry.publicKey) {
    return createEd25519Signer(
      entry.verifierAddress ?? ed25519VerifierAddress,
      entry.publicKey
    );
  }
  return null;
}

/** Build native (unencoded) policy params from a staged policy + signers. */
function buildNativePolicyParams(
  sp: SelectedPolicy,
  signers: SignerEntry[],
  webauthnVerifierAddress: string,
  ed25519VerifierAddress: string
): unknown {
  if (sp.policy.type === "threshold") {
    return createThresholdParams(sp.threshold || 1);
  }
  if (sp.policy.type === "spending_limit") {
    const limitStroops = BigInt(
      Math.floor(parseFloat(sp.spendingLimit || "1000") * STROOPS_PER_XLM)
    );
    const periodLedgers = (sp.spendingPeriodDays || 1) * LEDGERS_PER_DAY;
    return createSpendingLimitParams(limitStroops, periodLedgers);
  }
  if (sp.policy.type === "weighted_threshold") {
    const weights = new Map<Signer, number>();
    if (sp.signerWeights) {
      for (const entry of signers) {
        const weight = sp.signerWeights.get(entry.id);
        if (weight && weight > 0) {
          const signer = signerEntryToContractSigner(
            entry,
            webauthnVerifierAddress,
            ed25519VerifierAddress
          );
          if (signer) {
            weights.set(signer, weight);
          }
        }
      }
    }
    return createWeightedThresholdParams(sp.weightedThreshold || 1, weights);
  }
  // Custom policy - parse user-supplied JSON params
  try {
    return sp.customParams ? JSON.parse(sp.customParams) : {};
  } catch (error) {
    console.warn("Failed to parse custom policy params, using empty object:", error);
    return {};
  }
}

/**
 * Build the fully-encoded install param for a staged policy, ready to pass to
 * `kit.rules.add` / `kit.policies.add`. Known policy types are ScVal-encoded via
 * `kit.convertPolicyParams`; custom types pass their native params through.
 */
export function encodePolicyInstallParam(
  kit: SmartAccountKit,
  sp: SelectedPolicy,
  signers: SignerEntry[],
  webauthnVerifierAddress: string,
  ed25519VerifierAddress: string
): unknown {
  const native = buildNativePolicyParams(
    sp,
    signers,
    webauthnVerifierAddress,
    ed25519VerifierAddress
  );
  if (
    sp.policy.type === "threshold" ||
    sp.policy.type === "spending_limit" ||
    sp.policy.type === "weighted_threshold"
  ) {
    return kit.convertPolicyParams(sp.policy.type, native);
  }
  return native;
}

const DEFAULT_POLICY_FORM: Omit<SelectedPolicy, "policy"> = {
  threshold: 1,
  spendingLimit: "1000",
  spendingPeriodDays: 1,
  weightedThreshold: 1,
  signerWeights: new Map(),
  customParams: "{}",
};

/**
 * Load the policies on an existing rule with their live params, read via the
 * typed policy clients. Falls back to form defaults (marked `modified`) if a
 * getter fails or the policy type is unknown.
 */
export async function readRulePolicyParams(
  kit: SmartAccountKit,
  rule: ContextRule,
  knownPolicies: KnownPolicy[]
): Promise<SelectedPolicy[]> {
  const loaded: SelectedPolicy[] = [];

  for (const policyAddress of rule.policies) {
    const known = knownPolicies.find((p) => p.address === policyAddress);

    if (!known) {
      loaded.push({
        policy: {
          type: "custom",
          name: `Policy ${policyAddress.slice(0, 8)}...`,
          address: policyAddress,
        },
        customParams: "{}",
        modified: true,
      });
      continue;
    }

    try {
      if (known.type === "threshold") {
        const threshold = await readThresholdValue(kit, policyAddress, rule.id);
        loaded.push({
          ...DEFAULT_POLICY_FORM,
          policy: known,
          threshold,
          modified: false,
        });
      } else if (known.type === "spending_limit") {
        const { spendingLimitXlm, periodDays } = await readSpendingLimitParams(
          kit,
          policyAddress,
          rule.id
        );
        loaded.push({
          ...DEFAULT_POLICY_FORM,
          policy: known,
          spendingLimit: spendingLimitXlm.toString(),
          spendingPeriodDays: periodDays,
          modified: false,
        });
      } else if (known.type === "weighted_threshold") {
        const threshold = await readWeightedThresholdValue(kit, policyAddress, rule.id);
        loaded.push({
          ...DEFAULT_POLICY_FORM,
          policy: known,
          weightedThreshold: threshold,
          signerWeights: new Map(),
          modified: false,
        });
      } else {
        loaded.push({ ...DEFAULT_POLICY_FORM, policy: known, modified: false });
      }
    } catch (error) {
      console.warn(`Failed to read live params for ${known.type} policy:`, error);
      loaded.push({ ...DEFAULT_POLICY_FORM, policy: known, modified: true });
    }
  }

  return loaded;
}
