import { Address, xdr } from "@stellar/stellar-sdk";
import type { Client as SmartAccountClient, Signer as ContractSigner } from "smart-account-kit-bindings";
import { SmartAccountErrorCode, ValidationError } from "../errors";
import type { PolicyConfig } from "../types";
import type {
  SimpleThresholdAccountParams,
  SpendingLimitAccountParams,
  WeightedThresholdAccountParams,
} from "../contract-types";
import { signerToScVal } from "./auth-payload";
import { buildI128ScVal } from "./tx-ops";

function symbolEntry(key: string, val: xdr.ScVal): xdr.ScMapEntry {
  return new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
}

function requireU32(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`${field} must be a u32`);
  }
  return value;
}

function requireI128(value: unknown, field: string): bigint {
  if (typeof value !== "bigint" && typeof value !== "number") {
    throw new Error(`${field} must be a bigint or number`);
  }
  return BigInt(value);
}

function encodeThresholdParams(params: unknown): xdr.ScVal {
  const { threshold } = params as SimpleThresholdAccountParams;
  return xdr.ScVal.scvMap([
    symbolEntry("threshold", xdr.ScVal.scvU32(requireU32(threshold, "threshold"))),
  ]);
}

function encodeSpendingLimitParams(params: unknown): xdr.ScVal {
  const { period_ledgers, spending_limit } = params as SpendingLimitAccountParams;
  // Struct field order (period_ledgers < spending_limit) is the canonical map order.
  return xdr.ScVal.scvMap([
    symbolEntry("period_ledgers", xdr.ScVal.scvU32(requireU32(period_ledgers, "period_ledgers"))),
    symbolEntry("spending_limit", buildI128ScVal(requireI128(spending_limit, "spending_limit"))),
  ]);
}

function encodeWeightedThresholdParams(params: unknown): xdr.ScVal {
  const { signer_weights, threshold } = params as WeightedThresholdAccountParams;
  if (!(signer_weights instanceof Map)) {
    throw new Error("signer_weights must be a Map<Signer, number>");
  }
  const weightEntries: xdr.ScMapEntry[] = [];
  for (const [signer, weight] of signer_weights) {
    weightEntries.push(
      new xdr.ScMapEntry({
        key: signerToScVal(signer as ContractSigner),
        val: xdr.ScVal.scvU32(requireU32(weight, "signer weight")),
      })
    );
  }
  // Signer (vector) keys sort by their canonical XDR encoding.
  weightEntries.sort((a, b) => a.key().toXDR("hex").localeCompare(b.key().toXDR("hex")));
  return xdr.ScVal.scvMap([
    symbolEntry("signer_weights", xdr.ScVal.scvMap(weightEntries)),
    symbolEntry("threshold", xdr.ScVal.scvU32(requireU32(threshold, "threshold"))),
  ]);
}

const POLICY_PARAM_ENCODERS: Record<
  "threshold" | "spending_limit" | "weighted_threshold",
  (params: unknown) => xdr.ScVal
> = {
  threshold: encodeThresholdParams,
  spending_limit: encodeSpendingLimitParams,
  weighted_threshold: encodeWeightedThresholdParams,
};

/**
 * Convert policy install params into the ScVal the contract expects.
 *
 * The three example policies' param structs are encoded directly (no embedded
 * base64 contract spec blobs). The output is byte-identical to the generated
 * spec's encoding — see policies-ops.test.ts.
 *
 * @throws {ValidationError} If the params don't match the expected shape
 */
export function convertPolicyParams(
  _wallet: SmartAccountClient | undefined,
  policyType: "threshold" | "spending_limit" | "weighted_threshold",
  params: unknown
): xdr.ScVal {
  try {
    return POLICY_PARAM_ENCODERS[policyType](params);
  } catch (error) {
    // Never silently fall back to unconverted params: shipping the wrong ScVal
    // shape on-chain is a correctness hazard. Surface a typed error instead.
    throw new ValidationError(
      `Failed to convert ${policyType} policy parameters into an ScVal. ` +
        `Check that the params match the expected shape.`,
      SmartAccountErrorCode.INVALID_INPUT,
      {
        policyType,
        cause: error instanceof Error ? error.message : String(error),
      }
    );
  }
}

/**
 * Convert a list of {@link PolicyConfig} into the `Map<Address, Val>` the smart
 * account `__constructor` expects.
 *
 * Known policy types are converted via {@link convertPolicyParams}; `"custom"`
 * (or omitted-type) policies must supply an `xdr.ScVal` directly.
 *
 * @throws {ValidationError} If a custom policy's installParams is not an ScVal
 */
export function buildConstructorPolicies(
  policies: PolicyConfig[]
): Map<string, xdr.ScVal> {
  const map = new Map<string, xdr.ScVal>();
  for (const policy of policies) {
    let scParams: xdr.ScVal;
    if (policy.type && policy.type !== "custom") {
      scParams = convertPolicyParams(undefined, policy.type, policy.installParams);
    } else if (policy.installParams instanceof xdr.ScVal) {
      scParams = policy.installParams;
    } else {
      throw new ValidationError(
        `Policy ${policy.address}: custom policies must provide installParams as an xdr.ScVal ` +
          `(or set a known 'type').`,
        SmartAccountErrorCode.INVALID_INPUT,
        { address: policy.address }
      );
    }
    map.set(policy.address, scParams);
  }
  return map;
}

export function buildPoliciesScVal(
  wallet: SmartAccountClient | undefined,
  policies: Map<string, unknown>,
  policyTypes: Map<string, "threshold" | "spending_limit" | "weighted_threshold" | "custom">
): xdr.ScVal {
  if (!wallet) {
    throw new Error("Wallet not connected");
  }

  const entries: xdr.ScMapEntry[] = [];

  for (const [address, params] of policies) {
    const scAddress = new Address(address).toScVal();

    const policyType = policyTypes.get(address);
    let scParams: xdr.ScVal;

    if (policyType && policyType !== "custom") {
      scParams = convertPolicyParams(wallet, policyType, params);
    } else {
      const walletObj = wallet as unknown as Record<string, unknown>;
      const spec = walletObj.spec as { nativeToScVal?: (val: unknown, type: xdr.ScSpecTypeDef) => xdr.ScVal } | undefined;
      if (spec && typeof spec.nativeToScVal === "function") {
        try {
          scParams = spec.nativeToScVal(params, xdr.ScSpecTypeDef.scSpecTypeVal());
        } catch {
          scParams = xdr.ScVal.scvVoid();
        }
      } else {
        scParams = xdr.ScVal.scvVoid();
      }
    }

    entries.push(new xdr.ScMapEntry({
      key: scAddress,
      val: scParams,
    }));
  }

  entries.sort((a, b) => {
    const aXdr = a.key().toXDR("hex");
    const bXdr = b.key().toXDR("hex");
    return aXdr.localeCompare(bXdr);
  });

  return xdr.ScVal.scvMap(entries);
}
