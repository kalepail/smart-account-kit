import { Address, xdr } from "@stellar/stellar-sdk";
import type { Client as SmartAccountClient } from "smart-account-kit-bindings";

export function convertPolicyParams(
  wallet: SmartAccountClient | undefined,
  policyType: "threshold" | "spending_limit" | "weighted_threshold",
  params: unknown
): unknown {
  if (!wallet) {
    return params;
  }

  const udtNames: Record<string, string> = {
    threshold: "SimpleThresholdAccountParams",
    spending_limit: "SpendingLimitAccountParams",
    weighted_threshold: "WeightedThresholdAccountParams",
  };

  const udtName = udtNames[policyType];
  if (!udtName) {
    return params;
  }

  try {
    const udtType = xdr.ScSpecTypeDef.scSpecTypeUdt(
      new xdr.ScSpecTypeUdt({ name: udtName })
    );

    const walletObj = wallet as unknown as Record<string, unknown>;
    const spec = walletObj.spec as { nativeToScVal?: (val: unknown, type: xdr.ScSpecTypeDef) => xdr.ScVal } | undefined;
    if (spec && typeof spec.nativeToScVal === "function") {
      const scVal = spec.nativeToScVal(params, udtType);
      if (scVal.switch().name === "scvMap" && scVal.map()) {
        scVal.map()?.sort((a, b) => {
          const aKey = a.key().switch().name === "scvSymbol" ? a.key().sym().toString() : a.key().toXDR("hex");
          const bKey = b.key().switch().name === "scvSymbol" ? b.key().sym().toString() : b.key().toXDR("hex");
          return aKey.localeCompare(bKey);
        });
      }
      return scVal;
    }
    return params;
  } catch (error) {
    console.warn("[SmartAccountKit] Failed to convert policy params to ScVal:", error);
    return params;
  }
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
      const converted = convertPolicyParams(wallet, policyType, params);
      scParams = converted instanceof xdr.ScVal ? converted : xdr.ScVal.scvVoid();
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
