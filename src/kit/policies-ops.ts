import { Address, xdr } from "@stellar/stellar-sdk";
import { Spec as ContractSpec } from "@stellar/stellar-sdk/contract";
import type { Client as SmartAccountClient } from "smart-account-kit-bindings";

const POLICY_UDT_SPECS = {
  threshold: {
    udtName: "SimpleThresholdAccountParams",
    spec: new ContractSpec([
      "AAAAAQAAADhJbnN0YWxsYXRpb24gcGFyYW1ldGVycyBmb3IgdGhlIHNpbXBsZSB0aHJlc2hvbGQgcG9saWN5LgAAAAAAAAAcU2ltcGxlVGhyZXNob2xkQWNjb3VudFBhcmFtcwAAAAEAAAA5VGhlIG1pbmltdW0gbnVtYmVyIG9mIHNpZ25lcnMgcmVxdWlyZWQgZm9yIGF1dGhvcml6YXRpb24uAAAAAAAACXRocmVzaG9sZAAAAAAAAAQ=",
    ]),
  },
  spending_limit: {
    udtName: "SpendingLimitAccountParams",
    spec: new ContractSpec([
      "AAAAAQAAADZJbnN0YWxsYXRpb24gcGFyYW1ldGVycyBmb3IgdGhlIHNwZW5kaW5nIGxpbWl0IHBvbGljeS4AAAAAAAAAAAAaU3BlbmRpbmdMaW1pdEFjY291bnRQYXJhbXMAAAAAAAIAAAA8VGhlIHBlcmlvZCBpbiBsZWRnZXJzIG92ZXIgd2hpY2ggdGhlIHNwZW5kaW5nIGxpbWl0IGFwcGxpZXMuAAAADnBlcmlvZF9sZWRnZXJzAAAAAAAEAAAATlRoZSBtYXhpbXVtIGFtb3VudCB0aGF0IGNhbiBiZSBzcGVudCB3aXRoaW4gdGhlIHNwZWNpZmllZCBwZXJpb2QgKGluCnN0cm9vcHMpLgAAAAAADnNwZW5kaW5nX2xpbWl0AAAAAAAL",
    ]),
  },
  weighted_threshold: {
    udtName: "WeightedThresholdAccountParams",
    spec: new ContractSpec([
      "AAAAAgAAAEJSZXByZXNlbnRzIGRpZmZlcmVudCB0eXBlcyBvZiBzaWduZXJzIGluIHRoZSBzbWFydCBhY2NvdW50IHN5c3RlbS4AAAAAAAAAAAAGU2lnbmVyAAAAAAACAAAAAQAAAD1BIGRlbGVnYXRlZCBzaWduZXIgdGhhdCB1c2VzIGJ1aWx0LWluIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24uAAAAAAAACURlbGVnYXRlZAAAAAAAAAEAAAATAAAAAQAAAHJBbiBleHRlcm5hbCBzaWduZXIgd2l0aCBjdXN0b20gdmVyaWZpY2F0aW9uIGxvZ2ljLgpDb250YWlucyB0aGUgdmVyaWZpZXIgY29udHJhY3QgYWRkcmVzcyBhbmQgdGhlIHB1YmxpYyBrZXkgZGF0YS4AAAAAAAhFeHRlcm5hbAAAAAIAAAATAAAADg==",
      "AAAAAQAAADpJbnN0YWxsYXRpb24gcGFyYW1ldGVycyBmb3IgdGhlIHdlaWdodGVkIHRocmVzaG9sZCBwb2xpY3kuAAAAAAAAAAAAHldlaWdodGVkVGhyZXNob2xkQWNjb3VudFBhcmFtcwAAAAAAAgAAAC9NYXBwaW5nIG9mIHNpZ25lcnMgdG8gdGhlaXIgcmVzcGVjdGl2ZSB3ZWlnaHRzLgAAAAAOc2lnbmVyX3dlaWdodHMAAAAAA+wAAAfQAAAABlNpZ25lcgAAAAAABAAAADRUaGUgbWluaW11bSB0b3RhbCB3ZWlnaHQgcmVxdWlyZWQgZm9yIGF1dGhvcml6YXRpb24uAAAACXRocmVzaG9sZAAAAAAAAAQ=",
    ]),
  },
} as const;

export function convertPolicyParams(
  _wallet: SmartAccountClient | undefined,
  policyType: "threshold" | "spending_limit" | "weighted_threshold",
  params: unknown
): unknown {
  const policySpec = POLICY_UDT_SPECS[policyType];

  try {
    const udtType = xdr.ScSpecTypeDef.scSpecTypeUdt(
      new xdr.ScSpecTypeUdt({ name: policySpec.udtName })
    );
    const scVal = policySpec.spec.nativeToScVal(params, udtType);
    if (scVal.switch().name === "scvMap" && scVal.map()) {
      scVal.map()?.sort((a, b) => {
        const aKey =
          a.key().switch().name === "scvSymbol" ? a.key().sym().toString() : a.key().toXDR("hex");
        const bKey =
          b.key().switch().name === "scvSymbol" ? b.key().sym().toString() : b.key().toXDR("hex");
        return aKey.localeCompare(bKey);
      });
    }
    return scVal;
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
