import { describe, expect, it } from "vitest";
import { xdr } from "@stellar/stellar-sdk";
import { Client as SmartAccountClient } from "smart-account-kit-bindings";
import {
  createDefaultContext,
  createSpendingLimitParams,
  createThresholdParams,
  createWebAuthnSigner,
  createWeightedThresholdParams,
} from "../builders";
import { buildConstructorPolicies, convertPolicyParams } from "./policies-ops";
import { ValidationError } from "../errors";

function makeClient() {
  return new SmartAccountClient({
    contractId: "CCWODDOZPWGUCYXFKFQTCBVU2USQ75Q3V7XWPARAXTL56WP723PRMB7B",
    rpcUrl: "https://soroban-testnet.stellar.org",
    networkPassphrase: "Test SDF Network ; September 2015",
  });
}

function makePasskeySigner() {
  return createWebAuthnSigner(
    "CCMR63YE5T7MPWREF3PC5XNTTGXFSB4GYUGUIT5POHP2UGCS65TBIUUU",
    Uint8Array.from([4, ...new Array(64).fill(1)]),
    "cred123"
  );
}

describe("convertPolicyParams", () => {
  it("encodes threshold params for add_policy", () => {
    const client = makeClient();
    const params = convertPolicyParams(client, "threshold", createThresholdParams(1));

    expect(params).toBeInstanceOf(xdr.ScVal);
    expect(() =>
      client.spec.funcArgsToScVals("add_policy", {
        context_rule_id: 0,
        policy: "CB2WQXF2XXDGUV2CTVQ23RLN3ESI3IY5KKX3KVXWBNRTTWDHZM76NVKJ",
        install_param: params,
      })
    ).not.toThrow();
  });

  it("encodes spending-limit params for add_policy", () => {
    const client = makeClient();
    const params = convertPolicyParams(
      client,
      "spending_limit",
      createSpendingLimitParams(1_000_000n, 100)
    );

    expect(params).toBeInstanceOf(xdr.ScVal);
    expect(() =>
      client.spec.funcArgsToScVals("add_policy", {
        context_rule_id: 0,
        policy: "CBBZ2XP4LBDEO2EELTZKJSPQZDREFKCULL6CKIUQO53S42RZABOYQUK3",
        install_param: params,
      })
    ).not.toThrow();
  });

  it("encodes weighted-threshold params for add_context_rule", () => {
    const client = makeClient();
    const signer = makePasskeySigner();
    const weights = new Map([[signer, 1]]);
    const params = convertPolicyParams(
      client,
      "weighted_threshold",
      createWeightedThresholdParams(1, weights)
    );

    expect(params).toBeInstanceOf(xdr.ScVal);
    expect(() =>
      client.spec.funcArgsToScVals("add_context_rule", {
        context_type: createDefaultContext(),
        name: "Weighted Rule",
        valid_until: undefined,
        signers: [signer],
        policies: new Map([
          ["CCF65VXVORNOZBRR3EG3GZYSFS3ALDG44CDYN5T5KRWKYX6RXLKLXER4", params],
        ]),
      })
    ).not.toThrow();
  });

  it("throws a ValidationError instead of silently returning unconverted params", () => {
    const client = makeClient();
    // A threshold param shape that cannot be encoded as the UDT.
    expect(() =>
      convertPolicyParams(client, "threshold", { not_a_threshold: "nope" })
    ).toThrow(ValidationError);
  });
});

describe("buildConstructorPolicies", () => {
  const POLICY_A = "CB2WQXF2XXDGUV2CTVQ23RLN3ESI3IY5KKX3KVXWBNRTTWDHZM76NVKJ";
  const POLICY_B = "CBBZ2XP4LBDEO2EELTZKJSPQZDREFKCULL6CKIUQO53S42RZABOYQUK3";

  it("converts known policy types into a Map<Address, ScVal>", () => {
    const map = buildConstructorPolicies([
      { address: POLICY_A, type: "threshold", installParams: createThresholdParams(1) },
      {
        address: POLICY_B,
        type: "spending_limit",
        installParams: createSpendingLimitParams(1_000_000n, 100),
      },
    ]);

    expect(map.size).toBe(2);
    expect(map.get(POLICY_A)).toBeInstanceOf(xdr.ScVal);
    expect(map.get(POLICY_B)).toBeInstanceOf(xdr.ScVal);
  });

  it("passes through an xdr.ScVal for custom policies", () => {
    const custom = xdr.ScVal.scvVoid();
    const map = buildConstructorPolicies([
      { address: POLICY_A, type: "custom", installParams: custom },
    ]);
    expect(map.get(POLICY_A)).toBe(custom);
  });

  it("throws for a custom policy whose installParams is not an ScVal", () => {
    expect(() =>
      buildConstructorPolicies([
        { address: POLICY_A, type: "custom", installParams: { foo: 1 } },
      ])
    ).toThrow(ValidationError);
  });

  it("returns an empty map for no policies", () => {
    expect(buildConstructorPolicies([]).size).toBe(0);
  });
});
