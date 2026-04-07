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
import { convertPolicyParams } from "./policies-ops";

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
});
