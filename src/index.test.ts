import { describe, expect, it } from "vitest";
import * as sdk from "./index";

describe("package root exports", () => {
  it("preserves the compatibility helper exports", () => {
    expect(typeof sdk.validateAddress).toBe("function");
    expect(typeof sdk.validateAmount).toBe("function");
    expect(typeof sdk.validateNotEmpty).toBe("function");
    expect(typeof sdk.xlmToStroops).toBe("function");
    expect(typeof sdk.stroopsToXlm).toBe("function");
    expect(typeof sdk.truncateAddress).toBe("function");
    expect(typeof sdk.describeSignerType).toBe("function");
    expect(typeof sdk.signerMatchesCredential).toBe("function");
    expect(typeof sdk.signerMatchesAddress).toBe("function");
    expect(typeof sdk.formatSignerForDisplay).toBe("function");
    expect(typeof sdk.formatContextType).toBe("function");
    expect(typeof sdk.getCredentialIdFromSigner).toBe("function");
    expect(typeof sdk.signersEqual).toBe("function");
    expect(typeof sdk.getSignerKey).toBe("function");
    expect(typeof sdk.collectUniqueSigners).toBe("function");
  });
});
