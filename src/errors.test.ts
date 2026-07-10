import { describe, expect, it } from "vitest";
import {
  SmartAccountError,
  SmartAccountErrorCode,
  WalletNotConnectedError,
  CredentialNotFoundError,
  SignerNotFoundError,
  PolicyNotFoundError,
  SimulationError,
  SubmissionError,
  ValidationError,
  WebAuthnError,
  SessionError,
  ContractError,
  wrapError,
} from "./errors";

describe("SmartAccountError", () => {
  it("carries code, context and cause", () => {
    const cause = new Error("boom");
    const err = new SmartAccountError("failed", SmartAccountErrorCode.INVALID_INPUT, {
      context: { a: 1 },
      cause,
    });
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe(SmartAccountErrorCode.INVALID_INPUT);
    expect(err.context).toEqual({ a: 1 });
    expect(err.cause).toBe(cause);
    expect(err.name).toBe("SmartAccountError");
  });

  it("formats a detailed string with code, context and cause", () => {
    const err = new SmartAccountError("bad", SmartAccountErrorCode.INVALID_AMOUNT, {
      context: { field: "amount" },
      cause: new Error("root"),
    });
    const s = err.toDetailedString();
    expect(s).toContain(`[${SmartAccountErrorCode.INVALID_AMOUNT}]`);
    expect(s).toContain("bad");
    expect(s).toContain("amount");
    expect(s).toContain("root");
  });
});

describe("error subclasses", () => {
  it("WalletNotConnectedError includes the operation", () => {
    const err = new WalletNotConnectedError("transfer");
    expect(err.code).toBe(SmartAccountErrorCode.WALLET_NOT_CONNECTED);
    expect(err.message).toContain("transfer");
    expect(err.name).toBe("WalletNotConnectedError");
  });

  it("CredentialNotFoundError includes the id", () => {
    const err = new CredentialNotFoundError("cred-1");
    expect(err.code).toBe(SmartAccountErrorCode.CREDENTIAL_NOT_FOUND);
    expect(err.message).toContain("cred-1");
  });

  it("SignerNotFoundError supports an optional hint", () => {
    expect(new SignerNotFoundError("G123").message).toBe("No signer found for: G123");
    expect(new SignerNotFoundError("G123", "add it first").message).toBe(
      "No signer found for: G123. add it first"
    );
  });

  it("PolicyNotFoundError distinguishes rule context", () => {
    expect(new PolicyNotFoundError("CPOL").message).toBe("Policy not found: CPOL");
    expect(new PolicyNotFoundError("CPOL", 3).message).toBe(
      "Policy CPOL not found on context rule 3"
    );
    expect(new PolicyNotFoundError("CPOL").code).toBe(SmartAccountErrorCode.POLICY_NOT_FOUND);
  });

  it("SimulationError / SubmissionError carry their codes and details", () => {
    expect(new SimulationError("sim").code).toBe(
      SmartAccountErrorCode.TRANSACTION_SIMULATION_FAILED
    );
    const sub = new SubmissionError("sub", "hash123", { extra: 1 });
    expect(sub.code).toBe(SmartAccountErrorCode.TRANSACTION_SUBMISSION_FAILED);
    expect(sub.context).toMatchObject({ hash: "hash123", extra: 1 });
  });

  it("ValidationError defaults to INVALID_INPUT", () => {
    expect(new ValidationError("x").code).toBe(SmartAccountErrorCode.INVALID_INPUT);
    expect(new ValidationError("x", SmartAccountErrorCode.MISSING_CONFIG).code).toBe(
      SmartAccountErrorCode.MISSING_CONFIG
    );
  });

  it("WebAuthnError carries the cause", () => {
    const cause = new Error("cancelled");
    const err = new WebAuthnError(
      "webauthn",
      SmartAccountErrorCode.WEBAUTHN_CANCELLED,
      cause
    );
    expect(err.cause).toBe(cause);
  });

  it("SessionError defaults to SESSION_INVALID", () => {
    expect(new SessionError("s").code).toBe(SmartAccountErrorCode.SESSION_INVALID);
  });

  it("ContractError carries the contract code, name and family", () => {
    const err = new ContractError(3010, "TooManySigners", "SmartAccount", "too many");
    expect(err.code).toBe(SmartAccountErrorCode.CONTRACT_ERROR);
    expect(err.contractCode).toBe(3010);
    expect(err.contractErrorName).toBe("TooManySigners");
    expect(err.family).toBe("SmartAccount");
    expect(err.context).toMatchObject({ contractCode: 3010, contractErrorName: "TooManySigners" });
  });
});

describe("wrapError", () => {
  it("returns SmartAccountErrors unchanged", () => {
    const err = new ValidationError("x");
    expect(wrapError(err)).toBe(err);
  });

  it("wraps a plain Error, preserving the message and cause", () => {
    const original = new Error("root cause");
    const wrapped = wrapError(original, SmartAccountErrorCode.TRANSACTION_SIGNING_FAILED);
    expect(wrapped).toBeInstanceOf(SmartAccountError);
    expect(wrapped.code).toBe(SmartAccountErrorCode.TRANSACTION_SIGNING_FAILED);
    expect(wrapped.message).toBe("root cause");
    expect(wrapped.cause).toBe(original);
  });

  it("wraps a non-Error value", () => {
    const wrapped = wrapError("string failure");
    expect(wrapped.message).toBe("string failure");
    expect(wrapped.cause).toBeUndefined();
  });
});
