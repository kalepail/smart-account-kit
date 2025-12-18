/**
 * Custom error classes for the Smart Account Kit SDK.
 *
 * These provide structured error handling with error codes and context.
 *
 * @packageDocumentation
 */

/**
 * Error codes for Smart Account Kit operations.
 */
export enum SmartAccountErrorCode {
  // Configuration errors (1xxx)
  INVALID_CONFIG = 1001,
  MISSING_CONFIG = 1002,

  // Wallet state errors (2xxx)
  WALLET_NOT_CONNECTED = 2001,
  WALLET_ALREADY_EXISTS = 2002,
  WALLET_NOT_FOUND = 2003,

  // Credential errors (3xxx)
  CREDENTIAL_NOT_FOUND = 3001,
  CREDENTIAL_ALREADY_EXISTS = 3002,
  CREDENTIAL_INVALID = 3003,
  CREDENTIAL_DEPLOYMENT_FAILED = 3004,

  // WebAuthn errors (4xxx)
  WEBAUTHN_REGISTRATION_FAILED = 4001,
  WEBAUTHN_AUTHENTICATION_FAILED = 4002,
  WEBAUTHN_NOT_SUPPORTED = 4003,
  WEBAUTHN_CANCELLED = 4004,

  // Transaction errors (5xxx)
  TRANSACTION_SIMULATION_FAILED = 5001,
  TRANSACTION_SIGNING_FAILED = 5002,
  TRANSACTION_SUBMISSION_FAILED = 5003,
  TRANSACTION_TIMEOUT = 5004,

  // Signer errors (6xxx)
  SIGNER_NOT_FOUND = 6001,
  SIGNER_INVALID = 6002,

  // Validation errors (7xxx)
  INVALID_ADDRESS = 7001,
  INVALID_AMOUNT = 7002,
  INVALID_INPUT = 7003,

  // Storage errors (8xxx)
  STORAGE_READ_FAILED = 8001,
  STORAGE_WRITE_FAILED = 8002,

  // Session errors (9xxx)
  SESSION_EXPIRED = 9001,
  SESSION_INVALID = 9002,
}

/**
 * Base error class for all Smart Account Kit errors.
 */
export class SmartAccountError extends Error {
  /** Error code for programmatic error handling */
  readonly code: SmartAccountErrorCode;

  /** Additional context about the error */
  readonly context?: Record<string, unknown>;

  /** Original error that caused this error */
  readonly cause?: Error;

  constructor(
    message: string,
    code: SmartAccountErrorCode,
    options?: {
      context?: Record<string, unknown>;
      cause?: Error;
    }
  ) {
    super(message);
    this.name = "SmartAccountError";
    this.code = code;
    this.context = options?.context;
    this.cause = options?.cause;

    // Maintain proper stack trace in V8 environments
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SmartAccountError);
    }
  }

  /**
   * Create a formatted error message with code and context.
   */
  toDetailedString(): string {
    let msg = `[${this.code}] ${this.message}`;
    if (this.context) {
      msg += `\nContext: ${JSON.stringify(this.context, null, 2)}`;
    }
    if (this.cause) {
      msg += `\nCaused by: ${this.cause.message}`;
    }
    return msg;
  }
}

/**
 * Error thrown when wallet is not connected but operation requires it.
 */
export class WalletNotConnectedError extends SmartAccountError {
  constructor(operation?: string) {
    super(
      operation
        ? `Wallet must be connected to ${operation}`
        : "Wallet not connected",
      SmartAccountErrorCode.WALLET_NOT_CONNECTED,
      { context: operation ? { operation } : undefined }
    );
    this.name = "WalletNotConnectedError";
  }
}

/**
 * Error thrown when a credential cannot be found.
 */
export class CredentialNotFoundError extends SmartAccountError {
  constructor(credentialId: string) {
    super(
      `Credential not found: ${credentialId}`,
      SmartAccountErrorCode.CREDENTIAL_NOT_FOUND,
      { context: { credentialId } }
    );
    this.name = "CredentialNotFoundError";
  }
}

/**
 * Error thrown when a signer cannot be found.
 */
export class SignerNotFoundError extends SmartAccountError {
  constructor(identifier: string) {
    super(
      `No signer found for: ${identifier}`,
      SmartAccountErrorCode.SIGNER_NOT_FOUND,
      { context: { identifier } }
    );
    this.name = "SignerNotFoundError";
  }
}

/**
 * Error thrown when transaction simulation fails.
 */
export class SimulationError extends SmartAccountError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, SmartAccountErrorCode.TRANSACTION_SIMULATION_FAILED, {
      context: details,
    });
    this.name = "SimulationError";
  }
}

/**
 * Error thrown when transaction submission fails.
 */
export class SubmissionError extends SmartAccountError {
  constructor(message: string, hash?: string, details?: Record<string, unknown>) {
    super(message, SmartAccountErrorCode.TRANSACTION_SUBMISSION_FAILED, {
      context: { hash, ...details },
    });
    this.name = "SubmissionError";
  }
}

/**
 * Error thrown when input validation fails.
 */
export class ValidationError extends SmartAccountError {
  constructor(
    message: string,
    code:
      | SmartAccountErrorCode.INVALID_ADDRESS
      | SmartAccountErrorCode.INVALID_AMOUNT
      | SmartAccountErrorCode.INVALID_INPUT = SmartAccountErrorCode.INVALID_INPUT,
    context?: Record<string, unknown>
  ) {
    super(message, code, { context });
    this.name = "ValidationError";
  }
}

/**
 * Error thrown when WebAuthn operations fail.
 */
export class WebAuthnError extends SmartAccountError {
  constructor(
    message: string,
    code:
      | SmartAccountErrorCode.WEBAUTHN_REGISTRATION_FAILED
      | SmartAccountErrorCode.WEBAUTHN_AUTHENTICATION_FAILED
      | SmartAccountErrorCode.WEBAUTHN_NOT_SUPPORTED
      | SmartAccountErrorCode.WEBAUTHN_CANCELLED,
    cause?: Error
  ) {
    super(message, code, { cause });
    this.name = "WebAuthnError";
  }
}

/**
 * Error thrown when session is expired or invalid.
 */
export class SessionError extends SmartAccountError {
  constructor(
    message: string,
    code:
      | SmartAccountErrorCode.SESSION_EXPIRED
      | SmartAccountErrorCode.SESSION_INVALID = SmartAccountErrorCode.SESSION_INVALID
  ) {
    super(message, code);
    this.name = "SessionError";
  }
}

/**
 * Helper to wrap unknown errors in SmartAccountError.
 */
export function wrapError(
  err: unknown,
  defaultCode: SmartAccountErrorCode = SmartAccountErrorCode.INVALID_INPUT
): SmartAccountError {
  if (err instanceof SmartAccountError) {
    return err;
  }

  const message = err instanceof Error ? err.message : String(err);
  const cause = err instanceof Error ? err : undefined;

  return new SmartAccountError(message, defaultCode, { cause });
}
