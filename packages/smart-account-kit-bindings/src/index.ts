import { Buffer } from "buffer";
import { Address } from "@stellar/stellar-sdk";
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  MethodOptions,
  Result,
  Spec as ContractSpec,
} from "@stellar/stellar-sdk/contract";
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Timepoint,
  Duration,
} from "@stellar/stellar-sdk/contract";
export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";

if (typeof window !== "undefined") {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}









/**
 * Error codes for smart account operations.
 */
export const SmartAccountError = {
  /**
   * The specified context rule does not exist.
   */
  3000: {message:"ContextRuleNotFound"},
  /**
   * A duplicate context rule already exists.
   */
  3001: {message:"DuplicateContextRule"},
  /**
   * The provided context cannot be validated against any rule.
   */
  3002: {message:"UnvalidatedContext"},
  /**
   * External signature verification failed.
   */
  3003: {message:"ExternalVerificationFailed"},
  /**
   * Context rule must have at least one signer or policy.
   */
  3004: {message:"NoSignersAndPolicies"},
  /**
   * The valid_until timestamp is in the past.
   */
  3005: {message:"PastValidUntil"},
  /**
   * The specified signer was not found.
   */
  3006: {message:"SignerNotFound"},
  /**
   * The signer already exists in the context rule.
   */
  3007: {message:"DuplicateSigner"},
  /**
   * The specified policy was not found.
   */
  3008: {message:"PolicyNotFound"},
  /**
   * The policy already exists in the context rule.
   */
  3009: {message:"DuplicatePolicy"},
  /**
   * Too many signers in the context rule.
   */
  3010: {message:"TooManySigners"},
  /**
   * Too many policies in the context rule.
   */
  3011: {message:"TooManyPolicies"},
  /**
   * Too many context rules in the smart account.
   */
  3012: {message:"TooManyContextRules"}
}




/**
 * Metadata for a context rule.
 */
export interface Meta {
  /**
 * The type of context this rule applies to.
 */
context_type: ContextRuleType;
  /**
 * Human-readable name for the context rule.
 */
name: string;
  /**
 * Optional expiration ledger sequence for the rule.
 */
valid_until: Option<u32>;
}

/**
 * Represents different types of signers in the smart account system.
 */
export type Signer = {tag: "Delegated", values: readonly [string]} | {tag: "External", values: readonly [string, Buffer]};

/**
 * A collection of signatures mapped to their respective signers.
 */
export type Signatures = readonly [Map<Signer, Buffer>];


/**
 * A complete context rule defining authorization requirements.
 */
export interface ContextRule {
  /**
 * The type of context this rule applies to.
 */
context_type: ContextRuleType;
  /**
 * Unique identifier for the context rule.
 */
id: u32;
  /**
 * Human-readable name for the context rule.
 */
name: string;
  /**
 * List of policy contracts that must be satisfied.
 */
policies: Array<string>;
  /**
 * List of signers authorized by this rule.
 */
signers: Array<Signer>;
  /**
 * Optional expiration ledger sequence for the rule.
 */
valid_until: Option<u32>;
}

/**
 * Types of contexts that can be authorized by smart account rules.
 */
export type ContextRuleType = {tag: "Default", values: void} | {tag: "CallContract", values: readonly [string]} | {tag: "CreateContract", values: readonly [Buffer]};

/**
 * Storage keys for smart account data.
 */
export type SmartAccountStorageKey = {tag: "Signers", values: readonly [u32]} | {tag: "Policies", values: readonly [u32]} | {tag: "Ids", values: readonly [ContextRuleType]} | {tag: "Meta", values: readonly [u32]} | {tag: "NextId", values: void} | {tag: "Fingerprint", values: readonly [Buffer]} | {tag: "Count", values: void};


/**
 * Individual spending entry for tracking purposes.
 */
export interface SpendingEntry {
  /**
 * The amount spent in this transaction.
 */
amount: i128;
  /**
 * The ledger sequence when this transaction occurred.
 */
ledger_sequence: u32;
}


/**
 * Internal storage structure for spending limit tracking.
 */
export interface SpendingLimitData {
  /**
 * Cached total of all amounts in spending_history.
 */
cached_total_spent: i128;
  /**
 * The period in ledgers over which the spending limit applies.
 */
period_ledgers: u32;
  /**
 * History of spending transactions with their ledger sequences.
 */
spending_history: Array<SpendingEntry>;
  /**
 * The spending limit for the period.
 */
spending_limit: i128;
}

/**
 * Error codes for spending limit policy operations.
 */
export const SpendingLimitError = {
  /**
   * The smart account does not have a spending limit policy installed.
   */
  3220: {message:"SmartAccountNotInstalled"},
  /**
   * The spending limit has been exceeded.
   */
  3221: {message:"SpendingLimitExceeded"},
  /**
   * The spending limit or period is invalid.
   */
  3222: {message:"InvalidLimitOrPeriod"},
  /**
   * The transaction is not allowed by this policy.
   */
  3223: {message:"NotAllowed"},
  /**
   * The spending history has reached maximum capacity.
   */
  3224: {message:"HistoryCapacityExceeded"}
}

/**
 * Storage keys for spending limit policy data.
 */
export type SpendingLimitStorageKey = {tag: "AccountContext", values: readonly [string, u32]};


/**
 * Installation parameters for the spending limit policy.
 */
export interface SpendingLimitAccountParams {
  /**
 * The period in ledgers over which the spending limit applies.
 */
period_ledgers: u32;
  /**
 * The maximum amount that can be spent within the specified period (in
 * stroops).
 */
spending_limit: i128;
}


/**
 * Error codes for simple threshold policy operations.
 */
export const SimpleThresholdError = {
  /**
   * The smart account does not have a simple threshold policy installed.
   */
  3200: {message:"SmartAccountNotInstalled"},
  /**
   * When threshold is 0 or exceeds the number of available signers.
   */
  3201: {message:"InvalidThreshold"},
  /**
   * The transaction is not allowed by this policy.
   */
  3202: {message:"NotAllowed"}
}


/**
 * Storage keys for simple threshold policy data.
 */
export type SimpleThresholdStorageKey = {tag: "AccountContext", values: readonly [string, u32]};


/**
 * Installation parameters for the simple threshold policy.
 */
export interface SimpleThresholdAccountParams {
  /**
 * The minimum number of signers required for authorization.
 */
threshold: u32;
}

/**
 * Error codes for weighted threshold policy operations.
 */
export const WeightedThresholdError = {
  /**
   * The smart account does not have a weighted threshold policy installed.
   */
  3210: {message:"SmartAccountNotInstalled"},
  /**
   * The threshold value is invalid.
   */
  3211: {message:"InvalidThreshold"},
  /**
   * A mathematical operation would overflow.
   */
  3212: {message:"MathOverflow"},
  /**
   * The transaction is not allowed by this policy.
   */
  3213: {message:"NotAllowed"}
}


/**
 * Storage keys for weighted threshold policy data.
 */
export type WeightedThresholdStorageKey = {tag: "AccountContext", values: readonly [string, u32]};


/**
 * Installation parameters for the weighted threshold policy.
 */
export interface WeightedThresholdAccountParams {
  /**
 * Mapping of signers to their respective weights.
 */
signer_weights: Map<Signer, u32>;
  /**
 * The minimum total weight required for authorization.
 */
threshold: u32;
}

/**
 * Error types for WebAuthn verification operations.
 */
export const WebAuthnError = {
  /**
   * The signature payload is invalid or has incorrect format.
   */
  3110: {message:"SignaturePayloadInvalid"},
  /**
   * The client data exceeds the maximum allowed length.
   */
  3111: {message:"ClientDataTooLong"},
  /**
   * Failed to parse JSON from client data.
   */
  3112: {message:"JsonParseError"},
  /**
   * The type field in client data is not "webauthn.get".
   */
  3113: {message:"TypeFieldInvalid"},
  /**
   * The challenge in client data does not match expected value.
   */
  3114: {message:"ChallengeInvalid"},
  /**
   * The authenticator data format is invalid or too short.
   */
  3115: {message:"AuthDataFormatInvalid"},
  /**
   * The User Present (UP) bit is not set in authenticator flags.
   */
  3116: {message:"PresentBitNotSet"},
  /**
   * The User Verified (UV) bit is not set in authenticator flags.
   */
  3117: {message:"VerifiedBitNotSet"},
  /**
   * Invalid relationship between Backup Eligibility and State bits.
   */
  3118: {message:"BackupEligibilityAndStateNotSet"}
}


/**
 * WebAuthn signature data structure containing all components needed for
 * verification.
 * 
 * This structure encapsulates the signature and associated data generated
 * during a WebAuthn authentication ceremony.
 */
export interface WebAuthnSigData {
  /**
 * Raw authenticator data from the WebAuthn response.
 */
authenticator_data: Buffer;
  /**
 * Raw client data JSON from the WebAuthn response.
 */
client_data: Buffer;
  /**
 * The cryptographic signature (64 bytes for secp256r1).
 */
signature: Buffer;
}

export const UpgradeableError = {
  /**
   * When migration is attempted but not allowed due to upgrade state.
   */
  1100: {message:"MigrationNotAllowed"}
}



export const MerkleDistributorError = {
  /**
   * The merkle root is not set.
   */
  1300: {message:"RootNotSet"},
  /**
   * The provided index was already claimed.
   */
  1301: {message:"IndexAlreadyClaimed"},
  /**
   * The proof is invalid.
   */
  1302: {message:"InvalidProof"}
}

/**
 * Storage keys for the data associated with `MerkleDistributor`
 */
export type MerkleDistributorStorageKey = {tag: "Root", values: void} | {tag: "Claimed", values: readonly [u32]};

/**
 * Rounding direction for division operations
 */
export type Rounding = {tag: "Floor", values: void} | {tag: "Ceil", values: void};

export const SorobanFixedPointError = {
  /**
   * Arithmetic overflow occurred
   */
  1500: {message:"Overflow"},
  /**
   * Division by zero
   */
  1501: {message:"DivisionByZero"}
}

export const CryptoError = {
  /**
   * The merkle proof length is out of bounds.
   */
  1400: {message:"MerkleProofOutOfBounds"},
  /**
   * The index of the leaf is out of bounds.
   */
  1401: {message:"MerkleIndexOutOfBounds"},
  /**
   * No data in hasher state.
   */
  1402: {message:"HasherEmptyState"}
}



export const PausableError = {
  /**
   * The operation failed because the contract is paused.
   */
  1000: {message:"EnforcedPause"},
  /**
   * The operation failed because the contract is not paused.
   */
  1001: {message:"ExpectedPause"}
}

/**
 * Storage key for the pausable state
 */
export type PausableStorageKey = {tag: "Paused", values: void};

export interface Client {
  /**
   * Construct and simulate a execute transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Execute a function on a target contract.
   * 
   * This provides a secure mechanism for the smart account to invoke
   * functions on other contracts, such as updating policy
   * configurations. Requires smart account authorization.
   * 
   * # Arguments
   * 
   * * `target` - Address of the contract to invoke
   * * `target_fn` - Function name to call on the target contract
   * * `target_args` - Arguments to pass to the target function
   */
  execute: ({target, target_fn, target_args}: {target: string, target_fn: string, target_args: Array<any>}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a upgrade transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  upgrade: ({new_wasm_hash, operator}: {new_wasm_hash: Buffer, operator: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a add_policy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Add a policy to an existing context rule.
   * 
   * Requires smart account authorization.
   */
  add_policy: ({context_rule_id, policy, install_param}: {context_rule_id: u32, policy: string, install_param: any}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a add_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Add a signer to an existing context rule.
   * 
   * Requires smart account authorization.
   */
  add_signer: ({context_rule_id, signer}: {context_rule_id: u32, signer: Signer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a remove_policy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Remove a policy from an existing context rule.
   * 
   * Requires smart account authorization.
   */
  remove_policy: ({context_rule_id, policy}: {context_rule_id: u32, policy: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a remove_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Remove a signer from an existing context rule.
   * 
   * Requires smart account authorization.
   */
  remove_signer: ({context_rule_id, signer}: {context_rule_id: u32, signer: Signer}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a add_context_rule transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Add a new context rule to the smart account.
   * 
   * Requires smart account authorization.
   */
  add_context_rule: ({context_type, name, valid_until, signers, policies}: {context_type: ContextRuleType, name: string, valid_until: Option<u32>, signers: Array<Signer>, policies: Map<string, any>}, options?: MethodOptions) => Promise<AssembledTransaction<ContextRule>>

  /**
   * Construct and simulate a get_context_rule transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Retrieve a specific context rule by its ID.
   */
  get_context_rule: ({context_rule_id}: {context_rule_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<ContextRule>>

  /**
   * Construct and simulate a get_context_rules transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Retrieve all context rules of a specific type.
   */
  get_context_rules: ({context_rule_type}: {context_rule_type: ContextRuleType}, options?: MethodOptions) => Promise<AssembledTransaction<Array<ContextRule>>>

  /**
   * Construct and simulate a remove_context_rule transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Remove a context rule from the smart account.
   * 
   * Requires smart account authorization.
   */
  remove_context_rule: ({context_rule_id}: {context_rule_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a update_context_rule_name transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Update the name of an existing context rule.
   * 
   * Requires smart account authorization.
   */
  update_context_rule_name: ({context_rule_id, name}: {context_rule_id: u32, name: string}, options?: MethodOptions) => Promise<AssembledTransaction<ContextRule>>

  /**
   * Construct and simulate a update_context_rule_valid_until transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Update the expiration time of an existing context rule.
   * 
   * Requires smart account authorization.
   */
  update_context_rule_valid_until: ({context_rule_id, valid_until}: {context_rule_id: u32, valid_until: Option<u32>}, options?: MethodOptions) => Promise<AssembledTransaction<ContextRule>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
        /** Constructor/Initialization Args for the contract's `__constructor` method */
        {signers, policies}: {signers: Array<Signer>, policies: Map<string, any>},
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions &
      Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
      }
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy({signers, policies}, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAAAAAAAYtFeGVjdXRlIGEgZnVuY3Rpb24gb24gYSB0YXJnZXQgY29udHJhY3QuCgpUaGlzIHByb3ZpZGVzIGEgc2VjdXJlIG1lY2hhbmlzbSBmb3IgdGhlIHNtYXJ0IGFjY291bnQgdG8gaW52b2tlCmZ1bmN0aW9ucyBvbiBvdGhlciBjb250cmFjdHMsIHN1Y2ggYXMgdXBkYXRpbmcgcG9saWN5CmNvbmZpZ3VyYXRpb25zLiBSZXF1aXJlcyBzbWFydCBhY2NvdW50IGF1dGhvcml6YXRpb24uCgojIEFyZ3VtZW50cwoKKiBgdGFyZ2V0YCAtIEFkZHJlc3Mgb2YgdGhlIGNvbnRyYWN0IHRvIGludm9rZQoqIGB0YXJnZXRfZm5gIC0gRnVuY3Rpb24gbmFtZSB0byBjYWxsIG9uIHRoZSB0YXJnZXQgY29udHJhY3QKKiBgdGFyZ2V0X2FyZ3NgIC0gQXJndW1lbnRzIHRvIHBhc3MgdG8gdGhlIHRhcmdldCBmdW5jdGlvbgAAAAAHZXhlY3V0ZQAAAAADAAAAAAAAAAZ0YXJnZXQAAAAAABMAAAAAAAAACXRhcmdldF9mbgAAAAAAABEAAAAAAAAAC3RhcmdldF9hcmdzAAAAA+oAAAAAAAAAAA==",
        "AAAAAAAAAAAAAAAHdXBncmFkZQAAAAACAAAAAAAAAA1uZXdfd2FzbV9oYXNoAAAAAAAD7gAAACAAAAAAAAAACG9wZXJhdG9yAAAAEwAAAAA=",
        "AAAAAAAAAFBBZGQgYSBwb2xpY3kgdG8gYW4gZXhpc3RpbmcgY29udGV4dCBydWxlLgoKUmVxdWlyZXMgc21hcnQgYWNjb3VudCBhdXRob3JpemF0aW9uLgAAAAphZGRfcG9saWN5AAAAAAADAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAAAAAAGcG9saWN5AAAAAAATAAAAAAAAAA1pbnN0YWxsX3BhcmFtAAAAAAAAAAAAAAA=",
        "AAAAAAAAAFBBZGQgYSBzaWduZXIgdG8gYW4gZXhpc3RpbmcgY29udGV4dCBydWxlLgoKUmVxdWlyZXMgc21hcnQgYWNjb3VudCBhdXRob3JpemF0aW9uLgAAAAphZGRfc2lnbmVyAAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAAAAAAGc2lnbmVyAAAAAAfQAAAABlNpZ25lcgAAAAAAAA==",
        "AAAAAAAAAfdWZXJpZnkgYXV0aG9yaXphdGlvbiBmb3IgdGhlIHNtYXJ0IGFjY291bnQuCgpUaGlzIGZ1bmN0aW9uIGlzIGNhbGxlZCBieSB0aGUgU29yb2JhbiBob3N0IHdoZW4gYXV0aG9yaXphdGlvbiBpcwpyZXF1aXJlZC4gSXQgdmFsaWRhdGVzIHNpZ25hdHVyZXMgYWdhaW5zdCB0aGUgY29uZmlndXJlZCBjb250ZXh0CnJ1bGVzIGFuZCBwb2xpY2llcy4KCiMgQXJndW1lbnRzCgoqIGBzaWduYXR1cmVfcGF5bG9hZGAgLSBIYXNoIG9mIHRoZSBkYXRhIHRoYXQgd2FzIHNpZ25lZAoqIGBzaWduYXR1cmVzYCAtIE1hcCBvZiBzaWduZXJzIHRvIHRoZWlyIHNpZ25hdHVyZSBkYXRhCiogYGF1dGhfY29udGV4dHNgIC0gQ29udGV4dHMgYmVpbmcgYXV0aG9yaXplZCAoY29udHJhY3QgY2FsbHMsCmRlcGxveW1lbnRzLCBldGMuKQoKIyBSZXR1cm5zCgoqIGBPaygoKSlgIGlmIGF1dGhvcml6YXRpb24gc3VjY2VlZHMKKiBgRXJyKFNtYXJ0QWNjb3VudEVycm9yKWAgaWYgYXV0aG9yaXphdGlvbiBmYWlscwAAAAAMX19jaGVja19hdXRoAAAAAwAAAAAAAAARc2lnbmF0dXJlX3BheWxvYWQAAAAAAAPuAAAAIAAAAAAAAAAKc2lnbmF0dXJlcwAAAAAH0AAAAApTaWduYXR1cmVzAAAAAAAAAAAADWF1dGhfY29udGV4dHMAAAAAAAPqAAAH0AAAAAdDb250ZXh0AAAAAAEAAAPpAAAD7QAAAAAAAAAD",
        "AAAAAAAAAP1DcmVhdGVzIGEgZGVmYXVsdCBjb250ZXh0IHJ1bGUgd2l0aCB0aGUgcHJvdmlkZWQgc2lnbmVycyBhbmQgcG9saWNpZXMuCgojIEFyZ3VtZW50cwoKKiBgc2lnbmVyc2AgLSBWZWN0b3Igb2Ygc2lnbmVycyAoRGVsZWdhdGVkIG9yIEV4dGVybmFsKSB0aGF0IGNhbgphdXRob3JpemUgdHJhbnNhY3Rpb25zCiogYHBvbGljaWVzYCAtIE1hcCBvZiBwb2xpY3kgY29udHJhY3QgYWRkcmVzc2VzIHRvIHRoZWlyIGluc3RhbGxhdGlvbgpwYXJhbWV0ZXJzAAAAAAAADV9fY29uc3RydWN0b3IAAAAAAAACAAAAAAAAAAdzaWduZXJzAAAAA+oAAAfQAAAABlNpZ25lcgAAAAAAAAAAAAhwb2xpY2llcwAAA+wAAAATAAAAAAAAAAA=",
        "AAAAAAAAAFVSZW1vdmUgYSBwb2xpY3kgZnJvbSBhbiBleGlzdGluZyBjb250ZXh0IHJ1bGUuCgpSZXF1aXJlcyBzbWFydCBhY2NvdW50IGF1dGhvcml6YXRpb24uAAAAAAAADXJlbW92ZV9wb2xpY3kAAAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAAAAAAGcG9saWN5AAAAAAATAAAAAA==",
        "AAAAAAAAAFVSZW1vdmUgYSBzaWduZXIgZnJvbSBhbiBleGlzdGluZyBjb250ZXh0IHJ1bGUuCgpSZXF1aXJlcyBzbWFydCBhY2NvdW50IGF1dGhvcml6YXRpb24uAAAAAAAADXJlbW92ZV9zaWduZXIAAAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAAAAAAGc2lnbmVyAAAAAAfQAAAABlNpZ25lcgAAAAAAAA==",
        "AAAAAAAAAFNBZGQgYSBuZXcgY29udGV4dCBydWxlIHRvIHRoZSBzbWFydCBhY2NvdW50LgoKUmVxdWlyZXMgc21hcnQgYWNjb3VudCBhdXRob3JpemF0aW9uLgAAAAAQYWRkX2NvbnRleHRfcnVsZQAAAAUAAAAAAAAADGNvbnRleHRfdHlwZQAAB9AAAAAPQ29udGV4dFJ1bGVUeXBlAAAAAAAAAAAEbmFtZQAAABAAAAAAAAAAC3ZhbGlkX3VudGlsAAAAA+gAAAAEAAAAAAAAAAdzaWduZXJzAAAAA+oAAAfQAAAABlNpZ25lcgAAAAAAAAAAAAhwb2xpY2llcwAAA+wAAAATAAAAAAAAAAEAAAfQAAAAC0NvbnRleHRSdWxlAA==",
        "AAAAAAAAACtSZXRyaWV2ZSBhIHNwZWNpZmljIGNvbnRleHQgcnVsZSBieSBpdHMgSUQuAAAAABBnZXRfY29udGV4dF9ydWxlAAAAAQAAAAAAAAAPY29udGV4dF9ydWxlX2lkAAAAAAQAAAABAAAH0AAAAAtDb250ZXh0UnVsZQA=",
        "AAAAAAAAAC5SZXRyaWV2ZSBhbGwgY29udGV4dCBydWxlcyBvZiBhIHNwZWNpZmljIHR5cGUuAAAAAAARZ2V0X2NvbnRleHRfcnVsZXMAAAAAAAABAAAAAAAAABFjb250ZXh0X3J1bGVfdHlwZQAAAAAAB9AAAAAPQ29udGV4dFJ1bGVUeXBlAAAAAAEAAAPqAAAH0AAAAAtDb250ZXh0UnVsZQA=",
        "AAAAAAAAAFRSZW1vdmUgYSBjb250ZXh0IHJ1bGUgZnJvbSB0aGUgc21hcnQgYWNjb3VudC4KClJlcXVpcmVzIHNtYXJ0IGFjY291bnQgYXV0aG9yaXphdGlvbi4AAAATcmVtb3ZlX2NvbnRleHRfcnVsZQAAAAABAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAA=",
        "AAAAAAAAAFNVcGRhdGUgdGhlIG5hbWUgb2YgYW4gZXhpc3RpbmcgY29udGV4dCBydWxlLgoKUmVxdWlyZXMgc21hcnQgYWNjb3VudCBhdXRob3JpemF0aW9uLgAAAAAYdXBkYXRlX2NvbnRleHRfcnVsZV9uYW1lAAAAAgAAAAAAAAAPY29udGV4dF9ydWxlX2lkAAAAAAQAAAAAAAAABG5hbWUAAAAQAAAAAQAAB9AAAAALQ29udGV4dFJ1bGUA",
        "AAAAAAAAAF5VcGRhdGUgdGhlIGV4cGlyYXRpb24gdGltZSBvZiBhbiBleGlzdGluZyBjb250ZXh0IHJ1bGUuCgpSZXF1aXJlcyBzbWFydCBhY2NvdW50IGF1dGhvcml6YXRpb24uAAAAAAAfdXBkYXRlX2NvbnRleHRfcnVsZV92YWxpZF91bnRpbAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAAAAAALdmFsaWRfdW50aWwAAAAD6AAAAAQAAAABAAAH0AAAAAtDb250ZXh0UnVsZQA=",
        "AAAABQAAADdFdmVudCBlbWl0dGVkIHdoZW4gYSBwb2xpY3kgaXMgYWRkZWQgdG8gYSBjb250ZXh0IHJ1bGUuAAAAAAAAAAALUG9saWN5QWRkZWQAAAAAAQAAAAxwb2xpY3lfYWRkZWQAAAADAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAABnBvbGljeQAAAAAAEwAAAAAAAAAAAAAADWluc3RhbGxfcGFyYW0AAAAAAAAAAAAAAAAAAAI=",
        "AAAABQAAADdFdmVudCBlbWl0dGVkIHdoZW4gYSBzaWduZXIgaXMgYWRkZWQgdG8gYSBjb250ZXh0IHJ1bGUuAAAAAAAAAAALU2lnbmVyQWRkZWQAAAAAAQAAAAxzaWduZXJfYWRkZWQAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAAAAAAC",
        "AAAABQAAADtFdmVudCBlbWl0dGVkIHdoZW4gYSBwb2xpY3kgaXMgcmVtb3ZlZCBmcm9tIGEgY29udGV4dCBydWxlLgAAAAAAAAAADVBvbGljeVJlbW92ZWQAAAAAAAABAAAADnBvbGljeV9yZW1vdmVkAAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAABnBvbGljeQAAAAAAEwAAAAAAAAAC",
        "AAAABQAAADtFdmVudCBlbWl0dGVkIHdoZW4gYSBzaWduZXIgaXMgcmVtb3ZlZCBmcm9tIGEgY29udGV4dCBydWxlLgAAAAAAAAAADVNpZ25lclJlbW92ZWQAAAAAAAABAAAADnNpZ25lcl9yZW1vdmVkAAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAAAAAAC",
        "AAAABQAAACtFdmVudCBlbWl0dGVkIHdoZW4gYSBjb250ZXh0IHJ1bGUgaXMgYWRkZWQuAAAAAAAAAAAQQ29udGV4dFJ1bGVBZGRlZAAAAAEAAAASY29udGV4dF9ydWxlX2FkZGVkAAAAAAAGAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAABG5hbWUAAAAQAAAAAAAAAAAAAAAMY29udGV4dF90eXBlAAAH0AAAAA9Db250ZXh0UnVsZVR5cGUAAAAAAAAAAAAAAAALdmFsaWRfdW50aWwAAAAD6AAAAAQAAAAAAAAAAAAAAAdzaWduZXJzAAAAA+oAAAfQAAAABlNpZ25lcgAAAAAAAAAAAAAAAAAIcG9saWNpZXMAAAPqAAAAEwAAAAAAAAAC",
        "AAAABAAAAClFcnJvciBjb2RlcyBmb3Igc21hcnQgYWNjb3VudCBvcGVyYXRpb25zLgAAAAAAAAAAAAARU21hcnRBY2NvdW50RXJyb3IAAAAAAAANAAAAKlRoZSBzcGVjaWZpZWQgY29udGV4dCBydWxlIGRvZXMgbm90IGV4aXN0LgAAAAAAE0NvbnRleHRSdWxlTm90Rm91bmQAAAALuAAAAChBIGR1cGxpY2F0ZSBjb250ZXh0IHJ1bGUgYWxyZWFkeSBleGlzdHMuAAAAFER1cGxpY2F0ZUNvbnRleHRSdWxlAAALuQAAADpUaGUgcHJvdmlkZWQgY29udGV4dCBjYW5ub3QgYmUgdmFsaWRhdGVkIGFnYWluc3QgYW55IHJ1bGUuAAAAAAASVW52YWxpZGF0ZWRDb250ZXh0AAAAAAu6AAAAJ0V4dGVybmFsIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24gZmFpbGVkLgAAAAAaRXh0ZXJuYWxWZXJpZmljYXRpb25GYWlsZWQAAAAAC7sAAAA1Q29udGV4dCBydWxlIG11c3QgaGF2ZSBhdCBsZWFzdCBvbmUgc2lnbmVyIG9yIHBvbGljeS4AAAAAAAAUTm9TaWduZXJzQW5kUG9saWNpZXMAAAu8AAAAKVRoZSB2YWxpZF91bnRpbCB0aW1lc3RhbXAgaXMgaW4gdGhlIHBhc3QuAAAAAAAADlBhc3RWYWxpZFVudGlsAAAAAAu9AAAAI1RoZSBzcGVjaWZpZWQgc2lnbmVyIHdhcyBub3QgZm91bmQuAAAAAA5TaWduZXJOb3RGb3VuZAAAAAALvgAAAC5UaGUgc2lnbmVyIGFscmVhZHkgZXhpc3RzIGluIHRoZSBjb250ZXh0IHJ1bGUuAAAAAAAPRHVwbGljYXRlU2lnbmVyAAAAC78AAAAjVGhlIHNwZWNpZmllZCBwb2xpY3kgd2FzIG5vdCBmb3VuZC4AAAAADlBvbGljeU5vdEZvdW5kAAAAAAvAAAAALlRoZSBwb2xpY3kgYWxyZWFkeSBleGlzdHMgaW4gdGhlIGNvbnRleHQgcnVsZS4AAAAAAA9EdXBsaWNhdGVQb2xpY3kAAAALwQAAACVUb28gbWFueSBzaWduZXJzIGluIHRoZSBjb250ZXh0IHJ1bGUuAAAAAAAADlRvb01hbnlTaWduZXJzAAAAAAvCAAAAJlRvbyBtYW55IHBvbGljaWVzIGluIHRoZSBjb250ZXh0IHJ1bGUuAAAAAAAPVG9vTWFueVBvbGljaWVzAAAAC8MAAAAsVG9vIG1hbnkgY29udGV4dCBydWxlcyBpbiB0aGUgc21hcnQgYWNjb3VudC4AAAATVG9vTWFueUNvbnRleHRSdWxlcwAAAAvE",
        "AAAABQAAAC1FdmVudCBlbWl0dGVkIHdoZW4gYSBjb250ZXh0IHJ1bGUgaXMgcmVtb3ZlZC4AAAAAAAAAAAAAEkNvbnRleHRSdWxlUmVtb3ZlZAAAAAAAAQAAABRjb250ZXh0X3J1bGVfcmVtb3ZlZAAAAAEAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAQAAAAI=",
        "AAAABQAAAC1FdmVudCBlbWl0dGVkIHdoZW4gYSBjb250ZXh0IHJ1bGUgaXMgdXBkYXRlZC4AAAAAAAAAAAAAEkNvbnRleHRSdWxlVXBkYXRlZAAAAAAAAQAAABRjb250ZXh0X3J1bGVfdXBkYXRlZAAAAAQAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAQAAAAAAAAAEbmFtZQAAABAAAAAAAAAAAAAAAAxjb250ZXh0X3R5cGUAAAfQAAAAD0NvbnRleHRSdWxlVHlwZQAAAAAAAAAAAAAAAAt2YWxpZF91bnRpbAAAAAPoAAAABAAAAAAAAAAC",
        "AAAAAQAAABxNZXRhZGF0YSBmb3IgYSBjb250ZXh0IHJ1bGUuAAAAAAAAAARNZXRhAAAAAwAAAClUaGUgdHlwZSBvZiBjb250ZXh0IHRoaXMgcnVsZSBhcHBsaWVzIHRvLgAAAAAAAAxjb250ZXh0X3R5cGUAAAfQAAAAD0NvbnRleHRSdWxlVHlwZQAAAAApSHVtYW4tcmVhZGFibGUgbmFtZSBmb3IgdGhlIGNvbnRleHQgcnVsZS4AAAAAAAAEbmFtZQAAABAAAAAxT3B0aW9uYWwgZXhwaXJhdGlvbiBsZWRnZXIgc2VxdWVuY2UgZm9yIHRoZSBydWxlLgAAAAAAAAt2YWxpZF91bnRpbAAAAAPoAAAABA==",
        "AAAAAgAAAEJSZXByZXNlbnRzIGRpZmZlcmVudCB0eXBlcyBvZiBzaWduZXJzIGluIHRoZSBzbWFydCBhY2NvdW50IHN5c3RlbS4AAAAAAAAAAAAGU2lnbmVyAAAAAAACAAAAAQAAAD1BIGRlbGVnYXRlZCBzaWduZXIgdGhhdCB1c2VzIGJ1aWx0LWluIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24uAAAAAAAACURlbGVnYXRlZAAAAAAAAAEAAAATAAAAAQAAAHJBbiBleHRlcm5hbCBzaWduZXIgd2l0aCBjdXN0b20gdmVyaWZpY2F0aW9uIGxvZ2ljLgpDb250YWlucyB0aGUgdmVyaWZpZXIgY29udHJhY3QgYWRkcmVzcyBhbmQgdGhlIHB1YmxpYyBrZXkgZGF0YS4AAAAAAAhFeHRlcm5hbAAAAAIAAAATAAAADg==",
        "AAAAAQAAAD5BIGNvbGxlY3Rpb24gb2Ygc2lnbmF0dXJlcyBtYXBwZWQgdG8gdGhlaXIgcmVzcGVjdGl2ZSBzaWduZXJzLgAAAAAAAAAAAApTaWduYXR1cmVzAAAAAAABAAAAAAAAAAEwAAAAAAAD7AAAB9AAAAAGU2lnbmVyAAAAAAAO",
        "AAAAAQAAADxBIGNvbXBsZXRlIGNvbnRleHQgcnVsZSBkZWZpbmluZyBhdXRob3JpemF0aW9uIHJlcXVpcmVtZW50cy4AAAAAAAAAC0NvbnRleHRSdWxlAAAAAAYAAAApVGhlIHR5cGUgb2YgY29udGV4dCB0aGlzIHJ1bGUgYXBwbGllcyB0by4AAAAAAAAMY29udGV4dF90eXBlAAAH0AAAAA9Db250ZXh0UnVsZVR5cGUAAAAAJ1VuaXF1ZSBpZGVudGlmaWVyIGZvciB0aGUgY29udGV4dCBydWxlLgAAAAACaWQAAAAAAAQAAAApSHVtYW4tcmVhZGFibGUgbmFtZSBmb3IgdGhlIGNvbnRleHQgcnVsZS4AAAAAAAAEbmFtZQAAABAAAAAwTGlzdCBvZiBwb2xpY3kgY29udHJhY3RzIHRoYXQgbXVzdCBiZSBzYXRpc2ZpZWQuAAAACHBvbGljaWVzAAAD6gAAABMAAAAoTGlzdCBvZiBzaWduZXJzIGF1dGhvcml6ZWQgYnkgdGhpcyBydWxlLgAAAAdzaWduZXJzAAAAA+oAAAfQAAAABlNpZ25lcgAAAAAAMU9wdGlvbmFsIGV4cGlyYXRpb24gbGVkZ2VyIHNlcXVlbmNlIGZvciB0aGUgcnVsZS4AAAAAAAALdmFsaWRfdW50aWwAAAAD6AAAAAQ=",
        "AAAAAgAAAEBUeXBlcyBvZiBjb250ZXh0cyB0aGF0IGNhbiBiZSBhdXRob3JpemVkIGJ5IHNtYXJ0IGFjY291bnQgcnVsZXMuAAAAAAAAAA9Db250ZXh0UnVsZVR5cGUAAAAAAwAAAAAAAAAtRGVmYXVsdCBydWxlcyB0aGF0IGNhbiBhdXRob3JpemUgYW55IGNvbnRleHQuAAAAAAAAB0RlZmF1bHQAAAAAAQAAADBSdWxlcyBzcGVjaWZpYyB0byBjYWxsaW5nIGEgcGFydGljdWxhciBjb250cmFjdC4AAAAMQ2FsbENvbnRyYWN0AAAAAQAAABMAAAABAAAAQlJ1bGVzIHNwZWNpZmljIHRvIGNyZWF0aW5nIGEgY29udHJhY3Qgd2l0aCBhIHBhcnRpY3VsYXIgV0FTTSBoYXNoLgAAAAAADkNyZWF0ZUNvbnRyYWN0AAAAAAABAAAD7gAAACA=",
        "AAAAAgAAACRTdG9yYWdlIGtleXMgZm9yIHNtYXJ0IGFjY291bnQgZGF0YS4AAAAAAAAAFlNtYXJ0QWNjb3VudFN0b3JhZ2VLZXkAAAAAAAcAAAABAAAAUVN0b3JhZ2Uga2V5IGZvciBzaWduZXJzIG9mIGEgY29udGV4dCBydWxlLgpNYXBzIGNvbnRleHQgcnVsZSBJRCB0byBgVmVjPFNpZ25lcj5gLgAAAAAAAAdTaWduZXJzAAAAAAEAAAAEAAAAAQAAAFNTdG9yYWdlIGtleSBmb3IgcG9saWNpZXMgb2YgYSBjb250ZXh0IHJ1bGUuCk1hcHMgY29udGV4dCBydWxlIElEIHRvIGBWZWM8QWRkcmVzcz5gLgAAAAAIUG9saWNpZXMAAAABAAAABAAAAAEAAABbU3RvcmFnZSBrZXkgZm9yIGNvbnRleHQgcnVsZSBJRHMgYnkgdHlwZS4KTWFwcyBgQ29udGV4dFJ1bGVUeXBlYCB0byBgVmVjPHUzMj5gIG9mIHJ1bGUgSURzLgAAAAADSWRzAAAAAAEAAAfQAAAAD0NvbnRleHRSdWxlVHlwZQAAAAABAAAARlN0b3JhZ2Uga2V5IGZvciBjb250ZXh0IHJ1bGUgbWV0YWRhdGEuCk1hcHMgY29udGV4dCBydWxlIElEIHRvIGBNZXRhYC4AAAAAAARNZXRhAAAAAQAAAAQAAAAAAAAAM1N0b3JhZ2Uga2V5IGZvciB0aGUgbmV4dCBhdmFpbGFibGUgY29udGV4dCBydWxlIElELgAAAAAGTmV4dElkAAAAAAABAAAAN1N0b3JhZ2Uga2V5IGRlZmluaW5nIHRoZSBmaW5nZXJwcmludCBlYWNoIGNvbnRleHQgcnVsZS4AAAAAC0ZpbmdlcnByaW50AAAAAAEAAAPuAAAAIAAAAAAAAABbU3RvcmFnZSBrZXkgZm9yIHRoZSBjb3VudCBvZiBhY3RpdmUgY29udGV4dCBydWxlcy4KVXNlZCB0byBlbmZvcmNlIE1BWF9DT05URVhUX1JVTEVTIGxpbWl0LgAAAAAFQ291bnQAAAA=",
        "AAAAAQAAADBJbmRpdmlkdWFsIHNwZW5kaW5nIGVudHJ5IGZvciB0cmFja2luZyBwdXJwb3Nlcy4AAAAAAAAADVNwZW5kaW5nRW50cnkAAAAAAAACAAAAJVRoZSBhbW91bnQgc3BlbnQgaW4gdGhpcyB0cmFuc2FjdGlvbi4AAAAAAAAGYW1vdW50AAAAAAALAAAAM1RoZSBsZWRnZXIgc2VxdWVuY2Ugd2hlbiB0aGlzIHRyYW5zYWN0aW9uIG9jY3VycmVkLgAAAAAPbGVkZ2VyX3NlcXVlbmNlAAAAAAQ=",
        "AAAAAQAAADdJbnRlcm5hbCBzdG9yYWdlIHN0cnVjdHVyZSBmb3Igc3BlbmRpbmcgbGltaXQgdHJhY2tpbmcuAAAAAAAAAAARU3BlbmRpbmdMaW1pdERhdGEAAAAAAAAEAAAAMENhY2hlZCB0b3RhbCBvZiBhbGwgYW1vdW50cyBpbiBzcGVuZGluZ19oaXN0b3J5LgAAABJjYWNoZWRfdG90YWxfc3BlbnQAAAAAAAsAAAA8VGhlIHBlcmlvZCBpbiBsZWRnZXJzIG92ZXIgd2hpY2ggdGhlIHNwZW5kaW5nIGxpbWl0IGFwcGxpZXMuAAAADnBlcmlvZF9sZWRnZXJzAAAAAAAEAAAAPUhpc3Rvcnkgb2Ygc3BlbmRpbmcgdHJhbnNhY3Rpb25zIHdpdGggdGhlaXIgbGVkZ2VyIHNlcXVlbmNlcy4AAAAAAAAQc3BlbmRpbmdfaGlzdG9yeQAAA+oAAAfQAAAADVNwZW5kaW5nRW50cnkAAAAAAAAiVGhlIHNwZW5kaW5nIGxpbWl0IGZvciB0aGUgcGVyaW9kLgAAAAAADnNwZW5kaW5nX2xpbWl0AAAAAAAL",
        "AAAABAAAADFFcnJvciBjb2RlcyBmb3Igc3BlbmRpbmcgbGltaXQgcG9saWN5IG9wZXJhdGlvbnMuAAAAAAAAAAAAABJTcGVuZGluZ0xpbWl0RXJyb3IAAAAAAAUAAABCVGhlIHNtYXJ0IGFjY291bnQgZG9lcyBub3QgaGF2ZSBhIHNwZW5kaW5nIGxpbWl0IHBvbGljeSBpbnN0YWxsZWQuAAAAAAAYU21hcnRBY2NvdW50Tm90SW5zdGFsbGVkAAAMlAAAACVUaGUgc3BlbmRpbmcgbGltaXQgaGFzIGJlZW4gZXhjZWVkZWQuAAAAAAAAFVNwZW5kaW5nTGltaXRFeGNlZWRlZAAAAAAADJUAAAAoVGhlIHNwZW5kaW5nIGxpbWl0IG9yIHBlcmlvZCBpcyBpbnZhbGlkLgAAABRJbnZhbGlkTGltaXRPclBlcmlvZAAADJYAAAAuVGhlIHRyYW5zYWN0aW9uIGlzIG5vdCBhbGxvd2VkIGJ5IHRoaXMgcG9saWN5LgAAAAAACk5vdEFsbG93ZWQAAAAADJcAAAAyVGhlIHNwZW5kaW5nIGhpc3RvcnkgaGFzIHJlYWNoZWQgbWF4aW11bSBjYXBhY2l0eS4AAAAAABdIaXN0b3J5Q2FwYWNpdHlFeGNlZWRlZAAAAAyY",
        "AAAAAgAAACxTdG9yYWdlIGtleXMgZm9yIHNwZW5kaW5nIGxpbWl0IHBvbGljeSBkYXRhLgAAAAAAAAAXU3BlbmRpbmdMaW1pdFN0b3JhZ2VLZXkAAAAAAQAAAAEAAABEU3RvcmFnZSBrZXkgZm9yIHNwZW5kaW5nIGxpbWl0IGRhdGEgb2YgYSBzbWFydCBhY2NvdW50IGNvbnRleHQgcnVsZS4AAAAOQWNjb3VudENvbnRleHQAAAAAAAIAAAATAAAABA==",
        "AAAAAQAAADZJbnN0YWxsYXRpb24gcGFyYW1ldGVycyBmb3IgdGhlIHNwZW5kaW5nIGxpbWl0IHBvbGljeS4AAAAAAAAAAAAaU3BlbmRpbmdMaW1pdEFjY291bnRQYXJhbXMAAAAAAAIAAAA8VGhlIHBlcmlvZCBpbiBsZWRnZXJzIG92ZXIgd2hpY2ggdGhlIHNwZW5kaW5nIGxpbWl0IGFwcGxpZXMuAAAADnBlcmlvZF9sZWRnZXJzAAAAAAAEAAAATlRoZSBtYXhpbXVtIGFtb3VudCB0aGF0IGNhbiBiZSBzcGVudCB3aXRoaW4gdGhlIHNwZWNpZmllZCBwZXJpb2QgKGluCnN0cm9vcHMpLgAAAAAADnNwZW5kaW5nX2xpbWl0AAAAAAAL",
        "AAAABQAAADdFdmVudCBlbWl0dGVkIHdoZW4gYSBzcGVuZGluZyBsaW1pdCBwb2xpY3kgaXMgZW5mb3JjZWQuAAAAAAAAAAAbU3BlbmRpbmdMaW1pdFBvbGljeUVuZm9yY2VkAAAAAAEAAAAec3BlbmRpbmdfbGltaXRfcG9saWN5X2VuZm9yY2VkAAAAAAAFAAAAAAAAAA1zbWFydF9hY2NvdW50AAAAAAAAEwAAAAEAAAAAAAAAB2NvbnRleHQAAAAH0AAAAAdDb250ZXh0AAAAAAAAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAAAAAAAAAAAGYW1vdW50AAAAAAALAAAAAAAAAAAAAAAVdG90YWxfc3BlbnRfaW5fcGVyaW9kAAAAAAAACwAAAAAAAAAC",
        "AAAABAAAADNFcnJvciBjb2RlcyBmb3Igc2ltcGxlIHRocmVzaG9sZCBwb2xpY3kgb3BlcmF0aW9ucy4AAAAAAAAAABRTaW1wbGVUaHJlc2hvbGRFcnJvcgAAAAMAAABEVGhlIHNtYXJ0IGFjY291bnQgZG9lcyBub3QgaGF2ZSBhIHNpbXBsZSB0aHJlc2hvbGQgcG9saWN5IGluc3RhbGxlZC4AAAAYU21hcnRBY2NvdW50Tm90SW5zdGFsbGVkAAAMgAAAAD9XaGVuIHRocmVzaG9sZCBpcyAwIG9yIGV4Y2VlZHMgdGhlIG51bWJlciBvZiBhdmFpbGFibGUgc2lnbmVycy4AAAAAEEludmFsaWRUaHJlc2hvbGQAAAyBAAAALlRoZSB0cmFuc2FjdGlvbiBpcyBub3QgYWxsb3dlZCBieSB0aGlzIHBvbGljeS4AAAAAAApOb3RBbGxvd2VkAAAAAAyC",
        "AAAABQAAADlFdmVudCBlbWl0dGVkIHdoZW4gYSBzaW1wbGUgdGhyZXNob2xkIHBvbGljeSBpcyBlbmZvcmNlZC4AAAAAAAAAAAAAFFNpbXBsZVBvbGljeUVuZm9yY2VkAAAAAQAAABZzaW1wbGVfcG9saWN5X2VuZm9yY2VkAAAAAAAEAAAAAAAAAA1zbWFydF9hY2NvdW50AAAAAAAAEwAAAAEAAAAAAAAAB2NvbnRleHQAAAAH0AAAAAdDb250ZXh0AAAAAAAAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAAAAAAAAAAAVYXV0aGVudGljYXRlZF9zaWduZXJzAAAAAAAD6gAAB9AAAAAGU2lnbmVyAAAAAAAAAAAAAg==",
        "AAAAAgAAAC5TdG9yYWdlIGtleXMgZm9yIHNpbXBsZSB0aHJlc2hvbGQgcG9saWN5IGRhdGEuAAAAAAAAAAAAGVNpbXBsZVRocmVzaG9sZFN0b3JhZ2VLZXkAAAAAAAABAAAAAQAAAAAAAAAOQWNjb3VudENvbnRleHQAAAAAAAIAAAATAAAABA==",
        "AAAAAQAAADhJbnN0YWxsYXRpb24gcGFyYW1ldGVycyBmb3IgdGhlIHNpbXBsZSB0aHJlc2hvbGQgcG9saWN5LgAAAAAAAAAcU2ltcGxlVGhyZXNob2xkQWNjb3VudFBhcmFtcwAAAAEAAAA5VGhlIG1pbmltdW0gbnVtYmVyIG9mIHNpZ25lcnMgcmVxdWlyZWQgZm9yIGF1dGhvcml6YXRpb24uAAAAAAAACXRocmVzaG9sZAAAAAAAAAQ=",
        "AAAABAAAADVFcnJvciBjb2RlcyBmb3Igd2VpZ2h0ZWQgdGhyZXNob2xkIHBvbGljeSBvcGVyYXRpb25zLgAAAAAAAAAAAAAWV2VpZ2h0ZWRUaHJlc2hvbGRFcnJvcgAAAAAABAAAAEZUaGUgc21hcnQgYWNjb3VudCBkb2VzIG5vdCBoYXZlIGEgd2VpZ2h0ZWQgdGhyZXNob2xkIHBvbGljeSBpbnN0YWxsZWQuAAAAAAAYU21hcnRBY2NvdW50Tm90SW5zdGFsbGVkAAAMigAAAB9UaGUgdGhyZXNob2xkIHZhbHVlIGlzIGludmFsaWQuAAAAABBJbnZhbGlkVGhyZXNob2xkAAAMiwAAAChBIG1hdGhlbWF0aWNhbCBvcGVyYXRpb24gd291bGQgb3ZlcmZsb3cuAAAADE1hdGhPdmVyZmxvdwAADIwAAAAuVGhlIHRyYW5zYWN0aW9uIGlzIG5vdCBhbGxvd2VkIGJ5IHRoaXMgcG9saWN5LgAAAAAACk5vdEFsbG93ZWQAAAAADI0=",
        "AAAABQAAADtFdmVudCBlbWl0dGVkIHdoZW4gYSB3ZWlnaHRlZCB0aHJlc2hvbGQgcG9saWN5IGlzIGVuZm9yY2VkLgAAAAAAAAAAFldlaWdodGVkUG9saWN5RW5mb3JjZWQAAAAAAAEAAAAYd2VpZ2h0ZWRfcG9saWN5X2VuZm9yY2VkAAAABAAAAAAAAAANc21hcnRfYWNjb3VudAAAAAAAABMAAAABAAAAAAAAAAdjb250ZXh0AAAAB9AAAAAHQ29udGV4dAAAAAAAAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAAAAAAAAAAAFWF1dGhlbnRpY2F0ZWRfc2lnbmVycwAAAAAAA+oAAAfQAAAABlNpZ25lcgAAAAAAAAAAAAI=",
        "AAAAAgAAADBTdG9yYWdlIGtleXMgZm9yIHdlaWdodGVkIHRocmVzaG9sZCBwb2xpY3kgZGF0YS4AAAAAAAAAG1dlaWdodGVkVGhyZXNob2xkU3RvcmFnZUtleQAAAAABAAAAAQAAAKtTdG9yYWdlIGtleSBmb3IgdGhlIHRocmVzaG9sZCB2YWx1ZSBhbmQgc2lnbmVyIHdlaWdodHMgb2YgYSBzbWFydAphY2NvdW50IGNvbnRleHQgcnVsZS4gTWFwcyB0byBhIGBXZWlnaHRlZFRocmVzaG9sZEFjY291bnRQYXJhbXNgCmNvbnRhaW5pbmcgdGhyZXNob2xkIGFuZCBzaWduZXIgd2VpZ2h0cy4AAAAADkFjY291bnRDb250ZXh0AAAAAAACAAAAEwAAAAQ=",
        "AAAAAQAAADpJbnN0YWxsYXRpb24gcGFyYW1ldGVycyBmb3IgdGhlIHdlaWdodGVkIHRocmVzaG9sZCBwb2xpY3kuAAAAAAAAAAAAHldlaWdodGVkVGhyZXNob2xkQWNjb3VudFBhcmFtcwAAAAAAAgAAAC9NYXBwaW5nIG9mIHNpZ25lcnMgdG8gdGhlaXIgcmVzcGVjdGl2ZSB3ZWlnaHRzLgAAAAAOc2lnbmVyX3dlaWdodHMAAAAAA+wAAAfQAAAABlNpZ25lcgAAAAAABAAAADRUaGUgbWluaW11bSB0b3RhbCB3ZWlnaHQgcmVxdWlyZWQgZm9yIGF1dGhvcml6YXRpb24uAAAACXRocmVzaG9sZAAAAAAAAAQ=",
        "AAAABAAAADFFcnJvciB0eXBlcyBmb3IgV2ViQXV0aG4gdmVyaWZpY2F0aW9uIG9wZXJhdGlvbnMuAAAAAAAAAAAAAA1XZWJBdXRobkVycm9yAAAAAAAACQAAADlUaGUgc2lnbmF0dXJlIHBheWxvYWQgaXMgaW52YWxpZCBvciBoYXMgaW5jb3JyZWN0IGZvcm1hdC4AAAAAAAAXU2lnbmF0dXJlUGF5bG9hZEludmFsaWQAAAAMJgAAADNUaGUgY2xpZW50IGRhdGEgZXhjZWVkcyB0aGUgbWF4aW11bSBhbGxvd2VkIGxlbmd0aC4AAAAAEUNsaWVudERhdGFUb29Mb25nAAAAAAAMJwAAACZGYWlsZWQgdG8gcGFyc2UgSlNPTiBmcm9tIGNsaWVudCBkYXRhLgAAAAAADkpzb25QYXJzZUVycm9yAAAAAAwoAAAANFRoZSB0eXBlIGZpZWxkIGluIGNsaWVudCBkYXRhIGlzIG5vdCAid2ViYXV0aG4uZ2V0Ii4AAAAQVHlwZUZpZWxkSW52YWxpZAAADCkAAAA7VGhlIGNoYWxsZW5nZSBpbiBjbGllbnQgZGF0YSBkb2VzIG5vdCBtYXRjaCBleHBlY3RlZCB2YWx1ZS4AAAAAEENoYWxsZW5nZUludmFsaWQAAAwqAAAANlRoZSBhdXRoZW50aWNhdG9yIGRhdGEgZm9ybWF0IGlzIGludmFsaWQgb3IgdG9vIHNob3J0LgAAAAAAFUF1dGhEYXRhRm9ybWF0SW52YWxpZAAAAAAADCsAAAA8VGhlIFVzZXIgUHJlc2VudCAoVVApIGJpdCBpcyBub3Qgc2V0IGluIGF1dGhlbnRpY2F0b3IgZmxhZ3MuAAAAEFByZXNlbnRCaXROb3RTZXQAAAwsAAAAPVRoZSBVc2VyIFZlcmlmaWVkIChVVikgYml0IGlzIG5vdCBzZXQgaW4gYXV0aGVudGljYXRvciBmbGFncy4AAAAAAAARVmVyaWZpZWRCaXROb3RTZXQAAAAAAAwtAAAAP0ludmFsaWQgcmVsYXRpb25zaGlwIGJldHdlZW4gQmFja3VwIEVsaWdpYmlsaXR5IGFuZCBTdGF0ZSBiaXRzLgAAAAAfQmFja3VwRWxpZ2liaWxpdHlBbmRTdGF0ZU5vdFNldAAAAAwu",
        "AAAAAQAAAMhXZWJBdXRobiBzaWduYXR1cmUgZGF0YSBzdHJ1Y3R1cmUgY29udGFpbmluZyBhbGwgY29tcG9uZW50cyBuZWVkZWQgZm9yCnZlcmlmaWNhdGlvbi4KClRoaXMgc3RydWN0dXJlIGVuY2Fwc3VsYXRlcyB0aGUgc2lnbmF0dXJlIGFuZCBhc3NvY2lhdGVkIGRhdGEgZ2VuZXJhdGVkCmR1cmluZyBhIFdlYkF1dGhuIGF1dGhlbnRpY2F0aW9uIGNlcmVtb255LgAAAAAAAAAPV2ViQXV0aG5TaWdEYXRhAAAAAAMAAAAyUmF3IGF1dGhlbnRpY2F0b3IgZGF0YSBmcm9tIHRoZSBXZWJBdXRobiByZXNwb25zZS4AAAAAABJhdXRoZW50aWNhdG9yX2RhdGEAAAAAAA4AAAAwUmF3IGNsaWVudCBkYXRhIEpTT04gZnJvbSB0aGUgV2ViQXV0aG4gcmVzcG9uc2UuAAAAC2NsaWVudF9kYXRhAAAAAA4AAAA1VGhlIGNyeXB0b2dyYXBoaWMgc2lnbmF0dXJlICg2NCBieXRlcyBmb3Igc2VjcDI1NnIxKS4AAAAAAAAJc2lnbmF0dXJlAAAAAAAD7gAAAEA=",
        "AAAABAAAAAAAAAAAAAAAEFVwZ3JhZGVhYmxlRXJyb3IAAAABAAAAQVdoZW4gbWlncmF0aW9uIGlzIGF0dGVtcHRlZCBidXQgbm90IGFsbG93ZWQgZHVlIHRvIHVwZ3JhZGUgc3RhdGUuAAAAAAAAE01pZ3JhdGlvbk5vdEFsbG93ZWQAAAAETA==",
        "AAAABQAAACpFdmVudCBlbWl0dGVkIHdoZW4gdGhlIG1lcmtsZSByb290IGlzIHNldC4AAAAAAAAAAAAHU2V0Um9vdAAAAAABAAAACHNldF9yb290AAAAAQAAAAAAAAAEcm9vdAAAAA4AAAAAAAAAAg==",
        "AAAABQAAACdFdmVudCBlbWl0dGVkIHdoZW4gYW4gaW5kZXggaXMgY2xhaW1lZC4AAAAAAAAAAApTZXRDbGFpbWVkAAAAAAABAAAAC3NldF9jbGFpbWVkAAAAAAEAAAAAAAAABWluZGV4AAAAAAAAAAAAAAAAAAAC",
        "AAAABAAAAAAAAAAAAAAAFk1lcmtsZURpc3RyaWJ1dG9yRXJyb3IAAAAAAAMAAAAbVGhlIG1lcmtsZSByb290IGlzIG5vdCBzZXQuAAAAAApSb290Tm90U2V0AAAAAAUUAAAAJ1RoZSBwcm92aWRlZCBpbmRleCB3YXMgYWxyZWFkeSBjbGFpbWVkLgAAAAATSW5kZXhBbHJlYWR5Q2xhaW1lZAAAAAUVAAAAFVRoZSBwcm9vZiBpcyBpbnZhbGlkLgAAAAAAAAxJbnZhbGlkUHJvb2YAAAUW",
        "AAAAAgAAAD1TdG9yYWdlIGtleXMgZm9yIHRoZSBkYXRhIGFzc29jaWF0ZWQgd2l0aCBgTWVya2xlRGlzdHJpYnV0b3JgAAAAAAAAAAAAABtNZXJrbGVEaXN0cmlidXRvclN0b3JhZ2VLZXkAAAAAAgAAAAAAAAAoVGhlIE1lcmtsZSByb290IG9mIHRoZSBkaXN0cmlidXRpb24gdHJlZQAAAARSb290AAAAAQAAACNNYXBzIGFuIGluZGV4IHRvIGl0cyBjbGFpbWVkIHN0YXR1cwAAAAAHQ2xhaW1lZAAAAAABAAAABA==",
        "AAAAAgAAACpSb3VuZGluZyBkaXJlY3Rpb24gZm9yIGRpdmlzaW9uIG9wZXJhdGlvbnMAAAAAAAAAAAAIUm91bmRpbmcAAAACAAAAAAAAACVSb3VuZCB0b3dhcmQgbmVnYXRpdmUgaW5maW5pdHkgKGRvd24pAAAAAAAABUZsb29yAAAAAAAAAAAAACNSb3VuZCB0b3dhcmQgcG9zaXRpdmUgaW5maW5pdHkgKHVwKQAAAAAEQ2VpbA==",
        "AAAABAAAAAAAAAAAAAAAFlNvcm9iYW5GaXhlZFBvaW50RXJyb3IAAAAAAAIAAAAcQXJpdGhtZXRpYyBvdmVyZmxvdyBvY2N1cnJlZAAAAAhPdmVyZmxvdwAABdwAAAAQRGl2aXNpb24gYnkgemVybwAAAA5EaXZpc2lvbkJ5WmVybwAAAAAF3Q==",
        "AAAABAAAAAAAAAAAAAAAC0NyeXB0b0Vycm9yAAAAAAMAAAApVGhlIG1lcmtsZSBwcm9vZiBsZW5ndGggaXMgb3V0IG9mIGJvdW5kcy4AAAAAAAAWTWVya2xlUHJvb2ZPdXRPZkJvdW5kcwAAAAAFeAAAACdUaGUgaW5kZXggb2YgdGhlIGxlYWYgaXMgb3V0IG9mIGJvdW5kcy4AAAAAFk1lcmtsZUluZGV4T3V0T2ZCb3VuZHMAAAAABXkAAAAYTm8gZGF0YSBpbiBoYXNoZXIgc3RhdGUuAAAAEEhhc2hlckVtcHR5U3RhdGUAAAV6",
        "AAAABQAAACpFdmVudCBlbWl0dGVkIHdoZW4gdGhlIGNvbnRyYWN0IGlzIHBhdXNlZC4AAAAAAAAAAAAGUGF1c2VkAAAAAAABAAAABnBhdXNlZAAAAAAAAAAAAAI=",
        "AAAABQAAACxFdmVudCBlbWl0dGVkIHdoZW4gdGhlIGNvbnRyYWN0IGlzIHVucGF1c2VkLgAAAAAAAAAIVW5wYXVzZWQAAAABAAAACHVucGF1c2VkAAAAAAAAAAI=",
        "AAAABAAAAAAAAAAAAAAADVBhdXNhYmxlRXJyb3IAAAAAAAACAAAANFRoZSBvcGVyYXRpb24gZmFpbGVkIGJlY2F1c2UgdGhlIGNvbnRyYWN0IGlzIHBhdXNlZC4AAAANRW5mb3JjZWRQYXVzZQAAAAAAA+gAAAA4VGhlIG9wZXJhdGlvbiBmYWlsZWQgYmVjYXVzZSB0aGUgY29udHJhY3QgaXMgbm90IHBhdXNlZC4AAAANRXhwZWN0ZWRQYXVzZQAAAAAAA+k=",
        "AAAAAgAAACJTdG9yYWdlIGtleSBmb3IgdGhlIHBhdXNhYmxlIHN0YXRlAAAAAAAAAAAAElBhdXNhYmxlU3RvcmFnZUtleQAAAAAAAQAAAAAAAAAySW5kaWNhdGVzIHdoZXRoZXIgdGhlIGNvbnRyYWN0IGlzIGluIHBhdXNlZCBzdGF0ZS4AAAAAAAZQYXVzZWQAAA==" ]),
      options
    )
  }
  public readonly fromJSON = {
    execute: this.txFromJSON<null>,
        upgrade: this.txFromJSON<null>,
        add_policy: this.txFromJSON<null>,
        add_signer: this.txFromJSON<null>,
        remove_policy: this.txFromJSON<null>,
        remove_signer: this.txFromJSON<null>,
        add_context_rule: this.txFromJSON<ContextRule>,
        get_context_rule: this.txFromJSON<ContextRule>,
        get_context_rules: this.txFromJSON<Array<ContextRule>>,
        remove_context_rule: this.txFromJSON<null>,
        update_context_rule_name: this.txFromJSON<ContextRule>,
        update_context_rule_valid_until: this.txFromJSON<ContextRule>
  }
}