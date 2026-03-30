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
   * An internal ID counter (context rule, signer, or policy) has reached
   * its maximum value (`u32::MAX`) and cannot be incremented further.
   */
  3012: {message:"MathOverflow"},
  /**
   * External signer key data exceeds the maximum allowed size.
   */
  3013: {message:"KeyDataTooLarge"},
  /**
   * context_rule_ids length does not match auth_contexts length.
   */
  3014: {message:"ContextRuleIdsLengthMismatch"},
  /**
   * Context rule name exceeds the maximum allowed length.
   */
  3015: {message:"NameTooLong"},
  /**
   * A signer in `AuthPayload` is not part of any selected context rule.
   */
  3016: {message:"UnauthorizedSigner"}
}





/**
 * Represents different types of signers in the smart account system.
 */
export type Signer = {tag: "Delegated", values: readonly [string]} | {tag: "External", values: readonly [string, Buffer]};


/**
 * The authorization payload passed to `__check_auth`, bundling cryptographic
 * proofs with context rule selection.
 * 
 * This struct carries two distinct pieces of information that are both
 * required for authorization but cannot be derived from each other:
 * 
 * - `signers` maps each [`Signer`] to its raw signature bytes, providing
 * cryptographic proof that the signer actually signed the transaction
 * payload. A context rule stores which signer *identities* are authorized
 * (via `signer_ids`), but the rule does not contain the signatures
 * themselves — those must be supplied here.
 * 
 * - `context_rule_ids` tells the system which rule to validate for each auth
 * context. Because multiple rules can exist for the same context type, the
 * caller must explicitly select one per context rather than relying on
 * auto-discovery. Each entry is aligned by index with the `auth_contexts`
 * passed to `__check_auth`.
 * 
 * The length of `context_rule_ids` must equal the number of auth contexts;
 * a mismatch is rejected with
 * [`SmartAccountError::ContextRuleIdsLen
 */
export interface AuthPayload {
  /**
 * Per-context rule IDs, aligned by index with `auth_contexts`.
 */
context_rule_ids: Array<u32>;
  /**
 * Signature data mapped to each signer.
 */
signers: Map<Signer, Buffer>;
}


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
 * Global registry IDs for each policy, positionally aligned with
 * `policies`.
 */
policy_ids: Array<u32>;
  /**
 * Global registry IDs for each signer, positionally aligned with
 * `signers`.
 */
signer_ids: Array<u32>;
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

export interface Client {
  /**
   * Construct and simulate a execute transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Executes a function call on a target contract from within the smart
   * account context.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `target` - The address of the contract to call.
   * * `target_fn` - The function name to invoke on the target contract.
   * * `target_args` - Arguments to pass to the target function.
   * 
   * # Notes
   * 
   * Defaults to requiring authorization from the smart account itself
   * (`e.current_contract_address().require_auth()`) and then calling
   * `e.invoke_contract()`.
   */
  execute: ({target, target_fn, target_args}: {target: string, target_fn: string, target_args: Array<any>}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a upgrade transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  upgrade: ({new_wasm_hash, operator}: {new_wasm_hash: Buffer, operator: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a add_policy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Adds a new policy to an existing context rule, installs it, and returns
   * the assigned policy ID. The policy's `install` method will be called
   * during this operation.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_rule_id` - The ID of the context rule to modify.
   * * `policy` - The address of the policy contract to add.
   * * `install_param` - The installation parameter for the policy.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::ContextRuleNotFound`] - When no context rule
   * exists with the given ID.
   * * [`SmartAccountError::DuplicatePolicy`] - When the policy already
   * exists in the rule.
   * * [`SmartAccountError::TooManyPolicies`] - When adding would exceed
   * MAX_POLICIES (5).
   * 
   * # Events
   * 
   * * topics - `["policy_added", context_rule_id: u32]`
   * * data - `[policy_id: u32]`
   * 
   * # Notes
   * 
   * Defaults to requiring authorization from the smart account itself
   * (`e.current_contract_address().require_auth()`) and then delegating to
   * [`storage::add_policy`].
   */
  add_policy: ({context_rule_id, policy, install_param}: {context_rule_id: u32, policy: string, install_param: any}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a add_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Adds a new signer to an existing context rule, returning the assigned
   * signer ID.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_rule_id` - The ID of the context rule to modify.
   * * `signer` - The signer to add to the context rule.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::ContextRuleNotFound`] - When no context rule
   * exists with the given ID.
   * * [`SmartAccountError::DuplicateSigner`] - When the signer already
   * exists in the rule.
   * * [`SmartAccountError::TooManySigners`] - When adding would exceed
   * MAX_SIGNERS (15).
   * 
   * # Events
   * 
   * * topics - `["signer_added", context_rule_id: u32]`
   * * data - `[signer_id: u32]`
   * 
   * # Notes
   * 
   * Defaults to requiring authorization from the smart account itself
   * (`e.current_contract_address().require_auth()`) and then delegating to
   * [`storage::add_signer`].
   */
  add_signer: ({context_rule_id, signer}: {context_rule_id: u32, signer: Signer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_policy_id transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Retrieves the global registry ID for a policy.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `policy` - The policy address to look up.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::PolicyNotFound`] - When the policy is not
   * registered in the global registry.
   */
  get_policy_id: ({policy}: {policy: string}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a get_signer_id transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Retrieves the global registry ID for a signer.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `signer` - The signer to look up.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::SignerNotFound`] - When the signer is not
   * registered in the global registry.
   */
  get_signer_id: ({signer}: {signer: Signer}, options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a remove_policy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Removes a policy from an existing context rule and uninstalls it. The
   * policy's `uninstall` method will be called during this operation.
   * Removing the last policy is allowed only if the rule has at least
   * one signer.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_rule_id` - The ID of the context rule to modify.
   * * `policy_id` - The ID of the policy to remove from the context rule.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::ContextRuleNotFound`] - When no context rule
   * exists with the given ID.
   * * [`SmartAccountError::PolicyNotFound`] - When the policy doesn't exist
   * in the rule.
   * 
   * # Events
   * 
   * * topics - `["policy_removed", context_rule_id: u32]`
   * * data - `[policy_id: u32]`
   * 
   * # Notes
   * 
   * Defaults to requiring authorization from the smart account itself
   * (`e.current_contract_address().require_auth()`) and then delegating to
   * [`storage::remove_policy`].
   */
  remove_policy: ({context_rule_id, policy_id}: {context_rule_id: u32, policy_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a remove_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Removes a signer from an existing context rule. Removing the last signer
   * is allowed only if the rule has at least one policy.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_rule_id` - The ID of the context rule to modify.
   * * `signer_id` - The ID of the signer to remove from the context rule.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::ContextRuleNotFound`] - When no context rule
   * exists with the given ID.
   * * [`SmartAccountError::SignerNotFound`] - When the signer doesn't exist
   * in the rule.
   * 
   * # Events
   * 
   * * topics - `["signer_removed", context_rule_id: u32]`
   * * data - `[signer_id: u32]`
   * 
   * # Notes
   * 
   * Defaults to requiring authorization from the smart account itself
   * (`e.current_contract_address().require_auth()`) and then delegating to
   * [`storage::remove_signer`].
   */
  remove_signer: ({context_rule_id, signer_id}: {context_rule_id: u32, signer_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a add_context_rule transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Creates a new context rule with the specified configuration, returning
   * the newly created `ContextRule` with a unique ID assigned. Installs
   * all specified policies during creation.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_type` - The type of context this rule applies to.
   * * `name` - Human-readable name for the context rule.
   * * `valid_until` - Optional expiration ledger sequence.
   * * `signers` - List of signers authorized by this rule.
   * * `policies` - Map of policy addresses to their installation parameters.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::NoSignersAndPolicies`] - When both signers and
   * policies are empty.
   * * [`SmartAccountError::TooManySigners`] - When signers exceed
   * MAX_SIGNERS (15).
   * * [`SmartAccountError::TooManyPolicies`] - When policies exceed
   * MAX_POLICIES (5).
   * * [`SmartAccountError::DuplicateSigner`] - When the same signer appears
   * multiple times.
   * * [`SmartAccountError::PastValidUntil`] - When valid_until is in the
   * past.
   * * [`SmartAccountError::MathOverflow`] - When the context rule, si
   */
  add_context_rule: ({context_type, name, valid_until, signers, policies}: {context_type: ContextRuleType, name: string, valid_until: Option<u32>, signers: Array<Signer>, policies: Map<string, any>}, options?: MethodOptions) => Promise<AssembledTransaction<ContextRule>>

  /**
   * Construct and simulate a batch_add_signer transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  batch_add_signer: ({context_rule_id, signers}: {context_rule_id: u32, signers: Array<Signer>}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_context_rule transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Retrieves a context rule by its unique ID, returning the
   * `ContextRule` containing all metadata, signers, and policies.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_rule_id` - The unique identifier of the context rule to
   * retrieve.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::ContextRuleNotFound`] - When no context rule
   * exists with the given ID.
   */
  get_context_rule: ({context_rule_id}: {context_rule_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<ContextRule>>

  /**
   * Construct and simulate a remove_context_rule transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Removes a context rule and cleans up all associated data. This function
   * uninstalls all policies associated with the rule and removes all stored
   * data including signers, policies, and metadata.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_rule_id` - The ID of the context rule to remove.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::ContextRuleNotFound`] - When no context rule
   * exists with the given ID.
   * 
   * # Events
   * 
   * * topics - `["context_rule_removed", context_rule_id: u32]`
   * * data - `[]`
   * 
   * # Notes
   * 
   * Defaults to requiring authorization from the smart account itself
   * (`e.current_contract_address().require_auth()`) and then delegating to
   * [`storage::remove_context_rule`].
   */
  remove_context_rule: ({context_rule_id}: {context_rule_id: u32}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_context_rules_count transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Retrieves the number of all context rules, including expired rules.
   * Defaults to 0.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   */
  get_context_rules_count: (options?: MethodOptions) => Promise<AssembledTransaction<u32>>

  /**
   * Construct and simulate a update_context_rule_name transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Updates the name of an existing context rule, returning the updated
   * `ContextRule` with the new name.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_rule_id` - The ID of the context rule to update.
   * * `name` - The new human-readable name for the context rule.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::ContextRuleNotFound`] - When no context rule
   * exists with the given ID.
   * 
   * # Events
   * 
   * * topics - `["context_rule_meta_updated", context_rule_id: u32]`
   * * data - `[name: String, context_type: ContextRuleType, valid_until:
   * Option<u32>]`
   * 
   * # Notes
   * 
   * Defaults to requiring authorization from the smart account itself
   * (`e.current_contract_address().require_auth()`) and then delegating to
   * [`storage::update_context_rule_name`].
   */
  update_context_rule_name: ({context_rule_id, name}: {context_rule_id: u32, name: string}, options?: MethodOptions) => Promise<AssembledTransaction<ContextRule>>

  /**
   * Construct and simulate a update_context_rule_valid_until transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Updates the expiration time of an existing context rule, returning the
   * updated `ContextRule` with the new expiration time.
   * 
   * # Arguments
   * 
   * * `e` - Access to the Soroban environment.
   * * `context_rule_id` - The ID of the context rule to update.
   * * `valid_until` - New optional expiration ledger sequence. Use `None`
   * for no expiration.
   * 
   * # Errors
   * 
   * * [`SmartAccountError::ContextRuleNotFound`] - When no context rule
   * exists with the given ID.
   * * [`SmartAccountError::PastValidUntil`] - When valid_until is in the
   * past.
   * 
   * # Events
   * 
   * * topics - `["context_rule_meta_updated", context_rule_id: u32]`
   * * data - `[name: String, context_type: ContextRuleType, valid_until:
   * Option<u32>]`
   * 
   * # Notes
   * 
   * Defaults to requiring authorization from the smart account itself
   * (`e.current_contract_address().require_auth()`) and then delegating to
   * [`storage::update_context_rule_valid_until`].
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
      new ContractSpec([ "AAAAAAAAAeNFeGVjdXRlcyBhIGZ1bmN0aW9uIGNhbGwgb24gYSB0YXJnZXQgY29udHJhY3QgZnJvbSB3aXRoaW4gdGhlIHNtYXJ0CmFjY291bnQgY29udGV4dC4KCiMgQXJndW1lbnRzCgoqIGBlYCAtIEFjY2VzcyB0byB0aGUgU29yb2JhbiBlbnZpcm9ubWVudC4KKiBgdGFyZ2V0YCAtIFRoZSBhZGRyZXNzIG9mIHRoZSBjb250cmFjdCB0byBjYWxsLgoqIGB0YXJnZXRfZm5gIC0gVGhlIGZ1bmN0aW9uIG5hbWUgdG8gaW52b2tlIG9uIHRoZSB0YXJnZXQgY29udHJhY3QuCiogYHRhcmdldF9hcmdzYCAtIEFyZ3VtZW50cyB0byBwYXNzIHRvIHRoZSB0YXJnZXQgZnVuY3Rpb24uCgojIE5vdGVzCgpEZWZhdWx0cyB0byByZXF1aXJpbmcgYXV0aG9yaXphdGlvbiBmcm9tIHRoZSBzbWFydCBhY2NvdW50IGl0c2VsZgooYGUuY3VycmVudF9jb250cmFjdF9hZGRyZXNzKCkucmVxdWlyZV9hdXRoKClgKSBhbmQgdGhlbiBjYWxsaW5nCmBlLmludm9rZV9jb250cmFjdCgpYC4AAAAAB2V4ZWN1dGUAAAAAAwAAAAAAAAAGdGFyZ2V0AAAAAAATAAAAAAAAAAl0YXJnZXRfZm4AAAAAAAARAAAAAAAAAAt0YXJnZXRfYXJncwAAAAPqAAAAAAAAAAA=",
        "AAAAAAAAAAAAAAAHdXBncmFkZQAAAAACAAAAAAAAAA1uZXdfd2FzbV9oYXNoAAAAAAAD7gAAACAAAAAAAAAACG9wZXJhdG9yAAAAEwAAAAA=",
        "AAAAAAAAA6xBZGRzIGEgbmV3IHBvbGljeSB0byBhbiBleGlzdGluZyBjb250ZXh0IHJ1bGUsIGluc3RhbGxzIGl0LCBhbmQgcmV0dXJucwp0aGUgYXNzaWduZWQgcG9saWN5IElELiBUaGUgcG9saWN5J3MgYGluc3RhbGxgIG1ldGhvZCB3aWxsIGJlIGNhbGxlZApkdXJpbmcgdGhpcyBvcGVyYXRpb24uCgojIEFyZ3VtZW50cwoKKiBgZWAgLSBBY2Nlc3MgdG8gdGhlIFNvcm9iYW4gZW52aXJvbm1lbnQuCiogYGNvbnRleHRfcnVsZV9pZGAgLSBUaGUgSUQgb2YgdGhlIGNvbnRleHQgcnVsZSB0byBtb2RpZnkuCiogYHBvbGljeWAgLSBUaGUgYWRkcmVzcyBvZiB0aGUgcG9saWN5IGNvbnRyYWN0IHRvIGFkZC4KKiBgaW5zdGFsbF9wYXJhbWAgLSBUaGUgaW5zdGFsbGF0aW9uIHBhcmFtZXRlciBmb3IgdGhlIHBvbGljeS4KCiMgRXJyb3JzCgoqIFtgU21hcnRBY2NvdW50RXJyb3I6OkNvbnRleHRSdWxlTm90Rm91bmRgXSAtIFdoZW4gbm8gY29udGV4dCBydWxlCmV4aXN0cyB3aXRoIHRoZSBnaXZlbiBJRC4KKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpEdXBsaWNhdGVQb2xpY3lgXSAtIFdoZW4gdGhlIHBvbGljeSBhbHJlYWR5CmV4aXN0cyBpbiB0aGUgcnVsZS4KKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpUb29NYW55UG9saWNpZXNgXSAtIFdoZW4gYWRkaW5nIHdvdWxkIGV4Y2VlZApNQVhfUE9MSUNJRVMgKDUpLgoKIyBFdmVudHMKCiogdG9waWNzIC0gYFsicG9saWN5X2FkZGVkIiwgY29udGV4dF9ydWxlX2lkOiB1MzJdYAoqIGRhdGEgLSBgW3BvbGljeV9pZDogdTMyXWAKCiMgTm90ZXMKCkRlZmF1bHRzIHRvIHJlcXVpcmluZyBhdXRob3JpemF0aW9uIGZyb20gdGhlIHNtYXJ0IGFjY291bnQgaXRzZWxmCihgZS5jdXJyZW50X2NvbnRyYWN0X2FkZHJlc3MoKS5yZXF1aXJlX2F1dGgoKWApIGFuZCB0aGVuIGRlbGVnYXRpbmcgdG8KW2BzdG9yYWdlOjphZGRfcG9saWN5YF0uAAAACmFkZF9wb2xpY3kAAAAAAAMAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAAAAAAZwb2xpY3kAAAAAABMAAAAAAAAADWluc3RhbGxfcGFyYW0AAAAAAAAAAAAAAQAAAAQ=",
        "AAAAAAAAAxVBZGRzIGEgbmV3IHNpZ25lciB0byBhbiBleGlzdGluZyBjb250ZXh0IHJ1bGUsIHJldHVybmluZyB0aGUgYXNzaWduZWQKc2lnbmVyIElELgoKIyBBcmd1bWVudHMKCiogYGVgIC0gQWNjZXNzIHRvIHRoZSBTb3JvYmFuIGVudmlyb25tZW50LgoqIGBjb250ZXh0X3J1bGVfaWRgIC0gVGhlIElEIG9mIHRoZSBjb250ZXh0IHJ1bGUgdG8gbW9kaWZ5LgoqIGBzaWduZXJgIC0gVGhlIHNpZ25lciB0byBhZGQgdG8gdGhlIGNvbnRleHQgcnVsZS4KCiMgRXJyb3JzCgoqIFtgU21hcnRBY2NvdW50RXJyb3I6OkNvbnRleHRSdWxlTm90Rm91bmRgXSAtIFdoZW4gbm8gY29udGV4dCBydWxlCmV4aXN0cyB3aXRoIHRoZSBnaXZlbiBJRC4KKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpEdXBsaWNhdGVTaWduZXJgXSAtIFdoZW4gdGhlIHNpZ25lciBhbHJlYWR5CmV4aXN0cyBpbiB0aGUgcnVsZS4KKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpUb29NYW55U2lnbmVyc2BdIC0gV2hlbiBhZGRpbmcgd291bGQgZXhjZWVkCk1BWF9TSUdORVJTICgxNSkuCgojIEV2ZW50cwoKKiB0b3BpY3MgLSBgWyJzaWduZXJfYWRkZWQiLCBjb250ZXh0X3J1bGVfaWQ6IHUzMl1gCiogZGF0YSAtIGBbc2lnbmVyX2lkOiB1MzJdYAoKIyBOb3RlcwoKRGVmYXVsdHMgdG8gcmVxdWlyaW5nIGF1dGhvcml6YXRpb24gZnJvbSB0aGUgc21hcnQgYWNjb3VudCBpdHNlbGYKKGBlLmN1cnJlbnRfY29udHJhY3RfYWRkcmVzcygpLnJlcXVpcmVfYXV0aCgpYCkgYW5kIHRoZW4gZGVsZWdhdGluZyB0bwpbYHN0b3JhZ2U6OmFkZF9zaWduZXJgXS4AAAAAAAAKYWRkX3NpZ25lcgAAAAAAAgAAAAAAAAAPY29udGV4dF9ydWxlX2lkAAAAAAQAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAEAAAAE",
        "AAAAAAAAAfdWZXJpZnkgYXV0aG9yaXphdGlvbiBmb3IgdGhlIHNtYXJ0IGFjY291bnQuCgpUaGlzIGZ1bmN0aW9uIGlzIGNhbGxlZCBieSB0aGUgU29yb2JhbiBob3N0IHdoZW4gYXV0aG9yaXphdGlvbiBpcwpyZXF1aXJlZC4gSXQgdmFsaWRhdGVzIHNpZ25hdHVyZXMgYWdhaW5zdCB0aGUgY29uZmlndXJlZCBjb250ZXh0CnJ1bGVzIGFuZCBwb2xpY2llcy4KCiMgQXJndW1lbnRzCgoqIGBzaWduYXR1cmVfcGF5bG9hZGAgLSBIYXNoIG9mIHRoZSBkYXRhIHRoYXQgd2FzIHNpZ25lZAoqIGBzaWduYXR1cmVzYCAtIE1hcCBvZiBzaWduZXJzIHRvIHRoZWlyIHNpZ25hdHVyZSBkYXRhCiogYGF1dGhfY29udGV4dHNgIC0gQ29udGV4dHMgYmVpbmcgYXV0aG9yaXplZCAoY29udHJhY3QgY2FsbHMsCmRlcGxveW1lbnRzLCBldGMuKQoKIyBSZXR1cm5zCgoqIGBPaygoKSlgIGlmIGF1dGhvcml6YXRpb24gc3VjY2VlZHMKKiBgRXJyKFNtYXJ0QWNjb3VudEVycm9yKWAgaWYgYXV0aG9yaXphdGlvbiBmYWlscwAAAAAMX19jaGVja19hdXRoAAAAAwAAAAAAAAARc2lnbmF0dXJlX3BheWxvYWQAAAAAAAPuAAAAIAAAAAAAAAAKc2lnbmF0dXJlcwAAAAAH0AAAAAtBdXRoUGF5bG9hZAAAAAAAAAAADWF1dGhfY29udGV4dHMAAAAAAAPqAAAH0AAAAAdDb250ZXh0AAAAAAEAAAPpAAAAAgAAAAM=",
        "AAAAAAAAAP1DcmVhdGVzIGEgZGVmYXVsdCBjb250ZXh0IHJ1bGUgd2l0aCB0aGUgcHJvdmlkZWQgc2lnbmVycyBhbmQgcG9saWNpZXMuCgojIEFyZ3VtZW50cwoKKiBgc2lnbmVyc2AgLSBWZWN0b3Igb2Ygc2lnbmVycyAoRGVsZWdhdGVkIG9yIEV4dGVybmFsKSB0aGF0IGNhbgphdXRob3JpemUgdHJhbnNhY3Rpb25zCiogYHBvbGljaWVzYCAtIE1hcCBvZiBwb2xpY3kgY29udHJhY3QgYWRkcmVzc2VzIHRvIHRoZWlyIGluc3RhbGxhdGlvbgpwYXJhbWV0ZXJzAAAAAAAADV9fY29uc3RydWN0b3IAAAAAAAACAAAAAAAAAAdzaWduZXJzAAAAA+oAAAfQAAAABlNpZ25lcgAAAAAAAAAAAAhwb2xpY2llcwAAA+wAAAATAAAAAAAAAAA=",
        "AAAAAAAAAQJSZXRyaWV2ZXMgdGhlIGdsb2JhbCByZWdpc3RyeSBJRCBmb3IgYSBwb2xpY3kuCgojIEFyZ3VtZW50cwoKKiBgZWAgLSBBY2Nlc3MgdG8gdGhlIFNvcm9iYW4gZW52aXJvbm1lbnQuCiogYHBvbGljeWAgLSBUaGUgcG9saWN5IGFkZHJlc3MgdG8gbG9vayB1cC4KCiMgRXJyb3JzCgoqIFtgU21hcnRBY2NvdW50RXJyb3I6OlBvbGljeU5vdEZvdW5kYF0gLSBXaGVuIHRoZSBwb2xpY3kgaXMgbm90CnJlZ2lzdGVyZWQgaW4gdGhlIGdsb2JhbCByZWdpc3RyeS4AAAAAAA1nZXRfcG9saWN5X2lkAAAAAAAAAQAAAAAAAAAGcG9saWN5AAAAAAATAAAAAQAAAAQ=",
        "AAAAAAAAAPpSZXRyaWV2ZXMgdGhlIGdsb2JhbCByZWdpc3RyeSBJRCBmb3IgYSBzaWduZXIuCgojIEFyZ3VtZW50cwoKKiBgZWAgLSBBY2Nlc3MgdG8gdGhlIFNvcm9iYW4gZW52aXJvbm1lbnQuCiogYHNpZ25lcmAgLSBUaGUgc2lnbmVyIHRvIGxvb2sgdXAuCgojIEVycm9ycwoKKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpTaWduZXJOb3RGb3VuZGBdIC0gV2hlbiB0aGUgc2lnbmVyIGlzIG5vdApyZWdpc3RlcmVkIGluIHRoZSBnbG9iYWwgcmVnaXN0cnkuAAAAAAANZ2V0X3NpZ25lcl9pZAAAAAAAAAEAAAAAAAAABnNpZ25lcgAAAAAH0AAAAAZTaWduZXIAAAAAAAEAAAAE",
        "AAAAAAAAA1pSZW1vdmVzIGEgcG9saWN5IGZyb20gYW4gZXhpc3RpbmcgY29udGV4dCBydWxlIGFuZCB1bmluc3RhbGxzIGl0LiBUaGUKcG9saWN5J3MgYHVuaW5zdGFsbGAgbWV0aG9kIHdpbGwgYmUgY2FsbGVkIGR1cmluZyB0aGlzIG9wZXJhdGlvbi4KUmVtb3ZpbmcgdGhlIGxhc3QgcG9saWN5IGlzIGFsbG93ZWQgb25seSBpZiB0aGUgcnVsZSBoYXMgYXQgbGVhc3QKb25lIHNpZ25lci4KCiMgQXJndW1lbnRzCgoqIGBlYCAtIEFjY2VzcyB0byB0aGUgU29yb2JhbiBlbnZpcm9ubWVudC4KKiBgY29udGV4dF9ydWxlX2lkYCAtIFRoZSBJRCBvZiB0aGUgY29udGV4dCBydWxlIHRvIG1vZGlmeS4KKiBgcG9saWN5X2lkYCAtIFRoZSBJRCBvZiB0aGUgcG9saWN5IHRvIHJlbW92ZSBmcm9tIHRoZSBjb250ZXh0IHJ1bGUuCgojIEVycm9ycwoKKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpDb250ZXh0UnVsZU5vdEZvdW5kYF0gLSBXaGVuIG5vIGNvbnRleHQgcnVsZQpleGlzdHMgd2l0aCB0aGUgZ2l2ZW4gSUQuCiogW2BTbWFydEFjY291bnRFcnJvcjo6UG9saWN5Tm90Rm91bmRgXSAtIFdoZW4gdGhlIHBvbGljeSBkb2Vzbid0IGV4aXN0CmluIHRoZSBydWxlLgoKIyBFdmVudHMKCiogdG9waWNzIC0gYFsicG9saWN5X3JlbW92ZWQiLCBjb250ZXh0X3J1bGVfaWQ6IHUzMl1gCiogZGF0YSAtIGBbcG9saWN5X2lkOiB1MzJdYAoKIyBOb3RlcwoKRGVmYXVsdHMgdG8gcmVxdWlyaW5nIGF1dGhvcml6YXRpb24gZnJvbSB0aGUgc21hcnQgYWNjb3VudCBpdHNlbGYKKGBlLmN1cnJlbnRfY29udHJhY3RfYWRkcmVzcygpLnJlcXVpcmVfYXV0aCgpYCkgYW5kIHRoZW4gZGVsZWdhdGluZyB0bwpbYHN0b3JhZ2U6OnJlbW92ZV9wb2xpY3lgXS4AAAAAAA1yZW1vdmVfcG9saWN5AAAAAAAAAgAAAAAAAAAPY29udGV4dF9ydWxlX2lkAAAAAAQAAAAAAAAACXBvbGljeV9pZAAAAAAAAAQAAAAA",
        "AAAAAAAAAwJSZW1vdmVzIGEgc2lnbmVyIGZyb20gYW4gZXhpc3RpbmcgY29udGV4dCBydWxlLiBSZW1vdmluZyB0aGUgbGFzdCBzaWduZXIKaXMgYWxsb3dlZCBvbmx5IGlmIHRoZSBydWxlIGhhcyBhdCBsZWFzdCBvbmUgcG9saWN5LgoKIyBBcmd1bWVudHMKCiogYGVgIC0gQWNjZXNzIHRvIHRoZSBTb3JvYmFuIGVudmlyb25tZW50LgoqIGBjb250ZXh0X3J1bGVfaWRgIC0gVGhlIElEIG9mIHRoZSBjb250ZXh0IHJ1bGUgdG8gbW9kaWZ5LgoqIGBzaWduZXJfaWRgIC0gVGhlIElEIG9mIHRoZSBzaWduZXIgdG8gcmVtb3ZlIGZyb20gdGhlIGNvbnRleHQgcnVsZS4KCiMgRXJyb3JzCgoqIFtgU21hcnRBY2NvdW50RXJyb3I6OkNvbnRleHRSdWxlTm90Rm91bmRgXSAtIFdoZW4gbm8gY29udGV4dCBydWxlCmV4aXN0cyB3aXRoIHRoZSBnaXZlbiBJRC4KKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpTaWduZXJOb3RGb3VuZGBdIC0gV2hlbiB0aGUgc2lnbmVyIGRvZXNuJ3QgZXhpc3QKaW4gdGhlIHJ1bGUuCgojIEV2ZW50cwoKKiB0b3BpY3MgLSBgWyJzaWduZXJfcmVtb3ZlZCIsIGNvbnRleHRfcnVsZV9pZDogdTMyXWAKKiBkYXRhIC0gYFtzaWduZXJfaWQ6IHUzMl1gCgojIE5vdGVzCgpEZWZhdWx0cyB0byByZXF1aXJpbmcgYXV0aG9yaXphdGlvbiBmcm9tIHRoZSBzbWFydCBhY2NvdW50IGl0c2VsZgooYGUuY3VycmVudF9jb250cmFjdF9hZGRyZXNzKCkucmVxdWlyZV9hdXRoKClgKSBhbmQgdGhlbiBkZWxlZ2F0aW5nIHRvCltgc3RvcmFnZTo6cmVtb3ZlX3NpZ25lcmBdLgAAAAAADXJlbW92ZV9zaWduZXIAAAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAAAAAAJc2lnbmVyX2lkAAAAAAAABAAAAAA=",
        "AAAAAAAABABDcmVhdGVzIGEgbmV3IGNvbnRleHQgcnVsZSB3aXRoIHRoZSBzcGVjaWZpZWQgY29uZmlndXJhdGlvbiwgcmV0dXJuaW5nCnRoZSBuZXdseSBjcmVhdGVkIGBDb250ZXh0UnVsZWAgd2l0aCBhIHVuaXF1ZSBJRCBhc3NpZ25lZC4gSW5zdGFsbHMKYWxsIHNwZWNpZmllZCBwb2xpY2llcyBkdXJpbmcgY3JlYXRpb24uCgojIEFyZ3VtZW50cwoKKiBgZWAgLSBBY2Nlc3MgdG8gdGhlIFNvcm9iYW4gZW52aXJvbm1lbnQuCiogYGNvbnRleHRfdHlwZWAgLSBUaGUgdHlwZSBvZiBjb250ZXh0IHRoaXMgcnVsZSBhcHBsaWVzIHRvLgoqIGBuYW1lYCAtIEh1bWFuLXJlYWRhYmxlIG5hbWUgZm9yIHRoZSBjb250ZXh0IHJ1bGUuCiogYHZhbGlkX3VudGlsYCAtIE9wdGlvbmFsIGV4cGlyYXRpb24gbGVkZ2VyIHNlcXVlbmNlLgoqIGBzaWduZXJzYCAtIExpc3Qgb2Ygc2lnbmVycyBhdXRob3JpemVkIGJ5IHRoaXMgcnVsZS4KKiBgcG9saWNpZXNgIC0gTWFwIG9mIHBvbGljeSBhZGRyZXNzZXMgdG8gdGhlaXIgaW5zdGFsbGF0aW9uIHBhcmFtZXRlcnMuCgojIEVycm9ycwoKKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpOb1NpZ25lcnNBbmRQb2xpY2llc2BdIC0gV2hlbiBib3RoIHNpZ25lcnMgYW5kCnBvbGljaWVzIGFyZSBlbXB0eS4KKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpUb29NYW55U2lnbmVyc2BdIC0gV2hlbiBzaWduZXJzIGV4Y2VlZApNQVhfU0lHTkVSUyAoMTUpLgoqIFtgU21hcnRBY2NvdW50RXJyb3I6OlRvb01hbnlQb2xpY2llc2BdIC0gV2hlbiBwb2xpY2llcyBleGNlZWQKTUFYX1BPTElDSUVTICg1KS4KKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpEdXBsaWNhdGVTaWduZXJgXSAtIFdoZW4gdGhlIHNhbWUgc2lnbmVyIGFwcGVhcnMKbXVsdGlwbGUgdGltZXMuCiogW2BTbWFydEFjY291bnRFcnJvcjo6UGFzdFZhbGlkVW50aWxgXSAtIFdoZW4gdmFsaWRfdW50aWwgaXMgaW4gdGhlCnBhc3QuCiogW2BTbWFydEFjY291bnRFcnJvcjo6TWF0aE92ZXJmbG93YF0gLSBXaGVuIHRoZSBjb250ZXh0IHJ1bGUsIHNpAAAAEGFkZF9jb250ZXh0X3J1bGUAAAAFAAAAAAAAAAxjb250ZXh0X3R5cGUAAAfQAAAAD0NvbnRleHRSdWxlVHlwZQAAAAAAAAAABG5hbWUAAAAQAAAAAAAAAAt2YWxpZF91bnRpbAAAAAPoAAAABAAAAAAAAAAHc2lnbmVycwAAAAPqAAAH0AAAAAZTaWduZXIAAAAAAAAAAAAIcG9saWNpZXMAAAPsAAAAEwAAAAAAAAABAAAH0AAAAAtDb250ZXh0UnVsZQA=",
        "AAAAAAAAAAAAAAAQYmF0Y2hfYWRkX3NpZ25lcgAAAAIAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAAAAAAdzaWduZXJzAAAAA+oAAAfQAAAABlNpZ25lcgAAAAAAAA==",
        "AAAAAAAAAWVSZXRyaWV2ZXMgYSBjb250ZXh0IHJ1bGUgYnkgaXRzIHVuaXF1ZSBJRCwgcmV0dXJuaW5nIHRoZQpgQ29udGV4dFJ1bGVgIGNvbnRhaW5pbmcgYWxsIG1ldGFkYXRhLCBzaWduZXJzLCBhbmQgcG9saWNpZXMuCgojIEFyZ3VtZW50cwoKKiBgZWAgLSBBY2Nlc3MgdG8gdGhlIFNvcm9iYW4gZW52aXJvbm1lbnQuCiogYGNvbnRleHRfcnVsZV9pZGAgLSBUaGUgdW5pcXVlIGlkZW50aWZpZXIgb2YgdGhlIGNvbnRleHQgcnVsZSB0bwpyZXRyaWV2ZS4KCiMgRXJyb3JzCgoqIFtgU21hcnRBY2NvdW50RXJyb3I6OkNvbnRleHRSdWxlTm90Rm91bmRgXSAtIFdoZW4gbm8gY29udGV4dCBydWxlCmV4aXN0cyB3aXRoIHRoZSBnaXZlbiBJRC4AAAAAAAAQZ2V0X2NvbnRleHRfcnVsZQAAAAEAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAQAAB9AAAAALQ29udGV4dFJ1bGUA",
        "AAAAAAAAAqdSZW1vdmVzIGEgY29udGV4dCBydWxlIGFuZCBjbGVhbnMgdXAgYWxsIGFzc29jaWF0ZWQgZGF0YS4gVGhpcyBmdW5jdGlvbgp1bmluc3RhbGxzIGFsbCBwb2xpY2llcyBhc3NvY2lhdGVkIHdpdGggdGhlIHJ1bGUgYW5kIHJlbW92ZXMgYWxsIHN0b3JlZApkYXRhIGluY2x1ZGluZyBzaWduZXJzLCBwb2xpY2llcywgYW5kIG1ldGFkYXRhLgoKIyBBcmd1bWVudHMKCiogYGVgIC0gQWNjZXNzIHRvIHRoZSBTb3JvYmFuIGVudmlyb25tZW50LgoqIGBjb250ZXh0X3J1bGVfaWRgIC0gVGhlIElEIG9mIHRoZSBjb250ZXh0IHJ1bGUgdG8gcmVtb3ZlLgoKIyBFcnJvcnMKCiogW2BTbWFydEFjY291bnRFcnJvcjo6Q29udGV4dFJ1bGVOb3RGb3VuZGBdIC0gV2hlbiBubyBjb250ZXh0IHJ1bGUKZXhpc3RzIHdpdGggdGhlIGdpdmVuIElELgoKIyBFdmVudHMKCiogdG9waWNzIC0gYFsiY29udGV4dF9ydWxlX3JlbW92ZWQiLCBjb250ZXh0X3J1bGVfaWQ6IHUzMl1gCiogZGF0YSAtIGBbXWAKCiMgTm90ZXMKCkRlZmF1bHRzIHRvIHJlcXVpcmluZyBhdXRob3JpemF0aW9uIGZyb20gdGhlIHNtYXJ0IGFjY291bnQgaXRzZWxmCihgZS5jdXJyZW50X2NvbnRyYWN0X2FkZHJlc3MoKS5yZXF1aXJlX2F1dGgoKWApIGFuZCB0aGVuIGRlbGVnYXRpbmcgdG8KW2BzdG9yYWdlOjpyZW1vdmVfY29udGV4dF9ydWxlYF0uAAAAABNyZW1vdmVfY29udGV4dF9ydWxlAAAAAAEAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAA==",
        "AAAAAAAAAItSZXRyaWV2ZXMgdGhlIG51bWJlciBvZiBhbGwgY29udGV4dCBydWxlcywgaW5jbHVkaW5nIGV4cGlyZWQgcnVsZXMuCkRlZmF1bHRzIHRvIDAuCgojIEFyZ3VtZW50cwoKKiBgZWAgLSBBY2Nlc3MgdG8gdGhlIFNvcm9iYW4gZW52aXJvbm1lbnQuAAAAABdnZXRfY29udGV4dF9ydWxlc19jb3VudAAAAAAAAAAAAQAAAAQ=",
        "AAAAAAAAAthVcGRhdGVzIHRoZSBuYW1lIG9mIGFuIGV4aXN0aW5nIGNvbnRleHQgcnVsZSwgcmV0dXJuaW5nIHRoZSB1cGRhdGVkCmBDb250ZXh0UnVsZWAgd2l0aCB0aGUgbmV3IG5hbWUuCgojIEFyZ3VtZW50cwoKKiBgZWAgLSBBY2Nlc3MgdG8gdGhlIFNvcm9iYW4gZW52aXJvbm1lbnQuCiogYGNvbnRleHRfcnVsZV9pZGAgLSBUaGUgSUQgb2YgdGhlIGNvbnRleHQgcnVsZSB0byB1cGRhdGUuCiogYG5hbWVgIC0gVGhlIG5ldyBodW1hbi1yZWFkYWJsZSBuYW1lIGZvciB0aGUgY29udGV4dCBydWxlLgoKIyBFcnJvcnMKCiogW2BTbWFydEFjY291bnRFcnJvcjo6Q29udGV4dFJ1bGVOb3RGb3VuZGBdIC0gV2hlbiBubyBjb250ZXh0IHJ1bGUKZXhpc3RzIHdpdGggdGhlIGdpdmVuIElELgoKIyBFdmVudHMKCiogdG9waWNzIC0gYFsiY29udGV4dF9ydWxlX21ldGFfdXBkYXRlZCIsIGNvbnRleHRfcnVsZV9pZDogdTMyXWAKKiBkYXRhIC0gYFtuYW1lOiBTdHJpbmcsIGNvbnRleHRfdHlwZTogQ29udGV4dFJ1bGVUeXBlLCB2YWxpZF91bnRpbDoKT3B0aW9uPHUzMj5dYAoKIyBOb3RlcwoKRGVmYXVsdHMgdG8gcmVxdWlyaW5nIGF1dGhvcml6YXRpb24gZnJvbSB0aGUgc21hcnQgYWNjb3VudCBpdHNlbGYKKGBlLmN1cnJlbnRfY29udHJhY3RfYWRkcmVzcygpLnJlcXVpcmVfYXV0aCgpYCkgYW5kIHRoZW4gZGVsZWdhdGluZyB0bwpbYHN0b3JhZ2U6OnVwZGF0ZV9jb250ZXh0X3J1bGVfbmFtZWBdLgAAABh1cGRhdGVfY29udGV4dF9ydWxlX25hbWUAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAAAAAAEbmFtZQAAABAAAAABAAAH0AAAAAtDb250ZXh0UnVsZQA=",
        "AAAAAAAAA1xVcGRhdGVzIHRoZSBleHBpcmF0aW9uIHRpbWUgb2YgYW4gZXhpc3RpbmcgY29udGV4dCBydWxlLCByZXR1cm5pbmcgdGhlCnVwZGF0ZWQgYENvbnRleHRSdWxlYCB3aXRoIHRoZSBuZXcgZXhwaXJhdGlvbiB0aW1lLgoKIyBBcmd1bWVudHMKCiogYGVgIC0gQWNjZXNzIHRvIHRoZSBTb3JvYmFuIGVudmlyb25tZW50LgoqIGBjb250ZXh0X3J1bGVfaWRgIC0gVGhlIElEIG9mIHRoZSBjb250ZXh0IHJ1bGUgdG8gdXBkYXRlLgoqIGB2YWxpZF91bnRpbGAgLSBOZXcgb3B0aW9uYWwgZXhwaXJhdGlvbiBsZWRnZXIgc2VxdWVuY2UuIFVzZSBgTm9uZWAKZm9yIG5vIGV4cGlyYXRpb24uCgojIEVycm9ycwoKKiBbYFNtYXJ0QWNjb3VudEVycm9yOjpDb250ZXh0UnVsZU5vdEZvdW5kYF0gLSBXaGVuIG5vIGNvbnRleHQgcnVsZQpleGlzdHMgd2l0aCB0aGUgZ2l2ZW4gSUQuCiogW2BTbWFydEFjY291bnRFcnJvcjo6UGFzdFZhbGlkVW50aWxgXSAtIFdoZW4gdmFsaWRfdW50aWwgaXMgaW4gdGhlCnBhc3QuCgojIEV2ZW50cwoKKiB0b3BpY3MgLSBgWyJjb250ZXh0X3J1bGVfbWV0YV91cGRhdGVkIiwgY29udGV4dF9ydWxlX2lkOiB1MzJdYAoqIGRhdGEgLSBgW25hbWU6IFN0cmluZywgY29udGV4dF90eXBlOiBDb250ZXh0UnVsZVR5cGUsIHZhbGlkX3VudGlsOgpPcHRpb248dTMyPl1gCgojIE5vdGVzCgpEZWZhdWx0cyB0byByZXF1aXJpbmcgYXV0aG9yaXphdGlvbiBmcm9tIHRoZSBzbWFydCBhY2NvdW50IGl0c2VsZgooYGUuY3VycmVudF9jb250cmFjdF9hZGRyZXNzKCkucmVxdWlyZV9hdXRoKClgKSBhbmQgdGhlbiBkZWxlZ2F0aW5nIHRvCltgc3RvcmFnZTo6dXBkYXRlX2NvbnRleHRfcnVsZV92YWxpZF91bnRpbGBdLgAAAB91cGRhdGVfY29udGV4dF9ydWxlX3ZhbGlkX3VudGlsAAAAAAIAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAAAAAAt2YWxpZF91bnRpbAAAAAPoAAAABAAAAAEAAAfQAAAAC0NvbnRleHRSdWxlAA==",
        "AAAABQAAADdFdmVudCBlbWl0dGVkIHdoZW4gYSBwb2xpY3kgaXMgYWRkZWQgdG8gYSBjb250ZXh0IHJ1bGUuAAAAAAAAAAALUG9saWN5QWRkZWQAAAAAAQAAAAxwb2xpY3lfYWRkZWQAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAACXBvbGljeV9pZAAAAAAAAAQAAAAAAAAAAg==",
        "AAAABQAAADdFdmVudCBlbWl0dGVkIHdoZW4gYSBzaWduZXIgaXMgYWRkZWQgdG8gYSBjb250ZXh0IHJ1bGUuAAAAAAAAAAALU2lnbmVyQWRkZWQAAAAAAQAAAAxzaWduZXJfYWRkZWQAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAACXNpZ25lcl9pZAAAAAAAAAQAAAAAAAAAAg==",
        "AAAABQAAADtFdmVudCBlbWl0dGVkIHdoZW4gYSBwb2xpY3kgaXMgcmVtb3ZlZCBmcm9tIGEgY29udGV4dCBydWxlLgAAAAAAAAAADVBvbGljeVJlbW92ZWQAAAAAAAABAAAADnBvbGljeV9yZW1vdmVkAAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAACXBvbGljeV9pZAAAAAAAAAQAAAAAAAAAAg==",
        "AAAABQAAADtFdmVudCBlbWl0dGVkIHdoZW4gYSBzaWduZXIgaXMgcmVtb3ZlZCBmcm9tIGEgY29udGV4dCBydWxlLgAAAAAAAAAADVNpZ25lclJlbW92ZWQAAAAAAAABAAAADnNpZ25lcl9yZW1vdmVkAAAAAAACAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAACXNpZ25lcl9pZAAAAAAAAAQAAAAAAAAAAg==",
        "AAAABQAAACtFdmVudCBlbWl0dGVkIHdoZW4gYSBjb250ZXh0IHJ1bGUgaXMgYWRkZWQuAAAAAAAAAAAQQ29udGV4dFJ1bGVBZGRlZAAAAAEAAAASY29udGV4dF9ydWxlX2FkZGVkAAAAAAAGAAAAAAAAAA9jb250ZXh0X3J1bGVfaWQAAAAABAAAAAEAAAAAAAAABG5hbWUAAAAQAAAAAAAAAAAAAAAMY29udGV4dF90eXBlAAAH0AAAAA9Db250ZXh0UnVsZVR5cGUAAAAAAAAAAAAAAAALdmFsaWRfdW50aWwAAAAD6AAAAAQAAAAAAAAAAAAAAApzaWduZXJfaWRzAAAAAAPqAAAABAAAAAAAAAAAAAAACnBvbGljeV9pZHMAAAAAA+oAAAAEAAAAAAAAAAI=",
        "AAAABQAAAEFFdmVudCBlbWl0dGVkIHdoZW4gYSBwb2xpY3kgaXMgcmVnaXN0ZXJlZCBpbiB0aGUgZ2xvYmFsIHJlZ2lzdHJ5LgAAAAAAAAAAAAAQUG9saWN5UmVnaXN0ZXJlZAAAAAEAAAARcG9saWN5X3JlZ2lzdGVyZWQAAAAAAAACAAAAAAAAAAlwb2xpY3lfaWQAAAAAAAAEAAAAAQAAAAAAAAAGcG9saWN5AAAAAAATAAAAAAAAAAI=",
        "AAAABQAAAEFFdmVudCBlbWl0dGVkIHdoZW4gYSBzaWduZXIgaXMgcmVnaXN0ZXJlZCBpbiB0aGUgZ2xvYmFsIHJlZ2lzdHJ5LgAAAAAAAAAAAAAQU2lnbmVyUmVnaXN0ZXJlZAAAAAEAAAARc2lnbmVyX3JlZ2lzdGVyZWQAAAAAAAACAAAAAAAAAAlzaWduZXJfaWQAAAAAAAAEAAAAAQAAAAAAAAAGc2lnbmVyAAAAAAfQAAAABlNpZ25lcgAAAAAAAAAAAAI=",
        "AAAABAAAAClFcnJvciBjb2RlcyBmb3Igc21hcnQgYWNjb3VudCBvcGVyYXRpb25zLgAAAAAAAAAAAAARU21hcnRBY2NvdW50RXJyb3IAAAAAAAAQAAAAKlRoZSBzcGVjaWZpZWQgY29udGV4dCBydWxlIGRvZXMgbm90IGV4aXN0LgAAAAAAE0NvbnRleHRSdWxlTm90Rm91bmQAAAALuAAAADpUaGUgcHJvdmlkZWQgY29udGV4dCBjYW5ub3QgYmUgdmFsaWRhdGVkIGFnYWluc3QgYW55IHJ1bGUuAAAAAAASVW52YWxpZGF0ZWRDb250ZXh0AAAAAAu6AAAAJ0V4dGVybmFsIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24gZmFpbGVkLgAAAAAaRXh0ZXJuYWxWZXJpZmljYXRpb25GYWlsZWQAAAAAC7sAAAA1Q29udGV4dCBydWxlIG11c3QgaGF2ZSBhdCBsZWFzdCBvbmUgc2lnbmVyIG9yIHBvbGljeS4AAAAAAAAUTm9TaWduZXJzQW5kUG9saWNpZXMAAAu8AAAAKVRoZSB2YWxpZF91bnRpbCB0aW1lc3RhbXAgaXMgaW4gdGhlIHBhc3QuAAAAAAAADlBhc3RWYWxpZFVudGlsAAAAAAu9AAAAI1RoZSBzcGVjaWZpZWQgc2lnbmVyIHdhcyBub3QgZm91bmQuAAAAAA5TaWduZXJOb3RGb3VuZAAAAAALvgAAAC5UaGUgc2lnbmVyIGFscmVhZHkgZXhpc3RzIGluIHRoZSBjb250ZXh0IHJ1bGUuAAAAAAAPRHVwbGljYXRlU2lnbmVyAAAAC78AAAAjVGhlIHNwZWNpZmllZCBwb2xpY3kgd2FzIG5vdCBmb3VuZC4AAAAADlBvbGljeU5vdEZvdW5kAAAAAAvAAAAALlRoZSBwb2xpY3kgYWxyZWFkeSBleGlzdHMgaW4gdGhlIGNvbnRleHQgcnVsZS4AAAAAAA9EdXBsaWNhdGVQb2xpY3kAAAALwQAAACVUb28gbWFueSBzaWduZXJzIGluIHRoZSBjb250ZXh0IHJ1bGUuAAAAAAAADlRvb01hbnlTaWduZXJzAAAAAAvCAAAAJlRvbyBtYW55IHBvbGljaWVzIGluIHRoZSBjb250ZXh0IHJ1bGUuAAAAAAAPVG9vTWFueVBvbGljaWVzAAAAC8MAAACGQW4gaW50ZXJuYWwgSUQgY291bnRlciAoY29udGV4dCBydWxlLCBzaWduZXIsIG9yIHBvbGljeSkgaGFzIHJlYWNoZWQKaXRzIG1heGltdW0gdmFsdWUgKGB1MzI6Ok1BWGApIGFuZCBjYW5ub3QgYmUgaW5jcmVtZW50ZWQgZnVydGhlci4AAAAAAAxNYXRoT3ZlcmZsb3cAAAvEAAAAOkV4dGVybmFsIHNpZ25lciBrZXkgZGF0YSBleGNlZWRzIHRoZSBtYXhpbXVtIGFsbG93ZWQgc2l6ZS4AAAAAAA9LZXlEYXRhVG9vTGFyZ2UAAAALxQAAADxjb250ZXh0X3J1bGVfaWRzIGxlbmd0aCBkb2VzIG5vdCBtYXRjaCBhdXRoX2NvbnRleHRzIGxlbmd0aC4AAAAcQ29udGV4dFJ1bGVJZHNMZW5ndGhNaXNtYXRjaAAAC8YAAAA1Q29udGV4dCBydWxlIG5hbWUgZXhjZWVkcyB0aGUgbWF4aW11bSBhbGxvd2VkIGxlbmd0aC4AAAAAAAALTmFtZVRvb0xvbmcAAAALxwAAAENBIHNpZ25lciBpbiBgQXV0aFBheWxvYWRgIGlzIG5vdCBwYXJ0IG9mIGFueSBzZWxlY3RlZCBjb250ZXh0IHJ1bGUuAAAAABJVbmF1dGhvcml6ZWRTaWduZXIAAAAAC8g=",
        "AAAABQAAAC1FdmVudCBlbWl0dGVkIHdoZW4gYSBjb250ZXh0IHJ1bGUgaXMgcmVtb3ZlZC4AAAAAAAAAAAAAEkNvbnRleHRSdWxlUmVtb3ZlZAAAAAAAAQAAABRjb250ZXh0X3J1bGVfcmVtb3ZlZAAAAAEAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAQAAAAI=",
        "AAAABQAAAEVFdmVudCBlbWl0dGVkIHdoZW4gYSBwb2xpY3kgaXMgZGVyZWdpc3RlcmVkIGZyb20gdGhlIGdsb2JhbCByZWdpc3RyeS4AAAAAAAAAAAAAElBvbGljeURlcmVnaXN0ZXJlZAAAAAAAAQAAABNwb2xpY3lfZGVyZWdpc3RlcmVkAAAAAAEAAAAAAAAACXBvbGljeV9pZAAAAAAAAAQAAAABAAAAAg==",
        "AAAABQAAAEVFdmVudCBlbWl0dGVkIHdoZW4gYSBzaWduZXIgaXMgZGVyZWdpc3RlcmVkIGZyb20gdGhlIGdsb2JhbCByZWdpc3RyeS4AAAAAAAAAAAAAElNpZ25lckRlcmVnaXN0ZXJlZAAAAAAAAQAAABNzaWduZXJfZGVyZWdpc3RlcmVkAAAAAAEAAAAAAAAACXNpZ25lcl9pZAAAAAAAAAQAAAABAAAAAg==",
        "AAAABQAAAEJFdmVudCBlbWl0dGVkIHdoZW4gYSBjb250ZXh0IHJ1bGUgbmFtZSBvciB2YWxpZF91bnRpbCBhcmUgdXBkYXRlZC4AAAAAAAAAAAAWQ29udGV4dFJ1bGVNZXRhVXBkYXRlZAAAAAAAAQAAABljb250ZXh0X3J1bGVfbWV0YV91cGRhdGVkAAAAAAAAAwAAAAAAAAAPY29udGV4dF9ydWxlX2lkAAAAAAQAAAABAAAAAAAAAARuYW1lAAAAEAAAAAAAAAAAAAAAC3ZhbGlkX3VudGlsAAAAA+gAAAAEAAAAAAAAAAI=",
        "AAAAAgAAAEJSZXByZXNlbnRzIGRpZmZlcmVudCB0eXBlcyBvZiBzaWduZXJzIGluIHRoZSBzbWFydCBhY2NvdW50IHN5c3RlbS4AAAAAAAAAAAAGU2lnbmVyAAAAAAACAAAAAQAAAD1BIGRlbGVnYXRlZCBzaWduZXIgdGhhdCB1c2VzIGJ1aWx0LWluIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24uAAAAAAAACURlbGVnYXRlZAAAAAAAAAEAAAATAAAAAQAAAHJBbiBleHRlcm5hbCBzaWduZXIgd2l0aCBjdXN0b20gdmVyaWZpY2F0aW9uIGxvZ2ljLgpDb250YWlucyB0aGUgdmVyaWZpZXIgY29udHJhY3QgYWRkcmVzcyBhbmQgdGhlIHB1YmxpYyBrZXkgZGF0YS4AAAAAAAhFeHRlcm5hbAAAAAIAAAATAAAADg==",
        "AAAAAQAABABUaGUgYXV0aG9yaXphdGlvbiBwYXlsb2FkIHBhc3NlZCB0byBgX19jaGVja19hdXRoYCwgYnVuZGxpbmcgY3J5cHRvZ3JhcGhpYwpwcm9vZnMgd2l0aCBjb250ZXh0IHJ1bGUgc2VsZWN0aW9uLgoKVGhpcyBzdHJ1Y3QgY2FycmllcyB0d28gZGlzdGluY3QgcGllY2VzIG9mIGluZm9ybWF0aW9uIHRoYXQgYXJlIGJvdGgKcmVxdWlyZWQgZm9yIGF1dGhvcml6YXRpb24gYnV0IGNhbm5vdCBiZSBkZXJpdmVkIGZyb20gZWFjaCBvdGhlcjoKCi0gYHNpZ25lcnNgIG1hcHMgZWFjaCBbYFNpZ25lcmBdIHRvIGl0cyByYXcgc2lnbmF0dXJlIGJ5dGVzLCBwcm92aWRpbmcKY3J5cHRvZ3JhcGhpYyBwcm9vZiB0aGF0IHRoZSBzaWduZXIgYWN0dWFsbHkgc2lnbmVkIHRoZSB0cmFuc2FjdGlvbgpwYXlsb2FkLiBBIGNvbnRleHQgcnVsZSBzdG9yZXMgd2hpY2ggc2lnbmVyICppZGVudGl0aWVzKiBhcmUgYXV0aG9yaXplZAoodmlhIGBzaWduZXJfaWRzYCksIGJ1dCB0aGUgcnVsZSBkb2VzIG5vdCBjb250YWluIHRoZSBzaWduYXR1cmVzCnRoZW1zZWx2ZXMg4oCUIHRob3NlIG11c3QgYmUgc3VwcGxpZWQgaGVyZS4KCi0gYGNvbnRleHRfcnVsZV9pZHNgIHRlbGxzIHRoZSBzeXN0ZW0gd2hpY2ggcnVsZSB0byB2YWxpZGF0ZSBmb3IgZWFjaCBhdXRoCmNvbnRleHQuIEJlY2F1c2UgbXVsdGlwbGUgcnVsZXMgY2FuIGV4aXN0IGZvciB0aGUgc2FtZSBjb250ZXh0IHR5cGUsIHRoZQpjYWxsZXIgbXVzdCBleHBsaWNpdGx5IHNlbGVjdCBvbmUgcGVyIGNvbnRleHQgcmF0aGVyIHRoYW4gcmVseWluZyBvbgphdXRvLWRpc2NvdmVyeS4gRWFjaCBlbnRyeSBpcyBhbGlnbmVkIGJ5IGluZGV4IHdpdGggdGhlIGBhdXRoX2NvbnRleHRzYApwYXNzZWQgdG8gYF9fY2hlY2tfYXV0aGAuCgpUaGUgbGVuZ3RoIG9mIGBjb250ZXh0X3J1bGVfaWRzYCBtdXN0IGVxdWFsIHRoZSBudW1iZXIgb2YgYXV0aCBjb250ZXh0czsKYSBtaXNtYXRjaCBpcyByZWplY3RlZCB3aXRoCltgU21hcnRBY2NvdW50RXJyb3I6OkNvbnRleHRSdWxlSWRzTGVuAAAAAAAAAAtBdXRoUGF5bG9hZAAAAAACAAAAPFBlci1jb250ZXh0IHJ1bGUgSURzLCBhbGlnbmVkIGJ5IGluZGV4IHdpdGggYGF1dGhfY29udGV4dHNgLgAAABBjb250ZXh0X3J1bGVfaWRzAAAD6gAAAAQAAAAlU2lnbmF0dXJlIGRhdGEgbWFwcGVkIHRvIGVhY2ggc2lnbmVyLgAAAAAAAAdzaWduZXJzAAAAA+wAAAfQAAAABlNpZ25lcgAAAAAADg==",
        "AAAAAQAAADxBIGNvbXBsZXRlIGNvbnRleHQgcnVsZSBkZWZpbmluZyBhdXRob3JpemF0aW9uIHJlcXVpcmVtZW50cy4AAAAAAAAAC0NvbnRleHRSdWxlAAAAAAgAAAApVGhlIHR5cGUgb2YgY29udGV4dCB0aGlzIHJ1bGUgYXBwbGllcyB0by4AAAAAAAAMY29udGV4dF90eXBlAAAH0AAAAA9Db250ZXh0UnVsZVR5cGUAAAAAJ1VuaXF1ZSBpZGVudGlmaWVyIGZvciB0aGUgY29udGV4dCBydWxlLgAAAAACaWQAAAAAAAQAAAApSHVtYW4tcmVhZGFibGUgbmFtZSBmb3IgdGhlIGNvbnRleHQgcnVsZS4AAAAAAAAEbmFtZQAAABAAAAAwTGlzdCBvZiBwb2xpY3kgY29udHJhY3RzIHRoYXQgbXVzdCBiZSBzYXRpc2ZpZWQuAAAACHBvbGljaWVzAAAD6gAAABMAAABKR2xvYmFsIHJlZ2lzdHJ5IElEcyBmb3IgZWFjaCBwb2xpY3ksIHBvc2l0aW9uYWxseSBhbGlnbmVkIHdpdGgKYHBvbGljaWVzYC4AAAAAAApwb2xpY3lfaWRzAAAAAAPqAAAABAAAAElHbG9iYWwgcmVnaXN0cnkgSURzIGZvciBlYWNoIHNpZ25lciwgcG9zaXRpb25hbGx5IGFsaWduZWQgd2l0aApgc2lnbmVyc2AuAAAAAAAACnNpZ25lcl9pZHMAAAAAA+oAAAAEAAAAKExpc3Qgb2Ygc2lnbmVycyBhdXRob3JpemVkIGJ5IHRoaXMgcnVsZS4AAAAHc2lnbmVycwAAAAPqAAAH0AAAAAZTaWduZXIAAAAAADFPcHRpb25hbCBleHBpcmF0aW9uIGxlZGdlciBzZXF1ZW5jZSBmb3IgdGhlIHJ1bGUuAAAAAAAAC3ZhbGlkX3VudGlsAAAAA+gAAAAE",
        "AAAAAgAAAEBUeXBlcyBvZiBjb250ZXh0cyB0aGF0IGNhbiBiZSBhdXRob3JpemVkIGJ5IHNtYXJ0IGFjY291bnQgcnVsZXMuAAAAAAAAAA9Db250ZXh0UnVsZVR5cGUAAAAAAwAAAAAAAAAtRGVmYXVsdCBydWxlcyB0aGF0IGNhbiBhdXRob3JpemUgYW55IGNvbnRleHQuAAAAAAAAB0RlZmF1bHQAAAAAAQAAADBSdWxlcyBzcGVjaWZpYyB0byBjYWxsaW5nIGEgcGFydGljdWxhciBjb250cmFjdC4AAAAMQ2FsbENvbnRyYWN0AAAAAQAAABMAAAABAAAAQlJ1bGVzIHNwZWNpZmljIHRvIGNyZWF0aW5nIGEgY29udHJhY3Qgd2l0aCBhIHBhcnRpY3VsYXIgV0FTTSBoYXNoLgAAAAAADkNyZWF0ZUNvbnRyYWN0AAAAAAABAAAD7gAAACA=" ]),
      options
    )
  }
  public readonly fromJSON = {
    execute: this.txFromJSON<null>,
        upgrade: this.txFromJSON<null>,
        add_policy: this.txFromJSON<u32>,
        add_signer: this.txFromJSON<u32>,
        get_policy_id: this.txFromJSON<u32>,
        get_signer_id: this.txFromJSON<u32>,
        remove_policy: this.txFromJSON<null>,
        remove_signer: this.txFromJSON<null>,
        add_context_rule: this.txFromJSON<ContextRule>,
        batch_add_signer: this.txFromJSON<null>,
        get_context_rule: this.txFromJSON<ContextRule>,
        remove_context_rule: this.txFromJSON<null>,
        get_context_rules_count: this.txFromJSON<u32>,
        update_context_rule_name: this.txFromJSON<ContextRule>,
        update_context_rule_valid_until: this.txFromJSON<ContextRule>
  }
}