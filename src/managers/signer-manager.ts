/**
 * Signer Manager
 *
 * Manages signers (passkeys and delegated accounts) for context rules.
 */

import base64url from "base64url";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import type { AuthenticatorTransportFuture } from "@simplewebauthn/browser";
import type { Signer as ContractSigner } from "smart-account-kit-bindings";
import type { SmartAccountEventEmitter } from "../events";
import type { StorageAdapter, StoredCredential } from "../types";
import { buildKeyData } from "../utils";
import { SECP256R1_PUBLIC_KEY_SIZE } from "../constants";

/** Dependencies required by SignerManager */
export interface SignerManagerDeps {
  /** Get the connected wallet client, throws if not connected */
  requireWallet: () => {
    wallet: {
      add_signer: (args: { context_rule_id: number; signer: ContractSigner }) => Promise<AssembledTransaction<null>>;
      remove_signer: (args: { context_rule_id: number; signer: ContractSigner }) => Promise<AssembledTransaction<null>>;
    };
    contractId: string;
  };
  /** Storage adapter for credentials */
  storage: StorageAdapter;
  /** Event emitter */
  events: SmartAccountEventEmitter;
  /** WebAuthn verifier contract address */
  webauthnVerifierAddress: string;
  /** Create a passkey via WebAuthn */
  createPasskey: (appName: string, userName: string) => Promise<{
    rawResponse: { response: { transports?: AuthenticatorTransportFuture[] } };
    credentialId: string;
    publicKey: Uint8Array;
  }>;
}

/**
 * Manages signers for smart account context rules.
 */
export class SignerManager {
  constructor(private deps: SignerManagerDeps) {}

  /**
   * Add a new passkey signer to a context rule.
   * Creates a new WebAuthn passkey and registers it as an External signer.
   */
  async addPasskey(
    contextRuleId: number,
    appName: string,
    userName: string,
    options?: { nickname?: string }
  ) {
    const { wallet, contractId } = this.deps.requireWallet();

    // Create the passkey
    const { rawResponse, credentialId, publicKey } = await this.deps.createPasskey(
      appName,
      userName
    );

    // Store the credential
    const storedCredential: StoredCredential = {
      credentialId,
      publicKey,
      contractId,
      nickname: options?.nickname ?? `${userName} - ${new Date().toLocaleDateString()}`,
      createdAt: Date.now(),
      transports: rawResponse.response.transports,
      isPrimary: false,
      contextRuleId,
    };

    await this.deps.storage.save(storedCredential);

    // Emit credential created event
    this.deps.events.emit("credentialCreated", { credential: storedCredential });

    // Build the External signer for the contract
    const keyData = buildKeyData(publicKey, credentialId);
    const signer: ContractSigner = {
      tag: "External",
      values: [this.deps.webauthnVerifierAddress, keyData],
    };

    // Build and return the add_signer transaction
    const transaction = await wallet.add_signer({
      context_rule_id: contextRuleId,
      signer,
    });

    return {
      credentialId,
      publicKey,
      transaction,
    };
  }

  /**
   * Add a delegated signer (Stellar account) to a context rule.
   */
  async addDelegated(contextRuleId: number, publicKey: string) {
    const { wallet } = this.deps.requireWallet();

    const signer: ContractSigner = {
      tag: "Delegated",
      values: [publicKey],
    };

    return wallet.add_signer({
      context_rule_id: contextRuleId,
      signer,
    });
  }

  /**
   * Remove a signer from a context rule.
   */
  async remove(contextRuleId: number, signer: ContractSigner) {
    const { wallet } = this.deps.requireWallet();

    // If it's an External signer (passkey), remove from local storage
    if (signer.tag === "External") {
      const keyData = signer.values[1] as Buffer;
      // Only try to delete if keyData contains a credential ID suffix
      if (keyData.length > SECP256R1_PUBLIC_KEY_SIZE) {
        const credentialId = base64url.encode(keyData.slice(SECP256R1_PUBLIC_KEY_SIZE));
        await this.deps.storage.delete(credentialId);
      }
    }

    return wallet.remove_signer({
      context_rule_id: contextRuleId,
      signer,
    });
  }

  /**
   * Remove a passkey signer by credential ID.
   */
  async removePasskey(contextRuleId: number, credentialId: string) {
    const credential = await this.deps.storage.get(credentialId);
    if (!credential) {
      throw new Error(`Credential ${credentialId} not found in storage`);
    }

    const keyData = buildKeyData(credential.publicKey, credentialId);
    const signer: ContractSigner = {
      tag: "External",
      values: [this.deps.webauthnVerifierAddress, keyData],
    };

    return this.remove(contextRuleId, signer);
  }
}
