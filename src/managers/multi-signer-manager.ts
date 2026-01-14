/**
 * Multi-Signer Manager
 *
 * Handles multi-signature operations for smart accounts, coordinating
 * between passkey signers and external wallet signers.
 */

import {
  Address,
  hash,
  Operation,
  TransactionBuilder,
  xdr,
  rpc as rpcModule,
} from "@stellar/stellar-sdk";

const { assembleTransaction } = rpcModule;
import type { Keypair, Transaction, rpc } from "@stellar/stellar-sdk";
import type { AssembledTransaction } from "@stellar/stellar-sdk/contract";
import type { Signer as ContractSigner, ContextRuleType } from "smart-account-kit-bindings";
import type { ExternalSignerManager } from "../external-signers";
import type { SelectedSigner, SubmissionOptions, TransactionResult } from "../types";
import { BASE_FEE } from "../constants";
import { getCredentialIdFromSigner, collectUniqueSigners } from "../builders";

/** Type guard for transaction result with status and hash properties */
interface SendTransactionResult {
  status: string;
  hash?: string;
}

function isSendTransactionResult(value: unknown): value is SendTransactionResult {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    typeof (value as SendTransactionResult).status === "string"
  );
}

/** Options for multi-signer operations */
export interface MultiSignerOptions {
  /** Logger function */
  onLog?: (message: string, type?: "info" | "success" | "error") => void;
}

/** Dependencies required by MultiSignerManager */
export interface MultiSignerManagerDeps {
  /** Get current contract ID (if connected) */
  getContractId: () => string | undefined;
  /** Check if connected to a wallet */
  isConnected: () => boolean;
  /** Get context rules */
  getRules: (contextRuleType: ContextRuleType) => Promise<{ result?: Array<{ signers: ContractSigner[] }> }>;
  /** External signer manager for wallet signing */
  externalSigners: ExternalSignerManager;
  /** RPC server */
  rpc: rpc.Server;
  /** Network passphrase */
  networkPassphrase: string;
  /** Timeout in seconds for transactions */
  timeoutInSeconds: number;
  /** Deployer keypair for fee payment */
  deployerKeypair: Keypair;
  /** Deployer public key */
  deployerPublicKey: string;
  /** Sign an auth entry with passkey */
  signAuthEntry: (
    entry: xdr.SorobanAuthorizationEntry,
    options?: { credentialId?: string; expiration?: number }
  ) => Promise<xdr.SorobanAuthorizationEntry>;
  /** Send transaction and poll for result */
  sendAndPoll: (tx: Transaction) => Promise<TransactionResult>;
  /** Check if transaction has source_account auth (requires envelope signature) */
  hasSourceAccountAuth: (tx: Transaction) => boolean;
  /** Execute multi-signer transfer (complex implementation in kit.ts) */
  executeTransfer: (
    tokenContract: string,
    recipient: string,
    amount: number,
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions
  ) => Promise<TransactionResult>;
  /** Check if fee sponsoring should be used */
  shouldUseFeeSponsoring: (options?: SubmissionOptions) => boolean;
}

/**
 * Manages multi-signer operations for smart accounts.
 */
export class MultiSignerManager {
  constructor(private deps: MultiSignerManagerDeps) {}

  /**
   * Get available signers from on-chain context rules.
   */
  async getAvailableSigners(): Promise<ContractSigner[]> {
    if (!this.deps.isConnected()) {
      return [];
    }

    try {
      const defaultRulesResult = await this.deps.getRules({
        tag: "Default",
        values: undefined,
      });
      const defaultRules = defaultRulesResult.result || [];

      // Collect all signers from all rules, then deduplicate
      const allSigners = defaultRules.flatMap((rule) => rule.signers);
      return collectUniqueSigners(allSigners);
    } catch (error) {
      console.warn("[SmartAccountKit] Failed to fetch available signers:", error);
      return [];
    }
  }

  /**
   * Extract credential ID from a signer.
   */
  extractCredentialId(signer: ContractSigner): string | null {
    return getCredentialIdFromSigner(signer);
  }

  /**
   * Check if a signer matches a credential ID.
   */
  signerMatchesCredential(signer: ContractSigner, credentialId: string): boolean {
    const signerCredId = this.extractCredentialId(signer);
    return signerCredId === credentialId;
  }

  /**
   * Check if a signer matches a wallet address.
   */
  signerMatchesAddress(signer: ContractSigner, address: string): boolean {
    if (signer.tag !== "Delegated") return false;
    return signer.values[0] === address;
  }

  /**
   * Check if an operation needs multi-signer handling.
   */
  needsMultiSigner(signers: ContractSigner[]): boolean {
    // Check for delegated signers
    const hasDelegated = signers.some(s => s.tag === "Delegated");
    // Check for multiple signers
    const hasMultiple = signers.length > 1;
    return hasDelegated || hasMultiple;
  }

  /**
   * Build selected signers from available signers.
   */
  buildSelectedSigners(
    signers: ContractSigner[],
    activeCredentialId?: string | null
  ): SelectedSigner[] {
    const selected: SelectedSigner[] = [];

    for (const signer of signers) {
      if (signer.tag === "Delegated") {
        const address = signer.values[0] as string;
        if (this.deps.externalSigners.canSignFor(address)) {
          selected.push({
            signer,
            type: "wallet",
            walletAddress: address,
          });
        }
      } else {
        const credId = this.extractCredentialId(signer);
        if (credId && (!activeCredentialId || credId === activeCredentialId)) {
          selected.push({
            signer,
            type: "passkey",
            credentialId: credId,
          });
        }
      }
    }

    return selected;
  }

  /**
   * Execute a generic smart account operation with multiple signers.
   */
  async operation<T>(
    assembledTx: AssembledTransaction<T>,
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions
  ): Promise<TransactionResult> {
    const onLog = options?.onLog ?? (() => {});
    const contractId = this.deps.getContractId();

    if (!contractId) {
      return { success: false, hash: "", error: "Not connected to a wallet" };
    }

    const passkeySigners = selectedSigners.filter((s) => s.type === "passkey");
    const walletSigners = selectedSigners.filter((s) => s.type === "wallet");

    onLog(`Signing with ${passkeySigners.length} passkey(s) and ${walletSigners.length} wallet(s)`);

    // Validate wallet signers
    for (const walletSigner of walletSigners) {
      if (!walletSigner.walletAddress) continue;
      if (!this.deps.externalSigners.canSignFor(walletSigner.walletAddress)) {
        return {
          success: false,
          hash: "",
          error: `No signer available for address: ${walletSigner.walletAddress}. ` +
            `Use kit.externalSigners.addFromSecret() or kit.externalSigners.addFromWallet() to add a signer.`,
        };
      }
    }

    try {
      const builtTx = assembledTx.built;
      if (!builtTx) {
        return { success: false, hash: "", error: "Transaction not built" };
      }

      const ops = builtTx.operations;
      if (!ops || ops.length === 0) {
        return { success: false, hash: "", error: "No operations in transaction" };
      }

      const invokeOp = ops[0] as Operation.InvokeHostFunction;
      const authEntries = invokeOp.auth || [];

      onLog(`Found ${authEntries.length} auth entries to sign`);

      if (authEntries.length === 0) {
        onLog("No auth entries - submitting directly...");
        const result = await assembledTx.signAndSend();
        if (!isSendTransactionResult(result)) {
          return { success: false, hash: "", error: "Unexpected transaction result format" };
        }
        return {
          success: result.status === "SUCCESS",
          hash: result.hash || "",
          error: result.status !== "SUCCESS" ? "Transaction failed" : undefined,
        };
      }

      const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];
      const { sequence } = await this.deps.rpc.getLatestLedger();
      const expiration = sequence + 100;

      for (const entry of authEntries) {
        const credentials = entry.credentials();

        if (credentials.switch().name !== "sorobanCredentialsAddress") {
          signedAuthEntries.push(entry);
          continue;
        }

        const addressCreds = credentials.address();
        const authAddress = Address.fromScAddress(addressCreds.address()).toString();

        if (authAddress === contractId) {
          let signedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
          signedEntry.credentials().address().signatureExpirationLedger(expiration);

          // Sign with passkeys
          for (let i = 0; i < passkeySigners.length; i++) {
            const passkeySigner = passkeySigners[i];
            onLog(`Signing with passkey ${i + 1}/${passkeySigners.length}...`);
            signedEntry = await this.deps.signAuthEntry(signedEntry, {
              credentialId: passkeySigner?.credentialId,
              expiration,
            });
          }

          // Add delegated signers to signature map
          for (const walletSigner of walletSigners) {
            if (!walletSigner.walletAddress) continue;

            const delegatedSignerKey = xdr.ScVal.scvVec([
              xdr.ScVal.scvSymbol("Delegated"),
              xdr.ScVal.scvAddress(Address.fromString(walletSigner.walletAddress).toScAddress()),
            ]);

            const ourSig = signedEntry.credentials().address().signature();
            const emptyBytes = xdr.ScVal.scvBytes(Buffer.alloc(0));

            if (ourSig.switch().name === "scvVoid") {
              signedEntry.credentials().address().signature(
                xdr.ScVal.scvVec([
                  xdr.ScVal.scvMap([
                    new xdr.ScMapEntry({ key: delegatedSignerKey, val: emptyBytes }),
                  ]),
                ])
              );
            } else {
              const sigMap = ourSig.vec()?.[0].map();
              if (sigMap) {
                sigMap.push(new xdr.ScMapEntry({ key: delegatedSignerKey, val: emptyBytes }));
                sigMap.sort((a, b) => a.key().toXDR("hex").localeCompare(b.key().toXDR("hex")));
              }
            }
          }

          signedAuthEntries.push(signedEntry);

          // Create delegated signer auth entries
          if (walletSigners.length > 0) {
            onLog(`Creating auth entries for ${walletSigners.length} delegated signer(s)...`);

            const smartAccountPreimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
              new xdr.HashIdPreimageSorobanAuthorization({
                networkId: hash(Buffer.from(this.deps.networkPassphrase)),
                nonce: signedEntry.credentials().address().nonce(),
                signatureExpirationLedger: expiration,
                invocation: signedEntry.rootInvocation(),
              })
            );
            const signaturePayload = hash(smartAccountPreimage.toXDR());

            for (const walletSigner of walletSigners) {
              if (!walletSigner.walletAddress) continue;

              onLog(`Getting delegated auth from ${walletSigner.walletAddress.slice(0, 8)}...`);

              const delegatedNonce = xdr.Int64.fromString(Date.now().toString());

              const delegatedInvocation = new xdr.SorobanAuthorizedInvocation({
                function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
                  new xdr.InvokeContractArgs({
                    contractAddress: Address.fromString(contractId).toScAddress(),
                    functionName: "__check_auth",
                    args: [xdr.ScVal.scvBytes(signaturePayload)],
                  })
                ),
                subInvocations: [],
              });

              const delegatedPreimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
                new xdr.HashIdPreimageSorobanAuthorization({
                  networkId: hash(Buffer.from(this.deps.networkPassphrase)),
                  nonce: delegatedNonce,
                  signatureExpirationLedger: expiration,
                  invocation: delegatedInvocation,
                })
              );

              const { signedAuthEntry: walletSignatureBase64 } = await this.deps.externalSigners.signAuthEntry(
                delegatedPreimage.toXDR("base64"),
                walletSigner.walletAddress
              );

              const signatureBytes = Buffer.from(walletSignatureBase64, "base64");
              const walletPublicKeyBytes = Address.fromString(walletSigner.walletAddress)
                .toScAddress()
                .accountId()
                .ed25519();

              const signatureScVal = xdr.ScVal.scvVec([
                xdr.ScVal.scvMap([
                  new xdr.ScMapEntry({
                    key: xdr.ScVal.scvSymbol("public_key"),
                    val: xdr.ScVal.scvBytes(walletPublicKeyBytes),
                  }),
                  new xdr.ScMapEntry({
                    key: xdr.ScVal.scvSymbol("signature"),
                    val: xdr.ScVal.scvBytes(signatureBytes),
                  }),
                ]),
              ]);

              const walletSignedEntry = new xdr.SorobanAuthorizationEntry({
                credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
                  new xdr.SorobanAddressCredentials({
                    address: Address.fromString(walletSigner.walletAddress).toScAddress(),
                    nonce: delegatedNonce,
                    signatureExpirationLedger: expiration,
                    signature: signatureScVal,
                  })
                ),
                rootInvocation: delegatedInvocation,
              });
              signedAuthEntries.push(walletSignedEntry);
            }
          }
        } else {
          signedAuthEntries.push(entry);
        }
      }

      // Re-simulate with signed auth entries
      onLog("Re-simulating with signatures...");
      const freshSourceAccount = await this.deps.rpc.getAccount(this.deps.deployerPublicKey);
      const hostFunc = (ops[0] as Operation.InvokeHostFunction).func;

      const resimTx = new TransactionBuilder(freshSourceAccount, {
        fee: BASE_FEE,
        networkPassphrase: this.deps.networkPassphrase,
      })
        .addOperation(
          Operation.invokeHostFunction({
            func: hostFunc,
            auth: signedAuthEntries,
          })
        )
        .setTimeout(this.deps.timeoutInSeconds)
        .build();

      const resimResult = await this.deps.rpc.simulateTransaction(resimTx);

      if ("error" in resimResult) {
        return { success: false, hash: "", error: `Re-simulation failed: ${resimResult.error}` };
      }

      const resimTxXdr = resimTx.toXDR();
      const normalizedTx = TransactionBuilder.fromXDR(resimTxXdr, this.deps.networkPassphrase);
      const assembled = assembleTransaction(normalizedTx as Transaction, resimResult);
      const preparedTx = assembled.build() as Transaction;

      // Sign with deployer keypair if not using fee sponsoring, or if tx has source_account auth
      // (source_account auth requires envelope signature; Address auth has signature in entry)
      if (!this.deps.shouldUseFeeSponsoring() || this.deps.hasSourceAccountAuth(preparedTx)) {
        preparedTx.sign(this.deps.deployerKeypair);
      }

      onLog("Submitting transaction...");
      return this.deps.sendAndPoll(preparedTx);
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  /**
   * Execute a transfer with multiple signers.
   * Delegates to the kit's implementation which handles the complex XDR building.
   */
  async transfer(
    tokenContract: string,
    recipient: string,
    amount: number,
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions
  ): Promise<TransactionResult> {
    return this.deps.executeTransfer(tokenContract, recipient, amount, selectedSigners, options);
  }
}
