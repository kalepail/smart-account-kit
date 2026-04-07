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
import type {
  Client as SmartAccountClient,
  Signer as ContractSigner,
  ContextRuleType,
} from "smart-account-kit-bindings";
import type { ContractDetailsResponse } from "../indexer";
import type { ExternalSignerManager } from "../external-signers";
import type { SelectedSigner, SubmissionOptions, TransactionResult } from "../types";
import {
  BASE_FEE,
  AUTH_ENTRY_EXPIRATION_BUFFER,
} from "../constants";
import {
  getCredentialIdFromSigner,
  collectUniqueSigners,
} from "../signer-utils";
import {
  buildAuthDigest,
  buildAddressSignatureScVal,
  buildSignaturePayload,
  readAuthPayload,
  upsertAuthPayloadSigner,
  writeAuthPayload,
} from "../kit/auth-payload";
import { resolveContextRuleIdsForEntry } from "../kit/context-rules";
import { buildTokenTransferTargetArgs } from "../kit/tx-ops";
import { validateAddress, validateAmount, xlmToStroops } from "../utils";

export interface MultiSignerOptions {
  onLog?: (message: string, type?: "info" | "success" | "error") => void;
  forceMethod?: SubmissionOptions["forceMethod"];
  resolveContextRuleIds?: (
    entry: xdr.SorobanAuthorizationEntry,
    index: number
  ) => number[] | Promise<number[]>;
}

export interface MultiSignerManagerDeps {
  getContractId: () => string | undefined;
  isConnected: () => boolean;
  getRules: (contextRuleType: ContextRuleType) => Promise<Array<{ signers: ContractSigner[] }>>;
  getContractDetailsFromIndexer?: () => Promise<ContractDetailsResponse | null>;
  requireWallet: () => { wallet: SmartAccountClient };
  externalSigners: ExternalSignerManager;
  rpc: rpc.Server;
  networkPassphrase: string;
  timeoutInSeconds: number;
  deployerKeypair: Keypair;
  deployerPublicKey: string;
  signAuthEntry: (
    entry: xdr.SorobanAuthorizationEntry,
    options?: {
      credentialId?: string;
      expiration?: number;
      contextRuleIds?: number[];
      signer?: ContractSigner;
    }
  ) => Promise<xdr.SorobanAuthorizationEntry>;
  sendAndPoll: (tx: Transaction, options?: SubmissionOptions) => Promise<TransactionResult>;
  hasSourceAccountAuth: (tx: Transaction) => boolean;
  shouldUseFeeSponsoring: (options?: SubmissionOptions) => boolean;
}

export class MultiSignerManager {
  constructor(private deps: MultiSignerManagerDeps) {}

  async getAvailableSigners(): Promise<ContractSigner[]> {
    if (!this.deps.isConnected()) {
      return [];
    }

    try {
      const defaultRules = await this.deps.getRules({
        tag: "Default",
        values: undefined,
      });
      return collectUniqueSigners((defaultRules || []).flatMap((rule) => rule.signers));
    } catch (error) {
      console.warn("[SmartAccountKit] Failed to fetch available signers:", error);
      return [];
    }
  }

  needsMultiSigner(signers: ContractSigner[]): boolean {
    return signers.some((signer) => signer.tag === "Delegated") || signers.length > 1;
  }

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
        continue;
      }

      const credentialId = getCredentialIdFromSigner(signer);
      if (credentialId && (!activeCredentialId || credentialId === activeCredentialId)) {
        selected.push({
          signer,
          type: "passkey",
          credentialId,
        });
      }
    }

    return selected;
  }

  private async signWalletAddressAuthEntry(
    entry: xdr.SorobanAuthorizationEntry,
    authAddress: string,
    expiration: number
  ): Promise<xdr.SorobanAuthorizationEntry> {
    const signedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
    signedEntry.credentials().address().signatureExpirationLedger(expiration);

    const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
      new xdr.HashIdPreimageSorobanAuthorization({
        networkId: hash(Buffer.from(this.deps.networkPassphrase)),
        nonce: signedEntry.credentials().address().nonce(),
        signatureExpirationLedger: expiration,
        invocation: signedEntry.rootInvocation(),
      })
    );

    const { signedAuthEntry } = await this.deps.externalSigners.signAuthEntry(
      preimage.toXDR("base64"),
      authAddress
    );

    signedEntry.credentials().address().signature(
      buildAddressSignatureScVal(
        Address.fromString(authAddress).toScAddress().accountId().ed25519(),
        Buffer.from(signedAuthEntry, "base64")
      )
    );

    return signedEntry;
  }

  private async submitWithSelectedSigners(
    hostFunc: xdr.HostFunction,
    authEntries: xdr.SorobanAuthorizationEntry[],
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions
  ): Promise<TransactionResult> {
    const onLog = options?.onLog ?? (() => {});
    const contractId = this.deps.getContractId();

    if (!contractId) {
      return { success: false, hash: "", error: "Not connected to a wallet" };
    }

    const passkeySigners = selectedSigners.filter((signer) => signer.type === "passkey");
    const walletSigners = selectedSigners.filter((signer) => signer.type === "wallet");

    onLog(`Signing with ${passkeySigners.length} passkey(s) and ${walletSigners.length} wallet(s)`);

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
      onLog(`Found ${authEntries.length} auth entries to sign`);

      const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];
      const { sequence } = await this.deps.rpc.getLatestLedger();
      const expiration = sequence + AUTH_ENTRY_EXPIRATION_BUFFER;

      for (const [authEntryIndex, entry] of authEntries.entries()) {
        const credentials = entry.credentials();

        if (credentials.switch().name !== "sorobanCredentialsAddress") {
          signedAuthEntries.push(entry);
          continue;
        }

        const authAddress = Address.fromScAddress(credentials.address().address()).toString();

        if (authAddress !== contractId) {
          const walletSigner = walletSigners.find((signer) => signer.walletAddress === authAddress);
          if (!walletSigner || !this.deps.externalSigners.canSignFor(authAddress)) {
            return {
              success: false,
              hash: "",
              error: `Unsupported auth entry for ${authAddress}. Add an external signer for that address or remove it from the transaction.`,
            };
          }

          onLog(`Signing separate auth entry for ${authAddress.slice(0, 8)}...`);
          signedAuthEntries.push(
            await this.signWalletAddressAuthEntry(entry, authAddress, expiration)
          );
          continue;
        }

        let signedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
        signedEntry.credentials().address().signatureExpirationLedger(expiration);
        const selectedContractSigners = selectedSigners
          .map(({ signer }) => signer)
          .filter((signer): signer is ContractSigner => signer !== undefined);
        const resolvedContextRuleIds = options?.resolveContextRuleIds
          ? await options.resolveContextRuleIds(signedEntry, authEntryIndex)
          : await resolveContextRuleIdsForEntry(
            this.deps.requireWallet().wallet,
            signedEntry,
            selectedContractSigners,
            {
              getContractDetailsFromIndexer: this.deps.getContractDetailsFromIndexer,
              rpc: this.deps.rpc,
              contractId,
              networkPassphrase: this.deps.networkPassphrase,
              timeoutInSeconds: this.deps.timeoutInSeconds,
            }
          );

        for (const [index, passkeySigner] of passkeySigners.entries()) {
          onLog(`Signing with passkey ${index + 1}/${passkeySigners.length}...`);
          signedEntry = await this.deps.signAuthEntry(signedEntry, {
            credentialId: passkeySigner.credentialId,
            expiration,
            contextRuleIds: resolvedContextRuleIds,
            signer: passkeySigner.signer as ContractSigner | undefined,
          });
        }

        for (const walletSigner of walletSigners) {
          if (!walletSigner.walletAddress) continue;
          if (!walletSigner.signer) {
            return {
              success: false,
              hash: "",
              error: `Wallet signer ${walletSigner.walletAddress} is missing contract signer metadata. Use buildSelectedSigners() or provide the signer field explicitly.`,
            };
          }
        }

        const authPayload = readAuthPayload(signedEntry.credentials().address().signature());
        if (authPayload.context_rule_ids.length === 0) {
          authPayload.context_rule_ids = resolvedContextRuleIds;
        }

        for (const walletSigner of walletSigners) {
          if (!walletSigner.walletAddress) continue;
          upsertAuthPayloadSigner(authPayload, walletSigner.signer as ContractSigner, Buffer.alloc(0));
        }
        signedEntry.credentials().address().signature(writeAuthPayload(authPayload));
        signedAuthEntries.push(signedEntry);

        if (walletSigners.length === 0) {
          continue;
        }

        onLog(`Creating auth entries for ${walletSigners.length} delegated signer(s)...`);

        const signaturePayload = buildSignaturePayload(
          this.deps.networkPassphrase,
          signedEntry,
          expiration
        );
        const authDigest = buildAuthDigest(signaturePayload, authPayload.context_rule_ids);

        for (const walletSigner of walletSigners) {
          if (!walletSigner.walletAddress) continue;

          onLog(`Getting delegated auth from ${walletSigner.walletAddress.slice(0, 8)}...`);

          const delegatedNonce = xdr.Int64.fromString(Date.now().toString());
          const delegatedInvocation = new xdr.SorobanAuthorizedInvocation({
            function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
              new xdr.InvokeContractArgs({
                contractAddress: Address.fromString(contractId).toScAddress(),
                functionName: "__check_auth",
                args: [xdr.ScVal.scvBytes(authDigest)],
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

          signedAuthEntries.push(
            new xdr.SorobanAuthorizationEntry({
              credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
                new xdr.SorobanAddressCredentials({
                  address: Address.fromString(walletSigner.walletAddress).toScAddress(),
                  nonce: delegatedNonce,
                  signatureExpirationLedger: expiration,
                  signature: buildAddressSignatureScVal(
                    Address.fromString(walletSigner.walletAddress).toScAddress().accountId().ed25519(),
                    Buffer.from(walletSignatureBase64, "base64")
                  ),
                })
              ),
              rootInvocation: delegatedInvocation,
            })
          );
        }
      }

      onLog("Re-simulating with signatures...");
      const sourceAccount = await this.deps.rpc.getAccount(this.deps.deployerPublicKey);
      const resimTx = new TransactionBuilder(sourceAccount, {
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

      const normalizedTx = TransactionBuilder.fromXDR(
        resimTx.toXDR(),
        this.deps.networkPassphrase
      );
      const assembled = assembleTransaction(normalizedTx as Transaction, resimResult);
      const preparedTx = assembled.build() as Transaction;
      const submissionOptions: SubmissionOptions = { forceMethod: options?.forceMethod };

      if (!this.deps.shouldUseFeeSponsoring(submissionOptions) || this.deps.hasSourceAccountAuth(preparedTx)) {
        preparedTx.sign(this.deps.deployerKeypair);
      }

      onLog("Submitting transaction...");
      return this.deps.sendAndPoll(preparedTx, submissionOptions);
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  async operation<T>(
    assembledTx: AssembledTransaction<T>,
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions
  ): Promise<TransactionResult> {
    const onLog = options?.onLog ?? (() => {});

    try {
      const builtTx = assembledTx.built;
      if (!builtTx) {
        return { success: false, hash: "", error: "Transaction not built" };
      }

      const operations = builtTx.operations;
      if (!operations || operations.length === 0) {
        return { success: false, hash: "", error: "No operations in transaction" };
      }

      const invokeOp = operations[0] as Operation.InvokeHostFunction;
      const authEntries = invokeOp.auth || [];
      const submissionOptions: SubmissionOptions = { forceMethod: options?.forceMethod };

      if (authEntries.length === 0) {
        onLog("No auth entries - submitting directly...");
        const preparedTx = TransactionBuilder.fromXDR(
          builtTx.toXDR(),
          this.deps.networkPassphrase
        ) as Transaction;
        if (!this.deps.shouldUseFeeSponsoring(submissionOptions) || this.deps.hasSourceAccountAuth(preparedTx)) {
          preparedTx.sign(this.deps.deployerKeypair);
        }
        return this.deps.sendAndPoll(preparedTx, submissionOptions);
      }

      return this.submitWithSelectedSigners(
        invokeOp.func,
        authEntries,
        selectedSigners,
        options
      );
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  async transfer(
    tokenContract: string,
    recipient: string,
    amount: number,
    selectedSigners: SelectedSigner[],
    options?: MultiSignerOptions
  ): Promise<TransactionResult> {
    const contractId = this.deps.getContractId();
    if (!contractId) {
      return { success: false, hash: "", error: "Not connected to a wallet" };
    }

    try {
      validateAddress(tokenContract, "tokenContract");
      validateAddress(recipient, "recipient");
      validateAmount(amount, "amount");
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Validation failed",
      };
    }

    if (recipient === contractId) {
      return {
        success: false,
        hash: "",
        error: "Cannot transfer to self",
      };
    }

    const amountInStroops = xlmToStroops(amount);
    try {
      const { wallet } = this.deps.requireWallet();
      const assembledTx = await wallet.execute({
        target: tokenContract,
        target_fn: "transfer",
        target_args: buildTokenTransferTargetArgs(wallet, contractId, recipient, amountInStroops),
      } as Parameters<SmartAccountClient["execute"]>[0]);

      return this.operation(
        assembledTx,
        selectedSigners,
        options
      );
    } catch (err) {
      return {
        success: false,
        hash: "",
        error: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }
}
