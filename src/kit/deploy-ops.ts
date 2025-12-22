import { hash } from "@stellar/stellar-sdk";
import type { contract, rpc } from "@stellar/stellar-sdk";
import type { SubmissionOptions, TransactionResult } from "../types";
import type { RelayerClient } from "../relayer";
import type { StorageAdapter } from "../types";
import { buildKeyData } from "../utils";
import type { Signer as ContractSigner } from "smart-account-kit-bindings";
import { Client as SmartAccountClient } from "smart-account-kit-bindings";
import type { Keypair } from "@stellar/stellar-sdk";
import { getSubmissionMethod } from "./tx-ops";

export async function submitDeploymentTx<T>(
  deps: {
    storage: StorageAdapter;
    rpc: rpc.Server;
    relayer: RelayerClient | null;
  },
  tx: contract.AssembledTransaction<T>,
  credentialId: string,
  options?: SubmissionOptions
): Promise<TransactionResult> {
  try {
    let hashValue: string;
    let ledger: number | undefined;

    const method = getSubmissionMethod(deps.relayer, options);

    if (method === "relayer" && tx.signed && deps.relayer) {
      const relayerResult = await deps.relayer.sendXdr(tx.signed);

      if (!relayerResult.success) {
        throw new Error(relayerResult.error ?? "Relayer submission failed");
      }

      hashValue = relayerResult.hash ?? "";

      const txResult = await deps.rpc.pollTransaction(hashValue, { attempts: 10 });
      if (txResult.status === "SUCCESS") {
        ledger = txResult.ledger;
      } else if (txResult.status === "FAILED") {
        throw new Error("Transaction failed on-chain");
      }
    } else {
      const sentTx = await tx.send();
      const txResponse = sentTx.getTransactionResponse;
      hashValue = sentTx.sendTransactionResponse?.hash ?? "";
      ledger = txResponse?.status === "SUCCESS" ? txResponse.ledger : undefined;
    }

    await deps.storage.delete(credentialId);
    return {
      success: true,
      hash: hashValue,
      ledger,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : "Transaction failed";
    await deps.storage.update(credentialId, {
      deploymentStatus: "failed",
      deploymentError: error,
    });
    return {
      success: false,
      hash: "",
      error,
    };
  }
}

export async function buildDeployTransaction(
  deps: {
    accountWasmHash: string;
    webauthnVerifierAddress: string;
    networkPassphrase: string;
    rpcUrl: string;
    deployerKeypair: Keypair;
    timeoutInSeconds: number;
  },
  credentialId: Buffer,
  publicKey: Uint8Array
): Promise<contract.AssembledTransaction<null>> {
  const keyData = buildKeyData(publicKey, credentialId);
  const signer: ContractSigner = {
    tag: "External",
    values: [
      deps.webauthnVerifierAddress,
      keyData,
    ],
  };

  return SmartAccountClient.deploy(
    {
      signers: [signer],
      policies: new Map(),
    },
    {
      networkPassphrase: deps.networkPassphrase,
      rpcUrl: deps.rpcUrl,
      wasmHash: deps.accountWasmHash,
      publicKey: deps.deployerKeypair.publicKey(),
      salt: hash(credentialId),
      timeoutInSeconds: deps.timeoutInSeconds,
    }
  );
}
