import { contract, rpc } from "@stellar/stellar-sdk";
import {
  Account,
  Address,
  Keypair,
  Operation,
  Transaction,
  TransactionBuilder,
  hash,
  xdr,
} from "@stellar/stellar-sdk";
import type {
  SubmissionMethod,
  SubmissionOptions,
  TransactionResult,
} from "../types";
import type { RelayerClient } from "../relayer";
import type { Client as SmartAccountClient } from "smart-account-kit-bindings";
import {
  BASE_FEE,
  FRIENDBOT_RESERVE_XLM,
  FRIENDBOT_URL,
  LEDGERS_PER_HOUR,
} from "../constants";
import {
  buildAddressSignatureScVal,
  buildSignaturePreimage,
  createAddressCredentials,
  getAddressCredentials,
} from "./auth-payload";
import { validateAddress, validateAmount, xlmToStroops, stroopsToXlm } from "../utils";
import {
  SimulationError,
  SmartAccountErrorCode,
  SubmissionError,
  WalletNotConnectedError,
  wrapError,
} from "../errors";
import {
  decodeContractError,
  failedTransaction,
  simulationFailure,
  submissionFailure,
} from "../contract-errors";

type ResolveContextRuleIds = (
  entry: xdr.SorobanAuthorizationEntry,
  index: number
) => number[] | Promise<number[]>;

export function getSubmissionMethod(
  relayer: RelayerClient | null,
  options?: SubmissionOptions
): SubmissionMethod {
  if (options?.forceMethod) {
    return options.forceMethod;
  }

  if (relayer) {
    return "relayer";
  }

  return "rpc";
}

export function shouldUseFeeSponsoring(
  relayer: RelayerClient | null,
  options?: SubmissionOptions
): boolean {
  return getSubmissionMethod(relayer, options) === "relayer";
}

export async function sendAndPoll(
  deps: {
    rpc: rpc.Server;
    relayer: RelayerClient | null;
  },
  transaction: Transaction,
  options?: SubmissionOptions
): Promise<TransactionResult> {
  const method = getSubmissionMethod(deps.relayer, options);
  let hash: string;

  switch (method) {
    case "relayer": {
      if (!deps.relayer) {
        return failedTransaction(new SubmissionError("Relayer is not configured"));
      }

      const operations = transaction.operations;
      if (operations.length !== 1) {
        return failedTransaction(
          new SubmissionError("Relayer requires exactly one invokeHostFunction operation")
        );
      }

      const op = operations[0];
      if (op.type !== "invokeHostFunction") {
        return failedTransaction(
          new SubmissionError("Relayer only supports invokeHostFunction operations")
        );
      }

      const invokeOp = op as Operation.InvokeHostFunction;
      const funcXdr = invokeOp.func.toXDR("base64");
      const authXdrs = (invokeOp.auth ?? []).map((entry) => entry.toXDR("base64"));

      const relayerResult = await deps.relayer.send(funcXdr, authXdrs);

      if (!relayerResult.success) {
        return submissionFailure(
          relayerResult.error ?? "Relayer submission failed"
        );
      }

      hash = relayerResult.hash ?? "";
      break;
    }

    case "rpc":
    default: {
      const sendResult = await deps.rpc.sendTransaction(transaction);

      if (sendResult.status === "ERROR") {
        return submissionFailure(
          sendResult.errorResult?.toXDR("base64") ?? "Transaction submission failed",
          sendResult.hash
        );
      }

      hash = sendResult.hash;
      break;
    }
  }

  const txResult = await deps.rpc.pollTransaction(hash, {
    attempts: 10,
  });

  if (txResult.status === "SUCCESS") {
    return {
      success: true,
      hash,
      ledger: txResult.ledger,
    };
  }

  if (txResult.status === "FAILED") {
    const resultXdr = txResult.resultXdr?.toXDR("base64");
    return submissionFailure(
      resultXdr
        ? `Transaction failed on-chain: ${resultXdr}`
        : "Transaction failed on-chain",
      hash
    );
  }

  return failedTransaction(
    new SubmissionError("Transaction confirmation timed out", hash),
    hash
  );
}

export function hasSourceAccountAuth(transaction: Transaction): boolean {
  for (const op of transaction.operations) {
    if (op.type !== "invokeHostFunction") continue;

    const invokeOp = op as Operation.InvokeHostFunction;
    if (!invokeOp.auth) continue;

    for (const entry of invokeOp.auth) {
      if (entry.credentials().switch().name === "sorobanCredentialsSourceAccount") {
        return true;
      }
    }
  }
  return false;
}

const U64_MASK = BigInt("0xFFFFFFFFFFFFFFFF");

/**
 * Build an `scvI128` ScVal from a bigint stroop amount.
 *
 * Single source of truth for the i128 lo/hi split used by both the raw
 * host-function transfer builder and the spec-fallback target-args builder.
 */
export function buildI128ScVal(amount: bigint): xdr.ScVal {
  return xdr.ScVal.scvI128(
    new xdr.Int128Parts({
      lo: xdr.Uint64.fromString((amount & U64_MASK).toString()),
      hi: xdr.Int64.fromString((amount >> BigInt(64)).toString()),
    })
  );
}

export function buildTokenTransferHostFunction(
  tokenContract: string,
  fromAddress: string,
  toAddress: string,
  amountInStroops: bigint
): xdr.HostFunction {
  return xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: Address.fromString(tokenContract).toScAddress(),
      functionName: "transfer",
      args: [
        xdr.ScVal.scvAddress(Address.fromString(fromAddress).toScAddress()),
        xdr.ScVal.scvAddress(Address.fromString(toAddress).toScAddress()),
        buildI128ScVal(amountInStroops),
      ],
    })
  );
}

export function buildTokenTransferTargetArgs(
  wallet: SmartAccountClient | { spec?: { nativeToScVal?: (val: unknown, type: xdr.ScSpecTypeDef) => xdr.ScVal } },
  fromAddress: string,
  toAddress: string,
  amountInStroops: bigint
): xdr.ScVal[] {
  const spec = wallet?.spec;
  if (spec && typeof spec.nativeToScVal === "function") {
    return [
      spec.nativeToScVal(fromAddress, xdr.ScSpecTypeDef.scSpecTypeAddress()),
      spec.nativeToScVal(toAddress, xdr.ScSpecTypeDef.scSpecTypeAddress()),
      spec.nativeToScVal(amountInStroops, xdr.ScSpecTypeDef.scSpecTypeI128()),
    ];
  }

  return [
    xdr.ScVal.scvAddress(Address.fromString(fromAddress).toScAddress()),
    xdr.ScVal.scvAddress(Address.fromString(toAddress).toScAddress()),
    buildI128ScVal(amountInStroops),
  ];
}

/**
 * Sign a prepared transaction with the fee-paying source keypair when required.
 *
 * Single source of truth for the fee-sponsor guard: when the transaction is not
 * fee-sponsored via the relayer, or it still carries source-account auth, the
 * local keypair must sign as the fee payer. Consolidates the guard that was
 * duplicated across signAndSubmit, fundWallet, and the multi-signer paths.
 */
export function signFeePayer(
  transaction: Transaction,
  keypair: Keypair,
  deps: {
    shouldUseFeeSponsoring: (options?: SubmissionOptions) => boolean;
    hasSourceAccountAuth: (transaction: Transaction) => boolean;
  },
  options?: SubmissionOptions
): void {
  if (!deps.shouldUseFeeSponsoring(options) || deps.hasSourceAccountAuth(transaction)) {
    transaction.sign(keypair);
  }
}

/**
 * Re-simulate an invokeHostFunction transaction with signed auth entries, then
 * assemble the final prepared transaction.
 *
 * Single source of truth for the re-simulate -> assemble step that was
 * duplicated across signResimulateAndPrepare, fundWallet, and the multi-signer
 * submission path. Throws a decoded {@link ContractError} (or
 * {@link SimulationError}) when re-simulation fails, so callers can surface the
 * on-chain reason.
 */
export async function resimulateAndAssemble(
  deps: {
    rpc: rpc.Server;
    networkPassphrase: string;
    timeoutInSeconds: number;
  },
  sourceAccount: Account,
  hostFunc: xdr.HostFunction,
  signedAuthEntries: xdr.SorobanAuthorizationEntry[]
): Promise<Transaction> {
  const resimTx = new TransactionBuilder(sourceAccount, {
    fee: BASE_FEE,
    networkPassphrase: deps.networkPassphrase,
  })
    .addOperation(
      Operation.invokeHostFunction({
        func: hostFunc,
        auth: signedAuthEntries,
      })
    )
    .setTimeout(deps.timeoutInSeconds)
    .build();

  const resimResult = await deps.rpc.simulateTransaction(resimTx);

  if ("error" in resimResult) {
    throw (
      decodeContractError(resimResult.error) ??
      new SimulationError(`Re-simulation failed: ${resimResult.error}`)
    );
  }

  const normalizedTx = TransactionBuilder.fromXDR(resimTx.toXDR(), deps.networkPassphrase);
  return rpc.assembleTransaction(normalizedTx as Transaction, resimResult).build() as Transaction;
}

export async function signResimulateAndPrepare(
  deps: {
    rpc: rpc.Server;
    networkPassphrase: string;
    timeoutInSeconds: number;
    deployerKeypair: Keypair;
    signAuthEntry: (
      entry: xdr.SorobanAuthorizationEntry,
      options?: {
        credentialId?: string;
        expiration?: number;
        contextRuleIds?: number[];
      }
    ) => Promise<xdr.SorobanAuthorizationEntry>;
  },
  hostFunc: xdr.HostFunction,
  authEntries: xdr.SorobanAuthorizationEntry[],
  options?: {
    credentialId?: string;
    expiration?: number;
    resolveContextRuleIds?: ResolveContextRuleIds;
  }
): Promise<Transaction> {
  const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];
  for (const [index, authEntry] of authEntries.entries()) {
    const signedEntry = await deps.signAuthEntry(authEntry, {
      credentialId: options?.credentialId,
      expiration: options?.expiration,
      contextRuleIds: options?.resolveContextRuleIds
        ? await options.resolveContextRuleIds(authEntry, index)
        : undefined,
    });
    signedAuthEntries.push(signedEntry);
  }

  let sourceAccount;
  try {
    sourceAccount = await deps.rpc.getAccount(deps.deployerKeypair.publicKey());
  } catch (error) {
    throw new SubmissionError(
      `Re-simulation requires the deployer account to exist on-chain. ` +
      `Fund ${deps.deployerKeypair.publicKey()} before re-simulating transactions.`
    );
  }

  return resimulateAndAssemble(deps, sourceAccount, hostFunc, signedAuthEntries);
}

export async function sign(
  deps: {
    getContractId: () => string | undefined;
    getCredentialId: () => string | undefined;
    calculateExpiration: () => Promise<number>;
    signAuthEntry: (
      entry: xdr.SorobanAuthorizationEntry,
      options?: {
        credentialId?: string;
        expiration?: number;
        contextRuleIds?: number[];
      }
    ) => Promise<xdr.SorobanAuthorizationEntry>;
  },
  transaction: contract.AssembledTransaction<unknown>,
  options?: {
    credentialId?: string;
    expiration?: number;
    resolveContextRuleIds?: ResolveContextRuleIds;
  }
): Promise<contract.AssembledTransaction<unknown>> {
  const contractId = deps.getContractId();
  if (!contractId) {
    throw new WalletNotConnectedError("sign a transaction");
  }

  const credentialId = options?.credentialId ?? deps.getCredentialId();
  const expiration = options?.expiration ?? await deps.calculateExpiration();

  await transaction.signAuthEntries({
    address: contractId,
    authorizeEntry: async (entry: xdr.SorobanAuthorizationEntry) => {
      const clone = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
      const authEntries = transaction.simulationData?.result?.auth || [];
      const entryIndex = authEntries.findIndex((authEntry) => authEntry.toXDR("base64") === entry.toXDR("base64"));
      return deps.signAuthEntry(clone, {
        credentialId,
        expiration,
        contextRuleIds: entryIndex >= 0 && options?.resolveContextRuleIds
          ? await options.resolveContextRuleIds(clone, entryIndex)
          : undefined,
      });
    },
  });

  return transaction;
}

export async function signAndSubmit(
  deps: {
    getContractId: () => string | undefined;
    signResimulateAndPrepare: (
      hostFunc: xdr.HostFunction,
      authEntries: xdr.SorobanAuthorizationEntry[],
      options?: {
        credentialId?: string;
        expiration?: number;
        resolveContextRuleIds?: ResolveContextRuleIds;
      }
    ) => Promise<Transaction>;
    shouldUseFeeSponsoring: (options?: SubmissionOptions) => boolean;
    hasSourceAccountAuth: (transaction: Transaction) => boolean;
    sendAndPoll: (transaction: Transaction, options?: SubmissionOptions) => Promise<TransactionResult>;
    deployerKeypair: Keypair;
  },
  transaction: contract.AssembledTransaction<unknown>,
  options?: {
    credentialId?: string;
    expiration?: number;
    forceMethod?: SubmissionMethod;
    resolveContextRuleIds?: ResolveContextRuleIds;
  }
): Promise<TransactionResult> {
  if (!deps.getContractId()) {
    return failedTransaction(new WalletNotConnectedError("submit a transaction"));
  }

  try {
    const builtTx = transaction.built;
    if (!builtTx) {
      return failedTransaction(new SubmissionError("Transaction has no built transaction"));
    }

    const operations = builtTx.operations;
    if (operations.length !== 1) {
      return failedTransaction(new SubmissionError("Expected exactly one operation"));
    }

    const operation = operations[0];
    if (operation.type !== "invokeHostFunction") {
      return failedTransaction(new SubmissionError("Expected invokeHostFunction operation"));
    }

    const invokeOp = operation as Operation.InvokeHostFunction;

    const simData = transaction.simulationData;
    if (!simData?.result?.auth) {
      return failedTransaction(new SubmissionError("No simulation data or auth entries"));
    }

      const preparedTx = await deps.signResimulateAndPrepare(
        invokeOp.func,
        simData.result.auth,
        {
          credentialId: options?.credentialId,
          expiration: options?.expiration,
          resolveContextRuleIds: options?.resolveContextRuleIds,
        }
      );

    const submissionOpts: SubmissionOptions = { forceMethod: options?.forceMethod };
    signFeePayer(preparedTx, deps.deployerKeypair, deps, submissionOpts);

    return deps.sendAndPoll(preparedTx, submissionOpts);
  } catch (err) {
    return failedTransaction(wrapError(err, SmartAccountErrorCode.TRANSACTION_SIGNING_FAILED));
  }
}

export async function fundWallet(
  deps: {
    getContractId: () => string | undefined;
    rpc: rpc.Server;
    networkPassphrase: string;
    timeoutInSeconds: number;
    shouldUseFeeSponsoring: (options?: SubmissionOptions) => boolean;
    hasSourceAccountAuth: (transaction: Transaction) => boolean;
    sendAndPoll: (transaction: Transaction, options?: SubmissionOptions) => Promise<TransactionResult>;
  },
  nativeTokenContract: string,
  options?: { forceMethod?: SubmissionMethod }
): Promise<TransactionResult & { amount?: number }> {
  const contractId = deps.getContractId();
  if (!contractId) {
    return failedTransaction(new WalletNotConnectedError("fund a wallet"));
  }

  if (!deps.networkPassphrase.includes("Test")) {
    return failedTransaction(new SubmissionError("fundWallet() only works on testnet"));
  }

  try {
    const tempKeypair = Keypair.random();

    const friendbotResponse = await fetch(
      `${FRIENDBOT_URL}?addr=${tempKeypair.publicKey()}`
    );

    if (!friendbotResponse.ok) {
      const text = await friendbotResponse.text();
      return failedTransaction(new SubmissionError(`Friendbot error: ${text}`));
    }

    const RESERVE_XLM = FRIENDBOT_RESERVE_XLM;
    let sourceAccount = await deps.rpc.getAccount(tempKeypair.publicKey());

    const fromAddress = Address.fromString(tempKeypair.publicKey());

    const balanceKey = xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("Balance"),
      xdr.ScVal.scvAddress(fromAddress.toScAddress()),
    ]);

    let balanceXlm: number;
    try {
      const balanceData = await deps.rpc.getContractData(
        nativeTokenContract,
        balanceKey
      );
      const val = balanceData.val.contractData().val();
      if (val.switch().name === "scvI128") {
        const i128 = val.i128();
        const lo = BigInt(i128.lo().toString());
        const hi = BigInt(i128.hi().toString());
        const balanceStroops = (hi << BigInt(64)) | lo;
        balanceXlm = stroopsToXlm(balanceStroops);
      } else {
        balanceXlm = 10_000;
      }
    } catch (error) {
      console.warn("[SmartAccountKit] Failed to fetch temp account balance, using default:", error);
      balanceXlm = 10_000;
    }

    const transferAmount = balanceXlm - RESERVE_XLM;

    if (transferAmount <= 0) {
      return failedTransaction(new SubmissionError("Insufficient balance after reserve"));
    }

    const amountInStroops = xlmToStroops(transferAmount);

    const transferOp = Operation.invokeHostFunction({
      func: buildTokenTransferHostFunction(
        nativeTokenContract,
        fromAddress.toString(),
        contractId,
        amountInStroops
      ),
      auth: [],
    });

    const simulationTx = new TransactionBuilder(sourceAccount, {
      fee: BASE_FEE,
      networkPassphrase: deps.networkPassphrase,
    })
      .addOperation(transferOp)
      .setTimeout(30)
      .build();

    const simResult = await deps.rpc.simulateTransaction(simulationTx);

    if ("error" in simResult) {
      return simulationFailure(simResult.error);
    }

    const authEntries = simResult.result?.auth || [];
    const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];

    const currentLedger = simResult.latestLedger;
    const expirationLedger = currentLedger + LEDGERS_PER_HOUR; // ~1 hour

    for (const entry of authEntries) {
      const credType = entry.credentials().switch().name as string;

      // For source_account credentials, convert to Address credentials
      // so the Relayer can use its own channel accounts
      if (credType === "sorobanCredentialsSourceAccount") {
        // Generate a nonce for the new Address credential
        const nonce = xdr.Int64.fromString(Date.now().toString());

        // Create new Address credentials entry to replace source_account
        const addressEntry = new xdr.SorobanAuthorizationEntry({
          credentials: createAddressCredentials(
            new xdr.SorobanAddressCredentials({
              address: Address.fromString(tempKeypair.publicKey()).toScAddress(),
              nonce,
              signatureExpirationLedger: expirationLedger,
              signature: xdr.ScVal.scvVoid(),
            })
          ),
          rootInvocation: entry.rootInvocation(),
        });
        const preimage = buildSignaturePreimage(
          deps.networkPassphrase,
          addressEntry,
          expirationLedger
        );
        const payload = hash(preimage.toXDR());
        const signature = tempKeypair.sign(payload);
        getAddressCredentials(addressEntry.credentials()).signature(
          buildAddressSignatureScVal(
            tempKeypair.rawPublicKey(),
            signature
          )
        );

        signedAuthEntries.push(addressEntry);
        continue;
      }

      if (credType === "sorobanCredentialsAddressWithDelegates") {
        return failedTransaction(
          new SubmissionError(
            "ADDRESS_WITH_DELEGATES auth entries are not supported by fundWallet() yet"
          )
        );
      }

      // For Address credentials, sign them
      if (
        credType === "sorobanCredentialsAddress" ||
        credType === "sorobanCredentialsAddressV2"
      ) {
        const credentials = getAddressCredentials(entry.credentials());
        credentials.signatureExpirationLedger(expirationLedger);

        const preimage = buildSignaturePreimage(deps.networkPassphrase, entry, expirationLedger);
        const payload = hash(preimage.toXDR());
        const signature = tempKeypair.sign(payload);

        credentials.signature(buildAddressSignatureScVal(tempKeypair.rawPublicKey(), signature));

        signedAuthEntries.push(entry);
        continue;
      }

      // Unknown credential type - push as-is (shouldn't happen)
      signedAuthEntries.push(entry);
    }

    sourceAccount = await deps.rpc.getAccount(tempKeypair.publicKey());

    const invokeHostFn = simulationTx.operations[0] as Operation.InvokeHostFunction;

    const preparedTx = await resimulateAndAssemble(
      deps,
      sourceAccount,
      invokeHostFn.func,
      signedAuthEntries
    );

    const submissionOpts: SubmissionOptions = { forceMethod: options?.forceMethod };
    signFeePayer(preparedTx, tempKeypair, deps, submissionOpts);

    const txResult = await deps.sendAndPoll(preparedTx, submissionOpts);

    return {
      ...txResult,
      amount: txResult.success ? transferAmount : undefined,
    };
  } catch (err) {
    return failedTransaction(wrapError(err, SmartAccountErrorCode.TRANSACTION_SUBMISSION_FAILED));
  }
}
