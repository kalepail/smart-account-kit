import { contract, rpc } from "@stellar/stellar-sdk";
import {
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
import {
  BASE_FEE,
  FRIENDBOT_RESERVE_XLM,
  FRIENDBOT_URL,
  LEDGERS_PER_HOUR,
} from "../constants";
import { validateAddress, validateAmount, xlmToStroops, stroopsToXlm } from "../utils";

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
        return {
          success: false,
          hash: "",
          error: "Relayer is not configured",
        };
      }

      const operations = transaction.operations;
      if (operations.length !== 1) {
        return {
          success: false,
          hash: "",
          error: "Relayer requires exactly one invokeHostFunction operation",
        };
      }

      const op = operations[0];
      if (op.type !== "invokeHostFunction") {
        return {
          success: false,
          hash: "",
          error: "Relayer only supports invokeHostFunction operations",
        };
      }

      const invokeOp = op as Operation.InvokeHostFunction;
      const funcXdr = invokeOp.func.toXDR("base64");
      const authXdrs = (invokeOp.auth ?? []).map((entry) => entry.toXDR("base64"));

      const relayerResult = await deps.relayer.send(funcXdr, authXdrs);

      if (!relayerResult.success) {
        return {
          success: false,
          hash: "",
          error: relayerResult.error ?? "Relayer submission failed",
        };
      }

      hash = relayerResult.hash ?? "";
      break;
    }

    case "rpc":
    default: {
      const sendResult = await deps.rpc.sendTransaction(transaction);

      if (sendResult.status === "ERROR") {
        return {
          success: false,
          hash: sendResult.hash,
          error: sendResult.errorResult?.toXDR("base64") ?? "Transaction submission failed",
        };
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
    return {
      success: false,
      hash,
      error: "Transaction failed on-chain",
    };
  }

  return {
    success: false,
    hash,
    error: "Transaction confirmation timed out",
  };
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

export async function simulateHostFunction(
  deps: {
    rpc: rpc.Server;
    networkPassphrase: string;
    timeoutInSeconds: number;
    deployerKeypair: Keypair;
  },
  hostFunc: xdr.HostFunction
): Promise<{ authEntries: xdr.SorobanAuthorizationEntry[] }> {
  let sourceAccount;
  try {
    sourceAccount = await deps.rpc.getAccount(deps.deployerKeypair.publicKey());
  } catch (error) {
    throw new Error(
      `Simulation requires the deployer account to exist on-chain. ` +
      `Fund ${deps.deployerKeypair.publicKey()} before simulating transactions.`
    );
  }

  const simulationTx = new TransactionBuilder(sourceAccount, {
    fee: BASE_FEE,
    networkPassphrase: deps.networkPassphrase,
  })
    .addOperation(
      Operation.invokeHostFunction({
        func: hostFunc,
        auth: [],
      })
    )
    .setTimeout(deps.timeoutInSeconds)
    .build();

  const simResult = await deps.rpc.simulateTransaction(simulationTx);

  if ("error" in simResult) {
    throw new Error(`Simulation failed: ${simResult.error}`);
  }

  return {
    authEntries: simResult.result?.auth || [],
  };
}

export async function signResimulateAndPrepare(
  deps: {
    rpc: rpc.Server;
    networkPassphrase: string;
    timeoutInSeconds: number;
    deployerKeypair: Keypair;
    signAuthEntry: (
      entry: xdr.SorobanAuthorizationEntry,
      options?: { credentialId?: string; expiration?: number }
    ) => Promise<xdr.SorobanAuthorizationEntry>;
  },
  hostFunc: xdr.HostFunction,
  authEntries: xdr.SorobanAuthorizationEntry[],
  options?: {
    credentialId?: string;
    expiration?: number;
  }
): Promise<Transaction> {
  const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];
  for (const authEntry of authEntries) {
    const signedEntry = await deps.signAuthEntry(authEntry, {
      credentialId: options?.credentialId,
      expiration: options?.expiration,
    });
    signedAuthEntries.push(signedEntry);
  }

  let sourceAccount;
  try {
    sourceAccount = await deps.rpc.getAccount(deps.deployerKeypair.publicKey());
  } catch (error) {
    throw new Error(
      `Re-simulation requires the deployer account to exist on-chain. ` +
      `Fund ${deps.deployerKeypair.publicKey()} before re-simulating transactions.`
    );
  }

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
    throw new Error(`Re-simulation failed: ${resimResult.error}`);
  }

  const resimTxXdr = resimTx.toXDR();
  const normalizedTx = TransactionBuilder.fromXDR(resimTxXdr, deps.networkPassphrase);

  const assembled = rpc.assembleTransaction(normalizedTx as Transaction, resimResult);
  return assembled.build() as Transaction;
}

export async function sign(
  deps: {
    getContractId: () => string | undefined;
    getCredentialId: () => string | undefined;
    calculateExpiration: () => Promise<number>;
    signAuthEntry: (
      entry: xdr.SorobanAuthorizationEntry,
      options?: { credentialId?: string; expiration?: number }
    ) => Promise<xdr.SorobanAuthorizationEntry>;
  },
  transaction: contract.AssembledTransaction<unknown>,
  options?: {
    credentialId?: string;
    expiration?: number;
  }
): Promise<contract.AssembledTransaction<unknown>> {
  const contractId = deps.getContractId();
  if (!contractId) {
    throw new Error("Not connected to a wallet. Call connectWallet() first.");
  }

  const credentialId = options?.credentialId ?? deps.getCredentialId();
  const expiration = options?.expiration ?? await deps.calculateExpiration();

  await transaction.signAuthEntries({
    address: contractId,
    authorizeEntry: async (entry: xdr.SorobanAuthorizationEntry) => {
      const clone = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
      return deps.signAuthEntry(clone, { credentialId, expiration });
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
      options?: { credentialId?: string; expiration?: number }
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
  }
): Promise<TransactionResult> {
  if (!deps.getContractId()) {
    return { success: false, hash: "", error: "Not connected to a wallet. Call connectWallet() first." };
  }

  try {
    const builtTx = transaction.built;
    if (!builtTx) {
      return { success: false, hash: "", error: "Transaction has no built transaction" };
    }

    const operations = builtTx.operations;
    if (operations.length !== 1) {
      return { success: false, hash: "", error: "Expected exactly one operation" };
    }

    const operation = operations[0];
    if (operation.type !== "invokeHostFunction") {
      return { success: false, hash: "", error: "Expected invokeHostFunction operation" };
    }

    const invokeOp = operation as Operation.InvokeHostFunction;

    const simData = transaction.simulationData;
    if (!simData?.result?.auth) {
      return { success: false, hash: "", error: "No simulation data or auth entries" };
    }

    const preparedTx = await deps.signResimulateAndPrepare(
      invokeOp.func,
      simData.result.auth,
      { credentialId: options?.credentialId, expiration: options?.expiration }
    );

    const submissionOpts: SubmissionOptions = { forceMethod: options?.forceMethod };
    if (!deps.shouldUseFeeSponsoring(submissionOpts) || deps.hasSourceAccountAuth(preparedTx)) {
      preparedTx.sign(deps.deployerKeypair);
    }

    return deps.sendAndPoll(preparedTx, submissionOpts);
  } catch (err) {
    return {
      success: false,
      hash: "",
      error: err instanceof Error ? err.message : "Unknown error",
    };
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
    return { success: false, hash: "", error: "Not connected to a wallet" };
  }

  if (!deps.networkPassphrase.includes("Test")) {
    return {
      success: false,
      hash: "",
      error: "fundWallet() only works on testnet",
    };
  }

  try {
    const tempKeypair = Keypair.random();

    const friendbotResponse = await fetch(
      `${FRIENDBOT_URL}?addr=${tempKeypair.publicKey()}`
    );

    if (!friendbotResponse.ok) {
      const text = await friendbotResponse.text();
      return { success: false, hash: "", error: `Friendbot error: ${text}` };
    }

    const RESERVE_XLM = FRIENDBOT_RESERVE_XLM;
    let sourceAccount = await deps.rpc.getAccount(tempKeypair.publicKey());

    const tokenAddress = Address.fromString(nativeTokenContract);
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
      return { success: false, hash: "", error: "Insufficient balance after reserve" };
    }

    const amountInStroops = xlmToStroops(transferAmount);

    const toAddress = Address.fromString(contractId);

    const transferOp = Operation.invokeHostFunction({
      func: xdr.HostFunction.hostFunctionTypeInvokeContract(
        new xdr.InvokeContractArgs({
          contractAddress: tokenAddress.toScAddress(),
          functionName: "transfer",
          args: [
            xdr.ScVal.scvAddress(fromAddress.toScAddress()),
            xdr.ScVal.scvAddress(toAddress.toScAddress()),
            xdr.ScVal.scvI128(
              new xdr.Int128Parts({
                lo: xdr.Uint64.fromString((amountInStroops & BigInt("0xFFFFFFFFFFFFFFFF")).toString()),
                hi: xdr.Int64.fromString((amountInStroops >> BigInt(64)).toString()),
              })
            ),
          ],
        })
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
      return { success: false, hash: "", error: `Simulation failed: ${simResult.error}` };
    }

    const authEntries = simResult.result?.auth || [];
    const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];

    const currentLedger = simResult.latestLedger;
    const expirationLedger = currentLedger + LEDGERS_PER_HOUR; // ~1 hour

    for (const entry of authEntries) {
      const credType = entry.credentials().switch().name;

      // For source_account credentials, convert to Address credentials
      // so the Relayer can use its own channel accounts
      if (credType === "sorobanCredentialsSourceAccount") {
        // Generate a nonce for the new Address credential
        const nonce = xdr.Int64.fromString(Date.now().toString());

        const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
          new xdr.HashIdPreimageSorobanAuthorization({
            networkId: hash(Buffer.from(deps.networkPassphrase)),
            nonce,
            signatureExpirationLedger: expirationLedger,
            invocation: entry.rootInvocation(),
          })
        );
        const payload = hash(preimage.toXDR());
        const signature = tempKeypair.sign(payload);

        const sigEntry = new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("public_key"),
          val: xdr.ScVal.scvBytes(tempKeypair.rawPublicKey()),
        });
        const sigEntrySignature = new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("signature"),
          val: xdr.ScVal.scvBytes(signature),
        });

        // Create new Address credentials entry to replace source_account
        const addressEntry = new xdr.SorobanAuthorizationEntry({
          credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
            new xdr.SorobanAddressCredentials({
              address: Address.fromString(tempKeypair.publicKey()).toScAddress(),
              nonce,
              signatureExpirationLedger: expirationLedger,
              signature: xdr.ScVal.scvVec([xdr.ScVal.scvMap([sigEntry, sigEntrySignature])]),
            })
          ),
          rootInvocation: entry.rootInvocation(),
        });

        signedAuthEntries.push(addressEntry);
        continue;
      }

      // For Address credentials, sign them
      if (credType === "sorobanCredentialsAddress") {
        const credentials = entry.credentials().address();
        credentials.signatureExpirationLedger(expirationLedger);

        const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
          new xdr.HashIdPreimageSorobanAuthorization({
            networkId: hash(Buffer.from(deps.networkPassphrase)),
            nonce: credentials.nonce(),
            signatureExpirationLedger: credentials.signatureExpirationLedger(),
            invocation: entry.rootInvocation(),
          })
        );
        const payload = hash(preimage.toXDR());
        const signature = tempKeypair.sign(payload);

        const sigEntry = new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("public_key"),
          val: xdr.ScVal.scvBytes(tempKeypair.rawPublicKey()),
        });
        const sigEntrySignature = new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("signature"),
          val: xdr.ScVal.scvBytes(signature),
        });

        credentials.signature(
          xdr.ScVal.scvVec([xdr.ScVal.scvMap([sigEntry, sigEntrySignature])])
        );

        signedAuthEntries.push(entry);
        continue;
      }

      // Unknown credential type - push as-is (shouldn't happen)
      signedAuthEntries.push(entry);
    }

    sourceAccount = await deps.rpc.getAccount(tempKeypair.publicKey());

    const invokeHostFn = simulationTx.operations[0] as Operation.InvokeHostFunction;

    const txWithAuth = new TransactionBuilder(sourceAccount, {
      fee: BASE_FEE,
      networkPassphrase: deps.networkPassphrase,
    })
      .addOperation(
        Operation.invokeHostFunction({
          func: invokeHostFn.func,
          auth: signedAuthEntries,
        })
      )
      .setTimeout(30)
      .build();

    // Re-simulate with signed Address credentials to get correct footprint and fees.
    const resimResult = await deps.rpc.simulateTransaction(txWithAuth);

    if ("error" in resimResult) {
      return { success: false, hash: "", error: `Re-simulation failed: ${resimResult.error}` };
    }

    const txWithAuthXdr = txWithAuth.toXDR();
    const normalizedTxWithAuth = TransactionBuilder.fromXDR(txWithAuthXdr, deps.networkPassphrase);

    const preparedTx = rpc.assembleTransaction(normalizedTxWithAuth as Transaction, resimResult).build();

    const submissionOpts: SubmissionOptions = { forceMethod: options?.forceMethod };
    if (!deps.shouldUseFeeSponsoring(submissionOpts) || deps.hasSourceAccountAuth(preparedTx)) {
      preparedTx.sign(tempKeypair);
    }

    const txResult = await deps.sendAndPoll(preparedTx, submissionOpts);

    return {
      ...txResult,
      amount: txResult.success ? transferAmount : undefined,
    };
  } catch (err) {
    return {
      success: false,
      hash: "",
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}

export async function transfer(
  deps: {
    getContractId: () => string | undefined;
    rpc: rpc.Server;
    networkPassphrase: string;
    timeoutInSeconds: number;
    deployerKeypair: Keypair;
    shouldUseFeeSponsoring: (options?: SubmissionOptions) => boolean;
    hasSourceAccountAuth: (transaction: Transaction) => boolean;
    sendAndPoll: (transaction: Transaction, options?: SubmissionOptions) => Promise<TransactionResult>;
    signResimulateAndPrepare: (
      hostFunc: xdr.HostFunction,
      authEntries: xdr.SorobanAuthorizationEntry[],
      options?: { credentialId?: string; expiration?: number }
    ) => Promise<Transaction>;
  },
  tokenContract: string,
  recipient: string,
  amount: number,
  options?: {
    credentialId?: string;
    forceMethod?: SubmissionMethod;
  }
): Promise<TransactionResult> {
  const contractId = deps.getContractId();
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

  try {
    const amountInStroops = xlmToStroops(amount);

    const tokenAddress = Address.fromString(tokenContract);
    const fromAddress = Address.fromString(contractId);
    const toAddress = Address.fromString(recipient);

    const hostFunc = xdr.HostFunction.hostFunctionTypeInvokeContract(
      new xdr.InvokeContractArgs({
        contractAddress: tokenAddress.toScAddress(),
        functionName: "transfer",
        args: [
          xdr.ScVal.scvAddress(fromAddress.toScAddress()),
          xdr.ScVal.scvAddress(toAddress.toScAddress()),
          xdr.ScVal.scvI128(
            new xdr.Int128Parts({
              lo: xdr.Uint64.fromString((amountInStroops & BigInt("0xFFFFFFFFFFFFFFFF")).toString()),
              hi: xdr.Int64.fromString((amountInStroops >> BigInt(64)).toString()),
            })
          ),
        ],
      })
    );

    const { authEntries } = await simulateHostFunction(
      {
        rpc: deps.rpc,
        networkPassphrase: deps.networkPassphrase,
        timeoutInSeconds: deps.timeoutInSeconds,
        deployerKeypair: deps.deployerKeypair,
      },
      hostFunc
    );

    const preparedTx = await deps.signResimulateAndPrepare(
      hostFunc,
      authEntries,
      { credentialId: options?.credentialId }
    );

    const submissionOpts: SubmissionOptions = { forceMethod: options?.forceMethod };
    if (!deps.shouldUseFeeSponsoring(submissionOpts) || deps.hasSourceAccountAuth(preparedTx)) {
      preparedTx.sign(deps.deployerKeypair);
    }

    return deps.sendAndPoll(preparedTx, submissionOpts);
  } catch (err) {
    return {
      success: false,
      hash: "",
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}
