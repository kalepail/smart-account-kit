import type { SubmissionMethod, SubmissionOptions, TransactionResult, SelectedSigner } from "../types";
import type { ExternalSignerManager } from "../external-signers";
import { rpc } from "@stellar/stellar-sdk";
import { Address, Keypair, Operation, TransactionBuilder, Transaction, hash, xdr } from "@stellar/stellar-sdk";
import { BASE_FEE } from "../constants";

export async function multiSignersTransfer(
  deps: {
    getContractId: () => string | undefined;
    externalSigners: ExternalSignerManager;
    rpc: rpc.Server;
    networkPassphrase: string;
    timeoutInSeconds: number;
    deployerKeypair: Keypair;
    deployerPublicKey: string;
    signAuthEntry: (
      entry: xdr.SorobanAuthorizationEntry,
      options?: { credentialId?: string; expiration?: number }
    ) => Promise<xdr.SorobanAuthorizationEntry>;
    shouldUseFeeSponsoring: (options?: SubmissionOptions) => boolean;
    hasSourceAccountAuth: (transaction: Transaction) => boolean;
    sendAndPoll: (transaction: Transaction, options?: SubmissionOptions) => Promise<TransactionResult>;
  },
  tokenContract: string,
  recipient: string,
  amount: number,
  selectedSigners: SelectedSigner[],
  options?: { onLog?: (message: string, type?: "info" | "success" | "error") => void; forceMethod?: SubmissionMethod }
): Promise<TransactionResult> {
  const onLog = options?.onLog ?? (() => {});

  const contractId = deps.getContractId();
  if (!contractId) {
    return { success: false, hash: "", error: "Not connected to a wallet" };
  }

  const passkeySigners = selectedSigners.filter((s) => s.type === "passkey");
  const walletSigners = selectedSigners.filter((s) => s.type === "wallet");

  onLog(`Signing with ${passkeySigners.length} passkey(s) and ${walletSigners.length} wallet(s)`);

  for (const walletSigner of walletSigners) {
    if (!walletSigner.walletAddress) continue;
    if (!deps.externalSigners.canSignFor(walletSigner.walletAddress)) {
      return {
        success: false,
        hash: "",
        error: `No signer available for address: ${walletSigner.walletAddress}. ` +
          `Use kit.externalSigners.addFromSecret() or kit.externalSigners.addFromWallet() to add a signer.`,
      };
    }
  }

  try {
    const amountInStroops = BigInt(Math.round(amount * 10_000_000));

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
              lo: xdr.Uint64.fromString(
                (amountInStroops & BigInt("0xFFFFFFFFFFFFFFFF")).toString()
              ),
              hi: xdr.Int64.fromString((amountInStroops >> BigInt(64)).toString()),
            })
          ),
        ],
      })
    );

    onLog("Simulating transaction...");
    const sourceAccount = await deps.rpc.getAccount(deps.deployerPublicKey);

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
      return { success: false, hash: "", error: `Simulation failed: ${simResult.error}` };
    }

    const authEntries = simResult.result?.auth || [];
    onLog(`Found ${authEntries.length} auth entries to sign`);

    const signedAuthEntries: xdr.SorobanAuthorizationEntry[] = [];
    const { sequence } = await deps.rpc.getLatestLedger();
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

        for (let i = 0; i < passkeySigners.length; i++) {
          const passkeySigner = passkeySigners[i];
          onLog(`Signing smart account auth entry with passkey ${i + 1}/${passkeySigners.length}...`);
          const credentialId = passkeySigner?.credentialId;
          signedEntry = await deps.signAuthEntry(signedEntry, { credentialId, expiration });
        }

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

        const smartAccountPreimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
          new xdr.HashIdPreimageSorobanAuthorization({
            networkId: hash(Buffer.from(deps.networkPassphrase)),
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
              networkId: hash(Buffer.from(deps.networkPassphrase)),
              nonce: delegatedNonce,
              signatureExpirationLedger: expiration,
              invocation: delegatedInvocation,
            })
          );
          const delegatedPreimageXdr = delegatedPreimage.toXDR("base64");

          const { signedAuthEntry: walletSignatureBase64 } = await deps.externalSigners.signAuthEntry(
            delegatedPreimageXdr,
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
      } else {
        const walletSigner = walletSigners.find(
          (s) => s.walletAddress === authAddress
        );

        if (walletSigner && deps.externalSigners.canSignFor(authAddress)) {
          onLog(`Signing separate auth entry for ${authAddress.slice(0, 8)}...`);

          const entryClone = xdr.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
          entryClone.credentials().address().signatureExpirationLedger(expiration);

          const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
            new xdr.HashIdPreimageSorobanAuthorization({
              networkId: hash(Buffer.from(deps.networkPassphrase)),
              nonce: entryClone.credentials().address().nonce(),
              signatureExpirationLedger: expiration,
              invocation: entryClone.rootInvocation(),
            })
          );
          const preimageXdr = preimage.toXDR("base64");

          const { signedAuthEntry: signatureBase64 } = await deps.externalSigners.signAuthEntry(
            preimageXdr,
            authAddress
          );

          const signatureBytes = Buffer.from(signatureBase64, "base64");
          const publicKeyBytes = Address.fromString(authAddress)
            .toScAddress()
            .accountId()
            .ed25519();

          const signatureScVal = xdr.ScVal.scvVec([
            xdr.ScVal.scvMap([
              new xdr.ScMapEntry({
                key: xdr.ScVal.scvSymbol("public_key"),
                val: xdr.ScVal.scvBytes(publicKeyBytes),
              }),
              new xdr.ScMapEntry({
                key: xdr.ScVal.scvSymbol("signature"),
                val: xdr.ScVal.scvBytes(signatureBytes),
              }),
            ]),
          ]);

          entryClone.credentials().address().signature(signatureScVal);
          signedAuthEntries.push(entryClone);
        } else {
          onLog(`Warning: Unknown auth entry for ${authAddress}`, "error");
          signedAuthEntries.push(entry);
        }
      }
    }

    onLog("Re-simulating with signatures...");
    const freshSourceAccount = await deps.rpc.getAccount(deps.deployerPublicKey);

    const resimTx = new TransactionBuilder(freshSourceAccount, {
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
      return { success: false, hash: "", error: `Re-simulation failed: ${resimResult.error}` };
    }

    const resimTxXdr = resimTx.toXDR();
    const normalizedTx = TransactionBuilder.fromXDR(resimTxXdr, deps.networkPassphrase);
    const assembled = rpc.assembleTransaction(normalizedTx as Transaction, resimResult);
    const preparedTx = assembled.build() as Transaction;

    const submissionOpts: SubmissionOptions = { forceMethod: options?.forceMethod };
    if (!deps.shouldUseFeeSponsoring(submissionOpts) || deps.hasSourceAccountAuth(preparedTx)) {
      preparedTx.sign(deps.deployerKeypair);
    }

    onLog("Submitting transaction...");
    return deps.sendAndPoll(preparedTx, submissionOpts);
  } catch (err) {
    return {
      success: false,
      hash: "",
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}
