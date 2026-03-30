import { Address, Keypair, StrKey, hash, xdr } from "@stellar/stellar-sdk";
import type { Signer as ContractSigner } from "smart-account-kit-bindings";
import { buildKeyData } from "../utils";

export function makeAccount(seed: number): string {
  return Keypair.fromRawEd25519Seed(Buffer.alloc(32, seed)).publicKey();
}

export function makeContract(seed: number): string {
  return StrKey.encodeContract(hash(Buffer.from(`contract-${seed}`)));
}

export function makeDelegatedSigner(seed: number): ContractSigner {
  return {
    tag: "Delegated",
    values: [makeAccount(seed)],
  };
}

export function makeExternalSigner(
  verifierSeed: number,
  publicKeySeed: number,
  credentialSeed: number
): ContractSigner {
  const verifierAddress = makeContract(verifierSeed);
  const publicKey = Buffer.alloc(65, publicKeySeed);
  const credentialId = Buffer.alloc(20, credentialSeed);

  return {
    tag: "External",
    values: [verifierAddress, buildKeyData(publicKey, credentialId)],
  };
}

export function makeAddressAuthEntry(contractId: string): xdr.SorobanAuthorizationEntry {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(contractId).toScAddress(),
        nonce: xdr.Int64.fromString("1"),
        signatureExpirationLedger: 1,
        signature: xdr.ScVal.scvVoid(),
      })
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(contractId).toScAddress(),
          functionName: "__check_auth",
          args: [],
        })
      ),
      subInvocations: [],
    }),
  });
}
