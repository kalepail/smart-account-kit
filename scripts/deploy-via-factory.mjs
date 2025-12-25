#!/usr/bin/env node
/**
 * Deploy a smart wallet via factory contract using the relayer proxy.
 *
 * Usage: node scripts/deploy-via-factory.mjs
 */

import {
  Address,
  xdr,
  nativeToScVal,
  hash,
  StrKey,
  Networks,
} from '@stellar/stellar-sdk';

// Configuration from demo/.env
const CONFIG = {
  rpcUrl: 'https://soroban-rpc.mainnet.stellar.gateway.fm',
  networkPassphrase: Networks.PUBLIC,
  factoryAddress: 'CCMGFBBY44JOY6LMM2HTADT5MZ77W75PMAT2QS7GQ4KVNC2RSEBTIAEJ',
  wasmHash: 'f340242d143b42e273f628f44ccb907f55f5beb256f3de17de2c005fcdbc9783',
  webauthnVerifier: 'CDX3NZ2YODNGEFDHRK4DQLWM44R64WW6D6JHXC66B5236YP76H6BPCB3',
  relayerUrl: process.env.RELAYER_URL || 'https://your-relayer-proxy.example.com',
};

// Generate a unique salt for this deployment
const testId = `test-wallet-${Date.now()}`;
const salt = hash(Buffer.from(testId));

console.log('='.repeat(60));
console.log('Factory Wallet Deployment Script');
console.log('='.repeat(60));
console.log('Test ID:', testId);
console.log('Salt:', salt.toString('hex'));

// Create a fake passkey public key (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
const fakePublicKey = Buffer.alloc(65);
fakePublicKey[0] = 0x04;
for (let i = 1; i < 65; i++) fakePublicKey[i] = Math.floor(Math.random() * 256);

// Fake credential ID
const fakeCredentialId = Buffer.from(testId);

// key_data = pubkey + credentialId
const keyData = Buffer.concat([fakePublicKey, fakeCredentialId]);

console.log('Public Key (first 20 bytes):', fakePublicKey.slice(0, 20).toString('hex') + '...');
console.log('Credential ID:', fakeCredentialId.toString());

// Build External signer: External(verifier_address, key_data)
const signerEnum = xdr.ScVal.scvVec([
  nativeToScVal('External', { type: 'symbol' }),
  Address.fromString(CONFIG.webauthnVerifier).toScVal(),
  nativeToScVal(keyData, { type: 'bytes' }),
]);

// Constructor args: (signers: Vec<Signer>, policies: Map<Address, Val>)
const constructorArgs = xdr.ScVal.scvVec([
  xdr.ScVal.scvVec([signerEnum]), // one signer
  xdr.ScVal.scvMap([]) // empty policies
]);

// Build the factory.deploy() invocation
const hostFunc = xdr.HostFunction.hostFunctionTypeInvokeContract(
  new xdr.InvokeContractArgs({
    contractAddress: Address.fromString(CONFIG.factoryAddress).toScAddress(),
    functionName: 'deploy',
    args: [
      // wasm_hash: BytesN<32>
      nativeToScVal(Buffer.from(CONFIG.wasmHash, 'hex'), { type: 'bytes' }),
      // salt: BytesN<32>
      nativeToScVal(salt, { type: 'bytes' }),
      // constructor_args: Vec<Val>
      constructorArgs
    ]
  })
);

// Calculate expected contract address
const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
  new xdr.HashIdPreimageContractId({
    networkId: hash(Buffer.from(CONFIG.networkPassphrase)),
    contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
      new xdr.ContractIdPreimageFromAddress({
        address: Address.fromString(CONFIG.factoryAddress).toScAddress(),
        salt: salt,
      })
    ),
  })
);
const expectedContractId = StrKey.encodeContract(hash(preimage.toXDR()));

console.log('\nExpected Contract Address:', expectedContractId);
console.log('Factory Address:', CONFIG.factoryAddress);
console.log('Relayer URL:', CONFIG.relayerUrl);

const funcXdr = hostFunc.toXDR('base64');
console.log('\n--- Sending to Relayer ---');
console.log('func XDR length:', funcXdr.length);

try {
  const response = await fetch(CONFIG.relayerUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-client-name': 'smart-account-kit',
      'x-client-version': '0.2.5',
    },
    body: JSON.stringify({
      func: funcXdr,
      auth: []
    })
  });

  const result = await response.json();

  console.log('\n--- Relayer Response ---');
  console.log(JSON.stringify(result, null, 2));

  if (result.success) {
    console.log('\n SUCCESS!');
    console.log('Transaction Hash:', result.data?.hash || result.hash);
    console.log('Deployed Contract:', expectedContractId);
    console.log('\nView on Stellar Expert:');
    console.log(`https://stellar.expert/explorer/public/contract/${expectedContractId}`);
  } else {
    console.log('\n FAILED');
    console.log('Error:', result.error);
  }
} catch (err) {
  console.error('\n Request Error:', err.message);
}
