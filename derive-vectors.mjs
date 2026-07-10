// Inline reimplementation of deriveContractAddress using stellar-sdk
// directly (dodges the kit's strict-ESM resolution issue with
// extensionless imports in dist/). Matches the kit's utils.ts logic
// exactly — see
// smart-account-kit/src/utils.ts::deriveContractAddress.
import { Address, StrKey, hash, xdr } from "@stellar/stellar-sdk";

function deriveContractAddress(credentialId, deployerPublicKey, networkPassphrase) {
  const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
    new xdr.HashIdPreimageContractId({
      networkId: hash(Buffer.from(networkPassphrase)),
      contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
        new xdr.ContractIdPreimageFromAddress({
          address: Address.fromString(deployerPublicKey).toScAddress(),
          salt: hash(credentialId),
        })
      ),
    })
  );
  return StrKey.encodeContract(hash(preimage.toXDR()));
}

const TESTNET = "Test SDF Network ; September 2015";
const MAINNET = "Public Global Stellar Network ; September 2015";
const DEPLOYER = "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N";

const vectors = [
  { name: "zeros-16",  credHex: "00".repeat(16),  passphrase: TESTNET, deployer: DEPLOYER },
  { name: "zeros-32",  credHex: "00".repeat(32),  passphrase: TESTNET, deployer: DEPLOYER },
  { name: "ff-16",     credHex: "ff".repeat(16),  passphrase: TESTNET, deployer: DEPLOYER },
  { name: "random-16", credHex: "0123456789abcdef0123456789abcdef", passphrase: TESTNET, deployer: DEPLOYER },
  { name: "random-32", credHex: "deadbeefcafef00dfeedfacebaadf00d0123456789abcdef0123456789abcdef", passphrase: TESTNET, deployer: DEPLOYER },
  { name: "mainnet-same-cred", credHex: "0123456789abcdef0123456789abcdef", passphrase: MAINNET, deployer: DEPLOYER },
];

for (const v of vectors) {
  const credBuf = Buffer.from(v.credHex, "hex");
  const contractId = deriveContractAddress(credBuf, v.deployer, v.passphrase);
  console.log(JSON.stringify({ ...v, contractId }));
}
