import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { Address, hash, xdr } from "@stellar/stellar-sdk";
import base64url from "base64url";
import type { StorageAdapter } from "../types";
import type {
  Client as SmartAccountClient,
  Signer as ContractSigner,
  ContextRuleType,
  WebAuthnSigData,
} from "smart-account-kit-bindings";
import { WEBAUTHN_TIMEOUT_MS, SECP256R1_PUBLIC_KEY_SIZE } from "../constants";
import {
  compactSignature,
  extractPublicKeyFromAttestation,
  generateChallenge,
} from "../utils";

type ContractSignerId = ContractSigner;

type WebAuthnDeps = {
  rpId?: string;
  rpName: string;
  webAuthn: {
    startRegistration: (args: { optionsJSON: PublicKeyCredentialCreationOptionsJSON }) => Promise<RegistrationResponseJSON>;
    startAuthentication: (args: { optionsJSON: PublicKeyCredentialRequestOptionsJSON }) => Promise<AuthenticationResponseJSON>;
  };
};

type RequireWallet = () => { wallet: SmartAccountClient; contractId: string };

type SignAuthEntryDeps = WebAuthnDeps & {
  networkPassphrase: string;
  storage: StorageAdapter;
  webauthnVerifierAddress: string;
  calculateExpiration: () => Promise<number>;
  getCredentialId: () => string | undefined;
  requireWallet: RequireWallet;
};

export async function createPasskey(
  deps: WebAuthnDeps,
  appName: string,
  userName: string,
  authenticatorSelection?: {
    authenticatorAttachment?: "platform" | "cross-platform";
    residentKey?: "discouraged" | "preferred" | "required";
    userVerification?: "discouraged" | "preferred" | "required";
  }
): Promise<{
  rawResponse: RegistrationResponseJSON;
  credentialId: string;
  publicKey: Uint8Array;
}> {
  const now = new Date();
  const displayName = `${userName} — ${now.toLocaleString()}`;

  const options: PublicKeyCredentialCreationOptionsJSON = {
    challenge: generateChallenge(),
    rp: {
      id: deps.rpId,
      name: appName || deps.rpName,
    },
    user: {
      id: base64url(`${userName}:${now.getTime()}:${Math.random()}`),
      name: displayName,
      displayName,
    },
    authenticatorSelection: {
      residentKey: authenticatorSelection?.residentKey ?? "preferred",
      userVerification: authenticatorSelection?.userVerification ?? "preferred",
      authenticatorAttachment: authenticatorSelection?.authenticatorAttachment,
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    timeout: WEBAUTHN_TIMEOUT_MS,
  };

  const rawResponse = await deps.webAuthn.startRegistration({ optionsJSON: options });
  const publicKey = await extractPublicKeyFromAttestation(rawResponse.response);

  return {
    rawResponse,
    credentialId: rawResponse.id,
    publicKey,
  };
}

export async function authenticatePasskey(
  deps: WebAuthnDeps
): Promise<{ credentialId: string; rawResponse: AuthenticationResponseJSON }> {
  const authOptions: PublicKeyCredentialRequestOptionsJSON = {
    challenge: generateChallenge(),
    rpId: deps.rpId,
    userVerification: "preferred",
    timeout: WEBAUTHN_TIMEOUT_MS,
  };

  const rawResponse = await deps.webAuthn.startAuthentication({ optionsJSON: authOptions });

  return {
    credentialId: rawResponse.id,
    rawResponse,
  };
}

export async function signAuthEntry(
  deps: SignAuthEntryDeps,
  entry: xdr.SorobanAuthorizationEntry,
  options?: {
    credentialId?: string;
    expiration?: number;
  }
): Promise<xdr.SorobanAuthorizationEntry> {
  const entryXdrBytes = entry.toXDR();
  const normalizedEntry = xdr.SorobanAuthorizationEntry.fromXDR(entryXdrBytes);

  const credentials = normalizedEntry.credentials().address();
  const expiration = options?.expiration ?? await deps.calculateExpiration();
  credentials.signatureExpirationLedger(expiration);

  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: hash(Buffer.from(deps.networkPassphrase)),
      nonce: credentials.nonce(),
      signatureExpirationLedger: credentials.signatureExpirationLedger(),
      invocation: normalizedEntry.rootInvocation(),
    })
  );
  const payload = hash(preimage.toXDR());

  const credentialId = options?.credentialId ?? deps.getCredentialId();

  const authOptions: PublicKeyCredentialRequestOptionsJSON = {
    challenge: base64url(payload),
    rpId: deps.rpId,
    userVerification: "preferred",
    timeout: WEBAUTHN_TIMEOUT_MS,
    ...(credentialId && {
      allowCredentials: [{ id: credentialId, type: "public-key" }],
    }),
  };

  const authResponse = await deps.webAuthn.startAuthentication({
    optionsJSON: authOptions,
  });

  const rawSignature = base64url.toBuffer(authResponse.response.signature);
  const compactedSignature = compactSignature(rawSignature);

  const credentialIdBuffer = base64url.toBuffer(authResponse.id);
  const contextRuleTypes = buildContextRuleTypes(normalizedEntry);
  const keyData = await findKeyDataByCredentialId(
    deps.requireWallet,
    credentialIdBuffer,
    contextRuleTypes
  );

  const signerId: ContractSignerId = {
    tag: "External",
    values: [
      deps.webauthnVerifierAddress,
      keyData,
    ],
  };

  const webAuthnSigData = {
    authenticator_data: base64url.toBuffer(authResponse.response.authenticatorData),
    client_data: base64url.toBuffer(authResponse.response.clientDataJSON),
    signature: Buffer.from(compactedSignature),
  };

  const scMapEntry = buildSignatureMapEntry(signerId, webAuthnSigData);

  const currentSig = credentials.signature();
  if (currentSig.switch().name === "scvVoid") {
    credentials.signature(xdr.ScVal.scvVec([xdr.ScVal.scvMap([scMapEntry])]));
  } else {
    currentSig.vec()?.[0].map()?.push(scMapEntry);
  }

  const sigMap = credentials.signature().vec()?.[0].map();
  if (sigMap && sigMap.length > 1) {
    sigMap.sort((a, b) => {
      const aKeyXdr = a.key().toXDR("hex");
      const bKeyXdr = b.key().toXDR("hex");
      return aKeyXdr.localeCompare(bKeyXdr);
    });
  }

  if (credentialId) {
    await deps.storage.update(credentialId, { lastUsedAt: Date.now() });
  }

  return normalizedEntry;
}

async function findKeyDataByCredentialId(
  requireWallet: RequireWallet,
  credentialId: Buffer,
  contextRuleTypes: ContextRuleType[]
): Promise<Buffer> {
  const { wallet } = requireWallet();

  for (const contextRuleType of contextRuleTypes) {
    const rulesResult = await wallet.get_context_rules({
      context_rule_type: contextRuleType,
    });
    const rules = rulesResult.result;

    for (const rule of rules) {
      for (const signer of rule.signers) {
        if (signer.tag === "External") {
          const keyData = signer.values[1] as Buffer;
          if (keyData.length > SECP256R1_PUBLIC_KEY_SIZE) {
            const suffix = keyData.slice(SECP256R1_PUBLIC_KEY_SIZE);
            if (suffix.equals(credentialId)) {
              return keyData;
            }
          }
        }
      }
    }
  }

  throw new Error(
    `No signer found for credential ID: ${credentialId.toString("base64")}`
  );
}

function buildContextRuleTypes(
  entry: xdr.SorobanAuthorizationEntry
): ContextRuleType[] {
  const types: ContextRuleType[] = [];
  const seen = new Set<string>();

  const add = (type: ContextRuleType) => {
    let key: string;
    if (type.tag === "Default") {
      key = "Default";
    } else if (type.tag === "CallContract") {
      key = `CallContract:${type.values[0]}`;
    } else {
      const wasm = Buffer.from(type.values[0]);
      key = `CreateContract:${wasm.toString("hex")}`;
    }
    if (!seen.has(key)) {
      seen.add(key);
      types.push(type);
    }
  };

  const walk = (invocation: xdr.SorobanAuthorizedInvocation) => {
    const fn = invocation.function();
    const switchName = fn.switch().name;
    if (switchName === "sorobanAuthorizedFunctionTypeContractFn") {
      const args = fn.contractFn();
      const contractAddress = Address.fromScAddress(args.contractAddress()).toString();
      add({ tag: "CallContract", values: [contractAddress] });
    } else if (switchName.startsWith("sorobanAuthorizedFunctionTypeCreateContract")) {
      const wasmHash = extractCreateContractWasmHash(fn);
      if (wasmHash) {
        add({ tag: "CreateContract", values: [wasmHash] });
      }
    }

    for (const sub of invocation.subInvocations()) {
      walk(sub);
    }
  };

  walk(entry.rootInvocation());
  add({ tag: "Default", values: undefined });

  return types;
}

function extractCreateContractWasmHash(
  fn: xdr.SorobanAuthorizedFunction
): Buffer | null {
  const candidates: Array<unknown> = [];
  const fnAny = fn as unknown as {
    createContractHostFn?: () => unknown;
    createContractWithCtorHostFn?: () => unknown;
    createContractWithConstructorHostFn?: () => unknown;
  };

  if (typeof fnAny.createContractHostFn === "function") {
    candidates.push(fnAny.createContractHostFn());
  }
  if (typeof fnAny.createContractWithCtorHostFn === "function") {
    candidates.push(fnAny.createContractWithCtorHostFn());
  }
  if (typeof fnAny.createContractWithConstructorHostFn === "function") {
    candidates.push(fnAny.createContractWithConstructorHostFn());
  }

  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== "object") continue;
    const ctx = candidate as { executable?: unknown };
    const executable = typeof ctx.executable === "function"
      ? (ctx.executable as () => unknown)()
      : ctx.executable;
    if (!executable || typeof executable !== "object") continue;
    const execAny = executable as {
      switch?: () => { name: string };
      wasm?: (() => Buffer) | Buffer;
    };
    const execSwitch = execAny.switch?.();
    if (execSwitch && execSwitch.name === "contractExecutableWasm") {
      const wasm = typeof execAny.wasm === "function" ? execAny.wasm() : execAny.wasm;
      if (wasm) {
        return Buffer.from(wasm);
      }
    }
  }

  return null;
}

function buildSignatureMapEntry(
  signerId: ContractSignerId,
  sigData: WebAuthnSigData
): xdr.ScMapEntry {
  let keyVal: xdr.ScVal;
  if (signerId.tag === "Delegated") {
    keyVal = xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("Delegated"),
      xdr.ScVal.scvAddress(Address.fromString(signerId.values[0]).toScAddress()),
    ]);
  } else {
    keyVal = xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol("External"),
      xdr.ScVal.scvAddress(Address.fromString(signerId.values[0]).toScAddress()),
      xdr.ScVal.scvBytes(signerId.values[1]),
    ]);
  }

  const sigDataScVal = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("authenticator_data"),
      val: xdr.ScVal.scvBytes(sigData.authenticator_data),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("client_data"),
      val: xdr.ScVal.scvBytes(sigData.client_data),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("signature"),
      val: xdr.ScVal.scvBytes(sigData.signature),
    }),
  ]);

  const sigDataXdrBytes = sigDataScVal.toXDR();
  const sigVal = xdr.ScVal.scvBytes(sigDataXdrBytes);

  return new xdr.ScMapEntry({
    key: keyVal,
    val: sigVal,
  });
}
