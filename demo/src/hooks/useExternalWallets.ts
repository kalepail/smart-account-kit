import { useState, useCallback, useEffect } from "react";
import type { SmartAccountKit, ConnectedWallet } from "smart-account-kit";
import type { LogFn } from "../types";

/**
 * Maps an SDK external signer's type to a display wallet name.
 */
function walletNameForType(type: string): string {
  if (type === "keypair") return "Secret Key";
  if (type === "ed25519") return "Ed25519 Key";
  return "Unknown Wallet";
}

/**
 * Manages external (G-address / Ed25519) signers through the SDK's
 * externalSigners manager and mirrors them into a `connectedWallets` list for
 * the UI.
 */
export function useExternalWallets(kit: SmartAccountKit | null, log: LogFn) {
  const [connectedWallets, setConnectedWallets] = useState<ConnectedWallet[]>([]);

  // A new kit has a fresh (empty) external-signer manager; reset the mirror.
  useEffect(() => {
    setConnectedWallets([]);
  }, [kit]);

  const refreshConnectedWallets = useCallback(() => {
    if (!kit) return;
    const allSigners = kit.externalSigners.getAll();
    setConnectedWallets(
      allSigners.map((s) => ({
        address: s.address,
        walletId: s.walletId || s.type,
        walletName: s.walletName || walletNameForType(s.type),
      }))
    );
  }, [kit]);

  const connectWallet = useCallback(async (): Promise<ConnectedWallet | null> => {
    if (!kit) return null;
    const result = await kit.externalSigners.addFromWallet();
    refreshConnectedWallets();
    return result;
  }, [kit, refreshConnectedWallets]);

  const disconnectWallet = useCallback(async () => {
    if (!kit) return;
    await kit.externalSigners.removeAll();
    setConnectedWallets([]);
  }, [kit]);

  const disconnectWalletByAddress = useCallback(
    (address: string) => {
      if (!kit) return;
      kit.externalSigners.remove(address);
      refreshConnectedWallets();
    },
    [kit, refreshConnectedWallets]
  );

  const addFromSecret = useCallback(
    (secretKey: string): { address: string } | null => {
      if (!kit) return null;
      try {
        const result = kit.externalSigners.addFromSecret(secretKey);
        refreshConnectedWallets();
        log(`Added secret key signer: ${result.address.slice(0, 10)}...`, "success");
        return result;
      } catch (err) {
        const message = err instanceof Error ? err.message : "Failed to add secret key";
        log(`Failed to add secret key: ${message}`, "error");
        throw err;
      }
    },
    [kit, refreshConnectedWallets, log]
  );

  const addEd25519FromSecret = useCallback(
    (secretKey: string): { address: string; publicKey: string } | null => {
      if (!kit) return null;
      try {
        const result = kit.externalSigners.addEd25519FromSecret(secretKey);
        refreshConnectedWallets();
        log(`Registered Ed25519 signer: ${result.address.slice(0, 10)}...`, "success");
        return result;
      } catch (err) {
        const message = err instanceof Error ? err.message : "Failed to add Ed25519 key";
        log(`Failed to add Ed25519 key: ${message}`, "error");
        throw err;
      }
    },
    [kit, refreshConnectedWallets, log]
  );

  return {
    connectedWallets,
    setConnectedWallets,
    refreshConnectedWallets,
    connectWallet,
    disconnectWallet,
    disconnectWalletByAddress,
    addFromSecret,
    addEd25519FromSecret,
  };
}
