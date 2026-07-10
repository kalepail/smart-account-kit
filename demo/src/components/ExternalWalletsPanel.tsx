import type { ConnectedWallet } from "smart-account-kit";
import type { LogFn } from "../types";

interface ExternalWalletsPanelProps {
  connectedWallets: ConnectedWallet[];
  connectWallet: () => Promise<ConnectedWallet | null>;
  disconnectWallet: () => Promise<void>;
  disconnectWalletByAddress: (address: string) => void;
  log: LogFn;
}

/** External wallet connection card (Freighter/Lobstr/Albedo + secret keys). */
export function ExternalWalletsPanel({
  connectedWallets,
  connectWallet,
  disconnectWallet,
  disconnectWalletByAddress,
  log,
}: ExternalWalletsPanelProps) {
  return (
    <div className="card">
      <div className="section-header">
        <h3>External Wallets</h3>
        <span className={`status ${connectedWallets.length > 0 ? "connected" : "disconnected"}`}>
          {connectedWallets.length > 0 ? `${connectedWallets.length} Connected` : "None Connected"}
        </span>
      </div>
      <p className="panel-description">
        Connect external Stellar wallets (Freighter, Lobstr, Albedo, etc.) to sign transactions
        with Delegated signers. This enables multi-signer scenarios combining passkeys
        with traditional Stellar accounts. You can connect multiple wallets.
      </p>

      {connectedWallets.length > 0 && (
        <div className="connected-wallets-list-section">
          {connectedWallets.map((wallet) => (
            <div key={wallet.address} className="connected-wallet-banner">
              <div className="connected-wallet-info">
                <div className="wallet-details">
                  <span className="wallet-name">{wallet.walletName}</span>
                  <span className="wallet-address">
                    {wallet.address.slice(0, 8)}...{wallet.address.slice(-4)}
                  </span>
                </div>
              </div>
              <button
                className="secondary disconnect-btn small"
                onClick={async () => {
                  disconnectWalletByAddress(wallet.address);
                  log(`Disconnected ${wallet.walletName}: ${wallet.address.slice(0, 10)}...`);
                }}
                title="Disconnect this wallet"
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="button-group" style={{ marginTop: connectedWallets.length > 0 ? "12px" : "0" }}>
        <button
          className="secondary"
          onClick={async () => {
            log("Opening wallet connection modal...");
            try {
              const result = await connectWallet();
              if (result) {
                log(`Connected to ${result.walletName}: ${result.address.slice(0, 10)}...`, "success");
              }
            } catch (error) {
              // connect() throws on genuine failures (user cancellation returns
              // null). Surface it instead of an unhandled promise rejection.
              log(`Wallet connection failed: ${error instanceof Error ? error.message : String(error)}`, "error");
            }
          }}
        >
          {connectedWallets.length > 0 ? "+ Connect Another Wallet" : "Connect External Wallet"}
        </button>
        {connectedWallets.length > 0 && (
          <button
            className="secondary danger"
            onClick={async () => {
              await disconnectWallet();
              log("All external wallets disconnected");
            }}
          >
            Disconnect All
          </button>
        )}
      </div>
    </div>
  );
}
