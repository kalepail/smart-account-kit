import { useState } from "react";
import type { Signer } from "smart-account-kit-bindings";
import { ActiveSignerDisplay } from "./ActiveSignerDisplay";

interface WalletPanelProps {
  isConnected: boolean;
  contractId: string | null;
  balance: string | null;
  credentialId: string | null;
  activeSigner: Signer | null;
  loading: string | null;
  configValid: boolean;
  onCreate: (userName: string) => void;
  onConnect: () => void;
  onDisconnect: () => void;
  onFund: () => void;
}

/** Wallet status card: address/balance/active-signer + create/connect/fund. */
export function WalletPanel({
  isConnected,
  contractId,
  balance,
  credentialId,
  activeSigner,
  loading,
  configValid,
  onCreate,
  onConnect,
  onDisconnect,
  onFund,
}: WalletPanelProps) {
  const [userName, setUserName] = useState("");

  return (
    <div className="card">
      <div className="section-header">
        <h3>Wallet</h3>
        <span className={`status ${isConnected ? "connected" : "disconnected"}`}>
          {isConnected ? "Connected" : "Not Connected"}
        </span>
      </div>

      {isConnected && contractId && (
        <div className="wallet-info">
          <div className="info-box">
            <div className="label">Contract Address</div>
            <div className="value">{contractId}</div>
          </div>
          <div className="wallet-info-row">
            <div className="balance-display">
              <div className="balance-label">Balance</div>
              <div className="balance-value">
                {balance !== null ? `${balance} XLM` : "—"}
              </div>
            </div>
            <ActiveSignerDisplay
              credentialId={credentialId}
              activeSigner={activeSigner}
            />
          </div>
        </div>
      )}

      <div className="button-group" style={{ marginTop: "16px" }}>
        {!isConnected ? (
          <>
            <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
              <input
                type="text"
                value={userName}
                onChange={(e) => setUserName(e.target.value)}
                placeholder="Enter username (optional)"
              />
            </div>
            <button
              onClick={() => onCreate(userName)}
              disabled={loading !== null || !configValid}
            >
              {loading === "Creating wallet..." ? (
                <span className="spinner" />
              ) : (
                "Create Wallet"
              )}
            </button>
            <button
              className="secondary"
              onClick={onConnect}
              disabled={loading !== null || !configValid}
            >
              {loading === "Connecting..." ? (
                <span className="spinner" />
              ) : (
                "Connect Existing"
              )}
            </button>
          </>
        ) : (
          <>
            <button className="secondary" onClick={onDisconnect}>
              Disconnect
            </button>
            <button onClick={onFund} disabled={loading !== null}>
              {loading === "Funding wallet..." ? (
                <span className="spinner" />
              ) : (
                "Fund Wallet (Testnet)"
              )}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
