import type { KnownPolicy } from "../config";

interface ConfigPanelProps {
  accountWasmHash: string;
  setAccountWasmHash: (value: string) => void;
  webauthnVerifier: string;
  setWebauthnVerifier: (value: string) => void;
  configValid: boolean;
  hasRelayer: boolean;
  knownPolicies: KnownPolicy[];
}

/** Configuration card: editable WASM hash + WebAuthn verifier and status badges. */
export function ConfigPanel({
  accountWasmHash,
  setAccountWasmHash,
  webauthnVerifier,
  setWebauthnVerifier,
  configValid,
  hasRelayer,
  knownPolicies,
}: ConfigPanelProps) {
  return (
    <div className="card">
      <h3>Configuration</h3>
      <div className="form-group">
        <label>Smart Account WASM Hash</label>
        <input
          type="text"
          value={accountWasmHash}
          onChange={(e) => setAccountWasmHash(e.target.value)}
          placeholder="Enter deployed WASM hash..."
        />
      </div>
      <div className="form-group">
        <label>WebAuthn Verifier Address</label>
        <input
          type="text"
          value={webauthnVerifier}
          onChange={(e) => setWebauthnVerifier(e.target.value)}
          placeholder="C..."
        />
      </div>

      {/* Policy contracts - informational */}
      <details style={{ marginTop: "12px" }}>
        <summary style={{ cursor: "pointer", color: "#71717a", fontSize: "0.9rem" }}>
          Available Policy Contracts
        </summary>
        <div style={{ marginTop: "12px" }}>
          <p style={{ fontSize: "0.85rem", color: "#71717a", marginBottom: "12px" }}>
            These policy contracts are deployed to testnet and can be attached to context rules.
            Policies define additional conditions that must be met for a transaction to be authorized.
          </p>

          <div className="policy-list">
            {knownPolicies.map((policy) => (
              <div key={policy.address} className="policy-item">
                <div className="policy-info">
                  <span className="policy-name">{policy.name}</span>
                  <span className="policy-description">{policy.description}</span>
                  <code className="policy-address">{policy.address}</code>
                </div>
              </div>
            ))}
          </div>
        </div>
      </details>

      <div style={{ display: "flex", gap: "12px", alignItems: "center", marginTop: "16px" }}>
        <span className="network-badge">Testnet</span>
        <span className={`status ${configValid ? "connected" : "disconnected"}`}>
          {configValid ? "Config Valid" : "Missing Config"}
        </span>
        {hasRelayer && (
          <span
            className="status connected"
            title="Transactions are submitted through the OpenZeppelin Relayer — channel accounts pay the fees, your wallet pays none."
          >
            Fees Sponsored
          </span>
        )}
      </div>
    </div>
  );
}
