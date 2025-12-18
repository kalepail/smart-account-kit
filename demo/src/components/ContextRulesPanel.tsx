import { useState, useEffect, useCallback } from "react";
import type { SmartAccountKit, SelectedSigner, AssembledTransaction } from "smart-account-kit";
import {
  describeSignerType,
  truncateAddress,
  formatSignerForDisplay,
  formatContextType,
  type ConnectedWallet,
} from "smart-account-kit";
import type { ContextRule, Signer } from "smart-account-kit-bindings";

interface ContextRulesPanelProps {
  kit: SmartAccountKit;
  isConnected: boolean;
  onLog: (message: string, type?: "info" | "success" | "error") => void;
  onAddRule: () => void;
  onEditRule: (rule: ContextRule) => void;
  /** All connected wallets */
  connectedWallets: ConnectedWallet[];
  /** Function to connect external wallet */
  connectWallet: () => Promise<ConnectedWallet | null>;
}

/**
 * Get a human-readable description of a signer type (using SDK utility)
 */
function getSignerTypeLabel(signer: Signer): string {
  const description = describeSignerType(signer);
  // Map SDK description to shorter labels for UI
  if (description === "Stellar Account") return "Stellar Account";
  if (description === "Passkey (WebAuthn)") return "Passkey";
  if (description === "Ed25519") return "Ed25519";
  return "External";
}


/**
 * Get signer identifier (address for Delegated, credential ID hint for External)
 */
function getSignerIdentifier(signer: Signer): string {
  const { display } = formatSignerForDisplay(signer);
  return display;
}

export function ContextRulesPanel({
  kit,
  isConnected,
  onLog,
  onAddRule,
  onEditRule,
  connectedWallets,
  connectWallet,
}: ContextRulesPanelProps) {
  const [rules, setRules] = useState<ContextRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedRuleId, setExpandedRuleId] = useState<number | null>(null);

  const fetchRules = useCallback(async () => {
    if (!isConnected || !kit.wallet) return;

    setLoading(true);
    try {
      // Fetch Default context rules
      const defaultRulesResult = await kit.rules.getAll({
        tag: "Default",
        values: undefined,
      });
      const defaultRules = defaultRulesResult.result || [];

      // Note: In a full implementation, you'd also fetch CallContract and CreateContract rules
      // For now, just showing Default rules as that's the most common case
      setRules(defaultRules);
    } catch (error) {
      onLog(`Failed to fetch context rules: ${error}`, "error");
    } finally {
      setLoading(false);
    }
  }, [kit, isConnected, onLog]);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  /**
   * Build SelectedSigner array from a rule's signers for multi-signer operations.
   * Uses SDK's built-in helper.
   */
  const buildSelectedSigners = useCallback((ruleSigners: Signer[]): SelectedSigner[] => {
    return kit.multiSigners.buildSelectedSigners(ruleSigners);
  }, [kit]);

  /**
   * Check if multi-signer is needed.
   * Uses SDK's built-in helper.
   */
  const needsMultiSigner = useCallback((ruleSigners: Signer[]): boolean => {
    return kit.multiSigners.needsMultiSigner(ruleSigners);
  }, [kit]);

  /**
   * Sign and submit with multi-signer support if needed
   */
  const signAndSubmitWithMultiSigner = useCallback(
    async (tx: AssembledTransaction<unknown>, ruleSigners: Signer[]): Promise<{ success: boolean; error?: string }> => {
      if (!needsMultiSigner(ruleSigners)) {
        return kit.signAndSubmit(tx);
      }

      const selectedSigners = buildSelectedSigners(ruleSigners);
      // Use SDK's built-in multi-signer operation
      const result = await kit.multiSigners.operation(tx, selectedSigners, {
        onLog,
      });
      return { success: result.success, error: result.error };
    },
    [kit, onLog, needsMultiSigner, buildSelectedSigners]
  );

  const handleRemoveRule = async (ruleId: number) => {
    if (!confirm("Are you sure you want to remove this context rule?")) return;

    // Find the rule to get its signers
    const rule = rules.find((r) => r.id === ruleId);
    if (!rule) {
      onLog(`Rule ${ruleId} not found`, "error");
      return;
    }

    // Check if wallet connection is needed for delegated signers
    const hasDelegatedSigners = rule.signers.some((s) => s.tag === "Delegated");
    if (hasDelegatedSigners && connectedWallets.length === 0) {
      onLog("Connecting external wallet for G-address signature...");
      const result = await connectWallet();
      if (!result?.address) {
        onLog("External wallet connection required for multi-signer operations", "error");
        return;
      }
      onLog(`Connected wallet: ${result.address.slice(0, 8)}...`, "success");
    }

    onLog(`Removing context rule ${ruleId}...`);
    try {
      const tx = await kit.rules.remove(ruleId);
      const result = await signAndSubmitWithMultiSigner(tx, rule.signers);
      if (result.success) {
        onLog(`Context rule ${ruleId} removed successfully!`, "success");
        fetchRules();
      } else {
        throw new Error(result.error || "Failed to remove rule");
      }
    } catch (error) {
      onLog(`Failed to remove rule: ${error}`, "error");
    }
  };

  if (!isConnected) {
    return null;
  }

  return (
    <div className="card">
      <div className="section-header">
        <h3>Context Rules (On-Chain)</h3>
        <div style={{ display: "flex", gap: "8px" }}>
          <button className="small secondary" onClick={fetchRules} disabled={loading}>
            {loading ? <span className="spinner" /> : "Refresh"}
          </button>
          <button className="small" onClick={onAddRule}>
            + Add Rule
          </button>
        </div>
      </div>

      <p className="panel-description">
        Context rules define WHO can authorize WHAT operations. Each rule specifies signers and
        policies that control access.
      </p>

      {loading && rules.length === 0 ? (
        <div className="loading-state">
          <span className="spinner" /> Loading rules...
        </div>
      ) : rules.length === 0 ? (
        <div className="empty-state">
          No context rules found. The wallet may use a default configuration.
        </div>
      ) : (
        <div className="context-rules-list">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className={`context-rule-item ${expandedRuleId === rule.id ? "expanded" : ""}`}
            >
              <div
                className="rule-header"
                onClick={() => setExpandedRuleId(expandedRuleId === rule.id ? null : rule.id)}
              >
                <div className="rule-main">
                  <div className="rule-name">
                    <span className="rule-id">#{rule.id}</span>
                    {rule.name || "Unnamed Rule"}
                  </div>
                  <div className="rule-type">{formatContextType(rule.context_type)}</div>
                </div>
                <div className="rule-summary">
                  <span className="summary-badge">
                    {rule.signers.length} signer{rule.signers.length !== 1 ? "s" : ""}
                  </span>
                  <span className="summary-badge">
                    {rule.policies.length} polic{rule.policies.length !== 1 ? "ies" : "y"}
                  </span>
                  {rule.valid_until && (
                    <span className="summary-badge expiry">
                      Expires: ledger {rule.valid_until}
                    </span>
                  )}
                  <span className="expand-icon">{expandedRuleId === rule.id ? "−" : "+"}</span>
                </div>
              </div>

              {expandedRuleId === rule.id && (
                <div className="rule-details">
                  {/* Signers */}
                  <div className="detail-section">
                    <div className="detail-section-header">Signers</div>
                    {rule.signers.length === 0 ? (
                      <div className="detail-empty">No signers (policy-only rule)</div>
                    ) : (
                      <div className="signers-grid">
                        {rule.signers.map((signer, idx) => {
                          // Check if this delegated signer matches any connected wallet
                          const matchingWallet = signer.tag === "Delegated"
                            ? connectedWallets.find((w) => w.address === signer.values[0])
                            : undefined;

                          return (
                            <div key={idx} className={`signer-chip ${matchingWallet ? "connected" : ""}`}>
                              <span className="signer-type">{getSignerTypeLabel(signer)}</span>
                              <span className="signer-id">{getSignerIdentifier(signer)}</span>
                              {matchingWallet && (
                                <span className="signer-connected-badge">{matchingWallet.walletName}</span>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Policies */}
                  <div className="detail-section">
                    <div className="detail-section-header">Policies</div>
                    {rule.policies.length === 0 ? (
                      <div className="detail-empty">No policies (signer-only rule)</div>
                    ) : (
                      <div className="policies-list">
                        {rule.policies.map((policyAddr, idx) => (
                          <div key={idx} className="policy-item">
                            <span className="policy-icon">P</span>
                            <span className="policy-address">{truncateAddress(policyAddr)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="rule-actions">
                    <button className="small secondary" onClick={() => onEditRule(rule)}>
                      Edit Rule
                    </button>
                    <button className="small danger" onClick={() => handleRemoveRule(rule.id)}>
                      Remove Rule
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
