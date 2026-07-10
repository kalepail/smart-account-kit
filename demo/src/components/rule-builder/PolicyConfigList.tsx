import type { KnownPolicy } from "../../config";
import type { SelectedPolicy, SignerEntry } from "./types";

interface PolicyConfigListProps {
  selectedPolicies: SelectedPolicy[];
  setSelectedPolicies: (policies: SelectedPolicy[]) => void;
  /** Policy contracts available to add (already filtered for visibility). */
  visiblePolicies: KnownPolicy[];
  /** Signers staged in the rule (for weighted-threshold weights + max). */
  signers: SignerEntry[];
  selectedPolicyToAdd: string;
  setSelectedPolicyToAdd: (address: string) => void;
}

/**
 * The "Policies" section of the rule builder: the list of selected policies with
 * their per-type parameter editors, plus the add-policy dropdown.
 */
export function PolicyConfigList({
  selectedPolicies,
  setSelectedPolicies,
  visiblePolicies,
  signers,
  selectedPolicyToAdd,
  setSelectedPolicyToAdd,
}: PolicyConfigListProps) {
  return (
    <div className="form-group">
      <label>Policies (Optional)</label>
      <p className="form-hint">Add authorization policies for additional security.</p>

      {/* Currently selected policies */}
      {selectedPolicies.length > 0 && (
        <div className="selected-policies-list">
          {selectedPolicies.map((sp, index) => (
            <div key={index} className="selected-policy-item">
              <div className="selected-policy-header">
                <span className={`policy-type-badge policy-type-${sp.policy.type}`}>
                  {sp.policy.type}
                </span>
                <span className="policy-name">{sp.policy.name}</span>
                <button
                  className="remove-btn"
                  onClick={() => setSelectedPolicies(selectedPolicies.filter((_, i) => i !== index))}
                  title="Remove policy"
                >
                  &times;
                </button>
              </div>
              <code className="policy-address-small">{sp.policy.address}</code>

              {/* Policy-specific params */}
              {sp.policy.type === "threshold" && (
                <div className="policy-params">
                  <label>
                    Required signatures:
                    <input
                      type="number"
                      min={1}
                      max={signers.length || 15}
                      value={sp.threshold || 1}
                      onChange={(e) => {
                        const newPolicies = [...selectedPolicies];
                        newPolicies[index] = { ...sp, threshold: parseInt(e.target.value) || 1, modified: true };
                        setSelectedPolicies(newPolicies);
                      }}
                      style={{ width: "60px", marginLeft: "8px" }}
                    />
                    <span style={{ marginLeft: "8px", color: "#71717a" }}>
                      of {signers.length} signers
                    </span>
                  </label>
                </div>
              )}

              {sp.policy.type === "spending_limit" && (
                <div className="policy-params">
                  <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
                    <label>
                      Max:
                      <input
                        type="text"
                        value={sp.spendingLimit || "1000"}
                        onChange={(e) => {
                          const newPolicies = [...selectedPolicies];
                          newPolicies[index] = { ...sp, spendingLimit: e.target.value, modified: true };
                          setSelectedPolicies(newPolicies);
                        }}
                        style={{ width: "100px", marginLeft: "8px" }}
                      />
                      <span style={{ marginLeft: "4px" }}>XLM</span>
                    </label>
                    <label>
                      per
                      <input
                        type="number"
                        min={1}
                        value={sp.spendingPeriodDays || 1}
                        onChange={(e) => {
                          const newPolicies = [...selectedPolicies];
                          newPolicies[index] = { ...sp, spendingPeriodDays: parseInt(e.target.value) || 1, modified: true };
                          setSelectedPolicies(newPolicies);
                        }}
                        style={{ width: "60px", marginLeft: "8px" }}
                      />
                      <span style={{ marginLeft: "4px" }}>day(s)</span>
                    </label>
                  </div>
                </div>
              )}

              {sp.policy.type === "weighted_threshold" && (
                <div className="policy-params">
                  <div style={{ marginBottom: "12px" }}>
                    <label>
                      Required weight:
                      <input
                        type="number"
                        min={1}
                        value={sp.weightedThreshold || 1}
                        onChange={(e) => {
                          const newPolicies = [...selectedPolicies];
                          newPolicies[index] = { ...sp, weightedThreshold: parseInt(e.target.value) || 1, modified: true };
                          setSelectedPolicies(newPolicies);
                        }}
                        style={{ width: "80px", marginLeft: "8px" }}
                      />
                    </label>
                  </div>
                  {signers.length > 0 ? (
                    <div>
                      <div style={{ fontSize: "0.85rem", color: "#71717a", marginBottom: "8px" }}>
                        Signer weights:
                      </div>
                      {signers.map((signer) => {
                        const currentWeight = sp.signerWeights?.get(signer.id) || 0;
                        return (
                          <div key={signer.id} style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                            <span style={{ flex: 1, fontSize: "0.85rem", color: "#a1a1aa" }}>
                              {signer.label}
                            </span>
                            <input
                              type="number"
                              min={0}
                              value={currentWeight}
                              onChange={(e) => {
                                const newPolicies = [...selectedPolicies];
                                const newWeights = new Map(sp.signerWeights || new Map());
                                newWeights.set(signer.id, parseInt(e.target.value) || 0);
                                newPolicies[index] = { ...sp, signerWeights: newWeights, modified: true };
                                setSelectedPolicies(newPolicies);
                              }}
                              style={{ width: "60px" }}
                            />
                          </div>
                        );
                      })}
                      <div style={{ fontSize: "0.8rem", color: "#52525b", marginTop: "8px" }}>
                        Total weight: {
                          signers.reduce((sum, s) => sum + (sp.signerWeights?.get(s.id) || 0), 0)
                        }
                      </div>
                    </div>
                  ) : (
                    <div style={{ fontSize: "0.85rem", color: "#71717a", fontStyle: "italic" }}>
                      Add signers above to configure weights
                    </div>
                  )}
                </div>
              )}

              {sp.policy.type === "custom" && (
                <div className="policy-params">
                  <label>
                    Install params (JSON):
                    <input
                      type="text"
                      value={sp.customParams || "{}"}
                      onChange={(e) => {
                        const newPolicies = [...selectedPolicies];
                        newPolicies[index] = { ...sp, customParams: e.target.value, modified: true };
                        setSelectedPolicies(newPolicies);
                      }}
                      placeholder="{}"
                      style={{ marginLeft: "8px", width: "200px" }}
                    />
                  </label>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Add policy dropdown */}
      {visiblePolicies.length > 0 && (() => {
        const unselectedPolicies = visiblePolicies.filter(
          (p) => !selectedPolicies.some((sp) => sp.policy.address === p.address)
        );
        // Auto-select first available policy if none selected
        const effectiveSelection = selectedPolicyToAdd && unselectedPolicies.some((p) => p.address === selectedPolicyToAdd)
          ? selectedPolicyToAdd
          : unselectedPolicies[0]?.address || "";

        return (
          <div className="add-policy-section">
            <div className="add-signer-row">
              <select
                value={effectiveSelection}
                onChange={(e) => setSelectedPolicyToAdd(e.target.value)}
              >
                {unselectedPolicies.map((policy) => (
                  <option key={policy.address} value={policy.address}>
                    {policy.name} ({policy.type})
                  </option>
                ))}
              </select>
              <button
                className="small"
                onClick={() => {
                  const policy = visiblePolicies.find((p) => p.address === effectiveSelection);
                  if (policy) {
                    setSelectedPolicies([
                      ...selectedPolicies,
                      {
                        policy,
                        threshold: 1,
                        spendingLimit: "1000",
                        spendingPeriodDays: 1,
                        weightedThreshold: 1,
                        signerWeights: new Map(),
                        customParams: "{}",
                      },
                    ]);
                    // Reset selection to next available
                    setSelectedPolicyToAdd("");
                  }
                }}
                disabled={unselectedPolicies.length === 0}
              >
                Add Policy
              </button>
            </div>
          </div>
        );
      })()}

      {visiblePolicies.length === 0 && (
        <div className="form-hint" style={{ fontStyle: "italic" }}>
          No policy contracts configured. Enable policies in the Configuration section.
        </div>
      )}
    </div>
  );
}
