import { useState, useCallback } from "react";
import type { SmartAccountKit } from "smart-account-kit";
import { LEDGERS_PER_DAY } from "smart-account-kit";
import type { ContextRule, Signer } from "smart-account-kit-bindings";
import { STROOPS_PER_XLM } from "../constants";
import type { KnownPolicy } from "../config";
import type { LogFn } from "../types";
import { formatSignerForDisplay, truncateAddress } from "../utils/sdk";
import { useMultiSignerSubmit } from "../hooks/useMultiSignerSubmit";

interface PolicyInspectorProps {
  kit: SmartAccountKit;
  rule: ContextRule;
  policyAddress: string;
  /** The known policy metadata, if this address is a recognized policy type. */
  knownPolicy?: KnownPolicy;
  activeCredentialId: string | null;
  onLog: LogFn;
  onChanged: () => void;
}

/** Live per-signer weight read from a weighted-threshold policy. */
interface WeightRow {
  signer: Signer;
  label: string;
  weight: number;
}

/** Live params read from a policy for a given context rule. */
interface LiveParams {
  threshold?: number;
  weights?: WeightRow[];
  spendingLimitXlm?: string;
  periodDays?: number;
  totalSpentXlm?: string;
}

/**
 * Reads live policy params for a rule via the SDK's typed policy clients
 * (get_threshold / get_signer_weights / get_spending_limit_data) and edits them
 * via the matching setters, routed through the smart account's execute().
 *
 * Note: threshold policies are NOT auto-notified when a rule's signer set
 * changes — this panel is how you keep them in sync after editing signers.
 */
export function PolicyInspector({
  kit,
  rule,
  policyAddress,
  knownPolicy,
  activeCredentialId,
  onLog,
  onChanged,
}: PolicyInspectorProps) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [params, setParams] = useState<LiveParams | null>(null);
  const [thresholdInput, setThresholdInput] = useState("");
  const [limitInput, setLimitInput] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = useMultiSignerSubmit(kit, onLog);

  const load = useCallback(async () => {
    if (!knownPolicy) return;
    setLoading(true);
    try {
      if (knownPolicy.type === "threshold") {
        const threshold = await kit.policyClients
          .threshold(policyAddress)
          .getThreshold(rule.id);
        setParams({ threshold });
        setThresholdInput(String(threshold));
      } else if (knownPolicy.type === "weighted_threshold") {
        const client = kit.policyClients.weighted(policyAddress);
        const threshold = await client.getThreshold(rule.id);
        const weightMap = await client.getSignerWeights(rule);
        const weights: WeightRow[] = [...weightMap.entries()].map(
          ([signer, weight]) => ({
            signer,
            label: formatSignerForDisplay(signer).display,
            weight,
          })
        );
        setParams({ threshold, weights });
        setThresholdInput(String(threshold));
      } else if (knownPolicy.type === "spending_limit") {
        const data = await kit.policyClients
          .spendingLimit(policyAddress)
          .getSpendingLimitData(rule.id);
        const limitXlm = (Number(data.spending_limit) / STROOPS_PER_XLM).toString();
        const totalXlm = (
          Number(data.cached_total_spent) / STROOPS_PER_XLM
        ).toString();
        const periodDays =
          Math.round(Number(data.period_ledgers) / LEDGERS_PER_DAY) || 1;
        setParams({
          spendingLimitXlm: limitXlm,
          periodDays,
          totalSpentXlm: totalXlm,
        });
        setLimitInput(limitXlm);
      }
    } catch (error) {
      onLog(`Failed to read ${knownPolicy.type} policy: ${error}`, "error");
      setParams(null);
    } finally {
      setLoading(false);
    }
  }, [kit, knownPolicy, policyAddress, rule, onLog]);

  const toggle = useCallback(() => {
    const next = !expanded;
    setExpanded(next);
    if (next && !params && knownPolicy) {
      void load();
    }
  }, [expanded, params, knownPolicy, load]);

  const runSetter = useCallback(
    async (label: string, build: () => Promise<import("smart-account-kit").AssembledTransaction<unknown>>) => {
      setBusy(true);
      onLog(`${label}...`);
      try {
        const tx = await build();
        const result = await submit(tx, {
          ruleSigners: rule.signers,
          activeCredentialId,
        });
        if (result.success) {
          onLog(`${label} succeeded`, "success");
          await load();
          onChanged();
        } else {
          onLog(`${label} failed: ${result.error ?? "unknown error"}`, "error");
        }
      } catch (error) {
        onLog(`${label} failed: ${error}`, "error");
      } finally {
        setBusy(false);
      }
    },
    [submit, rule, activeCredentialId, onLog, load, onChanged]
  );

  const setThreshold = useCallback(() => {
    if (!knownPolicy) return;
    const value = parseInt(thresholdInput, 10);
    if (!Number.isFinite(value) || value < 1) {
      onLog("Threshold must be a positive integer", "error");
      return;
    }
    const client =
      knownPolicy.type === "weighted_threshold"
        ? kit.policyClients.weighted(policyAddress)
        : kit.policyClients.threshold(policyAddress);
    void runSetter(`Setting threshold to ${value}`, () =>
      client.setThreshold(value, rule)
    );
  }, [knownPolicy, thresholdInput, kit, policyAddress, rule, runSetter, onLog]);

  const setSpendingLimit = useCallback(() => {
    const xlm = parseFloat(limitInput);
    if (!Number.isFinite(xlm) || xlm <= 0) {
      onLog("Spending limit must be a positive amount", "error");
      return;
    }
    const stroops = BigInt(Math.floor(xlm * STROOPS_PER_XLM));
    void runSetter(`Setting spending limit to ${xlm} XLM`, () =>
      kit.policyClients.spendingLimit(policyAddress).setSpendingLimit(stroops, rule)
    );
  }, [limitInput, kit, policyAddress, rule, runSetter, onLog]);

  const setSignerWeight = useCallback(
    (row: WeightRow, weight: number) => {
      void runSetter(`Setting weight for ${row.label} to ${weight}`, () =>
        kit.policyClients
          .weighted(policyAddress)
          .setSignerWeight(row.signer, weight, rule)
      );
    },
    [kit, policyAddress, rule, runSetter]
  );

  return (
    <div className="policy-inspector">
      <button
        className="policy-inspector-toggle"
        onClick={toggle}
        title="Inspect and edit this policy's live params"
      >
        {knownPolicy ? `${knownPolicy.name} — ${expanded ? "hide" : "manage"}` : "Custom policy"}
      </button>

      {expanded && knownPolicy && (
        <div className="policy-inspector-body">
          {loading && (
            <div className="loading-state">
              <span className="spinner" /> Reading policy...
            </div>
          )}

          {!loading && params && knownPolicy.type === "threshold" && (
            <div className="policy-inspector-row">
              <span>Current threshold: <strong>{params.threshold}</strong></span>
              <input
                type="number"
                min={1}
                value={thresholdInput}
                onChange={(e) => setThresholdInput(e.target.value)}
                style={{ width: "70px" }}
              />
              <button className="small" onClick={setThreshold} disabled={busy}>
                {busy ? <span className="spinner" /> : "Set Threshold"}
              </button>
            </div>
          )}

          {!loading && params && knownPolicy.type === "weighted_threshold" && (
            <div className="policy-inspector-weighted">
              <div className="policy-inspector-row">
                <span>Required weight: <strong>{params.threshold}</strong></span>
                <input
                  type="number"
                  min={1}
                  value={thresholdInput}
                  onChange={(e) => setThresholdInput(e.target.value)}
                  style={{ width: "70px" }}
                />
                <button className="small" onClick={setThreshold} disabled={busy}>
                  {busy ? <span className="spinner" /> : "Set Threshold"}
                </button>
              </div>
              {params.weights && params.weights.length > 0 && (
                <div className="policy-inspector-weights">
                  <div className="detail-section-header">Signer weights</div>
                  {params.weights.map((row, idx) => (
                    <div key={idx} className="policy-inspector-row">
                      <span className="signer-id">{row.label}</span>
                      <input
                        type="number"
                        min={0}
                        defaultValue={row.weight}
                        style={{ width: "60px" }}
                        onBlur={(e) => {
                          const w = parseInt(e.target.value, 10);
                          if (Number.isFinite(w) && w !== row.weight) {
                            setSignerWeight(row, w);
                          }
                        }}
                        disabled={busy}
                      />
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {!loading && params && knownPolicy.type === "spending_limit" && (
            <div className="policy-inspector-row">
              <span>
                Limit: <strong>{params.spendingLimitXlm} XLM</strong> / {params.periodDays} day(s)
                {params.totalSpentXlm !== undefined && ` · spent ${params.totalSpentXlm} XLM`}
              </span>
              <input
                type="text"
                value={limitInput}
                onChange={(e) => setLimitInput(e.target.value)}
                style={{ width: "90px" }}
              />
              <span>XLM</span>
              <button className="small" onClick={setSpendingLimit} disabled={busy}>
                {busy ? <span className="spinner" /> : "Set Limit"}
              </button>
            </div>
          )}

          <code className="policy-address-small">{truncateAddress(policyAddress, 8)}</code>
        </div>
      )}
    </div>
  );
}
