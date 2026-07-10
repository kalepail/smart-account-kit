import { useState } from "react";
import type { SmartAccountKit } from "smart-account-kit";
import type { Signer } from "smart-account-kit-bindings";
import type { LogFn } from "../types";
import { useMultiSignerSubmit } from "../hooks/useMultiSignerSubmit";

interface AdvancedPanelProps {
  kit: SmartAccountKit;
  allSigners: Signer[];
  activeCredentialId: string | null;
  onLog: LogFn;
}

/**
 * Advanced operations, collapsed by default. Currently exposes the contract
 * WASM upgrade path (kit.upgrade), routed through the multi-signer flow so a
 * rule with several / non-passkey signers still works.
 */
export function AdvancedPanel({
  kit,
  allSigners,
  activeCredentialId,
  onLog,
}: AdvancedPanelProps) {
  const [newWasmHash, setNewWasmHash] = useState("");
  const [upgrading, setUpgrading] = useState(false);
  const submit = useMultiSignerSubmit(kit, onLog);

  const handleUpgrade = async () => {
    const hash = newWasmHash.trim().replace(/^0x/, "");
    if (hash.length !== 64 || !/^[0-9a-fA-F]+$/.test(hash)) {
      onLog("Invalid WASM hash. Must be 64 hex characters (32 bytes).", "error");
      return;
    }

    setUpgrading(true);
    onLog(`Upgrading contract to WASM ${hash.slice(0, 12)}...`);
    try {
      const tx = await kit.upgrade(hash);
      const result = await submit(tx, {
        ruleSigners: allSigners,
        activeCredentialId,
      });
      if (result.success) {
        onLog("Contract upgraded successfully!", "success");
        setNewWasmHash("");
      } else {
        onLog(`Upgrade failed: ${result.error ?? "unknown error"}`, "error");
      }
    } catch (error) {
      onLog(`Upgrade failed: ${error}`, "error");
    } finally {
      setUpgrading(false);
    }
  };

  return (
    <div className="card">
      <details>
        <summary style={{ cursor: "pointer" }}>
          <h3 style={{ display: "inline" }}>Advanced</h3>
        </summary>
        <div style={{ marginTop: "16px" }}>
          <div className="form-group">
            <label>Upgrade Contract WASM Hash</label>
            <p className="form-hint">
              Replaces this smart account's contract code (upgrade). Requires the
              account's own signature. Use with care.
            </p>
            <input
              type="text"
              value={newWasmHash}
              onChange={(e) => setNewWasmHash(e.target.value)}
              placeholder="New WASM hash (64 hex chars)"
            />
          </div>
          <div className="button-group">
            <button
              className="danger"
              onClick={handleUpgrade}
              disabled={upgrading || !newWasmHash.trim()}
            >
              {upgrading ? <span className="spinner" /> : "Upgrade Contract"}
            </button>
          </div>
        </div>
      </details>
    </div>
  );
}
