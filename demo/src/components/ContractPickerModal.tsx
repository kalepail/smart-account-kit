import type { IndexedContractSummary } from "smart-account-kit";

interface ContractPickerModalProps {
  contracts: IndexedContractSummary[];
  onSelect: (contract: IndexedContractSummary) => void;
  onCancel: () => void;
}

/** Modal shown when a passkey is registered with several smart accounts. */
export function ContractPickerModal({
  contracts,
  onSelect,
  onCancel,
}: ContractPickerModalProps) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-content contract-picker-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Select Smart Account</h3>
          <button className="close-btn" onClick={onCancel}>
            ×
          </button>
        </div>
        <p className="modal-description">
          Your passkey is registered with {contracts.length} smart accounts.
          Select which one to connect to:
        </p>
        <div className="contract-list">
          {contracts.map((contract) => (
            <div
              key={contract.contract_id}
              className="contract-option"
              onClick={() => onSelect(contract)}
            >
              <div className="contract-option-header">
                <code className="contract-address">
                  {contract.contract_id.slice(0, 8)}...{contract.contract_id.slice(-4)}
                </code>
              </div>
              <div className="contract-option-stats">
                <span className="stat">
                  {contract.context_rule_count} rule{contract.context_rule_count !== 1 ? "s" : ""}
                </span>
                <span className="stat">
                  {contract.external_signer_count + contract.delegated_signer_count} signer{(contract.external_signer_count + contract.delegated_signer_count) !== 1 ? "s" : ""}
                </span>
                <span className="stat ledger">
                  Ledger {contract.last_seen_ledger}
                </span>
              </div>
            </div>
          ))}
        </div>
        <div className="modal-footer">
          <button className="secondary" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
