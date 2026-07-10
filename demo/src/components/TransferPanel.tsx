import { useState } from "react";

interface TransferPanelProps {
  loading: string | null;
  onTransfer: (recipient: string, amount: string) => void;
}

/** Token transfer card (XLM). Owns recipient + amount inputs. */
export function TransferPanel({ loading, onTransfer }: TransferPanelProps) {
  const [transferTo, setTransferTo] = useState("");
  const [transferAmount, setTransferAmount] = useState("10");

  return (
    <div className="card">
      <h3>Token Transfer (XLM)</h3>
      <div className="form-group">
        <label>Recipient Address</label>
        <input
          type="text"
          value={transferTo}
          onChange={(e) => setTransferTo(e.target.value)}
          placeholder="G... or C..."
        />
      </div>
      <div className="form-group">
        <label>Amount (XLM)</label>
        <input
          type="text"
          value={transferAmount}
          onChange={(e) => setTransferAmount(e.target.value)}
          placeholder="10"
        />
      </div>
      <div className="button-group">
        <button
          onClick={() => onTransfer(transferTo, transferAmount)}
          disabled={loading !== null || !transferTo}
        >
          {loading === "Building transfer..." ? (
            <span className="spinner" />
          ) : (
            "Send Transfer"
          )}
        </button>
      </div>
    </div>
  );
}
