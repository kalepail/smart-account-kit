import { describe, expect, it, vi } from "vitest";
import { submitDeploymentTx } from "./deploy-ops";

function makeDeps() {
  return {
    storage: {
      delete: vi.fn(),
      update: vi.fn(),
    },
    rpc: {
      pollTransaction: vi.fn(),
    },
    relayer: {
      sendXdr: vi.fn(),
    },
  };
}

function makeTx(sendResult?: {
  sendTransactionResponse?: { hash?: string };
  getTransactionResponse?: { status?: string; ledger?: number };
}) {
  return {
    signed: { toXDR: vi.fn(() => "signed-xdr") },
    send: vi.fn().mockResolvedValue(
      sendResult ?? {
        sendTransactionResponse: { hash: "rpc-hash" },
        getTransactionResponse: { status: "SUCCESS", ledger: 456 },
      }
    ),
  };
}

describe("submitDeploymentTx", () => {
  it("submits deployments through relayer when relayer succeeds", async () => {
    const deps = makeDeps();
    const tx = makeTx();

    deps.relayer.sendXdr.mockResolvedValue({ success: true, hash: "relayer-hash" });
    deps.rpc.pollTransaction.mockResolvedValue({ status: "SUCCESS", ledger: 123 });

    const result = await submitDeploymentTx(deps as never, tx as never, "cred-1");

    expect(deps.relayer.sendXdr).toHaveBeenCalledWith(tx.signed);
    expect(tx.send).not.toHaveBeenCalled();
    expect(deps.rpc.pollTransaction).toHaveBeenCalledWith("relayer-hash", { attempts: 10 });
    expect(deps.storage.delete).toHaveBeenCalledWith("cred-1");
    expect(result).toEqual({
      success: true,
      hash: "relayer-hash",
      ledger: 123,
    });
  });

  it("falls back to rpc for deployments when relayer submission fails", async () => {
    const deps = makeDeps();
    const tx = makeTx();

    deps.relayer.sendXdr.mockResolvedValue({
      success: false,
      error: "Transaction fee must be equal to the resource fee",
    });

    const result = await submitDeploymentTx(deps as never, tx as never, "cred-2");

    expect(deps.relayer.sendXdr).toHaveBeenCalledWith(tx.signed);
    expect(tx.send).toHaveBeenCalledTimes(1);
    expect(deps.rpc.pollTransaction).not.toHaveBeenCalled();
    expect(deps.storage.delete).toHaveBeenCalledWith("cred-2");
    expect(result).toEqual({
      success: true,
      hash: "rpc-hash",
      ledger: 456,
    });
  });

  it("does not fall back when relayer is explicitly forced", async () => {
    const deps = makeDeps();
    const tx = makeTx();

    deps.relayer.sendXdr.mockResolvedValue({
      success: false,
      error: "Transaction fee must be equal to the resource fee",
    });

    const result = await submitDeploymentTx(
      deps as never,
      tx as never,
      "cred-3",
      { forceMethod: "relayer" }
    );

    expect(tx.send).not.toHaveBeenCalled();
    expect(deps.storage.delete).not.toHaveBeenCalled();
    expect(deps.storage.update).toHaveBeenCalledWith("cred-3", {
      deploymentStatus: "failed",
      deploymentError: "Transaction fee must be equal to the resource fee",
    });
    expect(result).toEqual({
      success: false,
      hash: "",
      error: "Transaction fee must be equal to the resource fee",
    });
  });
});
