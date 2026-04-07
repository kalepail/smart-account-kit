import { describe, expect, it, vi } from "vitest";
import { SignerManager } from "./signer-manager";
import { buildKeyData } from "../utils";
import { makeAccount, makeDelegatedSigner } from "./test-utils";

function makeDeps() {
  const wallet = {
    add_signer: vi.fn(),
    get_signer_id: vi.fn(),
    remove_signer: vi.fn(),
  };
  const storage = {
    save: vi.fn(),
    get: vi.fn(),
  };
  const events = {
    emit: vi.fn(),
  };
  const requireWallet = vi.fn(() => ({ wallet, contractId: "CCONTRACT" }));

  return {
    wallet,
    storage,
    events,
    requireWallet,
  };
}

describe("SignerManager", () => {
  it("adds a passkey signer and stores the credential", async () => {
    const deps = makeDeps();
    const publicKey = Buffer.alloc(65, 9);
    const credentialId = Buffer.from("credential-passkey").toString("base64url");
    deps.wallet.add_signer.mockResolvedValue({ result: 31 });
    const createPasskey = vi.fn().mockResolvedValue({
      rawResponse: { response: { transports: ["internal"] } },
      credentialId,
      publicKey,
    });
    const manager = new SignerManager({
      ...deps,
      createPasskey,
      webauthnVerifierAddress: "CCAAAAA",
    });

    const result = await manager.addPasskey(7, "App", "User", { nickname: "Backup" });

    expect(createPasskey).toHaveBeenCalledWith("App", "User");
    expect(deps.storage.save).toHaveBeenCalledWith(
      expect.objectContaining({
        credentialId,
        publicKey,
        contractId: "CCONTRACT",
        nickname: "Backup",
        contextRuleId: 7,
      })
    );
    expect(deps.events.emit).toHaveBeenCalledWith(
      "credentialCreated",
      expect.objectContaining({
        credential: expect.objectContaining({ credentialId, contractId: "CCONTRACT" }),
      })
    );
    expect(deps.wallet.add_signer).toHaveBeenCalledWith({
      context_rule_id: 7,
      signer: {
        tag: "External",
        values: ["CCAAAAA", buildKeyData(publicKey, credentialId)],
      },
    });
    expect(result).toEqual({
      credentialId,
      publicKey,
      transaction: { result: 31 },
    });
  });

  it("adds a delegated signer", async () => {
    const deps = makeDeps();
    deps.wallet.add_signer.mockResolvedValue({ result: 44 });
    const manager = new SignerManager({
      ...deps,
      createPasskey: vi.fn(),
      webauthnVerifierAddress: "CCAAAAA",
    });
    const publicKey = makeAccount(11);

    const result = await manager.addDelegated(2, publicKey);

    expect(deps.wallet.add_signer).toHaveBeenCalledWith({
      context_rule_id: 2,
      signer: makeDelegatedSigner(11),
    });
    expect(result).toEqual({ result: 44 });
  });

  it("removes a signer by resolving the global signer id", async () => {
    const deps = makeDeps();
    const signer = makeDelegatedSigner(7);
    deps.wallet.get_signer_id.mockResolvedValue({ result: 55 });
    deps.wallet.remove_signer.mockResolvedValue({ result: null });
    const manager = new SignerManager({
      ...deps,
      createPasskey: vi.fn(),
      webauthnVerifierAddress: "CCAAAAA",
    });

    const result = await manager.remove(3, signer);

    expect(deps.wallet.get_signer_id).toHaveBeenCalledWith({ signer });
    expect(deps.wallet.remove_signer).toHaveBeenCalledWith({
      context_rule_id: 3,
      signer_id: 55,
    });
    expect(result).toEqual({ result: null });
  });

});
