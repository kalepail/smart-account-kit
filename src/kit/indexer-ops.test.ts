import { describe, expect, it, vi } from "vitest";
import {
  discoverContractsByAddress,
  discoverContractsByCredential,
  getContractDetailsFromIndexer,
} from "./indexer-ops";

describe("indexer-ops", () => {
  it("normalizes base64url credential IDs to hex before lookup", async () => {
    const lookupByCredentialId = vi.fn().mockResolvedValue({
      contracts: [{ contract_id: "C1" }],
    });
    const indexer = {
      lookupByCredentialId,
    };

    const result = await discoverContractsByCredential(indexer as never, "AQID");

    expect(lookupByCredentialId).toHaveBeenCalledWith("010203");
    expect(result).toEqual([{ contract_id: "C1" }]);
  });

  it("lowercases hex credential IDs before lookup", async () => {
    const lookupByCredentialId = vi.fn().mockResolvedValue({
      contracts: [{ contract_id: "C2" }],
    });
    const indexer = {
      lookupByCredentialId,
    };

    const result = await discoverContractsByCredential(indexer as never, "AABBCC");

    expect(lookupByCredentialId).toHaveBeenCalledWith("aabbcc");
    expect(result).toEqual([{ contract_id: "C2" }]);
  });

  it("returns null when credential lookup is requested without an indexer", async () => {
    await expect(discoverContractsByCredential(null, "AQID")).resolves.toBeNull();
  });

  it("forwards address lookups to the indexer", async () => {
    const lookupByAddress = vi.fn().mockResolvedValue({
      contracts: [{ contract_id: "C3" }],
    });
    const indexer = {
      lookupByAddress,
    };

    const result = await discoverContractsByAddress(indexer as never, "GABC");

    expect(lookupByAddress).toHaveBeenCalledWith("GABC");
    expect(result).toEqual([{ contract_id: "C3" }]);
  });

  it("returns null when contract details are requested without an indexer", async () => {
    await expect(getContractDetailsFromIndexer(null, "CABC")).resolves.toBeNull();
  });

  it("forwards contract detail lookups to the indexer", async () => {
    const getContractDetails = vi.fn().mockResolvedValue({
      contractId: "CABC",
      summary: { contract_id: "CABC" },
      contextRules: [],
    });
    const indexer = {
      getContractDetails,
    };

    const result = await getContractDetailsFromIndexer(indexer as never, "CABC");

    expect(getContractDetails).toHaveBeenCalledWith("CABC");
    expect(result).toEqual({
      contractId: "CABC",
      summary: { contract_id: "CABC" },
      contextRules: [],
    });
  });
});
