import { describe, expect, it } from "vitest";
import { DEFAULT_INDEXER_URLS, IndexerClient } from "./indexer";

describe("IndexerClient network defaults", () => {
  it("includes default URLs for Stellar testnet and mainnet", () => {
    expect(DEFAULT_INDEXER_URLS["Test SDF Network ; September 2015"]).toBe(
      "https://smart-account-indexer.sdf-ecosystem.workers.dev"
    );
    expect(
      DEFAULT_INDEXER_URLS["Public Global Stellar Network ; September 2015"]
    ).toBe("https://smart-account-indexer-mainnet.sdf-ecosystem.workers.dev");
  });

  it("creates clients for both known Stellar networks", () => {
    expect(
      IndexerClient.forNetwork("Test SDF Network ; September 2015")
    ).not.toBeNull();
    expect(
      IndexerClient.forNetwork("Public Global Stellar Network ; September 2015")
    ).not.toBeNull();
  });
});
