import { afterEach, describe, expect, it, vi } from "vitest";
import { SmartAccountKit } from "./kit";
import { DEFAULT_INDEXER_URLS, IndexerClient } from "./indexer";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

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

  it("sends a configured API key or JWT as a bearer token", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const indexer = new IndexerClient({
      baseUrl: "https://indexer.example/",
      authToken: "test-api-key-or-jwt",
    });

    await expect(indexer.isHealthy()).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://indexer.example/",
      expect.objectContaining({
        headers: {
          Accept: "application/json",
          Authorization: "Bearer test-api-key-or-jwt",
        },
      })
    );
  });

  it("supports bearer tokens with network-default clients", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const indexer = IndexerClient.forNetwork(
      "Test SDF Network ; September 2015",
      { authToken: "network-token" }
    );

    await expect(indexer?.isHealthy()).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      `${DEFAULT_INDEXER_URLS["Test SDF Network ; September 2015"]}/`,
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer network-token",
        }),
      })
    );
  });

  it("omits Authorization when no token is configured", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const indexer = new IndexerClient({ baseUrl: "https://indexer.example" });

    await expect(indexer.isHealthy()).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://indexer.example/",
      expect.objectContaining({
        headers: { Accept: "application/json" },
      })
    );
  });

  it("fetches indexer statistics from the /api/stats endpoint", async () => {
    const statsBody = {
      stats: {
        total_events: 42,
        unique_contracts: 7,
        unique_credentials: 5,
        first_ledger: 100,
        last_ledger: 900,
        eventTypes: [{ event_type: "context_rule_added", count: 3 }],
      },
    };
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify(statsBody), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const indexer = new IndexerClient({ baseUrl: "https://indexer.example" });

    await expect(indexer.getStats()).resolves.toEqual(statsBody);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://indexer.example/api/stats",
      expect.anything()
    );
  });

  it("forwards SmartAccountKit indexerAuthToken configuration", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const kit = new SmartAccountKit({
      rpcUrl: "https://rpc.example",
      networkPassphrase: "Test SDF Network ; September 2015",
      accountWasmHash: "00".repeat(32),
      webauthnVerifierAddress: "CEXAMPLE",
      indexerUrl: "https://indexer.example",
      indexerAuthToken: "kit-token",
    });

    await expect(kit.indexer?.isHealthy()).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://indexer.example/",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer kit-token",
        }),
      })
    );
  });
});
