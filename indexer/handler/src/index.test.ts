import { afterEach, describe, expect, it, vi } from "vitest";
import app from "./index";

type SqlClient = {
  (strings: TemplateStringsArray, ...values: unknown[]): Promise<unknown>;
  end: ReturnType<typeof vi.fn>;
};

let currentSqlClient: SqlClient | null = null;

vi.mock("postgres", () => ({
  default: vi.fn(() => {
    if (!currentSqlClient) {
      throw new Error("No SQL client configured for this test");
    }

    return currentSqlClient;
  }),
}));

function createSqlClient(responses: unknown[]): SqlClient {
  const queue = [...responses];
  const sql = vi.fn(async () => {
    if (queue.length === 0) {
      throw new Error("Unexpected SQL query");
    }

    const next = queue.shift();

    if (next instanceof Error) {
      throw next;
    }

    return next;
  }) as unknown as SqlClient;

  sql.end = vi.fn(async () => undefined);

  return sql;
}

function createExecutionContext() {
  return {
    waitUntil: vi.fn(),
  } as any;
}

afterEach(() => {
  currentSqlClient = null;
  vi.clearAllMocks();
});

describe("handler routes", () => {
  it("returns contract details with only active context rules", async () => {
    currentSqlClient = createSqlClient([
      [
        {
          contract_id: "CCONTRACT",
          context_rule_count: 3,
          external_signer_count: 1,
          delegated_signer_count: 1,
          native_signer_count: 1,
          first_seen_ledger: 100,
          last_seen_ledger: 200,
          context_rule_ids: [1, 2, 3],
        },
      ],
      [{ context_rule_id: 2 }],
      [
        {
          context_rule_id: 3,
          signer_type: "Native",
          signer_address: "Cnative",
          credential_id: null,
          event_type: "signer_added",
          ledger_sequence: 30,
        },
        {
          context_rule_id: 1,
          signer_type: "External",
          signer_address: "Cpasskey",
          credential_id: "cred-1",
          event_type: "context_rule_added",
          ledger_sequence: 10,
        },
        {
          context_rule_id: 2,
          signer_type: "Delegated",
          signer_address: "Gremoved",
          credential_id: null,
          event_type: "signer_added",
          ledger_sequence: 20,
        },
        {
          context_rule_id: 1,
          signer_type: "Delegated",
          signer_address: "Gbackup",
          credential_id: null,
          event_type: "signer_added",
          ledger_sequence: 11,
        },
      ],
      [
        {
          context_rule_id: 1,
          policy_address: "CPOLICY1",
          install_params: { threshold: 2 },
          event_type: "context_rule_added",
          ledger_sequence: 12,
        },
        {
          context_rule_id: 2,
          policy_address: "CPOLICY2",
          install_params: { spending_limit: "1000" },
          event_type: "policy_added",
          ledger_sequence: 21,
        },
        {
          context_rule_id: 3,
          policy_address: "CPOLICY3",
          install_params: null,
          event_type: "policy_added",
          ledger_sequence: 31,
        },
      ],
    ]);

    const response = await app.fetch(
      new Request("http://localhost/api/contract/CCONTRACT"),
      { DATABASE_URL: "postgres://example" } as any,
      createExecutionContext()
    );

    expect(response.status).toBe(200);
    expect(currentSqlClient).not.toBeNull();
    expect(currentSqlClient?.end).toHaveBeenCalledTimes(1);

    await expect(response.json()).resolves.toEqual({
      contractId: "CCONTRACT",
      summary: {
        contract_id: "CCONTRACT",
        context_rule_count: 3,
        external_signer_count: 1,
        delegated_signer_count: 1,
        native_signer_count: 1,
        first_seen_ledger: 100,
        last_seen_ledger: 200,
        context_rule_ids: [1, 2, 3],
      },
      contextRules: [
        {
          context_rule_id: 1,
          signers: [
            {
              signer_type: "External",
              signer_address: "Cpasskey",
              credential_id: "cred-1",
            },
            {
              signer_type: "Delegated",
              signer_address: "Gbackup",
              credential_id: null,
            },
          ],
          policies: [
            {
              policy_address: "CPOLICY1",
              install_params: { threshold: 2 },
            },
          ],
        },
        {
          context_rule_id: 3,
          signers: [
            {
              signer_type: "Native",
              signer_address: "Cnative",
              credential_id: null,
            },
          ],
          policies: [
            {
              policy_address: "CPOLICY3",
              install_params: null,
            },
          ],
        },
      ],
    });
  });

  it("returns 404 when contract details are missing", async () => {
    currentSqlClient = createSqlClient([[]]);

    const response = await app.fetch(
      new Request("http://localhost/api/contract/CUNKNOWN"),
      { DATABASE_URL: "postgres://example" } as any,
      createExecutionContext()
    );

    expect(response.status).toBe(404);
    expect(currentSqlClient?.end).toHaveBeenCalledTimes(1);
    await expect(response.json()).resolves.toEqual({
      error: "Contract not found",
    });
  });

  it("returns active context rules even when signers and policies resolve empty", async () => {
    currentSqlClient = createSqlClient([
      [
        {
          contract_id: "CEMPTY",
          context_rule_count: 1,
          external_signer_count: 0,
          delegated_signer_count: 0,
          native_signer_count: 0,
          first_seen_ledger: 10,
          last_seen_ledger: 10,
          context_rule_ids: [0],
        },
      ],
      [],
      [],
      [],
    ]);

    const response = await app.fetch(
      new Request("http://localhost/api/contract/CEMPTY"),
      { DATABASE_URL: "postgres://example" } as any,
      createExecutionContext()
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      contractId: "CEMPTY",
      summary: {
        contract_id: "CEMPTY",
        context_rule_count: 1,
        external_signer_count: 0,
        delegated_signer_count: 0,
        native_signer_count: 0,
        first_seen_ledger: 10,
        last_seen_ledger: 10,
        context_rule_ids: [0],
      },
      contextRules: [
        {
          context_rule_id: 0,
          signers: [],
          policies: [],
        },
      ],
    });
  });

  it("returns lookup and stats payloads from the indexed views", async () => {
    currentSqlClient = createSqlClient([
      [
        {
          contract_id: "CLOOKUP1",
          context_rule_count: 2,
          external_signer_count: 1,
          delegated_signer_count: 0,
          native_signer_count: 1,
          first_seen_ledger: 11,
          last_seen_ledger: 22,
          context_rule_ids: [5, 8],
        },
        {
          contract_id: "CLOOKUP2",
          context_rule_count: 1,
          external_signer_count: 0,
          delegated_signer_count: 1,
          native_signer_count: 0,
          first_seen_ledger: 13,
          last_seen_ledger: 23,
          context_rule_ids: [9],
        },
      ],
      [
        {
          contract_id: "CLOOKUP3",
          context_rule_count: 1,
          external_signer_count: 1,
          delegated_signer_count: 0,
          native_signer_count: 0,
          first_seen_ledger: 14,
          last_seen_ledger: 24,
          context_rule_ids: [2],
        },
      ],
      [
        {
          total_events: 4,
          unique_contracts: 3,
          unique_credentials: 2,
          first_ledger: 10,
          last_ledger: 40,
        },
      ],
      [
        { event_type: "context_rule_added", count: 1 },
        { event_type: "signer_registered", count: 1 },
        { event_type: "policy_registered", count: 1 },
        { event_type: "context_rule_removed", count: 1 },
      ],
    ]);

    const lookupResponse = await app.fetch(
      new Request("http://localhost/api/lookup/Credential-ABC"),
      { DATABASE_URL: "postgres://example" } as any,
      createExecutionContext()
    );
    expect(lookupResponse.status).toBe(200);
    await expect(lookupResponse.json()).resolves.toEqual({
      credentialId: "credential-abc",
      contracts: [
        {
          contract_id: "CLOOKUP1",
          context_rule_count: 2,
          external_signer_count: 1,
          delegated_signer_count: 0,
          native_signer_count: 1,
          first_seen_ledger: 11,
          last_seen_ledger: 22,
          context_rule_ids: [5, 8],
        },
        {
          contract_id: "CLOOKUP2",
          context_rule_count: 1,
          external_signer_count: 0,
          delegated_signer_count: 1,
          native_signer_count: 0,
          first_seen_ledger: 13,
          last_seen_ledger: 23,
          context_rule_ids: [9],
        },
      ],
      count: 2,
    });

    const addressResponse = await app.fetch(
      new Request("http://localhost/api/lookup/address/GABC123"),
      { DATABASE_URL: "postgres://example" } as any,
      createExecutionContext()
    );
    expect(addressResponse.status).toBe(200);
    await expect(addressResponse.json()).resolves.toEqual({
      signerAddress: "GABC123",
      contracts: [
        {
          contract_id: "CLOOKUP3",
          context_rule_count: 1,
          external_signer_count: 1,
          delegated_signer_count: 0,
          native_signer_count: 0,
          first_seen_ledger: 14,
          last_seen_ledger: 24,
          context_rule_ids: [2],
        },
      ],
      count: 1,
    });

    const statsResponse = await app.fetch(
      new Request("http://localhost/api/stats"),
      { DATABASE_URL: "postgres://example" } as any,
      createExecutionContext()
    );
    expect(statsResponse.status).toBe(200);
    await expect(statsResponse.json()).resolves.toEqual({
      stats: {
        total_events: 4,
        unique_contracts: 3,
        unique_credentials: 2,
        first_ledger: 10,
        last_ledger: 40,
        eventTypes: [
          { event_type: "context_rule_added", count: 1 },
          { event_type: "signer_registered", count: 1 },
          { event_type: "policy_registered", count: 1 },
          { event_type: "context_rule_removed", count: 1 },
        ],
      },
    });

    expect(currentSqlClient?.end).toHaveBeenCalledTimes(3);
  });
});
