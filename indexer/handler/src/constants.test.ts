import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { EVENT_TYPES } from "./constants";

describe("EVENT_TYPES", () => {
  it("includes the migrated registry event vocabulary", () => {
    expect(EVENT_TYPES).toMatchObject({
      CONTEXT_RULE_ADDED: "context_rule_added",
      CONTEXT_RULE_META_UPDATED: "context_rule_meta_updated",
      CONTEXT_RULE_REMOVED: "context_rule_removed",
      SIGNER_ADDED: "signer_added",
      SIGNER_REMOVED: "signer_removed",
      SIGNER_REGISTERED: "signer_registered",
      SIGNER_DEREGISTERED: "signer_deregistered",
      POLICY_ADDED: "policy_added",
      POLICY_REMOVED: "policy_removed",
      POLICY_REGISTERED: "policy_registered",
      POLICY_DEREGISTERED: "policy_deregistered",
    });
  });
});

describe("schema.sql", () => {
  it("documents the active-rule and registry event model", () => {
    const schemaPath = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../schema.sql"
    );
    const schema = readFileSync(schemaPath, "utf8");

    expect(schema).toContain("processed_signers");
    expect(schema).toContain("processed_policies");
    expect(schema).toContain("contract_summary");
    expect(schema).toContain("context_rule_ids");
  });
});
