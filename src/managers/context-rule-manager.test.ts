import { describe, expect, it, vi } from "vitest";
import { ContextRuleManager } from "./context-rule-manager";
import { getFilteredContextRules, listContextRules } from "../kit/context-rules";
import { makeDelegatedSigner } from "./test-utils";

vi.mock("../kit/context-rules", () => ({
  listContextRules: vi.fn(),
  getFilteredContextRules: vi.fn(),
}));

function makeDeps() {
  const wallet = {
    add_context_rule: vi.fn(),
    get_context_rule: vi.fn(),
    remove_context_rule: vi.fn(),
    update_context_rule_name: vi.fn(),
    update_context_rule_valid_until: vi.fn(),
  };
  const requireWallet = vi.fn(() => ({ wallet }));
  const getContractDetailsFromIndexer = vi.fn();

  return {
    wallet,
    requireWallet,
    getContractDetailsFromIndexer,
  };
}

describe("ContextRuleManager", () => {
  it("adds a context rule through the wallet client", async () => {
    const deps = makeDeps();
    deps.wallet.add_context_rule.mockResolvedValue({ result: { id: 7 } });
    const manager = new ContextRuleManager(deps);
    const signers = [makeDelegatedSigner(1)];
    const policies = new Map<string, unknown>([["CPOLICY", { threshold: 2 }]]);

    const result = await manager.add(
      { tag: "Default", values: undefined },
      "Rule",
      signers,
      policies,
      123
    );

    expect(deps.requireWallet).toHaveBeenCalledTimes(1);
    expect(deps.wallet.add_context_rule).toHaveBeenCalledWith({
      context_type: { tag: "Default", values: undefined },
      name: "Rule",
      valid_until: 123,
      signers,
      policies,
    });
    expect(result).toEqual({ result: { id: 7 } });
  });

  it("gets a context rule by id", async () => {
    const deps = makeDeps();
    deps.wallet.get_context_rule.mockResolvedValue({ result: { id: 9 } });
    const manager = new ContextRuleManager(deps);

    const result = await manager.get(9);

    expect(deps.wallet.get_context_rule).toHaveBeenCalledWith({
      context_rule_id: 9,
    });
    expect(result).toEqual({ result: { id: 9 } });
  });

  it("lists active context rules through the shared helper", async () => {
    const deps = makeDeps();
    const rules = [{ id: 1 }, { id: 2 }];
    vi.mocked(listContextRules).mockResolvedValue(rules as never);
    const manager = new ContextRuleManager(deps);

    await expect(manager.list()).resolves.toEqual(rules);

    expect(listContextRules).toHaveBeenCalledWith(deps.wallet, {
      getContractDetailsFromIndexer: deps.getContractDetailsFromIndexer,
    });
  });

  it("filters rules by context type through the shared helper", async () => {
    const deps = makeDeps();
    const rules = [{ id: 3 }];
    vi.mocked(getFilteredContextRules).mockResolvedValue(rules as never);
    const manager = new ContextRuleManager(deps);
    const contextType = { tag: "CallContract", values: ["C".repeat(56)] } as const;

    await expect(manager.getAll(contextType)).resolves.toEqual(rules);

    expect(getFilteredContextRules).toHaveBeenCalledWith(deps.wallet, contextType, {
      getContractDetailsFromIndexer: deps.getContractDetailsFromIndexer,
    });
  });

  it("removes, renames, and updates context rules", async () => {
    const deps = makeDeps();
    deps.wallet.remove_context_rule.mockResolvedValue({ result: null });
    deps.wallet.update_context_rule_name.mockResolvedValue({ result: { id: 4 } });
    deps.wallet.update_context_rule_valid_until.mockResolvedValue({ result: { id: 4 } });
    const manager = new ContextRuleManager(deps);

    await expect(manager.remove(4)).resolves.toEqual({ result: null });
    await expect(manager.updateName(4, "New Name")).resolves.toEqual({ result: { id: 4 } });
    await expect(manager.updateExpiration(4, 456)).resolves.toEqual({ result: { id: 4 } });
    await expect(manager.updateExpiration(4)).resolves.toEqual({ result: { id: 4 } });

    expect(deps.wallet.remove_context_rule).toHaveBeenCalledWith({ context_rule_id: 4 });
    expect(deps.wallet.update_context_rule_name).toHaveBeenCalledWith({
      context_rule_id: 4,
      name: "New Name",
    });
    expect(deps.wallet.update_context_rule_valid_until).toHaveBeenLastCalledWith({
      context_rule_id: 4,
      valid_until: undefined,
    });
  });
});
