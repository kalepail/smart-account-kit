import { describe, expect, it, vi } from "vitest";
import { PolicyManager } from "./policy-manager";

function makeDeps() {
  const wallet = {
    add_policy: vi.fn(),
    get_policy_id: vi.fn(),
    remove_policy: vi.fn(),
  };

  const requireWallet = vi.fn(() => ({ wallet }));

  return { wallet, requireWallet };
}

describe("PolicyManager", () => {
  it("adds a policy through the wallet client", async () => {
    const deps = makeDeps();
    deps.wallet.add_policy.mockResolvedValue({ result: 11 });
    const manager = new PolicyManager(deps);

    const result = await manager.add(4, "CPOLICY", { threshold: 2 });

    expect(deps.requireWallet).toHaveBeenCalledTimes(1);
    expect(deps.wallet.add_policy).toHaveBeenCalledWith({
      context_rule_id: 4,
      policy: "CPOLICY",
      install_param: { threshold: 2 },
    });
    expect(result).toEqual({ result: 11 });
  });

  it("removes a policy by resolving the global policy id", async () => {
    const deps = makeDeps();
    deps.wallet.get_policy_id.mockResolvedValue({ result: 42 });
    deps.wallet.remove_policy.mockResolvedValue({ result: null });
    const manager = new PolicyManager(deps);

    const result = await manager.remove(9, "COTHER");

    expect(deps.wallet.get_policy_id).toHaveBeenCalledWith({
      policy: "COTHER",
    });
    expect(deps.wallet.remove_policy).toHaveBeenCalledWith({
      context_rule_id: 9,
      policy_id: 42,
    });
    expect(result).toEqual({ result: null });
  });

  it("throws when the policy is not present on the rule", async () => {
    const deps = makeDeps();
    deps.wallet.get_policy_id.mockResolvedValue({ result: undefined });
    const manager = new PolicyManager(deps);

    await expect(manager.remove(9, "CUNKNOWN")).rejects.toThrow(
      "Policy CUNKNOWN not found on context rule 9"
    );
    expect(deps.wallet.remove_policy).not.toHaveBeenCalled();
  });
});
