---
name: setup-policies
description: "Attach and configure authorization policies on Stellar smart account context rules using smart-account-kit. Use when a developer wants to set up threshold multisig, spending limits, weighted voting, M-of-N signatures, or any policy-enforced authorization on a Stellar smart account."
license: Apache-2.0
compatibility: Designed for Claude Code. Requires a connected SmartAccountKit instance and deployed policy contracts.
metadata:
  author: kalepail
  version: "0.3.0"
allowed-tools: Read Write Edit
---

# Set Up Smart Account Policies

Attach on-chain policy contracts to context rules to enforce authorization rules like M-of-N multisig, weighted voting, or spending limits.

## Prerequisites

- `SmartAccountKit` initialized and connected
- Deployed policy contract addresses (testnet defaults in `demo/.env.example`)
- A context rule to attach the policy to (see [manage-signers](../manage-signers/SKILL.md))

## Available Policy Types

| Policy | Builder | Description |
|--------|---------|-------------|
| Threshold | `createThresholdParams(m)` | Require M signatures from any of the rule's signers |
| Weighted | `createWeightedThresholdParams(threshold, weights)` | Weighted voting with a total-weight threshold |
| Spending limit | `createSpendingLimitParams(token, limit, period)` | Cap token spending per time window |

## Threshold Multisig (M-of-N)

Require M signatures from the signers on a context rule:

```typescript
import { createThresholdParams } from 'smart-account-kit';

// Require 2 signatures from any of the rule's signers
const params = createThresholdParams(2);
const installParams = kit.convertPolicyParams(params);

await kit.policies.add(
  0,                                              // context rule ID
  process.env.VITE_THRESHOLD_POLICY_ADDRESS!,
  installParams
);
```

## Weighted Threshold

Assign per-signer weights; transaction is authorized when cumulative weight reaches the threshold:

```typescript
import { createWeightedThresholdParams } from 'smart-account-kit';

const params = createWeightedThresholdParams(
  100,   // required total weight
  [
    { signerIndex: 0, weight: 70 },
    { signerIndex: 1, weight: 50 },
  ]
);
const installParams = kit.convertPolicyParams(params);

await kit.policies.add(
  0,
  process.env.VITE_WEIGHTED_THRESHOLD_POLICY_ADDRESS!,
  installParams
);
```

## Spending Limit

Cap how much of a token can be spent within a rolling ledger window:

```typescript
import { createSpendingLimitParams, LEDGERS_PER_DAY } from 'smart-account-kit';

const params = createSpendingLimitParams(
  process.env.VITE_NATIVE_TOKEN_CONTRACT!,  // token to limit
  BigInt(100 * 10_000_000),                 // 100 XLM (in stroops)
  LEDGERS_PER_DAY                           // resets every ~24h
);
const installParams = kit.convertPolicyParams(params);

await kit.policies.add(
  0,
  process.env.VITE_SPENDING_LIMIT_POLICY_ADDRESS!,
  installParams
);
```

## Time Constants

```typescript
import { LEDGERS_PER_HOUR, LEDGERS_PER_DAY, LEDGERS_PER_WEEK } from 'smart-account-kit';

LEDGERS_PER_HOUR  // ~720 ledgers
LEDGERS_PER_DAY   // ~17,280 ledgers
LEDGERS_PER_WEEK  // ~120,960 ledgers
```

## Multiple Policies on One Rule

A single context rule can have multiple policies. All must be satisfied for a transaction to be authorized:

```typescript
// Attach threshold policy
await kit.policies.add(0, thresholdPolicyAddress, thresholdInstallParams);

// Also attach spending limit
await kit.policies.add(0, spendingLimitAddress, spendingInstallParams);
```

## Remove a Policy

```typescript
await kit.policies.remove(0, policyAddress);
```

## Executing Multi-Sig Transactions

Once a threshold policy is attached, use `MultiSignerManager` for transactions:

```typescript
// Discover all available signers
const signers = await kit.multiSigners.getAvailableSigners();

if (kit.multiSigners.needsMultiSigner(signers)) {
  const selected = kit.multiSigners.buildSelectedSigners(
    signers,
    kit.activeCredentialId
  );

  // Execute a transfer requiring multiple signatures
  const result = await kit.multiSigners.transfer(
    tokenContract,
    recipient,
    amount,
    selected
  );
}
```

For arbitrary multi-sig operations:

```typescript
const tx = await kit.execute('CTARGET...', 'function_name', [arg1]);
const result = await kit.multiSigners.operation(tx, selected);
```

## Common Patterns

**2-of-3 multisig wallet**
1. Create a context rule
2. Add 3 passkey signers via `kit.signers.addPasskey()`
3. Attach a threshold policy with `createThresholdParams(2)`

**Daily spending limit with single signer**
1. Create a default context rule with 1 signer
2. Attach a spending limit policy capped to your daily budget

**High-value operation requires co-signer**
1. Create a `createCallContractContext` rule for the high-value contract
2. Add both your passkey and a hardware wallet G-address
3. Attach threshold with `createThresholdParams(2)`
