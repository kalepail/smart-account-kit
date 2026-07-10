# Changelog

## 0.4.0 — 2026-07-10

Ground-up audit and overhaul against the OpenZeppelin smart account contracts
([`stellar-contracts@1e513890`](https://github.com/OpenZeppelin/stellar-contracts/commit/1e513890ecf79833c9d6e7ef38a9358001c0b111),
the exact commit behind the Protocol 27 deployments). Breaking release; see
[`docs/migration-v0.4.0.md`](docs/migration-v0.4.0.md) for the complete
migration guide.

### SDK (`smart-account-kit@0.4.0`)

- **Full contract parity.** Every smart-account entry point is now wrapped:
  `kit.rules.count()`, `kit.signers.addBatch()`, `kit.signers.idOf()`,
  `kit.policies.idOf()`, and `kit.upgrade()`. `kit.wallet` remains as a raw
  escape hatch, but nothing is intentionally unwrapped anymore.
- **Typed policy clients.** `kit.policyClients` exposes threshold,
  weighted-threshold, and spending-limit clients with live getters
  (simulation) and setters routed through the account's `execute()` flow. The
  embedded base64 spec blobs are gone; conversion goes through the bindings
  spec.
- **Ed25519 signers end-to-end.** New `Ed25519Signer` signs the auth digest
  with a local keypair against the deployed Ed25519 verifier; configurable via
  `ed25519VerifierAddress`.
- **One signing pipeline.** The passkey, multi-signer, and funding flows share
  a single auth-digest/signature core
  (`auth_digest = sha256(signature_payload || context_rule_ids.to_xdr())`),
  eliminating three divergent implementations.
- **Unified error model.** Everything throws typed errors except submission
  methods, which return a discriminated `TransactionResult`. Contract failure
  codes (3000–3016 smart account, 3110–3119 WebAuthn, 3200–3227 policies) are
  decoded into `ContractError` with enum names.
- **Constructor policies.** `defaultPolicies` is now honored — new wallets can
  deploy with policies installed via constructor args.
- **Client-side limit validation.** `MAX_SIGNERS=15`, `MAX_POLICIES=5`,
  `MAX_NAME_SIZE=20` bytes, `MAX_EXTERNAL_KEY_SIZE=256` enforced before
  submission with clear errors.
- **Config additions.** `deployerSecret`, `externalSignerStorage`,
  `ed25519VerifierAddress`; probe defaults single-sourced; indexer URL
  resolution via `IndexerClient.forNetwork`.
- **Dead code removed** across the SDK; test suite grew from 117 to 325+ tests
  with every runtime module covered, including auth-digest and WebAuthn
  signature vectors.

### Audit follow-up fixes

A verified code-review pass over the release branch. See
[`docs/migration-v0.4.0.md`](docs/migration-v0.4.0.md#audit-follow-up-fixes) for
details and upgrade notes.

- **Host-order `ScMap` sort.** Signer maps (weighted-threshold params and the
  auth-payload signer map) sort by the Soroban host's key order (element-wise
  byte comparison), not the length-major XDR encoding — fixing occasional
  `InvalidInput` rejections for two same-verifier signers with different-length
  key data.
- **`kit.credentials.deploy()` honors policies** (`options.policies ??
  config.defaultPolicies`), matching `createWallet`; previously it silently
  deployed with no constructor policies.
- **Constructor policies validate before the passkey ceremony** in
  `createWallet`, so bad configs no longer orphan a created passkey.
- **`TransactionFailure.code` removed** — branch on `result.error.code`.
- **Policy params accept numeric strings** for u32/i128 fields, matching the
  spec; out-of-range/non-numeric strings throw.
- **Custom policy conversion hard-fails** instead of shipping a `Void` ScVal.
- **Wallet cancellation heuristic narrowed** to specific user-action phrases, so
  extension crashes / allowlist rejections surface as errors instead of being
  swallowed as a silent `null`.
- **`fundWallet()`** guards on the exact testnet passphrase (Futurenet no longer
  slips through) and reads the temp account's real native balance instead of a
  fabricated 10,000 XLM default.
- **Update-path validation** (`updateName`/`updateExpiration`), an optional
  `existingSignerCount` pre-check on `addBatch`, cryptographically random
  delegated auth nonces, a loud warning when an unsignable Ed25519 signer is
  dropped, and reduced redundant context-rule enumeration on signing/connect.

### Bindings (`smart-account-kit-bindings@0.3.0`)

- Regenerated from the canonical deployed testnet WASM
  (`1b5f4534…`); `pnpm verify:bindings` now checks the checked-in bindings
  against that hash and fails on drift. `build.sh` no longer silently sources
  a stale local `demo/.env`.

### Indexer & relayer proxy

- **Mercury is now the default indexer.** `DEFAULT_INDEXER_URLS` (and
  `IndexerClient.forNetwork`) resolve to Mercury's hosted `smart-account-indexer`
  REST service — testnet `https://testnet.mercurydata.app/rest/smart-account-indexer`,
  mainnet `https://mainnet.mercurydata.app/rest/smart-account-indexer`. Mercury's
  read endpoints are public and cover live + historical activity for every
  smart-account-kit contract (global backfill, no per-contract catch-up), so
  discovery works **zero-config with no token**. `indexerAuthToken` is now
  optional (gated/admin operations or a provider that requires it).
- **Self-hosted indexer stack removed.** The bespoke Goldsky Turbo pipeline
  (`indexer/goldsky/`) and the reference Cloudflare Worker (`indexer/handler/`,
  including its optional bearer-token gate) are gone — too expensive to operate,
  and Mercury indexes the same events as a managed service. The prior stack
  remains in git history. `indexer/demo/` stays and now targets Mercury.
- **Relayer proxy moved to the repo top level** (`relayer-proxy/`, was
  `indexer/relayer-proxy/`), reflecting that transaction submission is a distinct
  concern from indexing. It keeps its first test suite (22 tests), submit-path
  dedup, and docs for `/fee-usage` and `/status`, plus a new standalone README.

### Demo

- Rebuilt on the new API: `App.tsx` decomposed into hooks + panels, rule
  builder modularized, Ed25519 signer flows, live policy inspection/editing
  via the typed policy clients, batch signer add, and an advanced upgrade
  path. The indexer demo reads policy state through the same clients.
