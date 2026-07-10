# Smart Account Relayer Proxy

Cloudflare Worker that proxies transaction submission to the [OpenZeppelin Relayer Channels](https://docs.openzeppelin.com/relayer) service, so frontend apps can submit **fee-sponsored** Stellar transactions without exposing a Relayer API key.

This is a **separate concern from the [indexer](../indexer)**: the indexer answers discovery/read queries (which contracts a passkey signs for), while the relayer proxy submits transactions. They are deployed and operated independently.

It wraps the official [`@openzeppelin/relayer-plugin-channels`](https://www.npmjs.com/package/@openzeppelin/relayer-plugin-channels) `ChannelsClient` (`submitSorobanTransaction` for `func`+`auth`, `submitTransaction` for a signed `xdr`) and maps the plugin's `PluginExecutionError` / `PluginTransportError` onto HTTP responses.

## Features

- **Per-IP API key model**: the proxy mints one Relayer API key per client IP (via the Relayer's public `/gen` endpoint) and stores it in the `API_KEYS` KV namespace under `api-key:<ip>`, persisted indefinitely. Legacy plain-text / JSON-string KV values are migrated to the current record shape lazily on read.
- Relayer's usage limits reset every 24 hours on their side — no need to regenerate keys.
- Rate limiting via Relayer's built-in fair-use policy.
- Separate testnet and mainnet deployments. On testnet, if a channel account is missing after a network reset, the proxy funds it via Friendbot and retries for up to 5 minutes.

## API Endpoints

**Health Check**
```
GET /
```

**Submit Transaction**
```
POST /
Body: { "func": "base64-encoded-func", "auth": ["base64-auth-entry", ...] }
Body: { "xdr": "base64-encoded-xdr" }
```
Provide **either** `func` + `auth` (Relayer builds and signs with channel accounts — used for Address-credential operations like transfers) **or** `xdr` (Relayer fee-bumps an already-signed transaction — used for source-account auth like deployment). Supplying both, or neither, returns `400`.

**Fee Usage**
```
GET /fee-usage
```
Report whether the caller's IP has a minted Relayer API key and when it was created. Detailed fee accounting is not exposed by the managed Relayer service.

**Status**
```
GET /status
```
Return the resolved client IP, network, and whether an API key has been minted for that IP.

## Deployment

```bash
cd relayer-proxy
pnpm install

# Create KV namespace
wrangler kv namespace create API_KEYS
# Update wrangler.toml with your KV namespace ID

# Deploy (testnet)
wrangler deploy

# For mainnet production:
wrangler kv namespace create API_KEYS --env production
# Update wrangler.toml with the production KV namespace ID
wrangler deploy --env production
```

The proxy keeps its non-secret runtime config in `wrangler.toml` (`NETWORK` and `RELAYER_BASE_URL`); `.dev.vars.example` is only for optional local overrides during `wrangler dev`. The `API_KEYS` KV namespace IDs committed in `wrangler.toml` are Cloudflare resource identifiers, not secrets — they are safe to keep in source control (the per-IP Relayer keys stored *inside* the namespace never appear in the repo). This Worker requires no `wrangler secret` values.

## Tests

```bash
pnpm --filter smart-account-relayer-proxy test
```

## SDK Integration

```typescript
const kit = new SmartAccountKit({
  rpcUrl: 'https://soroban-testnet.stellar.org',
  networkPassphrase: 'Test SDF Network ; September 2015',
  accountWasmHash: '...',
  webauthnVerifierAddress: 'C...',
  // Submit fee-sponsored transactions through this proxy:
  relayerUrl: 'https://smart-account-relayer-proxy.your-domain.workers.dev',
});

// Transactions automatically use the Relayer when configured
const result = await kit.signAndSubmit(transaction);

// Or force a specific submission method
const forced = await kit.signAndSubmit(transaction, { forceMethod: 'relayer' });
```
