# Smart Account Kit Demo

A basic Vite + React frontend application for testing the Smart Account Kit SDK with WebAuthn passkey authentication on Stellar.

## Features

- **Wallet Creation**: Create a new smart wallet with a passkey as the primary signer
- **Wallet Connection**: Connect to an existing wallet using stored or discoverable passkeys
- **Contract Discovery**: Automatically discover smart accounts via indexer when connecting, with a fallback to the derived contract ID path if no indexed match is found
- **Context Rule Management**: Create, view, and edit context rules with signers and policies
- **Multi-Signer Support**: Add passkey and delegated (G-address) signers to context rules
- **Policy Support**: Configure threshold and spending limit policies, with weighted threshold available when configured
- **External Wallet Integration**: Connect Freighter or other Stellar wallets for delegated signing
- **Token Transfer**: Build and sign XLM transfer transactions with multi-signer support

## Demo Defaults

The checked-in `.env.example` shows the current default deployment set used by the demo. Your local `.env` can override any of these values:

| Contract | Default value |
|----------|---------------|
| **Smart Account WASM Hash** | `1b5f4534a76322da2ad7c745f6900857a6802b0ca79850c35a03561df997785a` |
| **WebAuthn Verifier** | `CC7EKIHQP3TN4CARQDND6CEOY2UXLWWC2X5GHTD5NLAT7BG5GPZIOM3F` |
| **Ed25519 Verifier** | `CAAVTMCBXEIBPR64EAASKFXERVPYFZA2JYP5A3BG6PESWEFUJX5IHKN4` |
| **Native XLM Token** | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |
| **Threshold Policy** | `CB3FATQKCIRIQOCYRUPCQ2KREQ7T4RPKS7EAEOZWPEPUKWEDRVROBCEG` |
| **Spending Limit Policy** | `CABXBYJNZ7IUW4G3D6BND5YCAQF3ASSDMDAOKQQ63UYFSO7WUU2TIP5G` |
| **Weighted Threshold Policy** | `CCMZ6X4KM3RC7HXWCZDTH7CMWIJXFPN6HLGKJBM63MCOW2AJ2V5W7YXY` |

The demo does not pin a default smart-account contract ID. Smart accounts are deployed per wallet from the uploaded WASM hash because deployment requires constructor args for `signers` and `policies`. If you need to regenerate bindings from a specific deployed instance for debugging, you can set `VITE_ACCOUNT_CONTRACT_ID` locally in `.env`.

### Uploaded WASM Hashes

These are the current checked-in testnet artifacts corresponding to the deployed contracts above:

| Contract | Uploaded WASM hash |
|----------|--------------------|
| **Smart Account** | `1b5f4534a76322da2ad7c745f6900857a6802b0ca79850c35a03561df997785a` |
| **WebAuthn Verifier** | `e63a030d0f1a1481e36059a4837c433083b33e704c1f9625b7314795b6d72b76` |
| **Ed25519 Verifier** | `60e8798db610bdaf3370d39ebda56ee1dc2c15ce1c3a9e28b528bfa24a06b477` |
| **Threshold Policy** | `cb6c0bd9cd06abba05f924ff4157b41aa1dd3891803c7c93b3b158e20986e592` |
| **Spending Limit Policy** | `e41b563c4454f5a6742acfa6d44e1ece96d443bb5f40efddd6ed05180210219a` |
| **Weighted Threshold Policy** | `7565d0a585254be47001281baef5bbc5d539ccbe1c813196b3c45995a6c15b74` |

## Setup

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev
```

Open `http://localhost:5173` in your browser.

The demo comes pre-configured with testnet contracts. To customize, copy `.env.example` to `.env` and edit as needed. For mainnet, start from `.env.mainnet.example`. Leave `VITE_WEIGHTED_THRESHOLD_POLICY_ADDRESS` blank if you do not want the weighted-threshold policy in the UI, and leave `VITE_RELAYER_URL` blank if you do not want fee-sponsored submissions.

The SDK auto-configures its hosted indexer for Stellar testnet and mainnet when you use a known network passphrase. Set `VITE_INDEXER_URL` to use a wire-compatible provider such as Mercury, and set `VITE_INDEXER_AUTH_TOKEN` when that provider expects `Authorization: Bearer <token>`. Because Vite embeds `VITE_*` values in the browser bundle, only use public or tightly scoped tokens; privileged/admin credentials belong behind a server.

This demo ships with testnet defaults, so a mainnet run also needs mainnet RPC and contract env values. Start from `.env.mainnet.example` to keep the network, WASM, verifier, policy, and indexer settings aligned.

## Agent-Browser Passkey Testing

This repo includes a helper for enabling a Chromium virtual authenticator on a live `agent-browser` session, so passkey flows can be smoke-tested without switching away from `agent-browser`.

```bash
# 1. Start the demo and open it with agent-browser
pnpm --filter smart-account-kit-demo exec vite --host 127.0.0.1 --port 5173
agent-browser --session demo-passkey open http://127.0.0.1:5173

# 2. Run your agent-browser steps while the helper keeps a virtual authenticator attached
pnpm agent-browser:webauthn run --session demo-passkey -- \
  bash -lc 'agent-browser --session demo-passkey snapshot -i && \
    agent-browser --session demo-passkey click @e8'
```

The helper attaches to the current page target over Chrome DevTools Protocol, keeps the virtual authenticator alive while the wrapped command runs, and removes it automatically afterward.

## Usage

### Creating a New Wallet

1. Enter a username (optional)
2. Click "Create Wallet"
3. Follow the browser prompt to create a passkey
4. The wallet contract is deployed to testnet automatically
5. Wait for confirmation (typically 5-10 seconds)

### Connecting to an Existing Wallet

1. Click "Connect Existing"
2. Select a passkey from the browser prompt
3. Your wallet will be connected

### Adding Additional Passkeys

1. Connect to a wallet first
2. Enter a name for the new passkey (optional)
3. Click "Add Passkey"
4. Follow the browser prompt to create a new passkey
5. The transaction is signed and submitted automatically
6. Wait for confirmation to see the new passkey added

### Transferring Tokens

1. Connect to a wallet first
2. Fund the wallet with testnet XLM using "Fund Wallet (Testnet)"
3. Enter a recipient address (G... or C...)
4. Enter the amount in XLM
5. Click "Send Transfer"
6. Authenticate with your passkey when prompted
7. The transaction is signed and submitted automatically
8. Wait for confirmation to verify the transfer succeeded

## Architecture

```
demo/
├── src/
│   ├── App.tsx           # Main application component
│   ├── main.tsx          # Entry point with Buffer polyfill
│   ├── styles.css        # Application styles
│   └── components/
│       ├── index.ts                # Component exports
│       ├── ActiveSignerDisplay.tsx # Shows currently active signer
│       ├── ContextRulesPanel.tsx   # Displays on-chain context rules
│       ├── ContextRuleBuilder.tsx  # Modal for creating/editing rules
│       └── SignerPicker.tsx        # Multi-signer selection modal
├── index.html            # HTML template
├── vite.config.ts        # Vite configuration
└── package.json          # Dependencies
```

## Notes

- Credentials stored in IndexedDB (persists across sessions)
- WebAuthn requires HTTPS in production (localhost works for development)
- Transactions auto-submit to Stellar testnet and wait for confirmation
- Contract addresses configurable via `.env` (see `.env.example`)
- Contract discovery prefers the indexer and falls back to the derived contract ID path when no indexed match is found
