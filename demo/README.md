# Smart Account Kit Demo

A basic Vite + React frontend application for testing the Smart Account Kit SDK with WebAuthn passkey authentication on Stellar/Soroban.

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
| **Smart Account WASM Hash** | `8537b8166c0078440a5324c12f6db48d6340d157c306a54c5ea81405abcc2611` |
| **WebAuthn Verifier** | `CCMR63YE5T7MPWREF3PC5XNTTGXFSB4GYUGUIT5POHP2UGCS65TBIUUU` |
| **Ed25519 Verifier** | `CCJOUKLCZVCXS4VIBBEA7S3SPWZQS5DPE5A4YG67RA3Z7E3SJZAUJFQA` |
| **Native XLM Token** | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |
| **Threshold Policy** | `CB2WQXF2XXDGUV2CTVQ23RLN3ESI3IY5KKX3KVXWBNRTTWDHZM76NVKJ` |
| **Spending Limit Policy** | `CBBZ2XP4LBDEO2EELTZKJSPQZDREFKCULL6CKIUQO53S42RZABOYQUK3` |
| **Weighted Threshold Policy** | `CCF65VXVORNOZBRR3EG3GZYSFS3ALDG44CDYN5T5KRWKYX6RXLKLXER4` |

The demo does not pin a default smart-account contract ID. Smart accounts are deployed per wallet from the uploaded WASM hash because deployment requires constructor args for `signers` and `policies`.

### Uploaded WASM Hashes

These are the latest uploaded testnet artifacts corresponding to the deployed contracts above:

| Contract | Uploaded WASM hash |
|----------|--------------------|
| **Smart Account** | `8537b8166c0078440a5324c12f6db48d6340d157c306a54c5ea81405abcc2611` |
| **WebAuthn Verifier** | `f83d679f0ead1836b255a0f4160b9766065436a3b1afb9b15d73b646d68c0725` |
| **Ed25519 Verifier** | `2c1dae0a0fd609d818df05fff5deff91c7565151d82b6259a61d03c8edfdeeca` |
| **Threshold Policy** | `967dc8b1b2840a77e216243c60a7766c0fe737e6d6db47d7b210f3bf589f681a` |
| **Spending Limit Policy** | `dfe58cb65409c25084706e71fde3a12dfadbafb93db3d3225fe8919f488d8cc8` |
| **Weighted Threshold Policy** | `c16f644b40b3bcb0bc5371fe5949ccd51226179adeac8429e75a6e5a6ac68c6e` |

## Setup

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev
```

Open `http://localhost:5173` in your browser.

The demo comes pre-configured with testnet contracts. To customize, copy `.env.example` to `.env` and edit as needed. Leave `VITE_WEIGHTED_THRESHOLD_POLICY_ADDRESS` blank if you do not want the weighted-threshold policy in the UI.

The SDK now auto-configures the hosted indexer for both Stellar testnet and mainnet when you use a known network passphrase. This demo still ships with testnet defaults, so a mainnet run also needs mainnet RPC and contract env values.

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
│       ├── SignerPicker.tsx        # Multi-signer selection modal
│       └── KnownSignersPanel.tsx   # Displays known signers
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
