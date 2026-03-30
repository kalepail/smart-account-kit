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
| **Smart Account WASM Hash** | `3e51f5b222dec74650f0b33367acb42a41ce497f72639230463070e666abba2c` |
| **WebAuthn Verifier** | `CATPTBRWVMH5ZCIKO5HN2F4FMPXVZEXC56RKGHRXCM7EEZGGXK7PICEH` |
| **Ed25519 Verifier** | `CAIKK32K3BZJYTWVTXHZFPIEEDBR6YCVTGPABH4UQUQ4XFA3OLYXG27G` |
| **Native XLM Token** | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |
| **Threshold Policy** | `CDDQLFG7CV74QHWPSP6NZIPNBR2PPCMTUVYCJF4P3ONDYHODRFGR7LWC` |
| **Spending Limit Policy** | `CBYLPYZGLQ6JVY2IQ5P23QLQPR3KAMMKMZLNWG6RUUKJDNYGPLVHK7U4` |
| **Weighted Threshold Policy** | Optional. Set `VITE_WEIGHTED_THRESHOLD_POLICY_ADDRESS` to expose it in the policy picker. |

The demo does not pin a default smart-account contract ID. Smart accounts are deployed per wallet from the uploaded WASM hash because deployment requires constructor args for `signers` and `policies`.

### Uploaded WASM Hashes

These are the latest uploaded testnet artifacts corresponding to the deployed contracts above:

| Contract | Uploaded WASM hash |
|----------|--------------------|
| **Smart Account** | `3e51f5b222dec74650f0b33367acb42a41ce497f72639230463070e666abba2c` |
| **WebAuthn Verifier** | `d84af9e7c31afece287fee8276ef7d6a64b236d596c043594c003e0f4032d1c7` |
| **Ed25519 Verifier** | `e88b7989f8c5e69d6a72cda8419844ef2753ab249fef422f31436c5c32e28623` |
| **Threshold Policy** | `5c87cedc0e485152a084c4b5435bdec88e41304a4316e82e37a84910715639f6` |
| **Spending Limit Policy** | `eca96954a8e76e366e74fbc95eced11666c939e130a5cc302b8363622e931018` |

## Setup

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev
```

Open `http://localhost:5173` in your browser.

The demo comes pre-configured with testnet contracts. To customize, copy `.env.example` to `.env` and edit as needed. Leave `VITE_WEIGHTED_THRESHOLD_POLICY_ADDRESS` blank if you do not want the weighted-threshold policy in the UI.

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
