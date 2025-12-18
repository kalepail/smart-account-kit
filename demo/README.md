# Smart Account Kit Demo

A basic Vite + React frontend application for testing the Smart Account Kit SDK with WebAuthn passkey authentication on Stellar/Soroban.

## Features

- **Wallet Creation**: Create a new smart wallet with a passkey as the primary signer
- **Wallet Connection**: Connect to an existing wallet using stored or discoverable passkeys
- **Contract Discovery**: Automatically discover smart accounts via indexer when connecting
- **Context Rule Management**: Create, view, and edit context rules with signers and policies
- **Multi-Signer Support**: Add passkey and delegated (G-address) signers to context rules
- **Policy Support**: Configure threshold, weighted threshold, and spending limit policies
- **External Wallet Integration**: Connect Freighter or other Stellar wallets for delegated signing
- **Token Transfer**: Build and sign XLM transfer transactions with multi-signer support

## Deployed Contracts (Testnet)

The following contracts are already deployed and pre-configured in the demo:

| Contract | Address/Hash |
|----------|--------------|
| **Smart Account WASM Hash** | `a12e8fa9621efd20315753bd4007d974390e31fbcb4a7ddc4dd0a0dec728bf2e` |
| **WebAuthn Verifier** | `CCQKLVCZYLMM67RZVCPHMDTT7UEJNLYSIQ57GYWRNDECZGDVB7I6G23Y` |
| **Native XLM Token** | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |
| **Threshold Policy** | `CDQEUI5I6OANOUU72EUMASMYFTNZSUSYZZB746QTJOFJGTXCRRR4FHRD` |
| **Spending Limit Policy** | `CBTH7MG5QFEAEEANZ47Y64PPV733F5K4MGVITQNYMWHDMISNBGCIJSFE` |
| **Weighted Threshold Policy** | `CD2AVNAKJIROTEZ6MZAXGML55Q3AFVRL72YXNURHT5VJES2WXNPT7MQE` |

## Setup

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev
```

Open `http://localhost:5173` in your browser.

The demo comes pre-configured with testnet contracts. To customize, copy `.env.example` to `.env` and edit as needed.

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
