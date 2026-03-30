#!/bin/bash

# Build Script for Smart Account Kit Bindings
#
# Generates TypeScript bindings from the configured smart-account target and builds the package.
#
# Prerequisites:
# - Stellar CLI installed (`stellar --version`)
# - Configuration in demo/.env (VITE_* variables)
# - Use VITE_ACCOUNT_WASM_HASH for the default repo flow; VITE_ACCOUNT_CONTRACT_ID is optional when targeting a specific deployed smart account instance

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BINDINGS_DIR="$KIT_DIR/packages/smart-account-kit-bindings"
DEMO_ENV="$KIT_DIR/demo/.env"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building smart-account-kit-bindings${NC}"
echo ""

# Load demo/.env
if [ -f "$DEMO_ENV" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            export "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
        fi
    done < "$DEMO_ENV"
else
    echo -e "${RED}Error: demo/.env not found${NC}"
    exit 1
fi

# Map VITE_ variables
STELLAR_RPC_URL="${STELLAR_RPC_URL:-$VITE_RPC_URL}"
STELLAR_NETWORK_PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-$VITE_NETWORK_PASSPHRASE}"
ACCOUNT_WASM_HASH="${ACCOUNT_WASM_HASH:-$VITE_ACCOUNT_WASM_HASH}"
ACCOUNT_CONTRACT_ID="${ACCOUNT_CONTRACT_ID:-$VITE_ACCOUNT_CONTRACT_ID}"

# Validate
if ! command -v stellar &> /dev/null; then
    echo -e "${RED}Error: stellar CLI not found${NC}"
    exit 1
fi

if [ -z "$STELLAR_RPC_URL" ] || [ -z "$STELLAR_NETWORK_PASSPHRASE" ]; then
    echo -e "${RED}Error: RPC URL or network passphrase not set in demo/.env${NC}"
    exit 1
fi

if [ -z "$ACCOUNT_WASM_HASH" ] && [ -z "$ACCOUNT_CONTRACT_ID" ]; then
    echo -e "${RED}Error: WASM hash or contract ID must be set in demo/.env${NC}"
    exit 1
fi

# Step 1: Generate bindings
echo -e "${YELLOW}Generating TypeScript bindings...${NC}"

STELLAR_CMD="stellar contract bindings typescript"
STELLAR_CMD="$STELLAR_CMD --rpc-url \"$STELLAR_RPC_URL\""
STELLAR_CMD="$STELLAR_CMD --network-passphrase \"$STELLAR_NETWORK_PASSPHRASE\""

if [ -n "$ACCOUNT_WASM_HASH" ]; then
    STELLAR_CMD="$STELLAR_CMD --wasm-hash $ACCOUNT_WASM_HASH"
else
    STELLAR_CMD="$STELLAR_CMD --contract-id $ACCOUNT_CONTRACT_ID"
fi

STELLAR_CMD="$STELLAR_CMD --output-dir \"$BINDINGS_DIR\" --overwrite"
eval $STELLAR_CMD

echo -e "${GREEN}Bindings generated${NC}"

# Step 2: Patch package.json for npm
echo -e "${YELLOW}Patching package.json...${NC}"

cd "$BINDINGS_DIR"

# Preserve version if it exists and isn't 0.0.0. Allow callers to force a
# specific publish version via BINDINGS_VERSION.
CURRENT_VERSION="${BINDINGS_VERSION:-}"
if [ -z "$CURRENT_VERSION" ]; then
    CURRENT_VERSION=$(node -p "require('./package.json').version || '0.1.0'" 2>/dev/null || echo "0.1.0")
fi
if [ "$CURRENT_VERSION" = "0.0.0" ]; then
    CURRENT_VERSION="0.1.0"
fi

node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.version = '$CURRENT_VERSION';
pkg.description = 'TypeScript bindings for OpenZeppelin Smart Account contracts on Stellar/Soroban';
pkg.main = 'dist/index.js';
pkg.module = 'dist/index.js';
pkg.types = 'dist/index.d.ts';
pkg.files = ['dist'];
pkg.author = 'OpenZeppelin';
pkg.license = 'MIT';
pkg.repository = { type: 'git', url: 'https://github.com/kalepail/smart-account-kit' };
pkg.peerDependencies = { '@stellar/stellar-sdk': '>=14.0.0' };
pkg.publishConfig = { registry: 'https://registry.npmjs.org/', access: 'public' };
if (pkg.dependencies && pkg.dependencies['@stellar/stellar-sdk']) {
    delete pkg.dependencies['@stellar/stellar-sdk'];
}
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"

# Step 3: Install and build
echo -e "${YELLOW}Building...${NC}"
cd "$KIT_DIR"
pnpm install
cd "$BINDINGS_DIR"
pnpm run build

echo ""
echo -e "${GREEN}smart-account-kit-bindings built (v$CURRENT_VERSION)${NC}"
