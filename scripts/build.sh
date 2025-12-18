#!/bin/bash

# Build Script for Smart Account Kit (Standalone)
#
# This script performs a complete build:
# 1. Updates root & demo dependencies (via ncu -u)
# 2. Generates TypeScript bindings from deployed contracts (via network)
# 3. Updates bindings dependencies and builds the binding package
# 4. Builds the main SDK
#
# Prerequisites:
# - Stellar CLI installed (`stellar --version`)
# - Node.js and pnpm installed
# - npm-check-updates installed (`pnpm add -g npm-check-updates`)
#
# Configuration is read from demo/.env (VITE_* variables)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(dirname "$SCRIPT_DIR")"
BINDINGS_DIR="$KIT_DIR/packages/smart-account-kit-bindings"
DEMO_ENV="$KIT_DIR/demo/.env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Smart Account Kit - Build${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to update dependencies in a directory
update_dependencies() {
    local dir="$1"
    local name="$2"

    if [ -f "$dir/package.json" ]; then
        echo -e "  Updating ${BLUE}$name${NC}..."
        cd "$dir"
        ncu -u --packageFile package.json 2>/dev/null || {
            echo -e "    ${YELLOW}No updates available or ncu failed${NC}"
        }
        cd "$KIT_DIR"
    fi
}

# Load demo/.env file if it exists
if [ -f "$DEMO_ENV" ]; then
    echo -e "${YELLOW}Loading configuration from demo/.env...${NC}"
    # Use while read to handle values with special characters (like semicolons)
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        # Export variable (handles values with spaces/semicolons)
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            export "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
        fi
    done < "$DEMO_ENV"
else
    echo -e "${YELLOW}No demo/.env found, using environment variables...${NC}"
fi

# Map VITE_ variables to standard names (demo/.env uses VITE_ prefix)
STELLAR_RPC_URL="${STELLAR_RPC_URL:-$VITE_RPC_URL}"
STELLAR_NETWORK_PASSPHRASE="${STELLAR_NETWORK_PASSPHRASE:-$VITE_NETWORK_PASSPHRASE}"
ACCOUNT_WASM_HASH="${ACCOUNT_WASM_HASH:-$VITE_ACCOUNT_WASM_HASH}"
ACCOUNT_CONTRACT_ID="${ACCOUNT_CONTRACT_ID:-$VITE_ACCOUNT_CONTRACT_ID}"

# Check for stellar CLI
if ! command -v stellar &> /dev/null; then
    echo -e "${RED}Error: stellar CLI not found. Please install it first.${NC}"
    echo -e "  Install: https://developers.stellar.org/docs/tools/stellar-cli"
    exit 1
fi

# Validate required environment variables
if [ -z "$STELLAR_RPC_URL" ]; then
    echo -e "${RED}Error: RPC URL not set${NC}"
    echo -e "  Set VITE_RPC_URL in demo/.env or export STELLAR_RPC_URL"
    exit 1
fi

if [ -z "$STELLAR_NETWORK_PASSPHRASE" ]; then
    echo -e "${RED}Error: Network passphrase not set${NC}"
    echo -e "  Set VITE_NETWORK_PASSPHRASE in demo/.env or export STELLAR_NETWORK_PASSPHRASE"
    exit 1
fi

if [ -z "$ACCOUNT_WASM_HASH" ] && [ -z "$ACCOUNT_CONTRACT_ID" ]; then
    echo -e "${RED}Error: Either WASM hash or contract ID must be set${NC}"
    echo -e "  Set VITE_ACCOUNT_WASM_HASH in demo/.env or export ACCOUNT_WASM_HASH"
    exit 1
fi

echo -e "Configuration:"
echo -e "  RPC URL: ${GREEN}$STELLAR_RPC_URL${NC}"
echo -e "  Network: ${GREEN}$STELLAR_NETWORK_PASSPHRASE${NC}"
if [ -n "$ACCOUNT_WASM_HASH" ]; then
    echo -e "  WASM Hash: ${GREEN}$ACCOUNT_WASM_HASH${NC}"
else
    echo -e "  Contract ID: ${GREEN}$ACCOUNT_CONTRACT_ID${NC}"
fi
echo ""

# Check for ncu (required)
if ! command -v ncu &> /dev/null; then
    echo -e "${RED}Error: npm-check-updates (ncu) not found.${NC}"
    echo -e "  Install: ${BLUE}pnpm add -g npm-check-updates${NC}"
    exit 1
fi

# Step 1: Update root and demo dependencies (before bindings generation)
echo -e "${YELLOW}Step 1: Updating package dependencies (root & demo)...${NC}"
update_dependencies "$KIT_DIR" "smart-account-kit (root)"
update_dependencies "$KIT_DIR/demo" "demo"
echo -e "${GREEN}✓ Dependencies updated${NC}"
echo ""

# Step 2: Generate TypeScript bindings
echo -e "${YELLOW}Step 2: Generating TypeScript bindings from network...${NC}"

mkdir -p "$BINDINGS_DIR"

# Preserve current version before stellar CLI overwrites package.json
BINDINGS_VERSION="0.1.0"
if [ -f "$BINDINGS_DIR/package.json" ]; then
    BINDINGS_VERSION=$(node -p "require('$BINDINGS_DIR/package.json').version || '0.1.0'")
    # Don't preserve 0.0.0 (stellar CLI default)
    if [ "$BINDINGS_VERSION" = "0.0.0" ]; then
        BINDINGS_VERSION="0.1.0"
    fi
    echo -e "  Preserving bindings version: ${GREEN}$BINDINGS_VERSION${NC}"
fi

# Build the stellar CLI command
STELLAR_CMD="stellar contract bindings typescript"
STELLAR_CMD="$STELLAR_CMD --rpc-url \"$STELLAR_RPC_URL\""
STELLAR_CMD="$STELLAR_CMD --network-passphrase \"$STELLAR_NETWORK_PASSPHRASE\""

if [ -n "$ACCOUNT_WASM_HASH" ]; then
    STELLAR_CMD="$STELLAR_CMD --wasm-hash $ACCOUNT_WASM_HASH"
else
    STELLAR_CMD="$STELLAR_CMD --contract-id $ACCOUNT_CONTRACT_ID"
fi

STELLAR_CMD="$STELLAR_CMD --output-dir \"$BINDINGS_DIR\""
STELLAR_CMD="$STELLAR_CMD --overwrite"

echo -e "  Running: ${BLUE}stellar contract bindings typescript${NC}"
eval $STELLAR_CMD

echo -e "${GREEN}✓ Bindings generated${NC}"
echo ""

# Step 3: Update bindings dependencies and build
echo -e "${YELLOW}Step 3: Building binding package...${NC}"
cd "$BINDINGS_DIR"

# Patch package.json with fields required for npm publishing
# (stellar CLI generates a minimal package.json that's missing these)
echo -e "  Patching package.json for npm publishing..."
export BINDINGS_VERSION
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.version = process.env.BINDINGS_VERSION || '0.1.0';
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
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
"

# Update bindings dependencies after stellar CLI generated package.json
echo -e "  Updating bindings dependencies..."
ncu -u --packageFile package.json

pnpm install
pnpm run build

echo -e "${GREEN}✓ Binding package built${NC}"
echo ""

# Step 4: Build main SDK
echo -e "${YELLOW}Step 4: Building Smart Account Kit SDK...${NC}"
cd "$KIT_DIR"

pnpm install
pnpm run build

echo -e "${GREEN}✓ SDK built${NC}"
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  Build Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Output:"
echo "  - Bindings: $BINDINGS_DIR/dist/"
echo "  - SDK: $KIT_DIR/dist/"
echo ""
