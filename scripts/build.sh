#!/bin/bash

# Build Script for Smart Account Kit SDK
#
# Builds the SDK. Version sync happens automatically via prebuild hook.
# Assumes bindings are already available (via npm or local build).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Building smart-account-kit${NC}"
echo ""

cd "$KIT_DIR"

# Build (prebuild hook syncs version automatically)
echo -e "${YELLOW}Building...${NC}"
pnpm run build

VERSION=$(node -p "require('./package.json').version")
echo ""
echo -e "${GREEN}smart-account-kit built (v$VERSION)${NC}"
