#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEMO_URL="${DEMO_URL:-http://localhost:5173}"
INDEXER_DEMO_URL="${INDEXER_DEMO_URL:-http://localhost:5174}"
INDEXER_API_URL="${INDEXER_API_URL:-https://smart-account-indexer.sdf-ecosystem.workers.dev}"
RECIPIENT_ADDRESS="${RECIPIENT_ADDRESS:-GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N}"
SESSION_NAME="${SESSION_NAME:-testnet-passkey-smoke-$(date +%s)}"
SKIP_INDEXER="${SKIP_INDEXER:-false}"
DEV_HOST="${DEV_HOST:-127.0.0.1}"

DEMO_SERVER_PID=""
INDEXER_SERVER_PID=""

wait_for_url() {
  local url="$1"
  local attempts="${2:-60}"

  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for $url" >&2
  return 1
}

start_vite_if_needed() {
  local port="$1"
  local filter="$2"
  local label="$3"
  local pid_var_name="$4"
  local log_path="/tmp/${label}.log"

  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "$label already running on port $port"
    return 0
  fi

  echo "Starting $label on port $port"
  (
    cd "$ROOT_DIR"
    pnpm --filter "$filter" exec vite --host "$DEV_HOST" --port "$port"
  ) >"$log_path" 2>&1 &

  local pid=$!
  printf -v "$pid_var_name" '%s' "$pid"
  wait_for_url "http://${DEV_HOST}:${port}"
}

cleanup() {
  local exit_code=$?

  if [[ -n "$DEMO_SERVER_PID" ]]; then
    kill "$DEMO_SERVER_PID" >/dev/null 2>&1 || true
  fi

  if [[ -n "$INDEXER_SERVER_PID" ]]; then
    kill "$INDEXER_SERVER_PID" >/dev/null 2>&1 || true
  fi

  agent-browser --session "$SESSION_NAME" close >/dev/null 2>&1 || true
  exit "$exit_code"
}

trap cleanup EXIT

start_vite_if_needed 5173 "smart-account-kit-demo" "smart-account-kit-demo-smoke" DEMO_SERVER_PID
start_vite_if_needed 5174 "indexer-demo" "indexer-demo-smoke" INDEXER_SERVER_PID

cd "$ROOT_DIR"

pnpm agent-browser:webauthn run --session "$SESSION_NAME" -- bash -lc \
  "SESSION_NAME='$SESSION_NAME' DEMO_URL='$DEMO_URL' INDEXER_DEMO_URL='$INDEXER_DEMO_URL' INDEXER_API_URL='$INDEXER_API_URL' RECIPIENT_ADDRESS='$RECIPIENT_ADDRESS' SKIP_INDEXER='$SKIP_INDEXER' bash scripts/browser-comprehensive-audit.sh"
