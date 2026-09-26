#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
export BESU_RPC_URL="${BESU_RPC_URL:-http://127.0.0.1:8545}"
export DEPLOYER_PRIVATE_KEY="${DEPLOYER_PRIVATE_KEY:-30389ef71a9f24675e4eb0f7c761a1b8c56fb21883a98a3cd8582585e4b7b1d8}"
export DEPLOYMENT_FILE="$ROOT/contracts/deployment.json"
export HEXWARDEN_ROOT="$ROOT"
export PORT="${PORT:-4000}"

"$ROOT/scripts/start.sh"
trap 'kill "$backend_pid" 2>/dev/null || true' EXIT

(cd "$ROOT/contracts" && npm run deploy)
(cd "$ROOT/backend" && npm run build && npm start) >"${TMPDIR:-/tmp}/hexwarden-dlt-backend.log" 2>&1 &
backend_pid=$!

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/api/blockchain/status" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

response=$(curl -fsS -F firmware=@"$ROOT/firmware/clean.bin" -F deviceModel=ESP32-X -F version=2.1 "http://127.0.0.1:$PORT/api/firmware/approve")
hash=$(printf '%s' "$response" | node -e 'let s=""; process.stdin.on("data", d => s += d).on("end", () => process.stdout.write(JSON.parse(s).hash))')
approved=$(curl -fsS "http://127.0.0.1:$PORT/api/firmware/$hash")
printf '%s' "$approved" | node -e 'let s=""; process.stdin.on("data", d => s += d).on("end", () => { if (!JSON.parse(s).approved) process.exit(1); })'
curl -fsS -X POST "http://127.0.0.1:$PORT/api/firmware/$hash/revoke" >/dev/null
revoked=$(curl -fsS "http://127.0.0.1:$PORT/api/firmware/$hash")
printf '%s' "$revoked" | node -e 'let s=""; process.stdin.on("data", d => s += d).on("end", () => { if (JSON.parse(s).approved) process.exit(1); })'
printf '%s\n' "integration test passed: $hash approved, queried, revoked, queried again"