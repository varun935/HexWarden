#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
export BESU_RPC_URL="${BESU_RPC_URL:-http://127.0.0.1:8545}"
export DEPLOYER_PRIVATE_KEY="${DEPLOYER_PRIVATE_KEY:-30389ef71a9f24675e4eb0f7c761a1b8c56fb21883a98a3cd8582585e4b7b1d8}"
export DEPLOYMENT_FILE="${DEPLOYMENT_FILE:-$ROOT/contracts/deployment.json}"
export HEXWARDEN_ROOT="$ROOT"

printf '%s\n' '--- Demo 1: analyze and attest clean firmware ---'
python3 -m hexwarden.cli "$ROOT/firmware/clean.bin"
printf '%s\n' 'Approve through the backend with:'
printf '%s\n' "curl -F firmware=@$ROOT/firmware/clean.bin -F deviceModel=ESP32-X -F version=2.1 http://127.0.0.1:4000/api/firmware/approve"
printf '%s\n' '--- Demo 2: modified firmware is a different SHA-256 and is not approved ---'
python3 "$ROOT/esp32-simulator/simulator.py" "$ROOT/firmware/trojan.bin" || true
printf '%s\n' '--- Demo 3: revoke the clean hash, then rerun the simulator ---'
printf '%s\n' 'Use the hash from Demo 1: curl -X POST http://127.0.0.1:4000/api/firmware/HASH/revoke'
printf '%s\n' 'The subsequent simulator lookup returns REVOKED; FirmwareApproved remains in the event history.'