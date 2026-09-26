#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p blockchain/generated blockchain/node1 blockchain/node2 blockchain/node3 blockchain/node4
docker-compose -f blockchain/docker-compose.yml up -d
echo "QBFT validators starting. Check with: docker-compose -f blockchain/docker-compose.yml ps"