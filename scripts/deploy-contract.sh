#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/../contracts"
npm install
npm run compile
npm run deploy