#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

for artifact in build/refund_claim_js/refund_claim.wasm build/refund_claim_final.zkey build/verification_key.json; do
  if [[ ! -f "$artifact" ]]; then
    echo "Missing $artifact; run: bash scripts/setup.sh" >&2
    exit 1
  fi
done

node src/demo.js
