#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results/experiment2
export NODE_OPTIONS="--max-old-space-size=32768"
{
  echo '$ npm run experiment:2'
  node scripts/prepare_experiment2.js
  node src/experiment2.js
  python3 plots/plot_experiment2.py
} 2>&1 | tee results/experiment2/full_run.log
