#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/core/tmp results/core
export TMPDIR="$PWD/build/core/tmp"
export PATH="/mnt/user-data/zjh/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$PWD/build/core/rust"
export NODE_OPTIONS="--max-old-space-size=$(node -p 'require("./configs/core.json").benchmark.node_heap_mib')"
export RAYON_NUM_THREADS=32 OMP_NUM_THREADS=32
export CORE_RUN_LOG="$PWD/results/core/full_run.log"
set +e
{
  date --iso-8601=seconds
  echo "COMMAND: bash scripts/run_core.sh ${*:-all}"
  node src/core/cli.js "${@:-all}"
} 2>&1 | tee -a "$CORE_RUN_LOG"
core_exit=${PIPESTATUS[0]}
printf 'Exit Code: %s\n' "$core_exit" | tee -a "$CORE_RUN_LOG"
exit "$core_exit"
