#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results/experiment1
if ! node - <<'NODE'
const fs=require('fs'),crypto=require('crypto');
const files=['build/task_final.zkey','build/verification_key.json','build/real_experiment1_js/real_experiment1.wasm','build/circuit.sha256'];
const hash=crypto.createHash('sha256').update(fs.readFileSync('circuits/real_experiment1.circom')).digest('hex');
process.exit(files.every(f=>fs.existsSync(f))&&fs.readFileSync('build/circuit.sha256','utf8').trim()===hash?0:1);
NODE
then
  bash scripts/setup.sh 2>&1 | tee results/experiment1/setup.log
fi
node src/experiment.js "$@" 2>&1 | tee results/experiment1/full_run.log
