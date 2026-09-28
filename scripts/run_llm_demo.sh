#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."

mkdir -p validation
log_file="validation/full_run.log"
: > "$log_file"

if ! curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  nohup ollama serve >> "$log_file" 2>&1 &
  for _ in $(seq 1 30); do
    curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
    sleep 1
  done
fi

node src/llm_demo.js >> "$log_file" 2>&1
exit_code=$?

if [[ -f validation/validation_results.json ]]; then
  final_status=$(node -e 'console.log(require("./validation/validation_results.json").final_status)')
else
  final_status="FAIL"
fi
{
  echo "Validation package generated:"
  echo
  echo "validation/DEMO_VALIDATION_REPORT.md"
  echo "validation/validation_results.json"
  echo "validation/full_run.log"
  echo
  echo "FINAL DEMO STATUS: $final_status"
} | tee -a "$log_file"
exit "$exit_code"
