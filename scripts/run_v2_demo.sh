#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."

mkdir -p validation_v2
log_file="validation_v2/full_run.log"
: > "$log_file"

for artifact in build/generic_assertions.r1cs build/generic_assertions_js/generic_assertions.wasm build/generic_assertions_final.zkey build/generic_verification_key.json; do
  if [[ ! -f "$artifact" ]]; then
    echo "Missing $artifact; run: bash scripts/setup.sh" >> "$log_file"
    exit 1
  fi
done

node src/v2_demo.js >> "$log_file" 2>&1
exit_code=$?

if [[ -f validation_v2/validation_results.json ]]; then
  final_status=$(node -e 'console.log(require("./validation_v2/validation_results.json").finalStatus)')
  node - <<'NODE' | tee -a "$log_file"
const r = require("./validation_v2/validation_results.json");
const mark = value => value ? "PASS" : "FAIL";
console.log(`Cross-Scenario Circuit Reuse: ${mark(r.properties.crossScenarioCircuitReuse)}`);
console.log(`Authenticated Evidence Root: ${mark(r.properties.authenticatedEvidenceRoot)}`);
console.log(`Private Evidence Protection: ${mark(r.properties.privateEvidenceProtection)}`);
console.log(`Verified Assertion Enforcement: ${mark(r.properties.verifiedAssertionEnforcement)}`);
console.log(`Hallucination Cannot Affect Action: ${mark(r.properties.hallucinationCannotAffectAction)}`);
console.log(`Multi-Agent Unverified Propagation Blocked: ${mark(r.properties.multiAgentUnverifiedPropagationBlocked)}`);
console.log("");
console.log(`FINAL V2 STATUS: ${r.finalStatus}`);
NODE
else
  final_status="FAIL"
  echo "FINAL V2 STATUS: FAIL" | tee -a "$log_file"
fi

exit "$exit_code"
