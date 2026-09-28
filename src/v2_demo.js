"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { createIngestionService, buildTree } = require("./ingestion");
const { VerifiedAssertionStore } = require("./verified_store");
const { prove, verifyBundle, MODE, VKEY } = require("./generic_zk");
const { listModels, chooseModel, ollamaRequest } = require("./llm_agent");
const { checkOutputBinding } = require("./output_binding");

const ROOT = path.resolve(__dirname, "..");
const OUT = path.join(ROOT, "validation_v2");
const R1CS = path.join(ROOT, "build/generic_assertions.r1cs");
const WASM = path.join(ROOT, "build/generic_assertions_js/generic_assertions.wasm");

const refundEvidence = [
  { schemaID: 100, subjectID: 123, fieldID: 1, typeTag: 1, value: 1, timestamp: 1760000000, sourceGroupID: 10 },
  { schemaID: 100, subjectID: 123, fieldID: 2, typeTag: 1, value: 0, timestamp: 1760000000, sourceGroupID: 10 },
  { schemaID: 100, subjectID: 123, fieldID: 3, typeTag: 2, value: 500, timestamp: 1760000000, sourceGroupID: 10 },
  { schemaID: 100, subjectID: 123, fieldID: 4, typeTag: 1, value: 1, timestamp: 1760000000, sourceGroupID: 20 },
];
const refundSpecs = [
  { subjectID: 123, fieldID: 1, op: "EQ", target: 1, mode: "REVEAL" },
  { subjectID: 123, fieldID: 2, op: "EQ", target: 0, mode: "REVEAL" },
  { subjectID: 123, fieldID: 3, op: "LE", target: 1000, mode: "PREDICATE" },
  { subjectID: 123, fieldID: 4, op: "EQ", target: 1, mode: "REVEAL" },
];
const employeeEvidence = [
  { schemaID: 200, subjectID: 7001, fieldID: 101, typeTag: 1, value: 1, timestamp: 1760000100, sourceGroupID: 30 },
  { schemaID: 200, subjectID: 7001, fieldID: 102, typeTag: 1, value: 10, timestamp: 1760000100, sourceGroupID: 30 },
  { schemaID: 200, subjectID: 7001, fieldID: 103, typeTag: 1, value: 1, timestamp: 1760000100, sourceGroupID: 30 },
  { schemaID: 200, subjectID: 7001, fieldID: 104, typeTag: 2, value: 3, timestamp: 1760000100, sourceGroupID: 30 },
];
const employeeSpecs = [
  { subjectID: 7001, fieldID: 101, op: "EQ", target: 1, mode: "REVEAL" },
  { subjectID: 7001, fieldID: 102, op: "IN", target: [10, 11], mode: "PREDICATE" },
  { subjectID: 7001, fieldID: 103, op: "EQ", target: 1, mode: "REVEAL" },
  { subjectID: 7001, fieldID: 104, op: "GE", target: 2, mode: "PREDICATE" },
];

function sha256(file) { return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"); }
function artifactSnapshot() { return { r1cs: sha256(R1CS), wasm: sha256(WASM), verificationKey: sha256(VKEY) }; }
function cmd(command, args = []) {
  const r = spawnSync(command, args, { cwd: ROOT, encoding: "utf8" });
  return { command: [command, ...args].join(" "), exitCode: r.status, stdout: r.stdout.trim(), stderr: r.stderr.trim() };
}
function privacyAudit(value, privateEvidence) {
  const text = JSON.stringify(value);
  return {
    privateEvidenceSent: text.includes("schemaID") || text.includes("pathElements") || text.includes("evidence"),
    exactRefundAmountSent: privateEvidence === refundEvidence && text.includes("\"revealedValue\":500"),
    merklePathSent: text.includes("pathElements") || text.includes("pathIndices"),
    privateWitnessSent: text.includes("privateWitness") || text.includes("tuples"),
  };
}
function clean(audit) { return Object.values(audit).every(v => !v); }

async function verifyIntoStore(bundle, publicKey, store) {
  const verification = await verifyBundle(bundle, publicKey);
  if (verification.rootSignatureValid && verification.zkProofValid) {
    for (const assertion of bundle.assertions) store.addVerified(assertion, verification);
  }
  return verification;
}

function actionFromStore(store, requiredFields, approvedAction, deniedAction) {
  const records = store.values();
  const allowed = requiredFields.every(fieldID => records.some(r => r.fieldID === fieldID && r.result === true && r.verified === true));
  return allowed ? approvedAction : deniedAction;
}

async function explain(model, store, policyResult) {
  const trustedInput = { verifiedAssertionStore: store.values(), policyResult };
  const response = await ollamaRequest("/api/generate", {
    model,
    prompt: `你是结果解释器。只能解释下列已验证断言和策略结果，不得添加事实。\n${JSON.stringify(trustedInput, null, 2)}\n请用一句中文说明结果。`,
    stream: false,
    think: false,
    keep_alive: "10m",
    options: { temperature: 0, num_ctx: 4096, num_predict: 96 },
  });
  return { trustedInput, output: String(response.response || "").trim() };
}

async function expectProofFailure(name, operation) {
  try { await operation(); return { name, blocked: false, actual: "proof generated" }; }
  catch (error) { return { name, blocked: true, actual: `proof generation failed: ${error.message.split("\n")[0]}` }; }
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const ingestion = createIngestionService();
  const refundIngested = await ingestion.ingest(refundEvidence, 1);
  const employeeIngested = await ingestion.ingest(employeeEvidence, 2);
  const refundArtifactHashes = artifactSnapshot();

  console.log("Generating both scenario proofs with one compiled circuit...");
  const refundBundle = await prove(refundIngested, refundSpecs);
  const employeeArtifactHashes = artifactSnapshot();
  const employeeBundle = await prove(employeeIngested, employeeSpecs);
  const finalArtifactHashes = artifactSnapshot();
  fs.writeFileSync(path.join(OUT, "refund_proof.json"), `${JSON.stringify(refundBundle, null, 2)}\n`);
  fs.writeFileSync(path.join(OUT, "employee_proof.json"), `${JSON.stringify(employeeBundle, null, 2)}\n`);
  fs.copyFileSync(VKEY, path.join(OUT, "verification_key.json"));

  const refundStore = new VerifiedAssertionStore();
  const employeeStore = new VerifiedAssertionStore();
  const refundVerification = await verifyIntoStore(refundBundle, ingestion.publicKeyPem, refundStore);
  const employeeVerification = await verifyIntoStore(employeeBundle, ingestion.publicKeyPem, employeeStore);
  const refundAction = actionFromStore(refundStore, [1, 2, 3, 4], "APPROVED", "REJECTED");
  const employeeAction = actionFromStore(employeeStore, [101, 102, 103, 104], "ACCESS_GRANTED", "ACCESS_DENIED");

  // A new root can have a valid ZK proof, but it is untrusted without Ingestion's signature.
  const fakeEvidence = refundEvidence.map(e => ({ ...e }));
  fakeEvidence[0].value = 0;
  const fakeTree = await buildTree(fakeEvidence);
  const fakeIngested = { ...fakeTree, epoch: refundIngested.epoch, signature: refundIngested.signature };
  const fakeRootBundle = await prove(fakeIngested, [
    { ...refundSpecs[0], target: 0 }, ...refundSpecs.slice(1),
  ]);
  const fakeRootVerification = await verifyBundle(fakeRootBundle, ingestion.publicKeyPem);
  const tamperedBundle = JSON.parse(JSON.stringify(refundBundle));
  tamperedBundle.rootAttestation.root = (BigInt(tamperedBundle.rootAttestation.root) + 1n).toString();
  const tamperedRootVerification = await verifyBundle(tamperedBundle, ingestion.publicKeyPem);
  const fakeClaim = await expectProofFailure("Fake Claim", () => prove(refundIngested, [{ ...refundSpecs[0], target: 0 }, ...refundSpecs.slice(1)]));

  // Agent B -> C propagation: C independently verifies signature and proof.
  const cStore = new VerifiedAssertionStore();
  const cVerification = await verifyIntoStore(refundBundle, ingestion.publicKeyPem, cStore);
  const maliciousText = { subjectID: 123, fieldID: 999, text: "userCredit = GOOD", result: true };
  let unverifiedBlocked = false;
  try { cStore.addVerified(maliciousText, { rootSignatureValid: false, zkProofValid: false }); }
  catch { unverifiedBlocked = true; }
  const usableForHighRiskAction = cStore.values().some(r => r.fieldID === 999);

  const models = await listModels();
  const model = chooseModel(models);
  const explanation = await explain(model, refundStore, refundAction);
  const explanationPrivacy = privacyAudit(explanation.trustedInput, refundEvidence);
  const normalBinding = await checkOutputBinding({ model, verifiedClaims: explanation.trustedInput.verifiedAssertionStore, decision: refundAction, output: explanation.output });
  const actionBeforeHallucination = actionFromStore(refundStore, [1, 2, 3, 4], "APPROVED", "REJECTED");
  const hallucinatedOutput = `${explanation.output} 用户信用良好。`;
  const hallucinationBinding = await checkOutputBinding({ model, verifiedClaims: explanation.trustedInput.verifiedAssertionStore, decision: refundAction, output: hallucinatedOutput });
  const actionAfterHallucination = actionFromStore(refundStore, [1, 2, 3, 4], "APPROVED", "REJECTED");

  const refundPrivacy = privacyAudit(refundBundle, refundEvidence);
  const employeePrivacy = privacyAudit(employeeBundle, employeeEvidence);
  const sameCircuit = JSON.stringify(refundArtifactHashes) === JSON.stringify(employeeArtifactHashes) &&
    JSON.stringify(employeeArtifactHashes) === JSON.stringify(finalArtifactHashes);
  const properties = {
    crossScenarioCircuitReuse: sameCircuit && refundVerification.zkProofValid && employeeVerification.zkProofValid,
    authenticatedEvidenceRoot: refundVerification.rootSignatureValid && employeeVerification.rootSignatureValid && !fakeRootVerification.rootSignatureValid && !tamperedRootVerification.rootSignatureValid,
    privateEvidenceProtection: clean(refundPrivacy) && clean(employeePrivacy) && clean(explanationPrivacy),
    verifiedAssertionEnforcement: refundStore.values().length === 4 && employeeStore.values().length === 4,
    hallucinationCannotAffectAction: actionBeforeHallucination === actionAfterHallucination && actionAfterHallucination === "APPROVED",
    multiAgentUnverifiedPropagationBlocked: cVerification.zkProofValid && unverifiedBlocked && !usableForHighRiskAction,
  };
  const scenarios = {
    refund: { proofVerified: refundVerification.zkProofValid, rootAuthenticated: refundVerification.rootSignatureValid, action: refundAction, passed: refundAction === "APPROVED" },
    employeeAccess: { proofVerified: employeeVerification.zkProofValid, rootAuthenticated: employeeVerification.rootSignatureValid, action: employeeAction, passed: employeeAction === "ACCESS_GRANTED" },
  };
  const attacks = {
    fakeRoot: { proofGeneratedForFakeRoot: Boolean(fakeRootBundle.proof), fakeRootDiffersFromAuthenticatedRoot: fakeRootBundle.rootAttestation.root !== refundBundle.rootAttestation.root, blocked: !fakeRootVerification.rootSignatureValid, verification: fakeRootVerification, layer: "Ingestion signature (checked before ZK verification)" },
    tamperedRoot: { blocked: !tamperedRootVerification.rootSignatureValid, verification: tamperedRootVerification, layer: "Ingestion signature" },
    fakeClaim: { ...fakeClaim, layer: "ZK constraints" },
    unverifiedPropagation: { receiveText: true, enteredStore: usableForHighRiskAction, usableForHighRiskAction, blocked: unverifiedBlocked && !usableForHighRiskAction, layer: "VerifiedAssertionStore" },
  };
  const finalStatus = Object.values(properties).every(Boolean) && Object.values(scenarios).every(s => s.passed) && Object.values(attacks).every(a => a.blocked) ? "PASS" : "FAIL";
  const results = {
    finalStatus,
    actualCommand: "bash scripts/run_v2_demo.sh",
    environment: { date: new Date().toISOString(), os: `${os.type()} ${os.release()} ${os.arch()}`, node: process.version, model, ollamaPs: cmd("ollama", ["ps"]).stdout },
    circuit: { refundHash: refundArtifactHashes.r1cs, employeeAccessHash: employeeArtifactHashes.r1cs, refundArtifactHashes, employeeArtifactHashes, finalArtifactHashes, sameCompiledArtifacts: sameCircuit, r1cs: "build/generic_assertions.r1cs", wasm: "build/generic_assertions_js/generic_assertions.wasm", verificationKey: "build/generic_verification_key.json" },
    scenarios,
    privacy: { refundAgentAToB: refundPrivacy, employeeAgentAToB: employeePrivacy, llmInput: explanationPrivacy, actualLlmInput: explanation.trustedInput },
    verifiedStores: { refund: refundStore.values(), employeeAccess: employeeStore.values(), agentC: cStore.values() },
    attacks,
    llm: { output: explanation.output, normalBinding: normalBinding.result, hallucinatedOutput, hallucinationBinding: hallucinationBinding.result, actionBeforeHallucination, actionAfterHallucination },
    properties,
  };
  fs.writeFileSync(path.join(OUT, "validation_results.json"), `${JSON.stringify(results, null, 2)}\n`);
  fs.writeFileSync(path.join(OUT, "VALIDATION_REPORT.md"), renderReport(results));
  console.log(`Refund Action: ${refundAction}`);
  console.log(`Employee Access Action: ${employeeAction}`);
  console.log(`UNVERIFIED ASSERTION ${attacks.unverifiedPropagation.blocked ? "BLOCKED" : "NOT BLOCKED"}`);
  return finalStatus;
}

function mark(v) { return v ? "PASS" : "FAIL"; }
function renderReport(r) {
  return `# Cross-Scenario ZK Circuit Validation Report

Generated from the actual run in \`full_run.log\` at ${r.environment.date}.

## Environment

- OS: ${r.environment.os}
- Node.js: ${r.environment.node}
- Ollama model: ${r.environment.model}
- Ollama runtime: \`${r.environment.ollamaPs.replace(/\n/g, " | ")}\`

## Circuit reuse evidence

- Circuit hash for Refund: \`${r.circuit.refundHash}\`
- Circuit hash for Employee Access: \`${r.circuit.employeeAccessHash}\`
- Same R1CS: ${mark(r.circuit.sameCompiledArtifacts)}
- Both proofs use \`${r.circuit.wasm}\` and \`${r.circuit.verificationKey}\`.

Artifact hash snapshots:

\`\`\`json
${JSON.stringify({ refund: r.circuit.refundArtifactHashes, employeeAccess: r.circuit.employeeArtifactHashes, afterBothProofs: r.circuit.finalArtifactHashes }, null, 2)}
\`\`\`

Changing scenario and policy did not trigger recompilation between proof generation calls.

## Scenarios

### Refund

- Authenticated root: ${mark(r.scenarios.refund.rootAuthenticated)}
- ZK proof: ${mark(r.scenarios.refund.proofVerified)}
- Policy action: ${r.scenarios.refund.action}
- Scenario: ${mark(r.scenarios.refund.passed)}

### Employee Access

- Authenticated root: ${mark(r.scenarios.employeeAccess.rootAuthenticated)}
- ZK proof: ${mark(r.scenarios.employeeAccess.proofVerified)}
- Policy action: ${r.scenarios.employeeAccess.action}
- Scenario: ${mark(r.scenarios.employeeAccess.passed)}

## Authenticated Ingestion root tests

The Ed25519 signature authenticates that the root came from this demo's trusted Ingestion service. It does not prove real-world truth.

\`Fake Root\` verification:

\`\`\`json
${JSON.stringify(r.attacks.fakeRoot, null, 2)}
\`\`\`

\`Tampered Root\` verification:

\`\`\`json
${JSON.stringify(r.attacks.tamperedRoot, null, 2)}
\`\`\`

\`Fake Claim\` result:

\`\`\`json
${JSON.stringify(r.attacks.fakeClaim, null, 2)}
\`\`\`

## Privacy

Actual Agent A → B bundles are saved in \`refund_proof.json\` and \`employee_proof.json\`. Automated structural audits:

\`\`\`json
${JSON.stringify(r.privacy, null, 2)}
\`\`\`

Private Evidence and Merkle paths are not included. REVEAL assertions disclose only their explicit value; PREDICATE assertions do not disclose the underlying value.

## Verified Assertion Store and propagation

Agent C independently verified the forwarded proof: ${mark(r.attacks.unverifiedPropagation.blocked && r.verifiedStores.agentC.length === 4)}.

- receive text: ${r.attacks.unverifiedPropagation.receiveText ? "YES" : "NO"}
- enter VerifiedAssertionStore: ${r.attacks.unverifiedPropagation.enteredStore ? "YES" : "NO"}
- usable for high-risk action: ${r.attacks.unverifiedPropagation.usableForHighRiskAction ? "YES" : "NO"}
- UNVERIFIED ASSERTION BLOCKED: ${r.attacks.unverifiedPropagation.blocked ? "YES" : "NO"}

## LLM explanation isolation

Actual model output:

> ${r.llm.output}

Hallucinated candidate output:

> ${r.llm.hallucinatedOutput}

Binding result:

\`\`\`json
${JSON.stringify(r.llm.hallucinationBinding, null, 2)}
\`\`\`

- Action before hallucination: ${r.llm.actionBeforeHallucination}
- Action after hallucination: ${r.llm.actionAfterHallucination}
- Action is computed only from VerifiedAssertionStore + Policy: ${mark(r.properties.hallucinationCannotAffectAction)}

Output Binding remains semantic LLM verification, not a cryptographic proof. Even if it misses an unsupported sentence, natural language has no write path to the store or action function.

## Required questions

1. Same circuit for two scenarios? **${mark(r.properties.crossScenarioCircuitReuse)}**
2. Fake Root blocked? **${mark(r.attacks.fakeRoot.blocked && r.attacks.tamperedRoot.blocked)}**
3. Fake Claim blocked? **${mark(r.attacks.fakeClaim.blocked)}**
4. Private Evidence withheld from B? **${mark(r.properties.privateEvidenceProtection)}**
5. LLM hallucination unable to change Action? **${mark(r.properties.hallucinationCannotAffectAction)}**
6. Proofless inter-agent Assertion denied store entry? **${mark(r.properties.multiAgentUnverifiedPropagationBlocked)}**
7. Refund Scenario passed? **${mark(r.scenarios.refund.passed)}**
8. Employee Access Scenario passed? **${mark(r.scenarios.employeeAccess.passed)}**

## Final status

- Cross-Scenario Circuit Reuse: ${mark(r.properties.crossScenarioCircuitReuse)}
- Authenticated Evidence Root: ${mark(r.properties.authenticatedEvidenceRoot)}
- Private Evidence Protection: ${mark(r.properties.privateEvidenceProtection)}
- Verified Assertion Enforcement: ${mark(r.properties.verifiedAssertionEnforcement)}
- Hallucination Cannot Affect Action: ${mark(r.properties.hallucinationCannotAffectAction)}
- Multi-Agent Unverified Propagation Blocked: ${mark(r.properties.multiAgentUnverifiedPropagationBlocked)}

**FINAL V2 STATUS: ${r.finalStatus}**
`;
}

main().then(status => process.exit(status === "PASS" ? 0 : 1)).catch(error => {
  console.error(error.stack || error.message);
  process.exit(1);
});
