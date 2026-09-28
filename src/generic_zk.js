"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { verifyRootSignature } = require("./ingestion");

const ROOT = path.resolve(__dirname, "..");
const WASM = path.join(ROOT, "build/generic_assertions_js/generic_assertions.wasm");
const ZKEY = path.join(ROOT, "build/generic_assertions_final.zkey");
const VKEY = path.join(ROOT, "build/generic_verification_key.json");

const OP = Object.freeze({ EQ: 1, LE: 2, GE: 3, IN: 4 });
const MODE = Object.freeze({ REVEAL: 1, PREDICATE: 2 });

function normalizeSpec(spec) {
  const targets = Array.isArray(spec.target) ? spec.target : [spec.target];
  if (targets.length < 1 || targets.length > 2) throw new Error("target must contain one or two values");
  return {
    subjectID: spec.subjectID,
    fieldID: spec.fieldID,
    op: typeof spec.op === "string" ? OP[spec.op] : spec.op,
    targets: [targets[0], targets[1] ?? 0],
    targetCount: targets.length,
    mode: typeof spec.mode === "string" ? MODE[spec.mode] : spec.mode,
  };
}

function circuitInput(ingested, specs) {
  const normalized = specs.map(normalizeSpec);
  return {
    root: ingested.root,
    assertionSubject: normalized.map(s => s.subjectID),
    assertionField: normalized.map(s => s.fieldID),
    assertionOp: normalized.map(s => s.op),
    assertionTargets: normalized.map(s => s.targets),
    assertionTargetCount: normalized.map(s => s.targetCount),
    assertionMode: normalized.map(s => s.mode),
    revealedValue: normalized.map((s, i) => s.mode === MODE.REVEAL ? ingested.tuples[i][4] : 0),
    evidence: ingested.tuples,
    pathElements: ingested.paths.map(p => p.pathElements),
    pathIndices: ingested.paths.map(p => p.pathIndices),
  };
}

function assertionRecords(root, specs, input) {
  return specs.map((original, i) => {
    const spec = normalizeSpec(original);
    const body = { subjectID: spec.subjectID, fieldID: spec.fieldID, op: spec.op, target: spec.targets.slice(0, spec.targetCount), mode: spec.mode, result: true };
    if (spec.mode === MODE.REVEAL) body.revealedValue = input.revealedValue[i];
    return { assertionId: crypto.createHash("sha256").update(JSON.stringify({ root, ...body })).digest("hex"), ...body };
  });
}

async function prove(ingested, specs) {
  const input = circuitInput(ingested, specs);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return {
    rootAttestation: { root: ingested.root, epoch: ingested.epoch, signature: ingested.signature },
    assertions: assertionRecords(ingested.root, specs, input),
    proof,
    publicSignals,
  };
}

function expectedPublicSignals(bundle) {
  const assertions = bundle.assertions;
  const paddedTargets = assertions.flatMap(a => [a.target[0], a.target[1] ?? 0]);
  return [
    bundle.rootAttestation.root,
    ...assertions.map(a => a.subjectID),
    ...assertions.map(a => a.fieldID),
    ...assertions.map(a => a.op),
    ...paddedTargets,
    ...assertions.map(a => a.target.length),
    ...assertions.map(a => a.mode),
    ...assertions.map(a => a.mode === MODE.REVEAL ? a.revealedValue : 0),
  ].map(String);
}

async function verifyBundle(bundle, trustedPublicKey) {
  const rootSignatureValid = verifyRootSignature(bundle.rootAttestation, trustedPublicKey);
  if (!rootSignatureValid) return { rootSignatureValid, zkProofValid: false };
  const statementBound = JSON.stringify(bundle.publicSignals) === JSON.stringify(expectedPublicSignals(bundle));
  if (!statementBound) return { rootSignatureValid, statementBound, zkProofValid: false };
  const vkey = JSON.parse(fs.readFileSync(VKEY, "utf8"));
  const zkProofValid = await snarkjs.groth16.verify(vkey, bundle.publicSignals, bundle.proof);
  return { rootSignatureValid, statementBound, zkProofValid };
}

module.exports = { OP, MODE, WASM, ZKEY, VKEY, normalizeSpec, circuitInput, assertionRecords, expectedPublicSignals, prove, verifyBundle };
