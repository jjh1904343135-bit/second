"use strict";

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { POLICY } = require("./policy");
const { evidenceFromKb, buildMerkle } = require("./build_merkle");

const ROOT = path.resolve(__dirname, "..");
const WASM = path.join(ROOT, "build/refund_claim_js/refund_claim.wasm");
const ZKEY = path.join(ROOT, "build/refund_claim_final.zkey");

function loadPrivateKb() {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "data/private_kb.json"), "utf8"));
}

function publicClaims(kb) {
  return {
    paymentStatus: kb.paymentStatus === 1 ? "PAID" : "UNPAID",
    refundStatus: kb.refundStatus === 0 ? "NOT_REFUNDED" : "REFUNDED",
    refundAmountLE1000: kb.refundAmount <= POLICY.refundAmountThreshold,
    authorization: kb.authorization === 1,
  };
}

function circuitInput(kb, evidence, tree, overrides = {}) {
  const claims = { ...publicClaims(kb), ...(overrides.claims || {}) };
  return {
    root: overrides.root || tree.root,
    orderId: kb.orderId,
    claimPaymentStatus: claims.paymentStatus === "PAID" ? 1 : 0,
    claimRefundStatus: claims.refundStatus === "NOT_REFUNDED" ? 0 : 1,
    claimRefundAmountPredicate: claims.refundAmountLE1000 ? 1 : 0,
    claimAuthorization: claims.authorization ? 1 : 0,
    refundAmountThreshold: POLICY.refundAmountThreshold,
    evidence: overrides.evidence || evidence,
    pathElements: tree.paths.map(p => p.pathElements),
    pathIndices: tree.paths.map(p => p.pathIndices),
  };
}

async function prepare(kb = loadPrivateKb()) {
  const evidence = evidenceFromKb(kb);
  const tree = await buildMerkle(evidence);
  return { kb, evidence, tree, claims: publicClaims(kb) };
}

async function prove(prepared, overrides = {}) {
  const input = circuitInput(prepared.kb, prepared.evidence, prepared.tree, overrides);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  // Only this deliberately minimal transport object crosses the A -> B boundary.
  return {
    orderId: prepared.kb.orderId,
    claims: { ...prepared.claims, ...(overrides.claims || {}) },
    merkleRoot: prepared.tree.root,
    proof,
    publicSignals,
  };
}

module.exports = { loadPrivateKb, publicClaims, circuitInput, prepare, prove };
