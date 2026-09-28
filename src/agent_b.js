"use strict";

const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { POLICY, evaluatePolicy } = require("./policy");

const VK = path.resolve(__dirname, "../build/verification_key.json");

function expectedPublicSignals(message) {
  return [
    message.merkleRoot,
    String(message.orderId),
    String(message.claims.paymentStatus === "PAID" ? 1 : 0),
    String(message.claims.refundStatus === "NOT_REFUNDED" ? 0 : 1),
    String(message.claims.refundAmountLE1000 ? 1 : 0),
    String(message.claims.authorization ? 1 : 0),
    String(POLICY.refundAmountThreshold),
  ];
}

async function verify(message) {
  // Prevent a valid proof being paired with a modified JSON Claim Bundle.
  if (JSON.stringify(message.publicSignals) !== JSON.stringify(expectedPublicSignals(message))) return false;
  const vkey = JSON.parse(fs.readFileSync(VK, "utf8"));
  return snarkjs.groth16.verify(vkey, message.publicSignals, message.proof);
}

async function decide(message) {
  const proofValid = await verify(message);
  const policyPassed = proofValid && evaluatePolicy(message.claims);
  return { proofValid, policyPassed, refundApproved: policyPassed };
}

function renderResult(orderId) {
  return `订单${orderId}已完成支付，当前尚未退款，\n退款金额满足1000元以内的限制，\n且存在有效退款授权。\n\nZK证据验证通过，退款条件满足。`;
}

module.exports = { expectedPublicSignals, verify, decide, renderResult };
