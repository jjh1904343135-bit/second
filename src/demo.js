"use strict";

const { prepare, prove } = require("./agent_a");
const { decide, renderResult } = require("./agent_b");
const { evidenceFromKb, buildMerkle } = require("./build_merkle");

async function mustFail(label, operation) {
  try {
    const value = await operation();
    if (value === false) {
      console.log(`${label}: BLOCKED`);
      return;
    }
    throw new Error("attack unexpectedly succeeded");
  } catch (error) {
    if (error.message === "attack unexpectedly succeeded") throw error;
    console.log(`${label}: BLOCKED`);
  }
}

async function main() {
  console.log("========== USER ==========\nRequest:\nRefund order #123\n");
  console.log("========== AGENT B POLICY ==========\npaymentStatus == PAID\nrefundStatus == NOT_REFUNDED\nrefundAmount <= 1000\nauthorization == TRUE\n");

  const prepared = await prepare();
  console.log("========== AGENT A ==========\nPrivate KB loaded\nPrivate evidence retrieved\nPrivate fields remain hidden\n");
  console.log(`Merkle Root:\n0x${BigInt(prepared.tree.root).toString(16)}\n`);
  console.log("Claim Bundle:\npaymentStatus = PAID\nrefundStatus = NOT_REFUNDED\nrefundAmount <= 1000 = TRUE\nauthorization = TRUE\n");
  console.log("Generating ZK proof...");
  const message = await prove(prepared);
  console.log("Proof generated.\n");

  console.log("========== AGENT B ==========\nReceiving Claim Bundle + Proof\n");
  const result = await decide(message);
  console.log(`ZK Verification:\n${result.proofValid ? "PASS" : "FAIL"}\n`);
  console.log(`Policy Evaluation:\n${result.policyPassed ? "PASS" : "FAIL"}\n`);
  console.log(`Refund Decision:\n${result.refundApproved ? "APPROVED" : "REJECTED"}\n`);
  if (!result.refundApproved) throw new Error("normal refund flow failed");
  console.log(renderResult(message.orderId));

  const serialized = JSON.stringify(message);
  const forbidden = ["Alice", "7281", "\"refundAmount\":500", "internalRiskScore", "customerId", "pathElements", "evidence"];
  if (forbidden.some(value => serialized.includes(value))) throw new Error("privacy boundary leaked private data");
  console.log("\n========== PRIVACY CHECK ==========\ncustomerName: NOT DISCLOSED\ncardLast4: NOT DISCLOSED\nexact refundAmount: NOT DISCLOSED\ninternalRiskScore: NOT DISCLOSED\n");

  console.log("========== ATTACK TESTS ==========");
  await mustFail("Fake Claim Attack", () => prove(prepared, { claims: { paymentStatus: "UNPAID" } }));

  const highKb = { ...prepared.kb, refundAmount: 1500 };
  const highEvidence = evidenceFromKb(highKb);
  const highPrepared = { kb: highKb, evidence: highEvidence, tree: await buildMerkle(highEvidence), claims: { ...prepared.claims, refundAmountLE1000: true } };
  await mustFail("Threshold Violation", () => prove(highPrepared));

  const fakeEvidence = prepared.evidence.map(row => [...row]);
  fakeEvidence[0][2] = 0;
  await mustFail("Fake Evidence Attack", () => prove(prepared, { evidence: fakeEvidence }));
}

main().then(
  () => process.exit(0),
  error => {
    console.error("Demo failed:", error.message);
    process.exit(1);
  },
);
