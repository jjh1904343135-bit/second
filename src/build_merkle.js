"use strict";

const { buildPoseidon } = require("circomlibjs");

const ATTR = Object.freeze({ PAYMENT_STATUS: 1, REFUND_STATUS: 2, REFUND_AMOUNT: 3, AUTHORIZATION: 4 });
const SOURCE = Object.freeze({ FINANCE: 1, USER_AUTH: 2 });

async function poseidonContext() {
  const poseidon = await buildPoseidon();
  const asString = value => poseidon.F.toString(value);
  return { poseidon, asString };
}

function evidenceFromKb(kb) {
  return [
    [kb.orderId, ATTR.PAYMENT_STATUS, kb.paymentStatus, SOURCE.FINANCE],
    [kb.orderId, ATTR.REFUND_STATUS, kb.refundStatus, SOURCE.FINANCE],
    [kb.orderId, ATTR.REFUND_AMOUNT, kb.refundAmount, SOURCE.FINANCE],
    [kb.orderId, ATTR.AUTHORIZATION, kb.authorization, SOURCE.USER_AUTH],
  ];
}

async function buildMerkle(evidence) {
  if (evidence.length !== 4) throw new Error("This minimal demo requires exactly four evidence records");
  const { poseidon, asString } = await poseidonContext();
  const leaves = evidence.map(item => asString(poseidon(item)));
  const level1 = [
    asString(poseidon([leaves[0], leaves[1]])),
    asString(poseidon([leaves[2], leaves[3]])),
  ];
  const root = asString(poseidon(level1));
  const paths = [
    { pathElements: [leaves[1], level1[1]], pathIndices: [0, 0] },
    { pathElements: [leaves[0], level1[1]], pathIndices: [1, 0] },
    { pathElements: [leaves[3], level1[0]], pathIndices: [0, 1] },
    { pathElements: [leaves[2], level1[0]], pathIndices: [1, 1] },
  ];
  return { root, leaves, paths };
}

module.exports = { ATTR, SOURCE, evidenceFromKb, buildMerkle };
