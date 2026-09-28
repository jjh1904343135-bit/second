"use strict";

const POLICY = Object.freeze({
  paymentStatus: 1,
  refundStatus: 0,
  refundAmountThreshold: 1000,
  authorization: 1,
});

function evaluatePolicy(claims) {
  return claims.paymentStatus === "PAID" &&
    claims.refundStatus === "NOT_REFUNDED" &&
    claims.refundAmountLE1000 === true &&
    claims.authorization === true;
}

module.exports = { POLICY, evaluatePolicy };
