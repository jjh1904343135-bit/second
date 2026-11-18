"use strict";
const { digest, recordCommit } = require("./codec");
const { verify, logLeaf } = require("./source");
const { Gamma_Q, Gamma_P, windowValid } = require("./baseline_rules");
const SCHEMES = [
  "B0_SIGNATURE_ONLY",
  "B1_MEMBERSHIP_ONLY",
  "B2_COMPLETE_QUERY_UNCHECKED_LINEAGE",
];
function withoutSignature({ signature, ...body }) {
  return body;
}
function signedBindingsValid(fixture) {
  return fixture.sourcePackages.every((pkg) =>
    verify(
      fixture.sources[pkg.checkpoint.source_id - 1].publicKey,
      digest("SOURCE_CP", withoutSignature(pkg.checkpoint)),
      pkg.checkpoint.signature,
    ),
  );
}

function runBaseline(scheme, fixture) {
  const { certifiedReferences: refs, task, states } = fixture;
  const signatures =
    signedBindingsValid(fixture) &&
    refs.every((ref) =>
      verify(
        fixture.sources[ref.record.source_id - 1].publicKey,
        recordCommit(ref.record),
        ref.signature,
      ),
    );
  if (!signatures)
    return {
      status: "INVALID_PROOF",
      stage: "SOURCE_SIGNATURE",
      action_authorized: false,
    };
  if (scheme !== "B0_SIGNATURE_ONLY") {
    const members = refs.every((ref) => {
      const state = states.find(
        (item) => item.statement.source_id === ref.record.source_id,
      );
      return (
        ref.opening.leaf === logLeaf(ref.event) &&
        state.logTree.verify(ref.opening, state.statement.log_root) &&
        recordCommit(ref.event.new_record) === recordCommit(ref.record)
      );
    });
    if (!members)
      return {
        status: "INVALID_PROOF",
        stage: "LOG_MEMBERSHIP",
        action_authorized: false,
      };
  }
  let recordsOK;
  let supportOK;
  if (scheme === "B2_COMPLETE_QUERY_UNCHECKED_LINEAGE") {
    let Q;
    try {
      Q = states.flatMap((state, i) =>
        Gamma_Q(state, task, fixture.witness.queries[i]),
      );
    } catch (error) {
      return {
        status: "INVALID_PROOF",
        action_authorized: false,
        stage: error.code || error.message,
      };
    }
    const honestLocal = Gamma_P(
      Q,
      refs.map((ref) => ref.record),
      { ...task, min_records: 1, min_issuers: 1 },
      states,
    );
    recordsOK = honestLocal.coverage && honestLocal.recordsOK;
    supportOK = honestLocal.supportOK;
  } else {
    recordsOK = refs.every(
      (ref) =>
        ref.record.business.assessment === 1 &&
        ref.record.business.risk_score <= task.max_risk_score &&
        windowValid(ref.record, task),
    );
    supportOK = refs.length > 0;
  }
  const claimedRecords =
    task.min_records > 1 ? fixture.selfReportedGroups.length : refs.length;
  const claimedIssuers = new Set(fixture.selfReportedGroups).size;
  const decision =
    recordsOK &&
    supportOK &&
    claimedRecords >= task.min_records &&
    claimedIssuers >= task.min_issuers;
  return {
    status: decision ? "ALLOW" : "DENY",
    action_authorized: Boolean(decision),
    stage: !recordsOK
      ? "POLICY"
      : !supportOK
        ? "LIFECYCLE"
        : !decision
          ? "SUPPORT_COUNT"
          : "ACCEPTED",
    record_count: claimedRecords,
    issuer_count: claimedIssuers,
  };
}

module.exports = { SCHEMES, runBaseline };
