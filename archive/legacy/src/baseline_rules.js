"use strict";
const { check, clone, digest, recordCommit } = require("./codec");
const { recordKey } = require("./source");

function hitTime(entry, task) {
  return (
    BigInt(entry.created_at) >= BigInt(task.created_from) &&
    BigInt(entry.created_at) < BigInt(task.created_until)
  );
}
function queryWitness(state, task) {
  let start = state.timeEntries.findIndex(
    (entry) => BigInt(entry.created_at) >= BigInt(task.created_from),
  );
  if (start < 0) start = state.timeEntries.length;
  let end = start;
  while (
    end < state.timeEntries.length &&
    BigInt(state.timeEntries[end].created_at) < BigInt(task.created_until)
  )
    end++;
  const entryAt = (index) =>
    index < 0 || index >= state.timeEntries.length
      ? null
      : {
          entry: clone(state.timeEntries[index]),
          opening: state.timeTree.opening(index),
        };
  return {
    left: entryAt(start - 1),
    entries: Array.from({ length: end - start }, (_, i) => entryAt(start + i)),
    right: entryAt(end),
  };
}

// Gamma_Q reference relation for the EXP1 time-index extension. NOT an actual circuit.
function Gamma_Q(state, task, witness) {
  check(witness && Array.isArray(witness.entries), "QUERY_WITNESS_MISSING");
  const verifyEntry = (item) => {
    check(
      item &&
        item.opening.leaf === digest("TIME_LEAF", item.entry) &&
        state.timeTree.verify(item.opening, state.statement.time_root),
      "TIME_MEMBERSHIP",
    );
    const index = Number(item.opening.index);
    check(
      index < state.statement.time_count &&
        item.entry.source_id === state.statement.source_id,
      "TIME_INDEX_RANGE",
    );
    return index;
  };
  let left = -1,
    right = state.statement.time_count;
  if (witness.left) {
    left = verifyEntry(witness.left);
    check(
      BigInt(witness.left.entry.created_at) < BigInt(task.created_from),
      "TIME_LEFT_BOUNDARY",
    );
  }
  if (witness.right) {
    right = verifyEntry(witness.right);
    check(
      BigInt(witness.right.entry.created_at) >= BigInt(task.created_until),
      "TIME_RIGHT_BOUNDARY",
    );
  }
  let previous = left;
  const result = [];
  for (const item of witness.entries) {
    const index = verifyEntry(item);
    check(index === previous + 1, "TIME_INTERIOR_ADJACENCY");
    check(hitTime(item.entry, task), "TIME_QUERY_RANGE");
    previous = index;
    if (
      item.entry.object_id === task.object_id &&
      item.entry.evidence_type === task.evidence_type
    ) {
      const current = state.current.get(item.entry.record_id);
      if (task.mode === "HISTORICAL_AUDIT") {
        const versions = [...state.versions.values()]
          .filter(
            (v) =>
              v.record.record_id === current.record_id &&
              BigInt(v.record.updated_at) <= BigInt(task.audit_time),
          )
          .sort((a, b) => b.record.version - a.record.version);
        if (versions.length) result.push(clone(versions[0].record));
      } else result.push(clone(current));
    }
  }
  check(previous + 1 === right, "TIME_RIGHT_ADJACENCY");
  check(
    witness.left !== null ||
      (witness.entries.length
        ? Number(witness.entries[0].opening.index) === 0
        : right === 0),
    "TIME_LEFT_SENTINEL",
  );
  check(
    witness.right !== null || previous + 1 === state.statement.time_count,
    "TIME_RIGHT_SENTINEL",
  );
  return result;
}

function windowValid(record, task) {
  const start = BigInt(
    task.mode === "HISTORICAL_AUDIT" ? task.audit_time : task.evaluation_time,
  );
  const end = BigInt(
    task.mode === "HISTORICAL_AUDIT" ? task.audit_time : task.deadline,
  );
  return (
    record.lifecycle === 1 &&
    BigInt(record.valid_from) <= start &&
    start <= end &&
    end < BigInt(record.valid_until) &&
    (BigInt(record.business.purpose_mask) &
      (1n << BigInt(task.purpose_bit))) !==
      0n
  );
}

// Gamma_P computes a decision (valid DENY is distinct from a bad proof).
function Gamma_P(Q, L, task, states) {
  const coverage =
    !task.require_each_source_nonempty ||
    task.required_sources.every((id) =>
      Q.some((record) => record.source_id === id),
    );
  const recordsOK = Q.every(
    (record) =>
      record.business.assessment === 1 &&
      record.business.risk_score <= task.max_risk_score &&
      windowValid(record, task),
  );
  let supportOK = true;
  const qualified = [];
  for (const root of L) {
    const current = Q.find(
      (record) =>
        recordKey(record) === recordKey(root) &&
        recordCommit(record) === recordCommit(root),
    );
    let allowed = Boolean(current) && windowValid(root, task);
    if (task.mode === "CURRENT_STATE") {
      const state = states.find(
        (item) => item.statement.source_id === root.source_id,
      );
      const life = state.lifeEntries.find(
        (item) => item.record_id === root.record_id,
      );
      allowed =
        allowed &&
        life?.record_commit === recordCommit(root) &&
        life.lifecycle === 1;
    }
    if (!allowed) supportOK = false;
    else qualified.push(root);
  }
  const recordCount = new Set(
    qualified.map((root) => `${root.source_id}:${root.record_id}`),
  ).size;
  const issuerCount = new Set(
    qualified.map(
      (root) =>
        task.source_groups.find((item) => item.source_id === root.source_id)
          ?.group_id,
    ),
  ).size;
  const enough =
    recordCount >= task.min_records && issuerCount >= task.min_issuers;
  const p = coverage && recordsOK,
    s = supportOK && enough;
  return {
    decision: Number(p && s),
    reason_code: !p ? 1 : !s ? 2 : 0,
    coverage,
    recordsOK,
    supportOK,
    recordCount,
    issuerCount,
  };
}
module.exports = { hitTime, queryWitness, Gamma_Q, Gamma_P, windowValid };
