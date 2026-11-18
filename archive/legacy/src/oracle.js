"use strict";

// Test harness only: independent raw-array model, not a proof input or receiver dependency.
// Deliberately does not call Gamma_Q, Gamma_P, Lambda, replay or the proof backend.
function groundTruth(task, sourceLogs, registryNodes, supportNodeSeqs) {
  const Q = [];
  const historicalRecords = new Map();
  for (const { source_id, events } of sourceLogs) {
    const selected = new Map();
    for (const event of events) {
      const r = event.new_record;
      historicalRecords.set(`${source_id}:${r.record_id}:${r.version}`, r);
      if (
        task.mode === "HISTORICAL_AUDIT" &&
        Number(r.updated_at) > task.audit_time
      )
        continue;
      const key = `${source_id}:${r.record_id}`;
      if (!selected.has(key) || selected.get(key).version < r.version)
        selected.set(key, r);
    }
    for (const r of selected.values()) {
      if (
        r.object_id === task.object_id &&
        r.evidence_type === task.evidence_type &&
        Number(r.created_at) >= task.created_from &&
        Number(r.created_at) < task.created_until
      )
        Q.push(r);
    }
  }
  const rootKeys = new Set();
  function visit(seq) {
    const node = registryNodes.find((n) => n.registry_seq === seq);
    if (!node) throw new Error("ORACLE_UNKNOWN_NODE");
    if (node.node_kind === 1)
      rootKeys.add(
        `${node.root_ref.source_id}:${node.root_ref.record_id}:${node.root_ref.version}`,
      );
    else for (const parent of node.parent_seqs) visit(parent);
  }
  for (const seq of supportNodeSeqs) visit(seq);
  const L = [...rootKeys].sort().map((key) => historicalRecords.get(key));
  const from =
    task.mode === "HISTORICAL_AUDIT" ? task.audit_time : task.evaluation_time;
  const until =
    task.mode === "HISTORICAL_AUDIT" ? task.audit_time : task.deadline;
  const inWindow = (r) =>
    r.lifecycle === 1 &&
    Number(r.valid_from) <= from &&
    until < Number(r.valid_until) &&
    Math.floor(r.business.purpose_mask / 2 ** task.purpose_bit) % 2 === 1;
  const coverage =
    !task.require_each_source_nonempty ||
    task.required_sources.every((id) => Q.some((r) => r.source_id === id));
  const recordsOK = Q.every(
    (r) =>
      r.business.assessment === 1 &&
      r.business.risk_score <= task.max_risk_score &&
      inWindow(r),
  );
  const qualified = L.filter(
    (root) =>
      Q.some(
        (q) =>
          q.source_id === root.source_id &&
          q.record_id === root.record_id &&
          q.version === root.version,
      ) && inWindow(root),
  );
  const supportOK = qualified.length === L.length;
  const recordCount = new Set(
    qualified.map((r) => `${r.source_id}/${r.record_id}`),
  ).size;
  const issuerCount = new Set(
    qualified.map(
      (r) =>
        task.source_groups.find((g) => g.source_id === r.source_id).group_id,
    ),
  ).size;
  const p = coverage && recordsOK;
  const s =
    supportOK &&
    recordCount >= task.min_records &&
    issuerCount >= task.min_issuers;
  return {
    Q,
    L,
    policy: {
      decision: Number(p && s),
      reason_code: !p ? 1 : !s ? 2 : 0,
      coverage,
      recordsOK,
      supportOK,
      recordCount,
      issuerCount,
    },
  };
}

module.exports = { groundTruth };
