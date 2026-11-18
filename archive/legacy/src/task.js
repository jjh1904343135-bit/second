"use strict";
const { check, digest } = require("./codec");
const PROFILE = "RCPEH_REAL_MIMC_3S4E8N_V2";
const TASK_FIELDS = [
  "protocol_version",
  "experiment_profile",
  "receiver_id",
  "nonce",
  "mode",
  "issued_at",
  "evaluation_time",
  "deadline",
  "audit_time",
  "max_confirmation_delay",
  "required_sources",
  "source_groups",
  "registry_id",
  "object_id",
  "evidence_type",
  "created_from",
  "created_until",
  "max_risk_score",
  "purpose_bit",
  "require_each_source_nonempty",
  "min_records",
  "min_issuers",
];
function validateTask(task) {
  check(
    task &&
      Object.keys(task).length === TASK_FIELDS.length &&
      TASK_FIELDS.every((key) => Object.hasOwn(task, key)),
    "TASK_SCHEMA",
  );
  check(
    task.protocol_version === 1 && task.experiment_profile === PROFILE,
    "TASK_PROFILE",
  );
  check(["CURRENT_STATE", "HISTORICAL_AUDIT"].includes(task.mode), "TASK_MODE");
  for (const key of [
    "issued_at",
    "evaluation_time",
    "deadline",
    "audit_time",
    "max_confirmation_delay",
    "receiver_id",
    "registry_id",
    "object_id",
    "evidence_type",
    "created_from",
    "created_until",
    "max_risk_score",
    "purpose_bit",
    "min_records",
    "min_issuers",
  ])
    check(Number.isSafeInteger(task[key]) && task[key] >= 0, "TASK_INTEGER");
  check(
    task.issued_at <= task.evaluation_time &&
      task.evaluation_time <= task.deadline &&
      task.created_from < task.created_until &&
      task.purpose_bit === 0 &&
      task.max_risk_score <= 10000,
    "TASK_RULES",
  );
  check(
    task.mode !== "HISTORICAL_AUDIT" || task.audit_time <= task.evaluation_time,
    "AUDIT_TIME",
  );
  check(
    typeof task.require_each_source_nonempty === "boolean" &&
      task.min_records > 0 &&
      task.min_issuers > 0 &&
      task.min_issuers <= 3 &&
      /^[0-9a-f]{64}$/.test(task.nonce),
    "TASK_POLICY",
  );
  check(
    Array.isArray(task.required_sources) &&
      task.required_sources.length > 0 &&
      task.required_sources.length <= 3 &&
      task.required_sources.every(
        (id, i) =>
          Number.isSafeInteger(id) &&
          id > 0 &&
          (!i || id > task.required_sources[i - 1]),
      ),
    "TASK_SOURCES",
  );
  check(
    Array.isArray(task.source_groups) &&
      task.source_groups.length === task.required_sources.length &&
      task.source_groups.every(
        (entry, i) =>
          Object.keys(entry).length === 2 &&
          entry.source_id === task.required_sources[i] &&
          Number.isSafeInteger(entry.group_id) &&
          entry.group_id > 0,
      ),
    "TASK_GROUPS",
  );
}
function defaultTask(seed, overrides = {}) {
  const task = {
    protocol_version: 1,
    experiment_profile: PROFILE,
    receiver_id: 9001,
    nonce: digest("NONCE", seed),
    mode: "CURRENT_STATE",
    issued_at: 60,
    evaluation_time: 60,
    deadline: 90,
    audit_time: 15,
    max_confirmation_delay: 10,
    required_sources: [1],
    source_groups: [{ source_id: 1, group_id: 11 }],
    registry_id: 8001,
    object_id: 7001,
    evidence_type: 1,
    created_from: 0,
    created_until: 20,
    max_risk_score: 5000,
    purpose_bit: 0,
    require_each_source_nonempty: true,
    min_records: 1,
    min_issuers: 1,
    ...overrides,
  };
  validateTask(task);
  return task;
}
module.exports = { PROFILE, validateTask, defaultTask };
