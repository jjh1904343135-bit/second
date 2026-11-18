"use strict";
const crypto = require("crypto");
const {
  check,
  clone,
  ZERO,
  encode,
  H,
  integer,
  recordCommit,
  digest,
} = require("./codec");
const { SparseMerkle } = require("./merkle");

function keyPair(seed) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      crypto.createHash("sha256").update(seed).digest(),
    ]),
    format: "der",
    type: "pkcs8",
  });
  return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}
function sign(key, hash) {
  return crypto.sign(null, Buffer.from(hash, "hex"), key).toString("hex");
}
function verify(key, hash, signature) {
  try {
    return crypto.verify(
      null,
      Buffer.from(hash, "hex"),
      key,
      Buffer.from(signature, "hex"),
    );
  } catch {
    return false;
  }
}
function logLeaf(event) {
  return H(
    "LOG_LEAF",
    Buffer.concat([
      integer(event.seq, 4),
      Buffer.from(H("EVENT", encode("event", event)), "hex"),
    ]),
  );
}
function recordKey(record) {
  return `${record.source_id}:${record.record_id}:${record.version}`;
}
function timeKey(record) {
  return [BigInt(record.created_at), record.record_id];
}
function compareTime(a, b) {
  const ak = timeKey(a),
    bk = timeKey(b);
  return ak[0] < bk[0] ? -1 : ak[0] > bk[0] ? 1 : ak[1] - bk[1];
}

function validateRecord(record) {
  encode("record", record);
  check(
    record.schema_version === 1 &&
      record.source_id > 0 &&
      record.record_id > 0 &&
      record.version > 0,
    "RECORD_IDENTITY",
  );
  check(
    record.slot_index < 4 &&
      [1, 2].includes(record.lifecycle) &&
      [1, 2, 3].includes(record.business.assessment) &&
      record.business.risk_score <= 10000,
    "RECORD_ENUM",
  );
  check(
    BigInt(record.created_at) <= BigInt(record.updated_at) &&
      BigInt(record.valid_from) < BigInt(record.valid_until),
    "RECORD_TIME",
  );
}

function replay(sourceId, events) {
  check(events.length <= 4, "CAPACITY_UNAVAILABLE");
  const current = new Map();
  const versions = new Map();
  const buckets = new Map();
  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    encode("event", event);
    validateRecord(event.new_record);
    const record = event.new_record;
    check(
      event.source_id === sourceId &&
        record.source_id === sourceId &&
        event.seq === i + 1 &&
        record.record_id === event.record_id,
      "EVENT_CONTINUITY",
    );
    const key = `${record.object_id}:${record.evidence_type}`;
    if (event.op === 1) {
      const count = buckets.get(key) || 0;
      check(
        !current.has(record.record_id) &&
          event.record_id === event.seq &&
          record.version === 1 &&
          event.prev_version === 0 &&
          event.prev_record_commit === ZERO &&
          record.lifecycle === 1 &&
          record.slot_index === count,
        "CREATE_RULES",
      );
      check(count < 4, "CAPACITY_UNAVAILABLE");
      buckets.set(key, count + 1);
    } else {
      const old = current.get(record.record_id);
      check(
        old && [2, 3].includes(event.op) && old.lifecycle === 1,
        "UPDATE_TARGET",
      );
      check(
        event.prev_version === old.version &&
          event.prev_record_commit === recordCommit(old) &&
          record.version === old.version + 1,
        "UPDATE_VERSION",
      );
      for (const field of [
        "source_id",
        "record_id",
        "object_id",
        "evidence_type",
        "created_at",
        "slot_index",
      ])
        check(record[field] === old[field], "IMMUTABLE_COORDINATE");
      check(
        BigInt(record.updated_at) >= BigInt(old.updated_at) &&
          record.lifecycle === (event.op === 3 ? 2 : 1),
        "UPDATE_LIFECYCLE",
      );
    }
    current.set(record.record_id, clone(record));
    versions.set(recordKey(record), {
      record: clone(record),
      event_seq: event.seq,
    });
  }
  const logTree = new SparseMerkle(
    "LOG",
    32,
    events.map((event) => [event.seq - 1, logLeaf(event)]),
  );
  const sorted = [...current.values()].sort(compareTime);
  const timeEntries = sorted.map((record) => ({
    source_id: sourceId,
    record_id: record.record_id,
    object_id: record.object_id,
    evidence_type: record.evidence_type,
    created_at: record.created_at,
  }));
  const timeTree = new SparseMerkle(
    "EXP1_TIME",
    32,
    timeEntries.map((entry, index) => [index, digest("TIME_LEAF", entry)]),
  );
  const lifeEntries = [...current.values()].map((record) => ({
    source_id: sourceId,
    record_id: record.record_id,
    version: record.version,
    lifecycle: record.lifecycle,
    record_commit: recordCommit(record),
  }));
  const state = {
    source_id: sourceId,
    log_length: events.length,
    log_root: logTree.root,
    time_root: timeTree.root,
    time_count: sorted.length,
  };
  return {
    current,
    versions,
    sorted,
    events: clone(events),
    timeEntries,
    lifeEntries,
    logTree,
    timeTree,
    statement: state,
  };
}

class Source {
  #keys;
  #events = [];
  constructor(id, seed) {
    this.id = id;
    this.#keys = keyPair(`${seed}/source/${id}`);
    this.publicKey = this.#keys.publicKey;
  }
  publish(event) {
    const trial = [...this.#events, clone(event)];
    replay(this.id, trial);
    this.#events = trial;
  }
  authorizedEvents() {
    return clone(this.#events);
  }
  baselineSignature(record) {
    check(
      this.#events.some(
        (event) => recordCommit(event.new_record) === recordCommit(record),
      ),
      "BASELINE_RECORD_NOT_PUBLISHED",
    );
    return sign(this.#keys.privateKey, recordCommit(record));
  }
  confirm(task) {
    const state = replay(this.id, this.#events);
    const body = {
      source_id: this.id,
      key_epoch: 1,
      log_length: state.statement.log_length,
      log_root: state.statement.log_root,
      confirmed_at: task.issued_at + this.id,
      task_digest: digest("TASK", task),
      receiver_id: task.receiver_id,
      nonce: task.nonce,
    };
    return {
      ...body,
      signature: sign(this.#keys.privateKey, digest("SOURCE_CP", body)),
    };
  }
}

function makeRecord({
  source = 1,
  id = 1,
  version = 1,
  created = 10,
  updated = created,
  slot = 0,
  assessment = 1,
  risk = 1200,
  lifecycle = 1,
  salt = "fixture",
}) {
  return {
    schema_version: 1,
    source_id: source,
    record_id: id,
    version,
    object_id: 7001,
    evidence_type: 1,
    slot_index: slot,
    created_at: String(created),
    updated_at: String(updated),
    valid_from: "0",
    valid_until: "1000000000",
    lifecycle,
    business: { assessment, risk_score: risk, purpose_mask: 1 },
    raw_digest: digest("RAW", [source, id, version, assessment, risk]),
    record_salt: digest("SALT", [salt, source, id, version]),
  };
}
function createEvent(record, seq) {
  return {
    schema_version: 1,
    source_id: record.source_id,
    seq,
    op: 1,
    record_id: record.record_id,
    prev_version: 0,
    prev_record_commit: ZERO,
    new_record: record,
  };
}
function updateEvent(old, record, seq, revoke = false) {
  return {
    schema_version: 1,
    source_id: record.source_id,
    seq,
    op: revoke ? 3 : 2,
    record_id: record.record_id,
    prev_version: old.version,
    prev_record_commit: recordCommit(old),
    new_record: record,
  };
}
module.exports = {
  keyPair,
  sign,
  verify,
  logLeaf,
  recordKey,
  compareTime,
  replay,
  Source,
  makeRecord,
  createEvent,
  updateEvent,
};
