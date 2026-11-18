"use strict";

// Enc_v1. JSON is transport only; commitments/signatures always consume these bytes.
const crypto = require("crypto");
const ZERO = "00".repeat(32);
const S = {};
S.business = [
  ["assessment", "u8"],
  ["risk_score", "u16"],
  ["purpose_mask", "u32"],
];
S.record = [
  ["schema_version", "u16"],
  ["source_id", "u32"],
  ["record_id", "u32"],
  ["version", "u32"],
  ["object_id", "u32"],
  ["evidence_type", "u16"],
  ["slot_index", "u8"],
  ["created_at", "u64"],
  ["updated_at", "u64"],
  ["valid_from", "u64"],
  ["valid_until", "u64"],
  ["lifecycle", "u8"],
  ["business", "business"],
  ["raw_digest", "bytes32"],
  ["record_salt", "bytes32"],
];
S.event = [
  ["schema_version", "u16"],
  ["source_id", "u32"],
  ["seq", "u32"],
  ["op", "u8"],
  ["record_id", "u32"],
  ["prev_version", "u32"],
  ["prev_record_commit", "bytes32"],
  ["new_record", "record"],
];
S.root_ref = [
  ["source_id", "u32"],
  ["record_id", "u32"],
  ["version", "u32"],
  ["event_seq", "u32"],
  ["record_commit", "bytes32"],
];
S.node = [
  ["schema_version", "u16"],
  ["registry_id", "u32"],
  ["registry_seq", "u32"],
  ["actor_id", "u32"],
  ["operation_id", "bytes32"],
  ["node_kind", "u8"],
  ["operation_type", "u8"],
  ["content_commit", "bytes32"],
  ["parent_count", "u8"],
  ["parents_commit", "bytes32"],
  ["root_ref", "root_ref"],
  ["registered_at", "u64"],
  ["parent_seqs", ["list", "u32"]],
  ["parents_salt", "bytes32"],
];
S.handoff = [
  ["schema_version", "u16"],
  ["task_digest", "bytes32"],
  ["receiver_id", "u32"],
  ["object_id", "u32"],
  ["decision", "u8"],
  ["reason_code", "u8"],
  ["deadline", "u64"],
];

function check(condition, code) {
  if (!condition) {
    const error = new Error(code);
    error.code = code;
    throw error;
  }
}
function integer(value, width) {
  if (width === 8)
    check(
      typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value),
      "U64_REQUIRES_DECIMAL_STRING",
    );
  else check(Number.isSafeInteger(value), "INVALID_INTEGER");
  const n = BigInt(value);
  check(n >= 0n && n < 1n << BigInt(width * 8), "INTEGER_OUT_OF_RANGE");
  const out = Buffer.alloc(width);
  let cursor = n;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(cursor & 255n);
    cursor >>= 8n;
  }
  return out;
}
function encodeType(type, value) {
  if (Array.isArray(type)) {
    check(Array.isArray(value), "INVALID_LIST");
    return Buffer.concat([
      integer(value.length, 4),
      ...value.map((v) => encodeType(type[1], v)),
    ]);
  }
  if (/^u(8|16|32|64)$/.test(type))
    return integer(value, Number(type.slice(1)) / 8);
  if (type === "bool") {
    check(value === true || value === false, "INVALID_BOOLEAN");
    return Buffer.from([Number(value)]);
  }
  if (/^bytes(32|64)$/.test(type)) {
    const width = Number(type.slice(5));
    check(
      typeof value === "string" &&
        new RegExp(`^[0-9a-f]{${width * 2}}$`).test(value),
      "INVALID_HEX",
    );
    return Buffer.from(value, "hex");
  }
  check(S[type], "UNKNOWN_SCHEMA");
  return encode(type, value);
}
function encode(name, value, omit = []) {
  check(
    value && typeof value === "object" && !Array.isArray(value),
    "INVALID_OBJECT",
  );
  const fields = S[name];
  check(
    fields &&
      Object.keys(value).length === fields.length &&
      fields.every(([key]) => Object.hasOwn(value, key)),
    `SCHEMA_FIELDS_${name}`,
  );
  // Validate omitted fields too, so unknown values cannot hide behind signature omission.
  const encoded = fields.map(([key, type]) => [
    key,
    encodeType(type, value[key]),
  ]);
  return Buffer.concat(
    encoded.filter(([key]) => !omit.includes(key)).map(([, bytes]) => bytes),
  );
}
function H(tag, bytes) {
  check(Buffer.isBuffer(bytes), "HASH_REQUIRES_BYTES");
  const domain = Buffer.from(`SEW1/${tag}`, "utf8");
  return crypto
    .createHash("sha256")
    .update(integer(domain.length, 4))
    .update(domain)
    .update(bytes)
    .digest("hex");
}
function recordCommit(record) {
  return H(
    "RECORD",
    Buffer.concat([
      encode("record", record, ["record_salt"]),
      Buffer.from(record.record_salt, "hex"),
    ]),
  );
}
function nodeCommit(node) {
  return H("REG_LEAF", encode("node", node, ["parent_seqs", "parents_salt"]));
}
function parentsCommit(registryId, parents, salt) {
  return H(
    "PARENTS",
    Buffer.concat([
      integer(registryId, 4),
      integer(parents.length, 1),
      encodeType(["list", "u32"], parents),
      encodeType("bytes32", salt),
    ]),
  );
}
function contentCommit(bytes, salt) {
  return H(
    "CONTENT",
    Buffer.concat([
      integer(bytes.length, 4),
      bytes,
      encodeType("bytes32", salt),
    ]),
  );
}
function handoffCommit(payload) {
  const salt = H("HANDOFF_SALT", encodeType("bytes32", payload.task_digest));
  return {
    salt,
    commit: H(
      "CONTENT",
      Buffer.concat([encode("handoff", payload), Buffer.from(salt, "hex")]),
    ),
  };
}

// Experimental schemas have explicit additional domains and are NOT profile_id=1 TaskSpec.
// Canonical binary encoding for task/checkpoint signatures; never hash JSON serialization.
function binary(value) {
  if (value === null) return Buffer.from([0]);
  if (typeof value === "boolean") return Buffer.from([1, Number(value)]);
  if (typeof value === "number") {
    check(Number.isSafeInteger(value) && value >= 0, "BINARY_NUMBER");
    return Buffer.concat([Buffer.from([2]), integer(String(value), 8)]);
  }
  if (typeof value === "string") {
    const bytes = Buffer.from(value);
    return Buffer.concat([Buffer.from([3]), integer(bytes.length, 4), bytes]);
  }
  if (Array.isArray(value))
    return Buffer.concat([
      Buffer.from([4]),
      integer(value.length, 4),
      ...value.map(binary),
    ]);
  check(value && typeof value === "object", "BINARY_TYPE");
  const keys = Object.keys(value).sort();
  return Buffer.concat([
    Buffer.from([5]),
    integer(keys.length, 4),
    ...keys.flatMap((key) => [binary(key), binary(value[key])]),
  ]);
}
function digest(tag, value) {
  return H(`EXP1/${tag}`, binary(value));
}
function clone(value) {
  return JSON.parse(JSON.stringify(value));
}
module.exports = {
  S,
  ZERO,
  check,
  integer,
  encodeType,
  encode,
  H,
  recordCommit,
  nodeCommit,
  parentsCommit,
  contentCommit,
  handoffCommit,
  binary,
  digest,
  clone,
};
