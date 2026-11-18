"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { buildMimcSponge } = require("circomlibjs");
const snarkjs = require("snarkjs");
const { check, clone, digest, handoffCommit } = require("./codec");
const { keyPair, sign, verify } = require("./source");

const { PROFILE, validateTask } = require("./task");
const BUILD = path.resolve(__dirname, "../build");
const WASM = path.join(BUILD, "real_experiment1_js/real_experiment1.wasm");
const ZKEY = path.join(BUILD, "task_final.zkey");
const VK = path.join(BUILD, "verification_key.json");
const hashFile = (file) =>
  crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const words = (hex) => {
  check(/^[0-9a-f]{64}$/.test(hex), "HEX_WORDS");
  return Array.from({ length: 8 }, (_, i) =>
    Number.parseInt(hex.slice(i * 8, i * 8 + 8), 16),
  );
};

async function hasher() {
  const mimc = await buildMimcSponge();
  return (kind, input) => {
    check(
      input.every((v) => Number.isSafeInteger(v) && v >= 0 && v < 2 ** 32),
      "WORD_RANGE",
    );
    return mimc
      .multiHash([1380141125, kind, input.length, ...input], 0, 2)
      .map((value) => mimc.F.toString(value));
  };
}

function eventWords(event) {
  const r = event.new_record;
  return [
    event.op,
    r.record_id,
    r.version,
    Number(r.created_at),
    Number(r.updated_at),
    Number(r.valid_from),
    Number(r.valid_until),
    r.lifecycle,
    r.business.assessment,
    r.business.risk_score,
    r.business.purpose_mask,
    r.object_id,
    r.evidence_type,
    r.slot_index,
    ...words(r.record_salt),
  ];
}
function publicSignals(input) {
  return [
    ...input.logRoot.flat(),
    ...input.timeRoot.flat(),
    ...input.lifeRoot.flat(),
    ...input.registryRoot,
    ...input.nonce,
    ...input.handoffCommit,
    input.mode,
    input.evaluationTime,
    input.auditTime,
    input.deadline,
    input.createdFrom,
    input.createdUntil,
    input.maxRisk,
    input.minRecords,
    input.minIssuers,
    ...input.groups,
    input.objectId,
    input.evidenceType,
    ...input.requiredSources,
    input.requireEach,
    input.decision,
    input.reason,
  ].map(String);
}
function publicInputFromMessage(task, message) {
  const records = [...message.checkpoints].sort(
    (a, b) => a.source_id - b.source_id,
  );
  check(
    records.length === 3 && records.every((cp, i) => cp.source_id === i + 1),
    "SOURCE_COVERAGE",
  );
  return {
    logRoot: records.map((cp) => cp.log_root),
    timeRoot: records.map((cp) => cp.time_root),
    lifeRoot: records.map((cp) => cp.life_root),
    registryRoot: message.registry_checkpoint.registry_root,
    nonce: words(task.nonce),
    handoffCommit: words(message.handoff.content_commit),
    mode: task.mode === "HISTORICAL_AUDIT" ? 1 : 0,
    evaluationTime: task.evaluation_time,
    auditTime: task.audit_time,
    deadline: task.deadline,
    createdFrom: task.created_from,
    createdUntil: task.created_until,
    maxRisk: task.max_risk_score,
    minRecords: task.min_records,
    minIssuers: task.min_issuers,
    groups: [1, 2, 3].map(
      (id) =>
        task.source_groups.find((g) => g.source_id === id)?.group_id || id * 11,
    ),
    objectId: task.object_id,
    evidenceType: task.evidence_type,
    requiredSources: [1, 2, 3].map((id) =>
      Number(task.required_sources.includes(id)),
    ),
    requireEach: Number(task.require_each_source_nonempty),
    decision: message.handoff.payload.decision,
    reason: message.handoff.payload.reason_code,
  };
}

// These source/R signing capabilities are held by the experiment's isolated source/R roles.
// They are never delivered to A/B/C with their proof messages.
async function prepareRealFixture(fixture, claimedDecision) {
  const hash = await hasher();
  const sourceKeys = [1, 2, 3].map((id) =>
    keyPair(`${fixture.seed}/real-source/${id}`),
  );
  const registryKeys = keyPair(`${fixture.seed}/real-registry`);
  const task = clone(fixture.task);
  validateTask(task);
  const events = [1, 2, 3].map((id) => {
    const sourceEvents = fixture.sources[id - 1].authorizedEvents();
    check(sourceEvents.length <= 4, "CAPACITY_UNAVAILABLE");
    return Array.from({ length: 4 }, (_, t) =>
      sourceEvents[t] ? eventWords(sourceEvents[t]) : Array(22).fill(0),
    );
  });
  const eventCount = [1, 2, 3].map(
    (id) => fixture.sources[id - 1].authorizedEvents().length,
  );
  const logRoot = events.map((sourceEvents, s) =>
    hash(1, [s + 1, eventCount[s], ...sourceEvents.flat()]),
  );
  const maps = [1, 2, 3].map((id) => {
    const map = new Map();
    for (const event of fixture.sources[id - 1].authorizedEvents())
      map.set(event.record_id, event.new_record);
    return map;
  });
  const sortedMaps = maps.map((map) =>
    [...map.values()].sort(
      (a, b) =>
        Number(a.created_at) - Number(b.created_at) ||
        a.record_id - b.record_id,
    ),
  );
  const timeRoot = sortedMaps.map((sorted, s) => {
    const row = [s + 1, sorted.length];
    for (let p = 0; p < 4; p++) {
      const r = sorted[p];
      row.push(
        r ? r.record_id : 0,
        r ? Number(r.created_at) : 0,
        Number(Boolean(r)),
      );
    }
    return hash(3, row);
  });
  const lifeRoot = maps.map((map, s) => {
    const row = [s + 1, map.size];
    for (let id = 1; id <= 4; id++) {
      const r = map.get(id);
      row.push(
        r ? r.version : 0,
        r ? r.lifecycle : 0,
        r ? Number(r.updated_at) : 0,
        r ? Number(r.valid_from) : 0,
        r ? Number(r.valid_until) : 0,
      );
    }
    return hash(4, row);
  });
  const payload = clone(fixture.payload);
  payload.task_digest = digest("TASK", task);
  if (claimedDecision !== undefined) {
    payload.decision = claimedDecision;
    payload.reason_code = claimedDecision ? 0 : payload.reason_code;
  }
  const handoff = handoffCommit(payload);
  const graph = clone(fixture.witness.graph);
  check(graph.length <= 8, "CAPACITY_UNAVAILABLE");
  // R authenticates A's submitted candidate output, not an oracle-approved decision.
  graph.at(-1).node.content_commit = handoff.commit;
  const remap = new Map(
    graph.map((item, i) => [item.node.registry_seq, i + 1]),
  );
  const nodes = Array.from({ length: 8 }, (_, i) => {
    if (!graph[i]) return Array(26).fill(0);
    const n = graph[i].node;
    const parent = [...n.parent_seqs.map((seq) => remap.get(seq))];
    check(parent.every(Number.isInteger), "MISSING_ANCESTOR");
    while (parent.length < 4) parent.push(0);
    return [
      1,
      n.node_kind,
      n.operation_type,
      n.root_ref.source_id,
      n.root_ref.record_id,
      n.root_ref.version,
      ...parent,
      ...words(n.content_commit),
      ...words(n.parents_salt),
    ];
  });
  const nonce = words(task.nonce);
  const commitment = words(handoff.commit);
  const registryRoot = hash(2, [...nodes.flat(), ...nonce, ...commitment]);
  const timeOrder = [];
  const returned = [];
  const leftBoundary = [];
  const rightBoundary = [];
  for (let s = 0; s < 3; s++) {
    const sorted = sortedMaps[s];
    const ids = sorted.map((r) => r.record_id);
    const bits = sorted.map((r) =>
      Number(
        Number(r.created_at) >= task.created_from &&
          Number(r.created_at) < task.created_until,
      ),
    );
    if (fixture.type === "P1_OMISSION" && !fixture.control) {
      const index = ids.indexOf(3);
      if (index >= 0) bits[index] = 0;
    }
    leftBoundary.push(
      sorted.filter((r) => Number(r.created_at) < task.created_from).length,
    );
    rightBoundary.push(
      sorted.filter((r) => Number(r.created_at) < task.created_until).length +
        1,
    );
    while (ids.length < 4) {
      ids.push(0);
      bits.push(0);
    }
    timeOrder.push(ids);
    returned.push(bits);
  }
  const input = {
    logRoot,
    timeRoot,
    lifeRoot,
    registryRoot,
    nonce,
    handoffCommit: commitment,
    mode: task.mode === "HISTORICAL_AUDIT" ? 1 : 0,
    evaluationTime: task.evaluation_time,
    auditTime: task.audit_time,
    deadline: task.deadline,
    createdFrom: task.created_from,
    createdUntil: task.created_until,
    maxRisk: task.max_risk_score,
    minRecords: task.min_records,
    minIssuers: task.min_issuers,
    groups: [1, 2, 3].map(
      (id) =>
        task.source_groups.find((g) => g.source_id === id)?.group_id || id * 11,
    ),
    objectId: task.object_id,
    evidenceType: task.evidence_type,
    requiredSources: [1, 2, 3].map((id) =>
      Number(task.required_sources.includes(id)),
    ),
    requireEach: Number(task.require_each_source_nonempty),
    decision: payload.decision,
    reason: payload.reason_code,
    events,
    eventCount,
    timeOrder,
    leftBoundary,
    rightBoundary,
    returned,
    nodes,
  };
  const checkpoints = logRoot.map((root, s) => {
    const body = {
      profile: PROFILE,
      source_id: s + 1,
      log_length: eventCount[s],
      log_root: root,
      time_root: timeRoot[s],
      life_root: lifeRoot[s],
      task_digest: digest("TASK", task),
      receiver_id: task.receiver_id,
      nonce: task.nonce,
    };
    return {
      ...body,
      signature: sign(sourceKeys[s].privateKey, digest("REAL_CP", body)),
    };
  });
  const rcp = {
    profile: PROFILE,
    registry_root: registryRoot,
    task_digest: digest("TASK", task),
    receiver_id: task.receiver_id,
    nonce: task.nonce,
    handoff_content_commit: handoff.commit,
  };
  const registry_checkpoint = {
    ...rcp,
    signature: sign(registryKeys.privateKey, digest("REAL_RCP", rcp)),
  };
  const receiverConfig = {
    profile: PROFILE,
    source_public_keys: sourceKeys.map((k) =>
      k.publicKey.export({ type: "spki", format: "pem" }),
    ),
    registry_public_key: registryKeys.publicKey.export({
      type: "spki",
      format: "pem",
    }),
    verification_key_sha256: fs.existsSync(VK) ? hashFile(VK) : null,
  };
  const message = {
    profile: PROFILE,
    task,
    checkpoints,
    registry_checkpoint,
    handoff: {
      payload,
      content_commit: handoff.commit,
      content_salt: handoff.salt,
    },
  };
  return { input, message, receiverConfig, hash };
}

async function generateProof(input) {
  check(fs.existsSync(ZKEY), "REAL_PROVING_KEY_UNAVAILABLE");
  const result = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  check(
    JSON.stringify(result.publicSignals) ===
      JSON.stringify(publicSignals(input)),
    "PUBLIC_LAYOUT_MISMATCH",
  );
  return result;
}

async function inspectPrivateCounters(input, file) {
  await snarkjs.wtns.calculate(input, WASM, file);
  const symbols = fs
    .readFileSync(path.join(BUILD, "real_experiment1.sym"), "utf8")
    .split("\n");
  const indices = {};
  for (const name of ["recordCount", "issuerCount"]) {
    const row = symbols.find((line) => line.endsWith(`,main.${name}`));
    check(row, "COUNTER_SYMBOL_MISSING");
    indices[name] = Number(row.split(",")[1]);
    check(indices[name] >= 0, "COUNTER_OPTIMIZED_OUT");
  }
  const fd = fs.openSync(file, "r");
  try {
    const head = Buffer.alloc(12);
    fs.readSync(fd, head, 0, 12, 0);
    check(head.toString("ascii", 0, 4) === "wtns", "WTNS_FORMAT");
    let offset = 12,
      dataStart,
      n8;
    for (let i = 0; i < head.readUInt32LE(8); i++) {
      const section = Buffer.alloc(12);
      fs.readSync(fd, section, 0, 12, offset);
      const id = section.readUInt32LE(0),
        size = Number(section.readBigUInt64LE(4));
      offset += 12;
      if (id === 1) {
        const field = Buffer.alloc(4);
        fs.readSync(fd, field, 0, 4, offset);
        n8 = field.readUInt32LE(0);
      }
      if (id === 2) dataStart = offset;
      offset += size;
    }
    check(n8 && dataStart, "WTNS_SECTIONS");
    const output = {};
    for (const [name, index] of Object.entries(indices)) {
      const bytes = Buffer.alloc(n8);
      fs.readSync(fd, bytes, 0, n8, dataStart + index * n8);
      output[name] = BigInt(
        `0x${Buffer.from(bytes).reverse().toString("hex")}`,
      ).toString();
    }
    return output;
  } finally {
    fs.closeSync(fd);
  }
}

async function verifyRealMessage(task, message, config) {
  try {
    validateTask(task);
    check(config.profile === PROFILE && message.profile === PROFILE, "PROFILE");
    check(
      config.verification_key_sha256 === hashFile(VK),
      "VERIFICATION_KEY_BINDING",
    );
    check(
      digest("TASK", task) === digest("TASK", message.task),
      "TASK_BINDING",
    );
    for (const cp of message.checkpoints) {
      const { signature, ...body } = cp;
      check(
        cp.source_id >= 1 &&
          cp.source_id <= 3 &&
          verify(
            config.source_public_keys[cp.source_id - 1],
            digest("REAL_CP", body),
            signature,
          ),
        "SOURCE_SIGNATURE",
      );
      check(
        cp.task_digest === digest("TASK", task) &&
          cp.receiver_id === task.receiver_id &&
          cp.nonce === task.nonce &&
          cp.profile === PROFILE,
        "CP_BINDING",
      );
    }
    const { signature, ...rcp } = message.registry_checkpoint;
    check(
      verify(config.registry_public_key, digest("REAL_RCP", rcp), signature),
      "REGISTRY_SIGNATURE",
    );
    check(
      rcp.task_digest === digest("TASK", task) &&
        rcp.nonce === task.nonce &&
        rcp.receiver_id === task.receiver_id,
      "RCP_BINDING",
    );
    const handoff = handoffCommit(message.handoff.payload);
    check(
      message.handoff.payload.task_digest === digest("TASK", task) &&
        message.handoff.payload.receiver_id === task.receiver_id &&
        message.handoff.payload.object_id === task.object_id &&
        message.handoff.payload.deadline === String(task.deadline),
      "PAYLOAD_TASK_BINDING",
    );
    check(
      handoff.commit === message.handoff.content_commit &&
        handoff.salt === message.handoff.content_salt &&
        rcp.handoff_content_commit === handoff.commit,
      "HANDOFF_BINDING",
    );
    const expected = publicSignals(publicInputFromMessage(task, message));
    check(
      JSON.stringify(expected) === JSON.stringify(message.publicSignals),
      "PUBLIC_INPUT_BINDING",
    );
    const vkey = JSON.parse(fs.readFileSync(VK));
    const valid = await snarkjs.groth16.verify(vkey, expected, message.proof);
    check(valid, "GROTH16_VERIFY");
    return {
      status: message.handoff.payload.decision ? "ALLOW" : "DENY",
      reason_code: message.handoff.payload.reason_code,
      proof_verified: true,
      action_authorized: message.handoff.payload.decision === 1,
    };
  } catch (error) {
    return {
      status: "INVALID_PROOF",
      stage: error.code || error.message,
      proof_verified: false,
      action_authorized: false,
    };
  }
}
module.exports = {
  PROFILE,
  BUILD,
  WASM,
  ZKEY,
  VK,
  words,
  hasher,
  eventWords,
  publicSignals,
  prepareRealFixture,
  generateProof,
  verifyRealMessage,
  inspectPrivateCounters,
  hashFile,
};
