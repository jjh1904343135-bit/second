"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { encode, recordCommit, clone } = require("../src/codec");
const {
  makeRecord,
  createEvent,
  updateEvent,
  replay,
} = require("../src/source");
const { Registry } = require("../src/registry");
const { defaultTask } = require("../src/task");
const { makeFixture, TYPES } = require("../src/fixture");
const { runBaseline, SCHEMES } = require("../src/baselines");
const { prepareRealFixture, publicSignals } = require("../src/proof");

const sample = {
  schema_version: 1,
  source_id: 1,
  record_id: 1,
  version: 1,
  object_id: 7001,
  evidence_type: 1,
  slot_index: 0,
  created_at: "10",
  updated_at: "10",
  valid_from: "10",
  valid_until: "1000",
  lifecycle: 1,
  business: { assessment: 1, risk_score: 1200, purpose_mask: 1 },
  raw_digest: "11".repeat(32),
  record_salt: "22".repeat(32),
};

test("record encoding preserves the published single-salt vector", () => {
  assert.equal(encode("record", sample, ["record_salt"]).length, 93);
  assert.equal(
    recordCommit(sample),
    "0a269da0fdf179b02a5b4fc03f2cd1c829facc25df65b86c7cf39e68662ed4c3",
  );
  assert.throws(
    () => encode("record", { ...sample, explanation: "extra" }),
    /SCHEMA_FIELDS/,
  );
  assert.throws(
    () => encode("record", { ...sample, record_id: 2 ** 32 }),
    /INTEGER_OUT_OF_RANGE/,
  );
  assert.throws(
    () => encode("record", { ...sample, created_at: "010" }),
    /U64/,
  );
});

test("source rejects skipped updates, version rollback and resurrection", () => {
  const old = makeRecord({}),
    first = createEvent(old, 1);
  assert.throws(
    () => replay(1, [first, { ...first, seq: 3 }]),
    /EVENT_CONTINUITY/,
  );
  const revoked = makeRecord({ version: 2, updated: 50, lifecycle: 2 });
  assert.throws(
    () =>
      replay(1, [first, updateEvent(old, { ...revoked, version: 1 }, 2, true)]),
    /UPDATE_VERSION/,
  );
  assert.throws(
    () =>
      replay(1, [
        first,
        updateEvent(old, revoked, 2, true),
        updateEvent(revoked, makeRecord({ version: 3, updated: 60 }), 3),
      ]),
    /UPDATE_TARGET/,
  );
});

test("registry fixes parent sets and consumes operation tickets once", () => {
  const registry = new Registry(),
    root = registry.importRecord(makeRecord({}), 1, 101, 12);
  assert.throws(() => registry.begin(102, 5, [root, root]), /REGISTRY_PARENTS/);
  assert.throws(() => registry.begin(102, 5, [99]), /REGISTRY_PARENTS/);
  const ticket = registry.begin(102, 5, [root]);
  registry.end(ticket, "11".repeat(32), 20);
  assert.throws(
    () => registry.end(ticket, "22".repeat(32), 21),
    /TICKET_REUSE/,
  );
});

test("unsupported task features and unknown experiment cases are rejected", () => {
  assert.throws(() => defaultTask("test", { purpose_bit: 1 }), /TASK_RULES/);
  assert.throws(() => defaultTask("test", { mode: "UNKNOWN" }), /TASK_MODE/);
  assert.throws(() => makeFixture("unknown", 1), /UNKNOWN_EXPERIMENT_CASE/);
});

test("all baseline comparisons retain the same attack and legitimate fixtures", () => {
  for (const type of TYPES) {
    const attack = makeFixture(type, 20261110);
    assert.equal(attack.oracle.decision, 0);
    const outcomes = SCHEMES.map(
      (scheme) => runBaseline(scheme, attack).action_authorized,
    );
    assert.deepEqual(
      outcomes,
      type === "P3_SAME_SOURCE_ECHO" ? [true, true, true] : [true, true, false],
    );
    const control = makeFixture(type, 20261110, true);
    assert.equal(control.oracle.decision, 1);
    for (const scheme of SCHEMES)
      assert.equal(runBaseline(scheme, control).action_authorized, true);
  }
  assert.equal(
    makeFixture("P2_STALE_MEMORY", 20261110, false, true).oracle.decision,
    1,
  );
});

const caseDir = path.resolve(
  __dirname,
  "../results/experiment1/public/P1_OMISSION-0-benign_control",
);
const hasProof = fs.existsSync(path.join(caseDir, "B-to-C-message.json"));

test(
  "refactoring preserves all 56 public inputs of an existing genuine proof",
  { skip: !hasProof },
  async () => {
    const prepared = await prepareRealFixture(
      makeFixture("P1_OMISSION", 20261110, true),
    );
    const previous = JSON.parse(
      fs.readFileSync(path.join(caseDir, "public.json")),
    );
    assert.deepEqual(publicSignals(prepared.input), previous);
  },
);

test(
  "isolated receiver still verifies real proofs and rejects forged bytes",
  { skip: !hasProof },
  () => {
    const taskFile = path.join(caseDir, "C-local-task.json"),
      configFile = path.join(caseDir, "C-trusted-config.json");
    const incoming = JSON.parse(
      fs.readFileSync(path.join(caseDir, "B-to-C-message.json")),
    );
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rc-peh-test-"));
    const receiver = (message) => {
      const messageFile = path.join(temp, "message.json");
      fs.writeFileSync(messageFile, JSON.stringify(message));
      const run = spawnSync(
        process.execPath,
        [
          path.resolve(__dirname, "../src/receiver.js"),
          taskFile,
          messageFile,
          configFile,
        ],
        { encoding: "utf8" },
      );
      assert.ok(run.stdout.trim(), run.stderr);
      return JSON.parse(run.stdout.trim().split("\n").at(-1));
    };
    assert.equal(receiver(incoming).proof_verified, true);
    const badSignal = clone(incoming);
    badSignal.publicSignals[54] = "0";
    assert.equal(receiver(badSignal).stage, "PUBLIC_INPUT_BINDING");
    const badProof = clone(incoming);
    badProof.proof.pi_a[0] = "0";
    assert.equal(receiver(badProof).proof_verified, false);
  },
);
