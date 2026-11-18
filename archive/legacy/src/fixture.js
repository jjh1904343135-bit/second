"use strict";
const {
  check,
  clone,
  digest,
  recordCommit,
  handoffCommit,
} = require("./codec");
const {
  Source,
  replay,
  makeRecord,
  createEvent,
  updateEvent,
} = require("./source");
const { Registry } = require("./registry");
const { queryWitness } = require("./baseline_rules");
const { defaultTask } = require("./task");
const { groundTruth } = require("./oracle");
const TYPES = ["P1_OMISSION", "P2_STALE_MEMORY", "P3_SAME_SOURCE_ECHO"];
function random(seed) {
  let state = seed >>> 0;
  return (low, high) => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return low + ((state >>> 0) % (high - low + 1));
  };
}

function makeFixture(type, seed, control = false, historical = false) {
  check(TYPES.includes(type), "UNKNOWN_EXPERIMENT_CASE");
  const rand = random(seed);
  const registry = new Registry();
  const sources = [1, 2, 3].map((id) => new Source(id, seed));
  const sourcesRequired = type === "P3_SAME_SOURCE_ECHO" ? [1, 2, 3] : [1];
  const task = defaultTask([type, seed, control, historical], {
    mode: historical ? "HISTORICAL_AUDIT" : "CURRENT_STATE",
    required_sources: sourcesRequired,
    source_groups: sourcesRequired.map((id) => ({
      source_id: id,
      group_id: id * 11,
    })),
    require_each_source_nonempty: type !== "P3_SAME_SOURCE_ECHO",
    min_records: type === "P3_SAME_SOURCE_ECHO" ? 3 : 1,
    min_issuers: type === "P3_SAME_SOURCE_ECHO" ? 3 : 1,
  });
  const e1 = makeRecord({ risk: rand(0, 4000), salt: `seed-${seed}` });
  sources[0].publish(createEvent(e1, 1));
  const root1 = registry.importRecord(e1, 1, 101, 12);
  let supportSeqs;
  let references = [e1];
  if (type === "P1_OMISSION") {
    // Event arrival order: time 10, then future time 30, then late time 11..19.
    const future = makeRecord({
      id: 2,
      slot: 1,
      created: 30 + rand(0, 10),
      salt: `future-${seed}`,
    });
    const e2 = makeRecord({
      id: 3,
      slot: 2,
      created: rand(11, 19),
      assessment: control ? 1 : 2,
      risk: control ? rand(0, 4000) : rand(5001, 10000),
      salt: `late-${seed}`,
    });
    sources[0].publish(createEvent(future, 2));
    sources[0].publish(createEvent(e2, 3));
    const m1 = registry.derive(101, 4, [root1], "private intermediate M1", 20);
    const m2 = registry.derive(102, 5, [m1], "private intermediate M2", 21);
    supportSeqs = [m2];
  } else if (type === "P2_STALE_MEMORY") {
    const m1 = registry.derive(101, 4, [root1], "private old memory M1", 20);
    const m2 = registry.derive(102, 5, [m1], "private old memory M2", 21);
    if (!control) {
      const e2 = makeRecord({
        source: 1,
        id: 1,
        version: 2,
        created: 10,
        updated: rand(40, 50),
        lifecycle: 2,
        assessment: 2,
        risk: rand(5001, 10000),
        salt: `revocation-${seed}`,
      });
      sources[0].publish(updateEvent(e1, e2, 2, true));
    }
    supportSeqs = [m2];
  } else {
    const m1 = registry.derive(101, 4, [root1], "private echo M1", 20);
    const m2 = registry.derive(102, 5, [m1], "private echo M2", 21);
    const m3 = registry.derive(103, 3, [m2], "private echo M3", 22);
    supportSeqs = [m1, m2, m3];
    if (control) {
      references = [e1];
      supportSeqs = [m1];
      for (const id of [2, 3]) {
        const record = makeRecord({
          source: id,
          risk: rand(0, 4000),
          salt: `independent-${seed}-${id}`,
        });
        sources[id - 1].publish(createEvent(record, 1));
        const root = registry.importRecord(record, 1, 101 + id, 23);
        supportSeqs.push(
          registry.derive(101 + id, 5, [root], `private independent ${id}`, 24),
        );
        references.push(record);
      }
    }
  }
  const states = sourcesRequired.map((id) =>
    replay(id, sources[id - 1].authorizedEvents()),
  );
  const sourcePackages = sourcesRequired.map((id, index) => ({
    checkpoint: sources[id - 1].confirm(task),
    statement: clone(states[index].statement),
  }));
  const honestQueries = states.map((state) => queryWitness(state, task));
  const queries = clone(honestQueries);
  if (type === "P1_OMISSION" && !control)
    queries[0].entries = queries[0].entries.filter(
      (item) => item.entry.record_id !== 3,
    );

  // Compute the actual registered root closure before creating the final structured output.
  const allNodes = registry.authorizedNodes();
  const {
    Q,
    L,
    policy: oracle,
  } = groundTruth(
    task,
    sourcesRequired.map((id) => ({
      source_id: id,
      events: sources[id - 1].authorizedEvents(),
    })),
    allNodes,
    supportSeqs,
  );
  const payload = {
    schema_version: 1,
    task_digest: digest("TASK", task),
    receiver_id: task.receiver_id,
    object_id: task.object_id,
    decision: oracle.decision,
    reason_code: oracle.reason_code,
    deadline: String(task.deadline),
  };
  const committed = handoffCommit(payload);
  const finalSeq = registry.handoff(
    102,
    [...supportSeqs].sort((a, b) => a - b),
    committed.commit,
    64,
  );
  const graph = registry.graph(finalSeq);
  const witness = { queries, graph };
  const certifiedReferences = references.map((record) => {
    const state = states.find(
      (item) => item.statement.source_id === record.source_id,
    );
    const version = [...state.versions.values()].find(
      (item) => recordCommit(item.record) === recordCommit(record),
    );
    return {
      record: clone(record),
      signature: sources[record.source_id - 1].baselineSignature(record),
      event: clone(state.events[version.event_seq - 1]),
      opening: state.logTree.opening(version.event_seq - 1),
    };
  });
  // Models the sender's unverified three independent labels in the vote-inflation attack.
  const selfReportedGroups =
    type === "P3_SAME_SOURCE_ECHO" ? [11, 22, 33] : [11];
  return {
    type,
    seed,
    control,
    historical,
    task,
    sources,
    states,
    registry,
    sourcePackages,
    honestQueries,
    witness,
    payload,
    committed,
    oracle,
    Q,
    L,
    certifiedReferences,
    selfReportedGroups,
  };
}

module.exports = { TYPES, makeFixture };
