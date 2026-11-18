"use strict";
const {
  check,
  clone,
  ZERO,
  digest,
  parentsCommit,
  contentCommit,
  nodeCommit,
  recordCommit,
} = require("./codec");

const EMPTY_REF = {
  source_id: 0,
  record_id: 0,
  version: 0,
  event_seq: 0,
  record_commit: ZERO,
};
class Registry {
  #tickets = new Map();
  #nodes = [];
  constructor(id = 8001) {
    this.id = id;
  }
  begin(actor, operation, parents) {
    check([1, 2, 3, 4, 5, 6].includes(operation), "REGISTRY_OPERATION");
    check(parents.length <= 4, "CAPACITY_UNAVAILABLE");
    check(
      parents.every(
        (seq, i) =>
          Number.isInteger(seq) &&
          seq > 0 &&
          seq <= this.#nodes.length &&
          (i === 0 || seq > parents[i - 1]),
      ),
      "REGISTRY_PARENTS",
    );
    check(
      operation === 1
        ? parents.length === 0
        : operation === 6 || parents.length > 0,
      "REGISTRY_PARENT_COUNT",
    );
    const id = digest("OPERATION", [
      this.id,
      this.#tickets.size + 1,
      actor,
      operation,
      parents,
    ]);
    this.#tickets.set(id, {
      actor,
      operation,
      parents: clone(parents),
      used: false,
    });
    return id;
  }
  end(ticket, commitment, at, rootRef = EMPTY_REF) {
    const op = this.#tickets.get(ticket);
    check(op && !op.used, "REGISTRY_TICKET_REUSE");
    const isRoot = op.operation === 1;
    check(
      isRoot
        ? rootRef.source_id > 0 && rootRef.record_commit === commitment
        : JSON.stringify(rootRef) === JSON.stringify(EMPTY_REF),
      "REGISTRY_ROOT_KIND",
    );
    const seq = this.#nodes.length + 1;
    const salt = digest("PARENT_SALT", [ticket, seq]);
    const node = {
      schema_version: 1,
      registry_id: this.id,
      registry_seq: seq,
      actor_id: op.actor,
      operation_id: ticket,
      node_kind: isRoot ? 1 : 2,
      operation_type: op.operation,
      content_commit: commitment,
      parent_count: op.parents.length,
      parents_commit: parentsCommit(this.id, op.parents, salt),
      root_ref: clone(rootRef),
      registered_at: String(at),
      parent_seqs: clone(op.parents),
      parents_salt: salt,
    };
    nodeCommit(node);
    this.#nodes.push(node);
    op.used = true;
    return seq;
  }
  importRecord(record, eventSeq, actor, at) {
    const ref = {
      source_id: record.source_id,
      record_id: record.record_id,
      version: record.version,
      event_seq: eventSeq,
      record_commit: recordCommit(record),
    };
    return this.end(this.begin(actor, 1, []), ref.record_commit, at, ref);
  }
  derive(actor, operation, parents, text, at) {
    const ticket = this.begin(actor, operation, parents);
    const salt = digest("INTERMEDIATE_SALT", ticket);
    return this.end(ticket, contentCommit(Buffer.from(text, "utf8"), salt), at);
  }
  handoff(actor, parents, commitment, at) {
    return this.end(this.begin(actor, 6, parents), commitment, at);
  }
  authorizedNodes() {
    return clone(this.#nodes);
  }
  graph(finalSeq) {
    const required = new Set();
    const visit = (seq) => {
      if (required.has(seq)) return;
      const node = this.#nodes[seq - 1];
      check(node, "REGISTRY_MISSING_PARENT");
      required.add(seq);
      node.parent_seqs.forEach(visit);
    };
    visit(finalSeq);
    return [...required]
      .sort((a, b) => a - b)
      .map((seq) => ({ node: clone(this.#nodes[seq - 1]) }));
  }
}
module.exports = { Registry, EMPTY_REF };
