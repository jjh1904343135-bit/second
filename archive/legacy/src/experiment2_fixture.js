"use strict";
const { buildMimcSponge } = require("circomlibjs");

const PUBLIC = {
  psi: ["oldSeq", "newSeq", "blockIndex", "oldLogRoot", "newLogRoot", "oldStateRoot", "newStateRoot"],
  gamma_q: ["timeRoot", "commitment", "nonce", "lower", "upper", "startIndex"],
  gamma_p: ["commitment", "nonce", "timeRoot", "lower", "upper", "evaluationTime", "deadline", "maxRisk", "decision"],
  lambda_sorted: ["inputCommit", "orderedCommit", "nonce", "recordCount"],
  lambda_naive: ["inputCommit", "orderedCommit", "nonce", "recordCount"],
};

async function helpers() {
  const mimc = await buildMimcSponge();
  const hash = (values, domain) => mimc.F.toString(mimc.multiHash(values, domain));
  const merkle = (leaves, depth) => {
    const levels = [leaves.map(String)], zero = ["0"];
    for (let h = 0; h < depth; h++) {
      zero.push(hash([zero[h], zero[h]], 202));
      const previous = levels[h], next = [];
      for (let j = 0; j < Math.ceil(previous.length / 2); j++)
        next.push(hash([previous[2*j] ?? zero[h], previous[2*j+1] ?? zero[h]], 202));
      levels.push(next);
    }
    return {
      root: levels[depth][0] ?? zero[depth],
      path(index, start = 0) {
        const result = [];
        for (let h = start; h < depth; h++) {
          result.push(levels[h][index ^ 1] ?? zero[h]);
          index = Math.floor(index / 2);
        }
        return result;
      },
    };
  };
  const commitment = (input) => hash([
    input.nonce, input.timeRoot, input.lower, input.upper, input.salt,
    ...input.records.flat(),
  ], 203);
  return { hash, merkle, commitment };
}

function record(oid, created = 1000 + oid) {
  return [oid, created, 10, 100000, 100 + (oid * 31) % 4000, 1, 1];
}

async function fixture(module, size, depth) {
  const h = await helpers();
  let input, oracle;
  if (module === "psi") {
    const previous = Array.from({ length: size }, (_, i) => record(i + 1));
    const records = Array.from({ length: size }, (_, i) => record(size + i + 1));
    const oldState = previous.map(r => h.hash(r, 201));
    const newState = [...oldState, ...records.map(r => h.hash(r, 201))];
    const oldLog = oldState.map((r, i) => h.hash([i + 1, r], 204));
    const newLog = [...oldLog, ...newState.slice(size).map((r, i) => h.hash([size+i+1, r], 204))];
    const state = h.merkle(oldState, depth), log = h.merkle(oldLog, depth);
    input = {
      oldSeq: size, newSeq: 2*size, blockIndex: 1,
      oldLogRoot: log.root, newLogRoot: h.merkle(newLog, depth).root,
      oldStateRoot: state.root, newStateRoot: h.merkle(newState, depth).root,
      records,
      logSiblings: log.path(1, Math.log2(size)),
      stateSiblings: state.path(1, Math.log2(size)),
    };
    oracle = { updated: size };
  } else if (module.startsWith("lambda")) {
    const original = Array.from({ length: size }, (_, i) => 1 + ((i * 7) % Math.ceil(size / 3)));
    const values = [...original].sort((a, b) => a-b);
    input = {
      inputCommit: h.hash(original, 205), orderedCommit: h.hash(values, 205),
      nonce: 20261111, recordCount: new Set(original).size, original, values,
    };
    oracle = { recordCount: new Set(original).size };
  } else {
    const records = Array.from({ length: size }, (_, i) => record(i + 1));
    const boundary = [record(size+1, 0), record(size+2, 5000)];
    const tree = h.merkle([boundary[0], ...records, boundary[1]].map(r => h.hash(r, 201)), depth);
    const shared = { timeRoot: tree.root, nonce: 20261111, lower: 1000, upper: 2000, records, salt: 987654321 };
    shared.commitment = h.commitment(shared);
    if (module === "gamma_q") {
      input = {
        ...shared, startIndex: 1, boundary,
        paths: [...records.map((_, i) => tree.path(i+1)), tree.path(0), tree.path(size+1)],
      };
    } else {
      input = { ...shared, evaluationTime: 2000, deadline: 3000, maxRisk: 5000, decision: 1 };
    }
    oracle = { commitment: shared.commitment, decision: 1 };
  }
  return { input, oracle, ...h };
}

function wrapper(module, size, depth) {
  const template = module === "psi" ? `Psi(${size},${depth})`
    : module === "gamma_q" ? `GammaQ(${size},${depth})`
    : module === "gamma_p" ? `GammaP(${size})`
    : `Lambda(${size},${Number(module === "lambda_naive")})`;
  return `pragma circom 2.1.6;\ninclude "../../../circuits/experiment2.circom";\ncomponent main {public [${PUBLIC[module].join(",")}]} = ${template};\n`;
}

module.exports = { fixture, wrapper, PUBLIC };
