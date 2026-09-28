"use strict";

const crypto = require("crypto");
const { buildPoseidon } = require("circomlibjs");

function canonicalRootMessage(root, epoch) {
  return Buffer.from(`${root}:${epoch}`, "utf8");
}

async function buildTree(evidence) {
  if (!Array.isArray(evidence) || evidence.length !== 4) throw new Error("Demo ingestion requires exactly four Evidence records");
  const poseidon = await buildPoseidon();
  const field = poseidon.F;
  const tuples = evidence.map(item => [item.schemaID, item.subjectID, item.fieldID, item.typeTag, item.value, item.timestamp, item.sourceGroupID]);
  const leaves = tuples.map(tuple => field.toString(poseidon(tuple)));
  const level1 = [field.toString(poseidon([leaves[0], leaves[1]])), field.toString(poseidon([leaves[2], leaves[3]]))];
  const root = field.toString(poseidon(level1));
  const paths = [
    { pathElements: [leaves[1], level1[1]], pathIndices: [0, 0] },
    { pathElements: [leaves[0], level1[1]], pathIndices: [1, 0] },
    { pathElements: [leaves[3], level1[0]], pathIndices: [0, 1] },
    { pathElements: [leaves[2], level1[0]], pathIndices: [1, 1] },
  ];
  return { root, tuples, paths };
}

function createIngestionService() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    async ingest(evidence, epoch) {
      const tree = await buildTree(evidence);
      const signature = crypto.sign(null, canonicalRootMessage(tree.root, epoch), privateKey).toString("base64");
      return { ...tree, epoch, signature };
    },
  };
}

function verifyRootSignature({ root, epoch, signature }, publicKeyPem) {
  try {
    return crypto.verify(null, canonicalRootMessage(root, epoch), publicKeyPem, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

module.exports = { canonicalRootMessage, buildTree, createIngestionService, verifyRootSignature };
