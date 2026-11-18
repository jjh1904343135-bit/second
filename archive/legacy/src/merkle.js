"use strict";
const { H, integer, encodeType, check } = require("./codec");

class SparseMerkle {
  constructor(kind, depth, entries = []) {
    check(Number.isInteger(depth) && depth > 0 && depth <= 48, "TREE_DEPTH");
    this.kind = kind;
    this.depth = depth;
    this.empty = [H(`${kind}_EMPTY`, Buffer.alloc(0))];
    for (let level = 0; level < depth; level++)
      this.empty.push(this.branch(level, this.empty[level], this.empty[level]));
    this.levels = [new Map()];
    for (const [key, leaf] of entries) {
      const index = BigInt(key);
      check(index >= 0n && index < 1n << BigInt(depth), "TREE_INDEX");
      check(!this.levels[0].has(index), "DUPLICATE_TREE_INDEX");
      encodeType("bytes32", leaf);
      this.levels[0].set(index, leaf);
    }
    for (let level = 0; level < depth; level++) {
      const next = new Map();
      for (const index of this.levels[level].keys()) {
        const parent = index >> 1n;
        next.set(
          parent,
          this.branch(
            level,
            this.levels[level].get(parent * 2n) || this.empty[level],
            this.levels[level].get(parent * 2n + 1n) || this.empty[level],
          ),
        );
      }
      this.levels.push(next);
    }
    this.root = this.levels[depth].get(0n) || this.empty[depth];
  }
  branch(level, left, right) {
    return H(
      `${this.kind}_BRANCH`,
      Buffer.concat([
        integer(level, 2),
        encodeType("bytes32", left),
        encodeType("bytes32", right),
      ]),
    );
  }
  opening(key) {
    let index = BigInt(key);
    const siblings = [];
    check(index >= 0n && index < 1n << BigInt(this.depth), "TREE_INDEX");
    for (let level = 0; level < this.depth; level++) {
      siblings.push(this.levels[level].get(index ^ 1n) || this.empty[level]);
      index >>= 1n;
    }
    return {
      index: String(key),
      leaf: this.levels[0].get(BigInt(key)) || this.empty[0],
      siblings,
    };
  }
  verify(opening, expectedRoot = this.root) {
    if (!opening || opening.siblings.length !== this.depth) return false;
    let index;
    try {
      index = BigInt(opening.index);
    } catch {
      return false;
    }
    if (index < 0n || index >= 1n << BigInt(this.depth)) return false;
    let hash = opening.leaf;
    try {
      for (let level = 0; level < this.depth; level++) {
        hash =
          index & 1n
            ? this.branch(level, opening.siblings[level], hash)
            : this.branch(level, hash, opening.siblings[level]);
        index >>= 1n;
      }
    } catch {
      return false;
    }
    return hash === expectedRoot;
  }
}
module.exports = { SparseMerkle };
