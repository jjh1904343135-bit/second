"use strict";

class VerifiedAssertionStore {
  #records = new Map();

  addVerified(assertion, verification) {
    if (!verification || verification.rootSignatureValid !== true || verification.zkProofValid !== true) {
      throw new Error("Only signature- and ZK-verified assertions may enter the store");
    }
    const record = Object.freeze({ ...assertion, verified: true });
    this.#records.set(record.assertionId, record);
    return record;
  }

  addFromNaturalLanguage() {
    throw new Error("Natural language cannot write to VerifiedAssertionStore");
  }

  values() { return [...this.#records.values()]; }
  has(assertionId) { return this.#records.has(assertionId); }
}

module.exports = { VerifiedAssertionStore };
