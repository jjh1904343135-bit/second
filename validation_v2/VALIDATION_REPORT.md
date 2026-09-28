# Cross-Scenario ZK Circuit Validation Report

Generated from the actual run in `full_run.log` at 2026-09-23T13:26:50.695Z.

## Environment

- OS: Linux 5.19.0-1010-nvidia-lowlatency x64
- Node.js: v20.20.2
- Ollama model: gemma4:26b
- Ollama runtime: `NAME          ID              SIZE     PROCESSOR    CONTEXT    UNTIL               | gemma4:26b    5571076f3d70    20 GB    100% GPU     4096       9 minutes from now`

## Circuit reuse evidence

- Circuit hash for Refund: `f3cebb66c6a436cc370989231bbe5825bed52d6201087be91fcd369a61d90fe4`
- Circuit hash for Employee Access: `f3cebb66c6a436cc370989231bbe5825bed52d6201087be91fcd369a61d90fe4`
- Same R1CS: PASS
- Both proofs use `build/generic_assertions_js/generic_assertions.wasm` and `build/generic_verification_key.json`.

Artifact hash snapshots:

```json
{
  "refund": {
    "r1cs": "f3cebb66c6a436cc370989231bbe5825bed52d6201087be91fcd369a61d90fe4",
    "wasm": "d2f72bb913ca9bfb1bdcf46f1867873f7a946ba2c61ef1bc487c6afc88dbccb2",
    "verificationKey": "95df64d9aba4394c8c89b0f1a288ee81bb2277f47884a2d531df48f3e6c974a6"
  },
  "employeeAccess": {
    "r1cs": "f3cebb66c6a436cc370989231bbe5825bed52d6201087be91fcd369a61d90fe4",
    "wasm": "d2f72bb913ca9bfb1bdcf46f1867873f7a946ba2c61ef1bc487c6afc88dbccb2",
    "verificationKey": "95df64d9aba4394c8c89b0f1a288ee81bb2277f47884a2d531df48f3e6c974a6"
  },
  "afterBothProofs": {
    "r1cs": "f3cebb66c6a436cc370989231bbe5825bed52d6201087be91fcd369a61d90fe4",
    "wasm": "d2f72bb913ca9bfb1bdcf46f1867873f7a946ba2c61ef1bc487c6afc88dbccb2",
    "verificationKey": "95df64d9aba4394c8c89b0f1a288ee81bb2277f47884a2d531df48f3e6c974a6"
  }
}
```

Changing scenario and policy did not trigger recompilation between proof generation calls.

## Scenarios

### Refund

- Authenticated root: PASS
- ZK proof: PASS
- Policy action: APPROVED
- Scenario: PASS

### Employee Access

- Authenticated root: PASS
- ZK proof: PASS
- Policy action: ACCESS_GRANTED
- Scenario: PASS

## Authenticated Ingestion root tests

The Ed25519 signature authenticates that the root came from this demo's trusted Ingestion service. It does not prove real-world truth.

`Fake Root` verification:

```json
{
  "proofGeneratedForFakeRoot": true,
  "fakeRootDiffersFromAuthenticatedRoot": true,
  "blocked": true,
  "verification": {
    "rootSignatureValid": false,
    "zkProofValid": false
  },
  "layer": "Ingestion signature (checked before ZK verification)"
}
```

`Tampered Root` verification:

```json
{
  "blocked": true,
  "verification": {
    "rootSignatureValid": false,
    "zkProofValid": false
  },
  "layer": "Ingestion signature"
}
```

`Fake Claim` result:

```json
{
  "name": "Fake Claim",
  "blocked": true,
  "actual": "proof generation failed: Error: Assert Failed. Error in template GenericAssertions_153 line: 108",
  "layer": "ZK constraints"
}
```

## Privacy

Actual Agent A → B bundles are saved in `refund_proof.json` and `employee_proof.json`. Automated structural audits:

```json
{
  "refundAgentAToB": {
    "privateEvidenceSent": false,
    "exactRefundAmountSent": false,
    "merklePathSent": false,
    "privateWitnessSent": false
  },
  "employeeAgentAToB": {
    "privateEvidenceSent": false,
    "exactRefundAmountSent": false,
    "merklePathSent": false,
    "privateWitnessSent": false
  },
  "llmInput": {
    "privateEvidenceSent": false,
    "exactRefundAmountSent": false,
    "merklePathSent": false,
    "privateWitnessSent": false
  },
  "actualLlmInput": {
    "verifiedAssertionStore": [
      {
        "assertionId": "2f0bff2d7c0f7da0efb6fbd5dc247ffe8e9764afa661a7e53f540b922674a656",
        "subjectID": 123,
        "fieldID": 1,
        "op": 1,
        "target": [
          1
        ],
        "mode": 1,
        "result": true,
        "revealedValue": 1,
        "verified": true
      },
      {
        "assertionId": "8f6990399dc247bc6ceb0b27b25a428af7a0763416915fcb98e8a2bb1da5de46",
        "subjectID": 123,
        "fieldID": 2,
        "op": 1,
        "target": [
          0
        ],
        "mode": 1,
        "result": true,
        "revealedValue": 0,
        "verified": true
      },
      {
        "assertionId": "73fd2fa7f425be5d76aee012aea435d0c08f8da1140efa4625a0fbb0648c2918",
        "subjectID": 123,
        "fieldID": 3,
        "op": 2,
        "target": [
          1000
        ],
        "mode": 2,
        "result": true,
        "verified": true
      },
      {
        "assertionId": "1be735f822538eff327122a05307ebdf7226740cda1f77b25c181034e90cfc92",
        "subjectID": 123,
        "fieldID": 4,
        "op": 1,
        "target": [
          1
        ],
        "mode": 1,
        "result": true,
        "revealedValue": 1,
        "verified": true
      }
    ],
    "policyResult": "APPROVED"
  }
}
```

Private Evidence and Merkle paths are not included. REVEAL assertions disclose only their explicit value; PREDICATE assertions do not disclose the underlying value.

## Verified Assertion Store and propagation

Agent C independently verified the forwarded proof: PASS.

- receive text: YES
- enter VerifiedAssertionStore: NO
- usable for high-risk action: NO
- UNVERIFIED ASSERTION BLOCKED: YES

## LLM explanation isolation

Actual model output:

> 针对主体 ID 为 123 的各项断言验证均通过，策略结果为已批准（APPROVED）。

Hallucinated candidate output:

> 针对主体 ID 为 123 的各项断言验证均通过，策略结果为已批准（APPROVED）。 用户信用良好。

Binding result:

```json
{
  "supported": false,
  "claims": [
    {
      "text": "针对主体 ID 为 123 的各项断言验证均通过",
      "status": "SUPPORTED"
    },
    {
      "text": "策略结果为已批准（APPROVED）",
      "status": "SUPPORTED"
    },
    {
      "text": "用户信用良好。",
      "status": "UNSUPPORTED"
    }
  ]
}
```

- Action before hallucination: APPROVED
- Action after hallucination: APPROVED
- Action is computed only from VerifiedAssertionStore + Policy: PASS

Output Binding remains semantic LLM verification, not a cryptographic proof. Even if it misses an unsupported sentence, natural language has no write path to the store or action function.

## Required questions

1. Same circuit for two scenarios? **PASS**
2. Fake Root blocked? **PASS**
3. Fake Claim blocked? **PASS**
4. Private Evidence withheld from B? **PASS**
5. LLM hallucination unable to change Action? **PASS**
6. Proofless inter-agent Assertion denied store entry? **PASS**
7. Refund Scenario passed? **PASS**
8. Employee Access Scenario passed? **PASS**

## Final status

- Cross-Scenario Circuit Reuse: PASS
- Authenticated Evidence Root: PASS
- Private Evidence Protection: PASS
- Verified Assertion Enforcement: PASS
- Hallucination Cannot Affect Action: PASS
- Multi-Agent Unverified Propagation Blocked: PASS

**FINAL V2 STATUS: PASS**
