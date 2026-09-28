# ZK Refund Agent — minimal end-to-end demo

This demo proves that four private evidence records committed in Agent A's Poseidon Merkle tree support the minimum claims required by Agent B. The exact refund amount and unrelated customer fields never cross the A-to-B boundary.

## Run

Requires Node.js 18+ and a Unix-like shell:

```bash
npm install
bash scripts/setup.sh
bash scripts/run_demo.sh
```

The setup compiles the Circom circuit and performs a local Groth16 trusted setup. The run command executes the successful flow, checks the transport object for private-data leakage, and runs three attacks that must be blocked.

## What is public and private

Public circuit inputs are the Merkle root, order ID, four minimal claim values, and the amount threshold. Private witnesses are the four evidence tuples and all Merkle paths. Agent B receives only the public Claim Bundle, root, Groth16 proof, and public signals.

The amount predicate uses `LessThan(32)` to prove `privateAmount < publicThreshold + 1`, which is equivalent to `privateAmount <= publicThreshold` for the demo's non-negative 32-bit values.

## Important limitation

This is a functional demo, not production cryptography. The setup uses deterministic, published entropy, so it is intentionally insecure for real funds. Production use requires an audited circuit, bounded/domain-separated encodings, a secure multi-party ceremony or suitable existing parameters, authenticated commitment publication, replay/nullifier handling, and transactional refund-state updates.

## Ollama output-binding extension

Run the ZK → policy → local LLM → semantic output-binding flow with:

```bash
bash scripts/run_llm_demo.sh
```

The validated environment used the only locally installed model, `gemma4:26b`. `ollama ps` reported `100% GPU` on an NVIDIA GeForce RTX 5090 D. No model was downloaded.

Ollama receives only this allow-listed object:

```json
{
  "verifiedClaims": {
    "orderId": 123,
    "paymentStatus": "PAID",
    "refundStatus": "NOT_REFUNDED",
    "refundAmountLE1000": true,
    "authorization": true
  },
  "policyResult": "APPROVED"
}
```

The actual validation run passed the normal case and blocked the fake-claim, threshold, fake-Merkle-evidence, hallucinated-output, and privacy-extraction cases. The privacy request is rejected before prompt construction, so it is not forwarded to Ollama. The hallucination case injects an unsupported statement into a candidate model output to deterministically exercise the output gate without putting that fact in the trusted LLM input.

The Output Binding checker uses a separate call to the same Ollama model with a strict JSON schema. It is a fail-closed semantic check, not a cryptographic proof, and can still make model-level classification errors. The independently auditable artifacts and raw run log are generated under `validation/`.

## V2: cross-scenario generic circuit

V2 replaces the fixed business-specific circuit with `circuits/generic_assertions.circom`. Its private Evidence tuple is:

```text
[schemaID, subjectID, fieldID, typeTag, value, timestamp, sourceGroupID]
```

Its public Assertion specifications select `EQ`, `LE`, `GE`, or `IN` and `REVEAL` or `PREDICATE`. `IN` supports up to two public members in this deliberately minimal circuit. No refund or employee field is encoded in the circuit.

Run from a prepared checkout with:

```bash
npm install
bash scripts/setup.sh
bash scripts/run_v2_demo.sh
```

The run uses one R1CS, WASM, proving key, and verification key for both Refund and Employee Access. It also tests Ed25519-authenticated Ingestion roots, fake roots, fake claims, Agent B → Agent C proof forwarding, proofless assertion rejection, private-Evidence isolation, and the fact that LLM text has no write path to the action computation.

The resulting independent audit package is in `validation_v2/`. Ingestion authentication means the Evidence belonged to a root signed by the trusted demo Ingestion service; it does not establish that the Evidence is absolute real-world truth.
