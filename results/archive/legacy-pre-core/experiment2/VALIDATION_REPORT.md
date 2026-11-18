# Experiment 2: real modular Groth16 cost measurements

Status: PASS. Date: 2026-11-11T06:49:40.791Z. Tree depth: 16.
Command: `npm run experiment:2`. Exit code: 0.
Backend: Circom circom2 npm package 0.2.23; circom compiler 2.2.3 / snarkjs 0.7.6, BN254 / MiMCSponge-220.
OS: Linux 5.19.0-1010-nvidia-lowlatency x64; Node: v20.20.2; CPU: Intel(R) Core(TM) i9-14900K; logical CPUs: 32.

## Timing definition

Each of 25 separately compiled parameter points generates 5 independent randomized Groth16 proofs from one fixed witness. All 125 proofs are actually verified. Constraints are read from the compiled R1CS using snarkjs.r1cs.info(). Prove time measures only awaited groth16.prove(); Verify time measures only awaited groth16.verify(), including its API decoding work. All five samples, including the first, enter the arithmetic mean. Curve initialization, witness generation, compilation, local phase-2 setup, input preparation and disk serialization are outside these timers; their metadata and exact raw samples are preserved. No samples are dropped. Runs are sequential on this shared host; no CPU pinning is claimed. Timing noise and power-of-two FFT domain changes can prevent monotone or perfectly linear curves.

## Measured relation and scope

- Psi: Groth16 batch CREATE-only transitions for contiguous aligned empty subtrees of two depth-16 Merkle trees (log and state). Every sequence, old empty opening and new root is constrained; paths above the changed subtrees are shared by a genuine batch multiproof. This is not Nova folding, does not measure REVISE/REVOKE, and does not implement the final protocol's entire multi-index updater.
- Lambda: deduplication kernel only, not the complete registered-DAG/ancestor closure. Both variants bind exactly the same original multiset, candidate list and output count. A MiMC Fiat-Shamir challenge of both binding commitments and the task nonce drives a field-product permutation check. Sorted adds adjacent unsigned comparisons; Naive compares each item to all preceding items. Common hashing and multiset binding are INCLUDED, so at these sizes they may dominate the asymptotic gain. The permutation check uses a random-oracle-style cryptographic assumption; it is not a deterministic permutation network or a completed formal soundness proof.
- GammaQ: N returned records plus two immediate neighbors each have a full depth-16 Merkle path. Record positions are contiguous, all returned timestamps are within the query, and both neighbors fall outside it. This component assumes the authenticated index has already been correctly maintained in sorted order. The benchmark is the nonempty interior-range workload, not all directory/sentinel cases of the final protocol.
- GammaP: opens exactly the same salted C_E and context as GammaQ, then checks lifecycle, assessment, risk and the evaluation/deadline window over every record. It does not redo Merkle membership. It is safe to reuse only with the verified GammaQ proof and equality of C_E, root, nonce and interval. It is not an independent replacement for source-state authentication. Each size's actual two proof outputs are composition-checked; C_E substitution is rejected.
- The compact 7-u32 record and domain-keyed MiMC encoding are an independent experiment-2 cost profile, not the final document's full record schema. Changing N or K here intentionally recompiles and changes the verification key; this experiment does not claim one fixed circuit with variable hidden capacity.

## Results (milliseconds)

| Module | Size | Constraints | Prove mean (ms) | Verify mean (ms) |
|---|---:|---:|---:|---:|
| psi | 4 | 109911 | 1502.926 | 6.169 |
| psi | 8 | 141668 | 2254.036 | 5.754 |
| psi | 16 | 209157 | 2852.355 | 7.288 |
| psi | 32 | 348110 | 5533.237 | 9.127 |
| psi | 64 | 629991 | 12464.145 | 10.666 |
| lambda_sorted | 8 | 13388 | 270.943 | 6.981 |
| lambda_naive | 8 | 13213 | 282.259 | 7.494 |
| lambda_sorted | 16 | 24836 | 447.010 | 11.248 |
| lambda_naive | 16 | 24701 | 461.804 | 8.100 |
| lambda_sorted | 32 | 47732 | 843.010 | 6.618 |
| lambda_naive | 32 | 48445 | 795.461 | 7.362 |
| lambda_sorted | 64 | 93524 | 1576.272 | 6.790 |
| lambda_naive | 64 | 99005 | 1567.137 | 7.392 |
| lambda_sorted | 128 | 185108 | 2788.392 | 6.220 |
| lambda_naive | 128 | 212413 | 3014.630 | 5.993 |
| gamma_q | 4 | 179091 | 2734.023 | 5.938 |
| gamma_p | 4 | 23356 | 421.755 | 6.540 |
| gamma_q | 8 | 302507 | 5522.792 | 8.105 |
| gamma_p | 8 | 43272 | 721.223 | 6.114 |
| gamma_q | 16 | 549339 | 11196.416 | 9.811 |
| gamma_p | 16 | 83104 | 1449.828 | 15.531 |
| gamma_q | 32 | 1043003 | 21470.386 | 17.959 |
| gamma_p | 32 | 162768 | 2803.848 | 6.273 |
| gamma_q | 64 | 2030331 | 49788.135 | 14.939 |
| gamma_p | 64 | 322096 | 6377.441 | 9.083 |

## Hypotheses, not imposed outcomes

GammaQ / GammaP prove-time ratios: 4: 6.48x, 8: 7.66x, 16: 7.72x, 32: 7.66x, 64: 7.81x.
At least 10x at every size: **NOT OBSERVED**.

Lambda naive / sorted total-constraint ratios: 8: 0.99x, 16: 0.99x, 32: 1.01x, 64: 1.06x, 128: 1.15x.
Lambda naive / sorted prove-time ratios: 8: 1.04x, 16: 1.03x, 32: 0.94x, 64: 0.99x, 128: 1.08x.
The panel displays actual data on linear axes, without forced trends or hand-entered speedups. Panel C includes a least-squares fit only as a measured trend, not an asymptotic proof. Functional validation passing does not mean every performance hypothesis was confirmed.

## Audit artifacts

metrics.csv: the three requested metrics plus point identifiers. trials.csv: all individual prove/verify samples. validation.json: raw samples, circuit/key hashes, composition checks and constraint-mutation outcomes. public/<point>/: all real proofs, public signals and verification key. private/<point>/: inputs/witnesses, ignored by Git. full_run.log: unabridged stdout and stderr. parameters.json: actual parameter-file digest checks. All artifacts are generated by the runner, not manually labeled.
