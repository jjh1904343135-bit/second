# Experiment 1 — security and ablations

Source: actual JSONL records, no expected outcomes substituted for observations. Shared normal proofs count as one independent control per profile. An unavailable source is not a cryptographic interception.

| Category | Profile | Interception | Construct failed | B rejected | Valid DENY | Unavailable | Normal non-ALLOW |
|---|---|---|---:|---:|---:|---:|---|
|omission|FULL|N/A (0 observations)|0|0|0|0|N/A|
|invalid_reuse|FULL|N/A (0 observations)|0|0|0|0|N/A|
|lineage|FULL|N/A (0 observations)|0|0|0|0|N/A|
|substitution|FULL|N/A (0 observations)|0|0|0|0|N/A|
|reason|FULL|N/A (0 observations)|0|0|0|0|N/A|
|omission|NO_QUERY|N/A (0 observations)|0|0|0|0|N/A|
|invalid_reuse|NO_QUERY|N/A (0 observations)|0|0|0|0|N/A|
|lineage|NO_QUERY|N/A (0 observations)|0|0|0|0|N/A|
|substitution|NO_QUERY|N/A (0 observations)|0|0|0|0|N/A|
|reason|NO_QUERY|N/A (0 observations)|0|0|0|0|N/A|
|omission|NO_VALIDITY|N/A (0 observations)|0|0|0|0|N/A|
|invalid_reuse|NO_VALIDITY|N/A (0 observations)|0|0|0|0|N/A|
|lineage|NO_VALIDITY|N/A (0 observations)|0|0|0|0|N/A|
|substitution|NO_VALIDITY|N/A (0 observations)|0|0|0|0|N/A|
|reason|NO_VALIDITY|N/A (0 observations)|0|0|0|0|N/A|
|omission|NO_LINEAGE|N/A (0 observations)|0|0|0|0|N/A|
|invalid_reuse|NO_LINEAGE|N/A (0 observations)|0|0|0|0|N/A|
|lineage|NO_LINEAGE|N/A (0 observations)|0|0|0|0|N/A|
|substitution|NO_LINEAGE|N/A (0 observations)|0|0|0|0|N/A|
|reason|NO_LINEAGE|N/A (0 observations)|0|0|0|0|N/A|
|omission|NO_BINDING|N/A (0 observations)|0|0|0|0|N/A|
|invalid_reuse|NO_BINDING|N/A (0 observations)|0|0|0|0|N/A|
|lineage|NO_BINDING|N/A (0 observations)|0|0|0|0|N/A|
|substitution|NO_BINDING|N/A (0 observations)|0|0|0|0|N/A|
|reason|NO_BINDING|N/A (0 observations)|0|0|0|0|N/A|

Full-protocol tested functionality: INCOMPLETE / FAIL. Coverage: PARTIAL. Each raw row includes modified factor, reference result, status, reason code, and failing checkpoint. Fixed tests and seeded variants are reported separately in attack-results.csv. Scope and availability controls are excluded from attack denominators. The same-content-node test uses two actual registered nodes with identical content.
