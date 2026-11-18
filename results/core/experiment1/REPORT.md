# Experiment 1 — security and ablations

Source: actual JSONL records, no expected outcomes substituted for observations. Shared normal proofs count as one independent control per profile. An unavailable source is not a cryptographic interception.

| Category | Profile | Interception | Construct failed | B rejected | Valid DENY | Unavailable | Normal non-ALLOW |
|---|---|---|---:|---:|---:|---:|---|
|omission|FULL|100.0% (50/50)|25|25|0|0|0.0% (0/1)|
|invalid_reuse|FULL|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|lineage|FULL|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|substitution|FULL|100.0% (50/50)|0|50|0|0|0.0% (0/1)|
|reason|FULL|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|omission|NO_QUERY|50.0% (25/50)|0|25|0|0|0.0% (0/1)|
|invalid_reuse|NO_QUERY|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|lineage|NO_QUERY|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|substitution|NO_QUERY|100.0% (50/50)|0|50|0|0|0.0% (0/1)|
|reason|NO_QUERY|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|omission|NO_VALIDITY|100.0% (50/50)|25|25|0|0|0.0% (0/1)|
|invalid_reuse|NO_VALIDITY|0.0% (0/50)|0|0|0|0|0.0% (0/1)|
|lineage|NO_VALIDITY|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|substitution|NO_VALIDITY|100.0% (50/50)|0|50|0|0|0.0% (0/1)|
|reason|NO_VALIDITY|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|omission|NO_LINEAGE|100.0% (50/50)|25|25|0|0|0.0% (0/1)|
|invalid_reuse|NO_LINEAGE|74.0% (37/50)|37|0|0|0|0.0% (0/1)|
|lineage|NO_LINEAGE|0.0% (0/50)|0|0|0|0|0.0% (0/1)|
|substitution|NO_LINEAGE|100.0% (50/50)|0|50|0|0|0.0% (0/1)|
|reason|NO_LINEAGE|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|omission|NO_BINDING|76.0% (38/50)|25|13|0|0|0.0% (0/1)|
|invalid_reuse|NO_BINDING|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|lineage|NO_BINDING|100.0% (50/50)|50|0|0|0|0.0% (0/1)|
|substitution|NO_BINDING|0.0% (0/50)|0|0|0|0|0.0% (0/1)|
|reason|NO_BINDING|100.0% (50/50)|50|0|0|0|0.0% (0/1)|

Full-protocol tested functionality: PASS. Coverage: COMPLETE. Each raw row includes modified factor, reference result, status, reason code, and failing checkpoint. Fixed tests and seeded variants are reported separately in attack-results.csv. Scope and availability controls are excluded from attack denominators. The same-content-node test uses two actual registered nodes with identical content.
