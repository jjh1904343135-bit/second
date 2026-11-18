# Core prerequisite

Status: PASS

Backend: real Nova BN254/Grumpkin Pedersen/IPA + compressed zero-knowledge export; one Groth16 Gamma/Lambda circuit.

- ALLOW: ALLOW, reason 0; independent receiver verified=true
- POLICY_DENY: DENY, reason 1; independent receiver verified=true
- INSUFFICIENT_SUPPORT: DENY, reason 2; independent receiver verified=true

State operations: CREATE, REVISE and REVOKE. Log depth 32; directory depth 48. Joint constraints: 1424669.

Psi fold: 5229.846511 ms; ZK export: 90333.612309 ms; serialized proof: 13112 bytes. Export and verification costs are real and must not be omitted. See validation.json for actual negative constraints, replay, privacy and proof-tampering outcomes. Private recursive IVC state is not an attachment.
