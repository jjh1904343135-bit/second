# Experiment 3 — actual agents and disclosure

Status: COMPLETE. Ollama model and complete digest are recorded in model-version.json. Real prompts, generation parameters and outputs are in *-trajectory.json. Model-generation wall time, offline context-tool verification, and frozen-trajectory replay wall time are distinct measurements.

| Scenario | Arm | Result | Replay including catch-up ms | Model ms (separate) | Handoff bytes | Witness bytes | Registration bytes |
|---|---|---|---:|---:|---:|---:|---:|
|normal|RCPEH|ALLOW|95750.2|104307.6|61123|69832|2414|
|normal|PLAIN_COMPLETE|ALLOW|5204.9|104307.6|130413|69832|2414|
|adverse_update|RCPEH|DENY|246532.3|1803.2|61123|69990|2417|
|adverse_update|PLAIN_COMPLETE|DENY|154880.7|1803.2|130571|69990|2417|
|stale_memory|RCPEH|DENY|248509.4|1982.0|61123|69828|2414|
|stale_memory|PLAIN_COMPLETE|DENY|156240.2|1982.0|130409|69828|2414|
|source_timeout|RCPEH|UNAVAILABLE|2839.8|0.0|0|0|0|
|source_timeout|PLAIN_COMPLETE|UNAVAILABLE|2834.3|0.0|0|0|0|

| B-visible information | RC-PEH | Plain complete verification |
|---|---|---|
| Source and registry checkpoints, task, result/reason | YES | YES |
| Private record bodies and salts | NO (audit required) | YES, intentional disclosure |
| Authentication paths and parent edges | NO (audit required) | YES, intentional disclosure |
| Free-form LLM text in structured B packet | NO | NO |
| Private Nova recursive checkpoint | NO | NO |

Model whitelist audit: true. Hallucination cannot change action: true. Paired-fixture byte equality: true; see privacy-pair.json for actual Q and ancestor counts, public checkpoint lengths, and exact B input files. Unique record markers are searched in actual B input; the plaintext baseline's deliberate disclosure is a design difference. These engineering audits do not replace the zero-knowledge argument, and do not claim to prevent an intentionally leaking sender from using other channels.
