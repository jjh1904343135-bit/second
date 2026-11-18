# Experiment 2 — measured cost and scale

Coverage: PARTIAL. Online costs include catching up a lagging state and exporting its real zero-knowledge proof. Compilation, setup, warmup, and initial maintenance have separate records. The per-point budget includes all these phases; no incomplete point is filled or fitted. Each arm rebuilds a fresh joint proof for each task.

| Point | Arm | Status | Samples | Median online ms | Q1–Q3 ms | Initial maintenance ms | Peak process-tree RSS GiB |
|---|---|---|---:|---:|---|---:|---:|
|capacity-1-4-4|reuse|TIMEOUT|6/10|23394.5|23381.7–23447.5|193742.4|16.81|
|capacity-1-4-4|rebuild|TIMEOUT|5/10|217750.1|217411.0–218003.2|193742.4|16.81|
|capacity-2-4-4|reuse|TIMEOUT|2/10|27423.7|27300.2–27547.1|391136.3|17.20|
|capacity-2-4-4|rebuild|TIMEOUT|1/10|418499.0|418499.0–418499.0|391136.3|17.20|
|capacity-3-4-4|reuse|TIMEOUT|1/10|31917.4|31917.4–31917.4|586472.4|17.56|
|capacity-3-4-4|rebuild|TIMEOUT|0/10|N/A|N/A|586472.4|17.56|
|capacity-3-8-4|reuse|TIMEOUT|1/10|42766.3|42766.3–42766.3|587395.3|24.70|
|capacity-3-8-4|rebuild|TIMEOUT|0/10|N/A|N/A|587395.3|24.70|
|capacity-3-16-4|reuse|TIMEOUT|1/10|50360.6|50360.6–50360.6|600489.9|26.52|
|capacity-3-16-4|rebuild|TIMEOUT|0/10|N/A|N/A|600489.9|26.52|
|capacity-3-16-8|reuse|TIMEOUT|0/10|N/A|N/A|590160.7|40.28|
|capacity-3-16-8|rebuild|TIMEOUT|0/10|N/A|N/A|590160.7|40.28|
|capacity-3-16-16|reuse|TIMEOUT|1/10|100891.4|100891.4–100891.4|587621.5|46.83|
|capacity-3-16-16|rebuild|TIMEOUT|0/10|N/A|N/A|587621.5|46.83|
|history-64|reuse|TIMEOUT|1/10|98857.5|98857.5–98857.5|586963.7|47.43|
|history-64|rebuild|TIMEOUT|0/10|N/A|N/A|586963.7|47.43|
|history-256|reuse|TIMEOUT|0/10|N/A|N/A|1007598.7|48.03|
|history-256|rebuild|TIMEOUT|0/10|N/A|N/A|1007598.7|48.03|
|history-1024|reuse|TIMEOUT|0/10|N/A|N/A|N/A|9.73|
|history-1024|rebuild|TIMEOUT|0/10|N/A|N/A|N/A|9.73|
|lag-0|reuse|TIMEOUT|1/10|98488.5|98488.5–98488.5|587305.9|46.98|
|lag-0|rebuild|TIMEOUT|0/10|N/A|N/A|587305.9|46.98|
|lag-1|reuse|TIMEOUT|0/10|N/A|N/A|583323.2|46.58|
|lag-1|rebuild|TIMEOUT|0/10|N/A|N/A|583323.2|46.58|
|lag-4|reuse|TIMEOUT|0/10|N/A|N/A|576334.8|46.92|
|lag-4|rebuild|TIMEOUT|0/10|N/A|N/A|576334.8|46.92|
|lag-16|reuse|TIMEOUT|0/10|N/A|N/A|551111.6|46.44|
|lag-16|rebuild|TIMEOUT|0/10|N/A|N/A|551111.6|46.44|
|tasks-1|reuse|TIMEOUT|1/10|98839.7|98839.7–98839.7|585420.5|46.69|
|tasks-1|rebuild|TIMEOUT|0/10|N/A|N/A|585420.5|46.69|
|tasks-2|reuse|TIMEOUT|0/10|N/A|N/A|587252.5|46.55|
|tasks-2|rebuild|TIMEOUT|0/10|N/A|N/A|587252.5|46.55|
|tasks-5|reuse|TIMEOUT|0/10|N/A|N/A|585781.2|47.06|
|tasks-5|rebuild|TIMEOUT|0/10|N/A|N/A|585781.2|47.06|
|tasks-10|reuse|TIMEOUT|0/10|N/A|N/A|587110.2|48.34|
|tasks-10|rebuild|TIMEOUT|0/10|N/A|N/A|587110.2|48.34|
|graph-chain_single|reuse|TIMEOUT|1/10|100234.8|100234.8–100234.8|597403.2|46.75|
|graph-chain_single|rebuild|TIMEOUT|0/10|N/A|N/A|597403.2|46.75|
|graph-chain_two|reuse|TIMEOUT|1/10|101402.0|101402.0–101402.0|589477.5|46.78|
|graph-chain_two|rebuild|TIMEOUT|0/10|N/A|N/A|589477.5|46.78|
|graph-diamond_single|reuse|TIMEOUT|1/10|98092.0|98092.0–98092.0|585699.3|48.16|
|graph-diamond_single|rebuild|TIMEOUT|0/10|N/A|N/A|585699.3|48.16|
|graph-diamond_two|reuse|TIMEOUT|1/10|98985.2|98985.2–98985.2|585214.8|46.82|
|graph-diamond_two|rebuild|TIMEOUT|0/10|N/A|N/A|585214.8|46.82|
|hits-1|reuse|TIMEOUT|1/10|99646.8|99646.8–99646.8|584755.7|47.02|
|hits-1|rebuild|TIMEOUT|0/10|N/A|N/A|584755.7|47.02|
|hits-4|reuse|TIMEOUT|1/10|98805.1|98805.1–98805.1|586648.2|46.68|
|hits-4|rebuild|TIMEOUT|0/10|N/A|N/A|586648.2|46.68|
|hits-16|reuse|TIMEOUT|1/10|100752.8|100752.8–100752.8|587851.9|47.88|
|hits-16|rebuild|TIMEOUT|0/10|N/A|N/A|587851.9|47.88|

Incremental-benefit hypothesis: NOT ESTABLISHED: no complete paired repeat-task configurations yet. Query and policy are one proof; no separate Gamma/P timings or order-of-magnitude claim is inferred. Constraint contributions use exclusive attribution of surviving optimized R1CS rows; mixed rows are shared_binding and all contributions must sum to the exact joint R1CS. RSS is sampled at 100 ms for the whole process tree. Thread count, original raw samples, cache flags and status details are in JSONL and manifests.
