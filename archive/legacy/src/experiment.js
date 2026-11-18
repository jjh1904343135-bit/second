"use strict";
const fs = require("fs");
const path = require("path");
const { performance } = require("perf_hooks");
const { spawnSync } = require("child_process");
const snarkjs = require("snarkjs");
const { makeFixture, TYPES } = require("./fixture");
const { runBaseline, SCHEMES } = require("./baselines");
const {
  prepareRealFixture,
  generateProof,
  inspectPrivateCounters,
  PROFILE,
  WASM,
  VK,
  ZKEY,
  BUILD,
  hashFile,
} = require("./proof");
const { clone, check } = require("./codec");

const OUT = path.resolve(__dirname, "../results/experiment1");
function constraintSource(error) {
  const match = error.message.match(/line:\s*(\d+)/);
  if (!match) return null;
  return fs
    .readFileSync(
      path.resolve(__dirname, "../circuits/real_experiment1.circom"),
      "utf8",
    )
    .split("\n")
    [Number(match[1]) - 1]?.trim();
}
function save(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
}
function receive(taskFile, messageFile, configFile) {
  const run = spawnSync(
    process.execPath,
    [path.join(__dirname, "receiver.js"), taskFile, messageFile, configFile],
    { encoding: "utf8", maxBuffer: 1024 * 1024 },
  );
  check(run.stdout?.trim(), `C_PROCESS_FAILED: ${run.stderr}`);
  return {
    ...JSON.parse(run.stdout.trim().split("\n").at(-1)),
    exit_code: run.status,
  };
}

async function main({ trials = 50 } = {}) {
  check(
    Number.isInteger(trials) && trials > 0 && trials <= 10000,
    "TRIAL_COUNT",
  );
  fs.mkdirSync(path.join(OUT, "private"), { recursive: true, mode: 0o700 });
  const results = [];
  for (let trial = 0; trial < trials; trial++)
    for (const type of TYPES)
      for (const sample of [
        "attack",
        "benign_control",
        ...(type === "P2_STALE_MEMORY" ? ["historical_audit_control"] : []),
      ]) {
        const id = `${type}-${trial}-${sample}`;
        console.log(`REAL ${id}`);
        const fixture = makeFixture(
          type,
          20261110 + trial,
          sample === "benign_control",
          sample === "historical_audit_control",
        );
        const prepared = await prepareRealFixture(fixture);
        const inputFile = path.join(OUT, "private", id, "input.json");
        save(inputFile, prepared.input);
        const record = {
          id,
          type,
          trial,
          sample,
          expected_allow: fixture.oracle.decision === 1,
          baseline: {},
          backend: "Groth16-BN254-MiMC",
          real_zk: true,
        };
        if (
          trial === 0 &&
          type === "P3_SAME_SOURCE_ECHO" &&
          sample === "attack"
        ) {
          record.constraint_audit = {};
          for (const mutation of ["unpublished_root", "unresolved_parent"]) {
            const bad = clone(prepared.input);
            if (mutation === "unpublished_root") bad.nodes[0][4] = 4;
            else {
              const final = bad.nodes.filter((row) => row[0] === 1).length - 1;
              bad.nodes[final][6] = 9;
            }
            bad.registryRoot = prepared.hash(2, [
              ...bad.nodes.flat(),
              ...bad.nonce,
              ...bad.handoffCommit,
            ]);
            save(path.join(OUT, "private", id, `${mutation}-input.json`), bad);
            try {
              await generateProof(bad);
              record.constraint_audit[mutation] = { rejected: false };
            } catch (error) {
              record.constraint_audit[mutation] = {
                rejected: /Assert Failed/.test(error.message),
                constraint: constraintSource(error),
              };
            }
          }
        }
        if (sample === "attack" && type !== "P1_OMISSION") {
          const forged = await prepareRealFixture(fixture, 1);
          save(
            path.join(OUT, "private", id, "forged-ALLOW-input.json"),
            forged.input,
          );
          try {
            await generateProof(forged.input);
            record.forged_allow_rejected = false;
          } catch (error) {
            record.forged_allow_rejected = /Assert Failed/.test(error.message);
            record.forged_allow_error = error.message;
            record.forged_allow_constraint = constraintSource(error);
          }
        }
        for (const scheme of SCHEMES)
          record.baseline[scheme] = runBaseline(scheme, fixture);
        let started = performance.now();
        let generation;
        try {
          generation = await generateProof(prepared.input);
          record.proof_generated = true;
          record.witness_generated = true;
        } catch (error) {
          record.proof_generated = false;
          record.witness_generated = false;
          record.proof_generation_error = error.message;
          record.failed_constraint_source = constraintSource(error);
          record.status = "CONSTRUCTION_REJECTED";
          record.action_authorized = false;
          record.correct =
            type === "P1_OMISSION" &&
            sample === "attack" &&
            /Assert Failed/.test(error.message) &&
            Boolean(record.failed_constraint_source?.includes("leftBoundary"));
          record.generation_ms = performance.now() - started;
          results.push(record);
          save(path.join(OUT, "private", id, "result.json"), record);
          continue;
        }
        record.generation_ms = performance.now() - started;
        const message = {
          ...prepared.message,
          proof: generation.proof,
          publicSignals: generation.publicSignals,
        };
        const dir = path.join(OUT, "public", id);
        const messageFile = path.join(dir, "B-to-C-message.json");
        const taskFile = path.join(dir, "C-local-task.json");
        const configFile = path.join(dir, "C-trusted-config.json");
        const firstHopFile = path.join(dir, "A-to-B-message.json");
        save(firstHopFile, message);
        save(taskFile, prepared.message.task);
        save(configFile, prepared.receiverConfig);
        const bVerified = receive(taskFile, firstHopFile, configFile);
        record.B_verification = {
          ...bVerified,
          role: "forwarding verification only",
          action_authorized: false,
        };
        // B forwards the exact received proof bytes; it cannot replace provenance or regenerate a proof.
        fs.copyFileSync(firstHopFile, messageFile);
        record.proof_forwarded_byte_identical =
          hashFile(firstHopFile) === hashFile(messageFile);
        save(path.join(dir, "proof.json"), generation.proof);
        save(path.join(dir, "public.json"), generation.publicSignals);
        started = performance.now();
        const verified = receive(taskFile, messageFile, configFile);
        record.verification_ms = performance.now() - started;
        Object.assign(record, verified);
        record.correct =
          verified.proof_verified &&
          verified.action_authorized === record.expected_allow &&
          bVerified.proof_verified &&
          record.proof_forwarded_byte_identical;
        if (record.forged_allow_rejected !== undefined)
          record.correct = record.correct && record.forged_allow_rejected;
        if (record.constraint_audit)
          record.correct =
            record.correct &&
            Object.values(record.constraint_audit).every((r) => r.rejected);
        // Verify proof bytes independently with the CLI and record genuine output.
        const cli = spawnSync(
          path.resolve(__dirname, "../node_modules/.bin/snarkjs"),
          [
            "groth16",
            "verify",
            VK,
            path.join(dir, "public.json"),
            path.join(dir, "proof.json"),
          ],
          { encoding: "utf8" },
        );
        record.cli_verification = {
          exit_code: cli.status,
          stdout: cli.stdout,
          stderr: cli.stderr,
        };
        console.log(
          `  B verified=${bVerified.proof_verified}; C=${verified.status}; ${cli.stdout.replace(/\x1b\[[0-9;]*m/g, "").trim()}`,
        );
        record.correct =
          record.correct && cli.status === 0 && /OK!/.test(cli.stdout);
        // A scalar public-input change must fail the actual pairing verifier, not just a JS gate.
        const badSignals = [...generation.publicSignals];
        badSignals[badSignals.length - 2] = String(
          1 - Number(badSignals.at(-2)),
        );
        record.tampered_public_input_rejected = !(await snarkjs.groth16.verify(
          JSON.parse(fs.readFileSync(VK)),
          badSignals,
          generation.proof,
        ));
        // Altering a proof point must likewise be rejected by the pairing verifier.
        const badProof = clone(generation.proof);
        badProof.pi_a[0] = "0";
        try {
          record.tampered_proof_rejected = !(await snarkjs.groth16.verify(
            JSON.parse(fs.readFileSync(VK)),
            generation.publicSignals,
            badProof,
          ));
        } catch {
          record.tampered_proof_rejected = true;
        }
        record.correct =
          record.correct &&
          record.tampered_public_input_rejected &&
          record.tampered_proof_rejected;
        if (type === "P3_SAME_SOURCE_ECHO") {
          const counters = await inspectPrivateCounters(
            prepared.input,
            path.join(OUT, "private", id, "count-inspection.wtns"),
          );
          save(
            path.join(OUT, "private", id, "circuit-counters.json"),
            counters,
          );
          record.circuit_counters_from_witness = counters;
          console.log(
            `  Circuit witness: RecordCount=${counters.recordCount}, IssuerCount=${counters.issuerCount}`,
          );
          const count = sample === "attack" ? "1" : "3";
          record.correct =
            record.correct &&
            counters.recordCount === count &&
            counters.issuerCount === count;
        }
        save(path.join(dir, "C-verification.json"), record);
        results.push(record);
      }
  const rows = [];
  for (const type of TYPES)
    for (const scheme of [...SCHEMES, "RC_PEH_REAL"]) {
      const attacks = results.filter(
          (r) => r.type === type && r.sample === "attack",
        ),
        controls = results.filter(
          (r) => r.type === type && r.sample !== "attack",
        );
      const allows = (r) =>
        scheme === "RC_PEH_REAL"
          ? r.action_authorized
          : r.baseline[scheme].action_authorized;
      const blocked = attacks.filter((r) => !allows(r)).length,
        falsePositive = controls.filter((r) => !allows(r)).length;
      rows.push({
        attack: type,
        scheme,
        blocked,
        attacks: attacks.length,
        interception_rate_pct: (100 * blocked) / attacks.length,
        false_positive: falsePositive,
        controls: controls.length,
        false_positive_rate_pct: (100 * falsePositive) / controls.length,
      });
    }
  const summary = {
    profile: PROFILE,
    backend: "Groth16-BN254-MiMC",
    real_proofs: true,
    trials_per_attack: trials,
    status: results.every((r) => r.correct) ? "PASS" : "FAIL",
    real_proofs_generated: results.filter((r) => r.proof_generated).length,
    proofs_verified_by_independent_C: results.filter((r) => r.proof_verified)
      .length,
    cases: results,
    rows,
    artifacts: {
      circuit: hashFile(
        path.resolve(__dirname, "../circuits/real_experiment1.circom"),
      ),
      r1cs: hashFile(path.join(BUILD, "real_experiment1.r1cs")),
      wasm: hashFile(WASM),
      verification_key: fs.existsSync(VK) ? hashFile(VK) : null,
    },
    scope:
      "Bounded 3-source/4-event/8-node MiMC joint proof. State is recomputed from complete source-authenticated event vectors in this Groth16 circuit; this is not the final split Nova IVC architecture or its full-depth tree profile.",
  };
  save(path.join(OUT, "validation.json"), summary);
  {
    fs.copyFileSync(VK, path.join(OUT, "verification_key.json"));
    fs.writeFileSync(path.join(OUT, "paper_table.md"), table(summary));
    const latex = [
      "\\begin{tabular}{lrrrr}",
      "Attack & Signature & Membership & Query-only & RC-PEH \\\\",
      "\\hline",
      ...TYPES.map(
        (type) =>
          `${type.replaceAll("_", "\\_")} & ${[
            "B0_SIGNATURE_ONLY",
            "B1_MEMBERSHIP_ONLY",
            "B2_COMPLETE_QUERY_UNCHECKED_LINEAGE",
            "RC_PEH_REAL",
          ]
            .map((s) => {
              const row = rows.find((r) => r.attack === type && r.scheme === s);
              return `${row.interception_rate_pct}\\% / ${row.false_positive_rate_pct}\\%`;
            })
            .join(" & ")} \\\\`,
      ),
      "\\end{tabular}",
    ];
    fs.writeFileSync(
      path.join(OUT, "paper_table.tex"),
      latex.join("\n") + "\n",
    );
    fs.writeFileSync(
      path.join(OUT, "performance.csv"),
      [
        "case,proof_generation_ms,C_process_verification_ms,proof_verified",
        ...results.map((r) =>
          [
            r.id,
            r.generation_ms,
            r.verification_ms ?? "",
            Boolean(r.proof_verified),
          ].join(","),
        ),
      ].join("\n") + "\n",
    );
    save(path.join(OUT, "manifest.json"), {
      profile: PROFILE,
      backend: summary.backend,
      node: process.version,
      artifacts: summary.artifacts,
      circuit_metadata: JSON.parse(
        fs.readFileSync(path.join(BUILD, "metadata.json")),
      ),
      command: `npm run experiment:1 -- --trials ${trials}`,
    });
  }
  console.table(rows);
  console.log(`REAL EXPERIMENT 1 STATUS: ${summary.status}`);
  return summary;
}
function table(r) {
  const names = {
    P1_OMISSION: "隐瞒不报 P1",
    P2_STALE_MEMORY: "拿旧当新 P2",
    P3_SAME_SOURCE_ECHO: "同源刷票 P3",
  };
  const schemes = [
    "B0_SIGNATURE_ONLY",
    "B1_MEMBERSHIP_ONLY",
    "B2_COMPLETE_QUERY_UNCHECKED_LINEAGE",
    "RC_PEH_REAL",
  ];
  const lines = TYPES.map(
    (type) =>
      `| ${names[type]} | ${schemes
        .map((s) => {
          const row = r.rows.find((x) => x.attack === type && x.scheme === s);
          return `${row.interception_rate_pct}% / ${row.false_positive_rate_pct}%`;
        })
        .join(" | ")} |`,
  );
  return `# 实验 1：真实证明的本地协作实验\n\n后端：Groth16 + MiMC。每格为拦截率 / 误报率。每类 ${r.trials_per_attack} 组攻击，正常／历史审计对照单独计数。\n\n| 攻击 | 仅签名 B0 | 成员存在 B1 | 完整查询、不验传承 B2 | RC-PEH（真实 Π） |\n|---|---:|---:|---:|---:|\n${lines.join("\n")}\n\n实际生成 ${r.real_proofs_generated} 个 Groth16 证明；独立 Agent C 进程验证通过 ${r.proofs_verified_by_independent_C} 个。正常 DENY 证明也计入验证成功，只有 ALLOW 授权行动。遗漏 witness 在生成阶段被电路拒绝。public/ 包含实际 proof/public/message、CLI 验证输出和 C 的结果。\n\n配置范围：${r.scope}\n\n当前运行状态：${r.status}。这些小样本结果不代表普适安全证明；独立 Nova IVC 尚未实现。\n`;
}
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length && !(args.length === 2 && args[0] === "--trials")) {
    console.error("Usage: npm run experiment:1 -- --trials <1..10000>");
    process.exit(1);
  }
  main({ trials: args.length ? Number(args[1]) : 50 })
    .then((r) => process.exit(r.status === "PASS" ? 0 : 1))
    .catch((e) => {
      console.error(e.stack);
      process.exit(1);
    });
}
module.exports = { main };
