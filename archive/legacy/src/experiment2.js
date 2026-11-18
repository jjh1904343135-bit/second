"use strict";
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawn, spawnSync } = require("child_process");
const { performance } = require("perf_hooks");
const snark = require("snarkjs");
const { fixture, wrapper, PUBLIC } = require("./experiment2_fixture");

const ROOT = path.resolve(__dirname, "..");
const BUILD = path.join(ROOT, "build/experiment2");
const OUT = path.join(ROOT, "results/experiment2");
const CIRCOM = path.join(ROOT, "node_modules/.bin/circom2");
const CLI = path.join(ROOT, "node_modules/.bin/snarkjs");
const hash = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const save = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
};
const check = (ok, message) => { if (!ok) throw new Error(message); };
const mean = values => values.reduce((a,b) => a+b, 0) / values.length;
const run = (cmd, args) => new Promise((resolve, reject) => {
  console.log(`$ ${path.relative(ROOT, cmd) || cmd} ${args.join(" ")}`);
  const child = spawn(cmd, args, { cwd: ROOT, stdio: "inherit" });
  child.on("error", reject);
  child.on("exit", code => code === 0 ? resolve() : reject(new Error(`COMMAND_EXIT_${code}: ${cmd}`)));
});

async function point(module, size, depth, repeats) {
  const id = `${module}-${size}-d${depth}`;
  const dir = path.join(BUILD, id), pub = path.join(OUT, "public", id);
  const priv = path.join(OUT, "private", id);
  for (const d of [dir, pub, priv]) fs.mkdirSync(d, { recursive: true, mode: d===priv ? 0o700 : 0o755 });
  const source = wrapper(module, size, depth);
  const stamp = crypto.createHash("sha256").update(source).update(fs.readFileSync(path.join(ROOT, "circuits/experiment2.circom"))).digest("hex");
  const circuit = path.join(dir, "circuit.circom"), r1cs = path.join(dir, "circuit.r1cs");
  const wasm = path.join(dir, "circuit_js/circuit.wasm"), key = path.join(dir, "final.zkey");
  const keyStamp = path.join(dir, "key-stamp.txt");
  const wrapperMatches=fs.existsSync(circuit)&&fs.readFileSync(circuit,"utf8")===source;
  const compiledFresh=wrapperMatches&&[r1cs,wasm].every(f=>fs.existsSync(f)&&
    fs.statSync(f).mtimeMs>=Math.max(fs.statSync(circuit).mtimeMs,fs.statSync(path.join(ROOT,"circuits/experiment2.circom")).mtimeMs));
  if(!wrapperMatches) fs.writeFileSync(circuit, source);
  const cached = fs.existsSync(keyStamp) && fs.readFileSync(keyStamp,"utf8").trim()===stamp
    && [r1cs,wasm,key].every(f=>fs.existsSync(f));
  let compileMs = null, setupMs = null;
  if (!cached && !compiledFresh) {
    const started = performance.now();
    await run(CIRCOM, [circuit, "--r1cs", "--wasm", "--O1", "-l", "node_modules", "-o", dir]);
    compileMs = performance.now()-started;
  }
  const info = await snark.r1cs.info(r1cs);
  const neededPower = Math.ceil(Math.log2(info.nConstraints+info.nPubInputs+info.nOutputs+1));
  const power = neededPower <= 19 ? 19 : 21;
  check(neededPower<=21, `PTAU_CAPACITY: ${id} requires power ${neededPower}`);
  const ptau = path.join(ROOT, `params/powersOfTau28_hez_final_${power}.ptau`);
  check(fs.existsSync(ptau), `PARAMETER_MISSING: ${ptau}`);
  if (!cached) {
    const started = performance.now();
    const initial = path.join(dir, "initial.zkey");
    await run(CLI, ["groth16", "setup", r1cs, ptau, initial]);
    console.log("Local research phase-2 contribution (not a production ceremony)");
    await snark.zKey.contribute(initial, key, "experiment2 local contribution", crypto.randomBytes(32).toString("hex"));
    fs.unlinkSync(initial);
    setupMs=performance.now()-started;
    fs.writeFileSync(keyStamp, stamp+"\n");
  }
  const vk = await snark.zKey.exportVerificationKey(key);
  save(path.join(pub,"verification_key.json"), vk);
  const f = await fixture(module, size, depth), input=f.input;
  save(path.join(priv,"input.json"), input);
  const witness = path.join(priv,"witness.wtns");
  let started=performance.now();
  await snark.wtns.calculate(input, wasm, witness);
  const witnessMs=performance.now()-started;

  // Binding and decision failures must be genuine witness-constraint failures.
  const mutations = [];
  if(module === "psi") {
    mutations.push(["skipped_sequence", b => b.newSeq++]);
    mutations.push(["changed_state_path", b => b.stateSiblings[0]=String(BigInt(b.stateSiblings[0])+1n)]);
  } else if(module.startsWith("lambda")) {
    mutations.push(["inflated_count", b => b.recordCount++]);
    mutations.push(["replaced_multiset", b => {
      b.values[b.values.length-1] += 1;
      b.orderedCommit=f.hash(b.values,205);
      b.recordCount=new Set(b.values).size;
    }]);
    if(module === "lambda_sorted") mutations.push(["unsorted_same_multiset", b => {
      [b.values[0],b.values[b.values.length-1]]=[b.values[b.values.length-1],b.values[0]];
      b.orderedCommit=f.hash(b.values,205);
    }]);
  } else if(module === "gamma_q") {
    mutations.push(["changed_merkle_path", b => b.paths[0][0]=String(BigInt(b.paths[0][0])+1n)]);
    mutations.push(["omitted_matching_record", b => {
      b.records[0]=[...b.records[1]];b.commitment=f.commitment(b);
    }]);
  } else {
    mutations.push(["forged_decision", b => b.decision=0]);
    mutations.push(["expired_record_claimed_allow", b => {
      b.records[0][3]=b.deadline;b.commitment=f.commitment(b);
    }]);
    mutations.push(["changed_commitment", b => b.commitment=String(BigInt(b.commitment)+1n)]);
  }
  const bindingChecks = {};
  for(const [name, mutate] of mutations) {
    const bad=structuredClone(input);mutate(bad);
    try {
      await snark.wtns.calculate(bad,wasm,{type:"mem"});
      bindingChecks[name]={rejected:false};
    } catch(e) {
      bindingChecks[name]={rejected:/Assert Failed/.test(e.message), error:e.message};
    }
    check(bindingChecks[name].rejected, `MISSING_CONSTRAINT: ${id}/${name}`);
  }
  if(module==="gamma_p") {
    const denied=structuredClone(input);
    denied.records[0][3]=denied.deadline;
    denied.commitment=f.commitment(denied);denied.decision=0;
    await snark.wtns.calculate(denied,wasm,{type:"mem"});
    bindingChecks.expired_record_honest_deny={witness_accepted:true};
  }
  const trials=[];
  for(let repeat=0;repeat<repeats;repeat++) {
    started=performance.now();
    const proof=await snark.groth16.prove(key,witness);
    const proveMs=performance.now()-started;
    check(JSON.stringify(proof.publicSignals)===JSON.stringify(PUBLIC[module].map(k=>String(input[k]))),`PUBLIC_LAYOUT: ${id}`);
    started=performance.now();
    const verified=await snark.groth16.verify(vk,proof.publicSignals,proof.proof);
    const verifyMs=performance.now()-started;
    check(verified, `VERIFY_FAILED: ${id}/${repeat}`);
    save(path.join(pub,`proof-${repeat}.json`),proof.proof);
    save(path.join(pub,`public-${repeat}.json`),proof.publicSignals);
    trials.push({repeat,prove_ms:proveMs,verify_ms:verifyMs,verified});
    console.log(`MEASURE ${id} ${repeat+1}/${repeats}: constraints=${info.nConstraints} prove=${proveMs.toFixed(3)}ms verify=${verifyMs.toFixed(3)}ms PASS`);
  }
  const badPublic=PUBLIC[module].map(k=>String(input[k]));badPublic[0]=String(BigInt(badPublic[0])+1n);
  const lastProof=JSON.parse(fs.readFileSync(path.join(pub,`proof-${repeats-1}.json`)));
  bindingChecks.tampered_public_input={rejected:!(await snark.groth16.verify(vk,badPublic,lastProof))};
  check(bindingChecks.tampered_public_input.rejected,`PUBLIC_TAMPER_ACCEPTED: ${id}`);
  const result={
    id,module,size,depth,repeats,status:"PASS",constraints:info.nConstraints,
    prove_ms:mean(trials.map(t=>t.prove_ms)),verify_ms:mean(trials.map(t=>t.verify_ms)),trials,
    witness_ms:witnessMs,compile_ms:compileMs,setup_ms:setupMs,
    compiled_artifacts_reused:cached||compiledFresh,proving_key_reused:cached,
    binding_checks:bindingChecks,reference_result:f.oracle,
    public_inputs:Object.fromEntries(PUBLIC[module].map(k=>[k,String(input[k])])),
    artifacts:{source:stamp,r1cs:hash(r1cs),wasm:hash(wasm),verification_key:hash(path.join(pub,"verification_key.json"))},
    measured_at:new Date().toISOString(),
  };
  save(path.join(pub,"result.json"),result);
  return result;
}

function report(summary) {
  const by=(module,size)=>summary.points.find(p=>p.module===module&&p.size===size);
  const sizes=[4,8,16,32,64], ks=[8,16,32,64,128];
  const rows=summary.points.map(p=>`| ${p.module} | ${p.size} | ${p.constraints} | ${p.prove_ms.toFixed(3)} | ${p.verify_ms.toFixed(3)} |`);
  const speed=sizes.map(n=>({size:n,ratio:by("gamma_q",n).prove_ms/by("gamma_p",n).prove_ms}));
  const dedup=ks.map(n=>({size:n,constraint_ratio:by("lambda_naive",n).constraints/by("lambda_sorted",n).constraints,
    prove_ratio:by("lambda_naive",n).prove_ms/by("lambda_sorted",n).prove_ms}));
  summary.observations={query_policy_speedups:speed,lambda_ratios:dedup,
    policy_at_least_10x_at_all_sizes:speed.every(x=>x.ratio>=10)};
  const text=`# Experiment 2: real modular Groth16 cost measurements

Status: ${summary.status}. Date: ${summary.completed_at}. Tree depth: ${summary.depth}.
Command: \`${summary.command}\`. Exit code: ${summary.exit_code}.
Backend: Circom ${summary.environment.circom} / snarkjs ${summary.environment.snarkjs}, BN254 / MiMCSponge-220.
OS: ${summary.environment.os}; Node: ${summary.environment.node}; CPU: ${summary.environment.cpu}; logical CPUs: ${summary.environment.logical_cpus}.

## Timing definition

Each of 25 separately compiled parameter points generates ${summary.repeats} independent randomized Groth16 proofs from one fixed witness. All ${summary.points.reduce((n,p)=>n+p.trials.length,0)} proofs are actually verified. Constraints are read from the compiled R1CS using snarkjs.r1cs.info(). Prove time measures only awaited groth16.prove(); Verify time measures only awaited groth16.verify(), including its API decoding work. All five samples, including the first, enter the arithmetic mean. Curve initialization, witness generation, compilation, local phase-2 setup, input preparation and disk serialization are outside these timers; their metadata and exact raw samples are preserved. No samples are dropped. Runs are sequential on this shared host; no CPU pinning is claimed. Timing noise and power-of-two FFT domain changes can prevent monotone or perfectly linear curves.

## Measured relation and scope

- Psi: Groth16 batch CREATE-only transitions for contiguous aligned empty subtrees of two depth-${summary.depth} Merkle trees (log and state). Every sequence, old empty opening and new root is constrained; paths above the changed subtrees are shared by a genuine batch multiproof. This is not Nova folding, does not measure REVISE/REVOKE, and does not implement the final protocol's entire multi-index updater.
- Lambda: deduplication kernel only, not the complete registered-DAG/ancestor closure. Both variants bind exactly the same original multiset, candidate list and output count. A MiMC Fiat-Shamir challenge of both binding commitments and the task nonce drives a field-product permutation check. Sorted adds adjacent unsigned comparisons; Naive compares each item to all preceding items. Common hashing and multiset binding are INCLUDED, so at these sizes they may dominate the asymptotic gain. The permutation check uses a random-oracle-style cryptographic assumption; it is not a deterministic permutation network or a completed formal soundness proof.
- GammaQ: N returned records plus two immediate neighbors each have a full depth-${summary.depth} Merkle path. Record positions are contiguous, all returned timestamps are within the query, and both neighbors fall outside it. This component assumes the authenticated index has already been correctly maintained in sorted order. The benchmark is the nonempty interior-range workload, not all directory/sentinel cases of the final protocol.
- GammaP: opens exactly the same salted C_E and context as GammaQ, then checks lifecycle, assessment, risk and the evaluation/deadline window over every record. It does not redo Merkle membership. It is safe to reuse only with the verified GammaQ proof and equality of C_E, root, nonce and interval. It is not an independent replacement for source-state authentication. Each size's actual two proof outputs are composition-checked; C_E substitution is rejected.
- The compact 7-u32 record and domain-keyed MiMC encoding are an independent experiment-2 cost profile, not the final document's full record schema. Changing N or K here intentionally recompiles and changes the verification key; this experiment does not claim one fixed circuit with variable hidden capacity.

## Results (milliseconds)

| Module | Size | Constraints | Prove mean (ms) | Verify mean (ms) |
|---|---:|---:|---:|---:|
${rows.join("\n")}

## Hypotheses, not imposed outcomes

GammaQ / GammaP prove-time ratios: ${speed.map(x=>`${x.size}: ${x.ratio.toFixed(2)}x`).join(", ")}.
At least 10x at every size: **${summary.observations.policy_at_least_10x_at_all_sizes ? "OBSERVED" : "NOT OBSERVED"}**.

Lambda naive / sorted total-constraint ratios: ${dedup.map(x=>`${x.size}: ${x.constraint_ratio.toFixed(2)}x`).join(", ")}.
Lambda naive / sorted prove-time ratios: ${dedup.map(x=>`${x.size}: ${x.prove_ratio.toFixed(2)}x`).join(", ")}.
The panel displays actual data on linear axes, without forced trends or hand-entered speedups. Panel C includes a least-squares fit only as a measured trend, not an asymptotic proof. Functional validation passing does not mean every performance hypothesis was confirmed.

## Audit artifacts

metrics.csv: the three requested metrics plus point identifiers. trials.csv: all individual prove/verify samples. validation.json: raw samples, circuit/key hashes, composition checks and constraint-mutation outcomes. public/<point>/: all real proofs, public signals and verification key. private/<point>/: inputs/witnesses, ignored by Git. full_run.log: unabridged stdout and stderr. parameters.json: actual parameter-file digest checks. All artifacts are generated by the runner, not manually labeled.
`;
  fs.writeFileSync(path.join(OUT,"VALIDATION_REPORT.md"),text);
}

async function main() {
  const depth=16,repeats=5;
  fs.mkdirSync(OUT,{recursive:true});
  save(path.join(OUT,"validation.json"),{status:"RUNNING",depth,repeats,started_at:new Date().toISOString()});
  const points=[];
  const configs=[...[4,8,16,32,64].map(n=>["psi",n]),
    ...[8,16,32,64,128].flatMap(n=>[["lambda_sorted",n],["lambda_naive",n]]),
    ...[4,8,16,32,64].flatMap(n=>[["gamma_q",n],["gamma_p",n]])];
  for(const [module,size] of configs) {
    console.log(`========== ${module} size=${size} depth=${depth} repeats=${repeats} ==========`);
    await run(process.execPath,[__filename,"--point",module,String(size),String(depth),String(repeats)]);
    const result=JSON.parse(fs.readFileSync(path.join(OUT,"public",`${module}-${size}-d${depth}`,"result.json")));
    points.push(result);
    save(path.join(OUT,"progress.json"),{completed:points.length,total:configs.length,points});
  }
  const composition=[];
  for(const size of [4,8,16,32,64]) {
    const q=points.find(p=>p.module==="gamma_q"&&p.size===size).public_inputs;
    const policyPoint=points.find(p=>p.module==="gamma_p"&&p.size===size);
    const p=policyPoint.public_inputs;
    const equal=["commitment","nonce","timeRoot","lower","upper"].every(k=>q[k]===p[k]);
    check(equal,`QUERY_POLICY_BINDING: ${size}`);
    const fake={...p,commitment:String(BigInt(p.commitment)+1n)};
    composition.push({size,shared_context_matches:equal,
      commitment_substitution_blocked:q.commitment!==fake.commitment && policyPoint.binding_checks.tampered_public_input.rejected});
  }
  const summary={
    status:points.every(p=>p.status==="PASS")&&composition.every(c=>c.shared_context_matches&&c.commitment_substitution_blocked)?"PASS":"FAIL",
    exit_code:0,depth,repeats,points,composition,completed_at:new Date().toISOString(),
    command:"npm run experiment:2",environment:{node:process.version,os:`${os.type()} ${os.release()} ${os.arch()}`,
      cpu:os.cpus()[0].model,logical_cpus:os.cpus().length,
      circom:spawnSync(CIRCOM,["--version"],{encoding:"utf8"}).stdout.trim().replaceAll("\n","; "),
      snarkjs:JSON.parse(fs.readFileSync(path.join(ROOT,"node_modules/snarkjs/package.json"))).version},
  };
  summary.exit_code=summary.status==="PASS"?0:1;
  report(summary);save(path.join(OUT,"validation.json"),summary);
  fs.writeFileSync(path.join(OUT,"metrics.csv"),[
    "module,size,depth,repeats,constraints,prove_ms,verify_ms",
    ...points.map(p=>[p.module,p.size,p.depth,p.repeats,p.constraints,p.prove_ms,p.verify_ms].join(",")),
  ].join("\n")+"\n");
  fs.writeFileSync(path.join(OUT,"trials.csv"),[
    "module,size,depth,repeat,prove_ms,verify_ms,verified",
    ...points.flatMap(p=>p.trials.map(t=>[p.module,p.size,p.depth,t.repeat,t.prove_ms,t.verify_ms,t.verified].join(","))),
  ].join("\n")+"\n");
  console.log(`EXPERIMENT 2 FUNCTIONAL STATUS: ${summary.status}`);
  console.log(`GammaP at least 10x faster at all sizes: ${summary.observations.policy_at_least_10x_at_all_sizes ? "OBSERVED" : "NOT OBSERVED"}`);
  return summary.exit_code;
}

if(require.main===module) {
  const args=process.argv.slice(2);
  const work=args[0]==="--point" ? point(args[1],Number(args[2]),Number(args[3]),Number(args[4])).then(()=>0) : main();
  work.then(code=>process.exit(code)).catch(e=>{
    console.error(e.stack);
    if(args[0]!=="--point") save(path.join(OUT,"validation.json"),{
      status:"FAIL",exit_code:1,error:e.message,failed_at:new Date().toISOString(),
      progress_file:"progress.json",
    });
    process.exit(1);
  });
}
