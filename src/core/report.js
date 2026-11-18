"use strict";
const fs=require("fs"),path=require("path"),{OUT,ROOT,save,run}=require("./runtime"),D=require("./data");
const read=f=>fs.existsSync(f)?JSON.parse(fs.readFileSync(f)):null;
const lines=f=>fs.existsSync(f)?fs.readFileSync(f,"utf8").trim().split("\n").filter(Boolean).map(JSON.parse):[];
const pct=(n,d)=>d?`${(100*n/d).toFixed(1)}% (${n}/${d})`:"N/A (0 observations)";
function quantile(a,q){if(!a.length)return null;const s=[...a].sort((a,b)=>a-b),at=(s.length-1)*q,lo=Math.floor(at);return s[lo]+(s[Math.ceil(at)]-s[lo])*(at-lo);}
const summary=a=>({n:a.length,median:quantile(a,.5),q1:quantile(a,.25),q3:quantile(a,.75)});
function csv(file,rows) {
  if(!rows.length){fs.writeFileSync(file,"status\nNO_OBSERVATIONS\n");return;}
  const keys=[...new Set(rows.flatMap(Object.keys))],quote=v=>'"'+String(typeof v==="object"?JSON.stringify(v):v??"").replaceAll('"','""')+'"';
  fs.writeFileSync(file,keys.map(quote).join(",")+"\n"+rows.map(r=>keys.map(k=>quote(r[k])).join(",")).join("\n")+"\n");
}
function security() {
  const dir=path.join(OUT,"experiment1");fs.mkdirSync(dir,{recursive:true});const manifest=read(path.join(dir,"input-manifest.json")),profiles=require("./security").PROFILES,table=[],raw=[];
  for(const profile of profiles) {
    const rows=lines(path.join(dir,profile,"raw.jsonl")),normal=read(path.join(dir,profile,"normal-control.json"));raw.push(...rows);
    for(const family of Object.keys(require("./security").FAMILIES)) {
      const attacks=rows.filter(r=>r.family===family&&r.phase==="seeded"&&r.attack_sample!==false),n=attacks.length;
      table.push({family,profile,observed:n,planned:D.CONFIG.security_variants_per_category,blocked:attacks.filter(r=>r.blocked).length,construction_failures:attacks.filter(r=>r.outcome==="construction_failure").length,verification_rejections:attacks.filter(r=>r.outcome==="verification_rejection").length,valid_denials:attacks.filter(r=>r.outcome==="valid_deny").length,unavailable:attacks.filter(r=>r.outcome==="unavailable").length,accepted:attacks.filter(r=>r.outcome==="accepted").length,interception_rate:n?attacks.filter(r=>r.blocked).length/n:null,normal_control_unique_samples:normal?1:0,normal_non_allow:normal?Number(normal.actual.status!=="ALLOW"):null,normal_unavailable:normal?Number(normal.actual.status==="UNAVAILABLE"):null});
    }
  }
  csv(path.join(dir,"attack-results.csv"),raw);csv(path.join(dir,"summary.csv"),table);save(path.join(dir,"summary.json"),table);
  const fixed=raw.filter(r=>r.phase==="fixed"&&r.ablation==="FULL"),full=raw.filter(r=>r.ablation==="FULL"&&r.attack_sample!==false);
  const result={coverage_complete:!!manifest&&table.every(r=>r.observed===r.planned),full_protocol_functional:full.length>0&&full.every(r=>r.pass)&&fixed.every(r=>r.pass)&&fixed.length===Object.values(require("./security").FAMILIES).flat().length,table};
  const text=`# Experiment 1 — security and ablations\n\nSource: actual JSONL records, no expected outcomes substituted for observations. Shared normal proofs count as one independent control per profile. An unavailable source is not a cryptographic interception.\n\n| Category | Profile | Interception | Construct failed | B rejected | Valid DENY | Unavailable | Normal non-ALLOW |\n|---|---|---|---:|---:|---:|---:|---|\n`+table.map(r=>`|${r.family}|${r.profile}|${pct(r.blocked,r.observed)}|${r.construction_failures}|${r.verification_rejections}|${r.valid_denials}|${r.unavailable}|${r.normal_non_allow===null?"N/A":pct(r.normal_non_allow,r.normal_control_unique_samples)}|`).join("\n")+`\n\nFull-protocol tested functionality: ${result.full_protocol_functional?"PASS":"INCOMPLETE / FAIL"}. Coverage: ${result.coverage_complete?"COMPLETE":"PARTIAL"}. Each raw row includes modified factor, reference result, status, reason code, and failing checkpoint. Fixed tests and seeded variants are reported separately in attack-results.csv. Scope and availability controls are excluded from attack denominators. The same-content-node test uses two actual registered nodes with identical content.\n`;
  fs.writeFileSync(path.join(dir,"REPORT.md"),text);return result;
}
function performance() {
  const dir=path.join(OUT,"experiment2");fs.mkdirSync(dir,{recursive:true});const configs=require("./performance").matrix(),rows=[],samples=[];
  for(const c of configs) {
    const raw=lines(path.join(dir,c.id,"raw.jsonl")),state=read(path.join(dir,c.id,"status.json"));
    for(const r of raw.filter(r=>r.stage==="sample"))samples.push({configuration:c.id,...r});
    for(const arm of ["reuse","rebuild"]) {
      const s=raw.filter(r=>r.stage==="sample"&&r.arm===arm),initial=raw.find(r=>r.stage==="initial_maintenance"),setup=raw.find(r=>r.stage==="offline_setup");
      rows.push({configuration:c.id,scan:c.scan,capacity:c.capacity,history:c.history,lag:c.lag,tasks:c.tasks,topology:c.topology,hits:c.hits,arm,status:state?.status||"NOT_RUN",wall_ms:summary(s.map(r=>r.wall_ms)),cumulative_including_maintenance_ms:summary(s.map(r=>r.wall_ms+(arm==="reuse"?initial?.wall_ms||0:0))),initial_maintenance_ms:initial?.wall_ms??null,setup_ms:setup?.wall_ms??null,cache:setup?.cache??null,constraint_accounting:setup?.accounting??null,peak_rss_bytes:state?.execution?.sampled_process_tree_peak_rss_bytes??null,stages:s.map(r=>r.stages)});
    }
  }
  const complete=rows.every(r=>r.wall_ms.n===D.CONFIG.benchmark.repetitions&&r.status==="COMPLETE");
  save(path.join(dir,"summary.json"),rows);csv(path.join(dir,"samples.csv"),samples);csv(path.join(dir,"summary.csv"),rows);
  const benefit=rows.filter(r=>r.scan==="tasks"&&r.arm==="reuse"&&r.wall_ms.n===10).map(r=>{const other=rows.find(b=>b.configuration===r.configuration&&b.arm==="rebuild"&&b.wall_ms.n===10);return {configuration:r.configuration,supported:!!other&&r.cumulative_including_maintenance_ms.median<other.cumulative_including_maintenance_ms.median,reuse:r.cumulative_including_maintenance_ms,rebuild:other?.cumulative_including_maintenance_ms};});
  fs.writeFileSync(path.join(dir,"REPORT.md"),`# Experiment 2 — measured cost and scale\n\nCoverage: ${complete?"COMPLETE":"PARTIAL"}. Online costs include catching up a lagging state and exporting its real zero-knowledge proof. Compilation, setup, warmup, and initial maintenance have separate records. The per-point budget includes all these phases; no incomplete point is filled or fitted. Each arm rebuilds a fresh joint proof for each task.\n\n| Point | Arm | Status | Samples | Median online ms | Q1–Q3 ms | Initial maintenance ms | Peak process-tree RSS GiB |\n|---|---|---|---:|---:|---|---:|---:|\n`+rows.map(r=>`|${r.configuration}|${r.arm}|${r.status}|${r.wall_ms.n}/10|${r.wall_ms.median?.toFixed(1)??"N/A"}|${r.wall_ms.q1===null?"N/A":`${r.wall_ms.q1.toFixed(1)}–${r.wall_ms.q3.toFixed(1)}`}|${r.initial_maintenance_ms?.toFixed(1)??"N/A"}|${r.peak_rss_bytes===null?"N/A":(r.peak_rss_bytes/1024**3).toFixed(2)}|`).join("\n")+`\n\nIncremental-benefit hypothesis: ${benefit.length?JSON.stringify(benefit):"NOT ESTABLISHED: no complete paired repeat-task configurations yet"}. Query and policy are one proof; no separate Gamma/P timings or order-of-magnitude claim is inferred. Constraint contributions use exclusive attribution of surviving optimized R1CS rows; mixed rows are shared_binding and all contributions must sum to the exact joint R1CS. RSS is sampled at 100 ms for the whole process tree. Thread count, original raw samples, cache flags and status details are in JSONL and manifests.\n`);
  return {coverage_complete:complete,benefit_evidence:benefit,rows};
}
function agents() {
  const dir=path.join(OUT,"experiment3");fs.mkdirSync(dir,{recursive:true});const result=read(path.join(dir,"results.json")),rows=lines(path.join(dir,"raw.jsonl"));csv(path.join(dir,"summary.csv"),rows);
  fs.writeFileSync(path.join(dir,"REPORT.md"),`# Experiment 3 — actual agents and disclosure\n\nStatus: ${result?.status||read(path.join(dir,"status.json"))?.status||"NOT_RUN"}. Ollama model and complete digest are recorded in model-version.json. Real prompts, generation parameters and outputs are in *-trajectory.json. Model-generation wall time, offline context-tool verification, and frozen-trajectory replay wall time are distinct measurements.\n\n| Scenario | Arm | Result | Replay including catch-up ms | Model ms (separate) | Handoff bytes | Witness bytes | Registration bytes |\n|---|---|---|---:|---:|---:|---:|---:|\n`+rows.map(r=>`|${r.scenario}|${r.arm}|${r.status}|${r.task_wall_ms.toFixed(1)}|${r.model_wall_ms.toFixed(1)}|${r.handoff_bytes}|${r.witness_bytes}|${r.registration_bytes}|`).join("\n")+`\n\n| B-visible information | RC-PEH | Plain complete verification |\n|---|---|---|\n| Source and registry checkpoints, task, result/reason | YES | YES |\n| Private record bodies and salts | NO (audit required) | YES, intentional disclosure |\n| Authentication paths and parent edges | NO (audit required) | YES, intentional disclosure |\n| Free-form LLM text in structured B packet | NO | NO |\n| Private Nova recursive checkpoint | NO | NO |\n\nModel whitelist audit: ${result?.model_input_whitelist_pass??"NOT_RUN"}. Hallucination cannot change action: ${result?.hallucination_cannot_change_action??"NOT_RUN"}. Paired-fixture byte equality: ${result?.privacy_pair?.equal_bytes??"NOT_RUN"}; see privacy-pair.json for actual Q and ancestor counts, public checkpoint lengths, and exact B input files. Unique record markers are searched in actual B input; the plaintext baseline's deliberate disclosure is a design difference. These engineering audits do not replace the zero-knowledge argument, and do not claim to prevent an intentionally leaking sender from using other channels.\n`);
  return {coverage_complete:result?.status==="COMPLETE"&&rows.length===8,results:result};
}
async function main() {
  fs.mkdirSync(OUT,{recursive:true});const gate=read(path.join(OUT,"prerequisite/validation.json")),one=security(),two=performance(),three=agents(),tests=read(path.join(OUT,"tests.json"));
  const functional=gate?.status==="PASS"&&tests?.status==="PASS"&&one.full_protocol_functional&&three.results?.hallucination_cannot_change_action===true;
  const result={generated_at:new Date().toISOString(),functional_status:functional?"PASS":"INCOMPLETE / FAIL",prerequisite:gate?.status||"NOT_RUN",mandatory_tests:tests?.status||"NOT_RUN",experiment_coverage:{security:one.coverage_complete,performance:two.coverage_complete,agents:three.coverage_complete},performance_hypotheses:two.benefit_evidence.length?two.benefit_evidence:"NOT_ESTABLISHED",external_comparisons:"DEFERRED_BY_SCOPE"};
  save(path.join(OUT,"validation_results.json"),result);
  const evidence=[];
  function publish(dir) {
    if(!fs.existsSync(dir))return;
    for(const e of fs.readdirSync(dir,{withFileTypes:true})) {
      const file=path.join(dir,e.name);if(e.isDirectory()){publish(file);continue;}
      if(!["proof.json","public.json","psi.bin"].includes(e.name))continue;
      const rel=path.relative(path.join(OUT,"private"),file),dest=path.join(OUT,"proofs",rel);fs.mkdirSync(path.dirname(dest),{recursive:true});
      fs.copyFileSync(file,dest);evidence.push({file:path.relative(OUT,dest),sha256:require("./backend").fileHash(dest),bytes:fs.statSync(dest).size});
      if(e.name==="psi.bin") {const r=read(path.join(dir,"result.json"));if(r?.statement)save(path.join(path.dirname(dest),"statement.json"),{...r.statement});}
    }
  }
  if(gate?.artifacts?.private_dir)publish(gate.artifacts.private_dir);
  for(const name of ["experiment1","experiment2","experiment3"]) {const m=read(path.join(OUT,name,"input-manifest.json"));if(m?.private_input_directory)publish(m.private_input_directory);}
  const build=path.join(ROOT,"build/core");
  if(fs.existsSync(build))for(const e of fs.readdirSync(build)) {
    for(const rel of ["nova/vk.bin","verification_key.json"]) {
      const vk=path.join(build,e,rel);if(!fs.existsSync(vk))continue;const sha=require("./backend").fileHash(vk);
      const dest=path.join(OUT,"verification_keys",sha,path.basename(rel));fs.mkdirSync(path.dirname(dest),{recursive:true});if(!fs.existsSync(dest))fs.copyFileSync(vk,dest);
      evidence.push({file:path.relative(OUT,dest),sha256:sha,bytes:fs.statSync(dest).size});
    }
  }
  save(path.join(OUT,"public-artifact-manifest.json"),evidence);
  fs.writeFileSync(path.join(OUT,"VALIDATION_REPORT.md"),`# RC-PEH core validation\n\nGenerated from actual artifacts at ${result.generated_at}.\n\n- Functionality: **${result.functional_status}**\n- Real Nova + joint Groth16 prerequisite: **${result.prerequisite}**\n- Mandatory implementation tests: **${result.mandatory_tests}**\n- Security coverage: **${one.coverage_complete?"COMPLETE":"PARTIAL"}**\n- Performance coverage: **${two.coverage_complete?"COMPLETE":"PARTIAL"}**\n- Agent/disclosure coverage: **${three.coverage_complete?"COMPLETE":"PARTIAL"}**\n- Performance hypothesis: ${JSON.stringify(result.performance_hypotheses)}\n\nSee [prerequisite](prerequisite/VALIDATION_REPORT.md), [experiment 1](experiment1/REPORT.md), [experiment 2](experiment2/REPORT.md), [experiment 3](experiment3/REPORT.md), manifest.json and full_run.log. Private inputs and recursive states remain under private/ and are not B attachments. Old experiments are archived with incompatible measurement semantics and never included in these tables. External paper replication is deferred.\n`);
  const plot=await run("python3",[path.join(ROOT,"plots/core/plot_core.py")],{quiet:true,timeout:60000,log:path.join(OUT,"plots.log")});
  console.log(`CORE Functionality: ${result.functional_status}\nExperiment Coverage: ${one.coverage_complete&&two.coverage_complete&&three.coverage_complete?"COMPLETE":"PARTIAL"}\nPerformance Hypothesis: ${two.benefit_evidence.length?"SEE MEASUREMENTS":"NOT ESTABLISHED"}`);return {...result,plot_status:plot.status};
}
module.exports={main,security,performance,agents,summary,csv};
