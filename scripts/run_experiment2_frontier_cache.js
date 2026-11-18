"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const D = require("../src/core/data");
const F = require("../src/core/fixtures");
const B = require("../src/core/backend");
const cli = require("../src/core/cli");
const {ROOT, OUT, RUN_ID, run, save} = require("../src/core/runtime");
const profile = D.profile(3,16,16);
const history = 64, repetitions = 3, tasks = 3;
const deltas = [1,16];
const arms = ["incremental","rebuild"];
const id = "capacity-3-16-16";
const baselineRun = "2026-11-16T13-23-58-840Z-922246";
const baseline = path.join(OUT,"private","experiment2-"+baselineRun,id);
const scheduledAudit = "/mnt/user-data/zjh/.local/state/rcpeh-20261117/exp2-audit/summary.json";
const result = path.join(OUT,"experiment2-frontier-cache",RUN_ID);
const read = file => JSON.parse(fs.readFileSync(file,"utf8"));
const atomic = (file, value) => { save(file+".tmp",value); fs.renameSync(file+".tmp",file); };
const stats = (values) => {
  const sorted = [...values].sort((a,b)=>a-b);
  const at = q => { const i=(sorted.length-1)*q, j=Math.floor(i); return sorted[j]+(sorted[Math.ceil(i)]-sorted[j])*(i-j); };
  return {median:at(0.5),q1:at(0.25),q3:at(0.75),samples:sorted.length};
};

function fixture() {
  cli.gate();
  const audit=read(scheduledAudit);
  assert.equal(audit.status,"PASS");
  assert.equal(audit.run_id,baselineRun);
  assert.equal(audit.source_revision,cli.revision());
  assert.equal(audit.verified.length,20);
  const events=read(path.join(baseline,"events.json"));
  assert.equal(events.length,profile.sources);
  assert.ok(events.every(log=>log.length===history));
  const cached=events.map((_,i)=>read(path.join(baseline,"maintained-"+i,"result.json")));
  for (const state of cached) {
    assert.equal(state.statement.num_steps,history);
    assert.ok(fs.statSync(state.checkpoint).size>0);
    assert.equal(B.fileHash(state.file),state.proof_sha256);
  }
  return {events,cached};
}

function newEvents(source,delta,rep) {
  const lastVersions = new Map(source.current);
  return Array.from({length:delta},(_,i)=>{
    const id=1+i%4;
    const record=D.clone(lastVersions.get(id));
    record.version++;
    record.updated_at=String(2000+i);
    record.record_salt=D.tagged("FRONTIER_CACHE_FIXTURE_SALT",[RUN_ID,delta,rep,i]);
    lastVersions.set(id,record);
    return {op:2,record};
  });
}

async function worker() {
  const {events,cached}=fixture();
  const revision=cli.revision();
  const hash=await D.hashing();
  const prev=F.replay(profile,hash,events);
  const setupStart=performance.now();
  const keys={psi:await B.psiKeys(profile,hash,result),joint:await B.jointKeys(profile,result)};
  for (const [i,state] of cached.entries()) {
    assert.equal(state.vk_id,keys.psi.vk_id);
    assert.deepEqual(state.statement.output,prev[i].state);
  }
  const inputs={run_id:RUN_ID,source_revision:revision,baseline_run:baselineRun,base_events_sha256:B.fileHash(path.join(baseline,"events.json")),benchmark_source_sha256:B.fileHash(__filename),node:process.version,limits:D.CONFIG.benchmark,profile,history_per_source:history,changed_source_id:1,deltas,repetitions,tasks_per_frontier:tasks,setup_ms:performance.now()-setupStart,verification_keys:{psi:keys.psi.vk_id,joint:keys.joint.vk_id},note:"One update per frontier per arm. Unchanged sources use the same existing state proofs. Each task gets a fresh joint proof. Existing 64-event base checkpoints are prepared before measured time."};
  atomic(path.join(result,"input-manifest.json"),inputs);
  const byArm=[];
  const raw=path.join(result,"raw.jsonl");
  const append=x=>fs.appendFileSync(raw,JSON.stringify({...x,recorded_at:new Date().toISOString()})+"\n");
  console.log("Ready: cached genesis-to-64 checkpoints match all three original event logs");
  for(const [deltaIndex,delta] of deltas.entries()) {
    for(let rep=0;rep<repetitions;rep++) {
      const order=(rep+deltaIndex)%2===0?arms:[...arms].reverse();
      const added=newEvents(prev[0],delta,rep);
      const pairDir=path.join(result,"private","delta-"+delta,"rep-"+rep);
      save(path.join(pairDir,"new-events.json"),added);
      const graphs = [];
      for (const arm of order) {
        assert.equal(cli.revision(),revision,"Source revision changed");
        const armDir=path.join(pairDir,arm);
        console.log("START",delta,rep,arm);
        const start=performance.now();
        let source;
        if(arm==="incremental") {
          source=prev[0].fork();
          for(const {op,record} of added)source.apply(op,D.clone(record));
        } else {
          [source]=F.replay(profile,hash,[[...events[0],...added]]);
        }
        const index_ms=performance.now()-start;
        const newState=await B.proveState(source,keys.psi,path.join(armDir,"state"),{resume:arm==="incremental"?cached[0]:null});
        const state_ready_ms=performance.now()-start;
        const states=[newState,cached[1],cached[2]];
        const srcs=[source,prev[1],prev[2]];
        const stateMetrics={delta,rep,arm,state_ready_ms,index_ms,psi_witness_ms:newState.witness_ms,psi_fold_ms:newState.fold_ms,psi_export_ms:newState.export_ms,processed_events:arm==="incremental"?delta:history+delta};
        append({stage:"frontier_ready",...stateMetrics});
        console.log("FRONTIER_READY",delta,rep,arm,state_ready_ms.toFixed(1),"ms");

        const samples=[];
        for(let i=0;i<tasks;i++) {
          const taskStart=performance.now();
          const task=D.task(profile,[RUN_ID,delta,rep,i],{psi_vk_id:keys.psi.vk_id,task_vk_id:keys.joint.vk_id,max_risk_score:5000+i});
          const taskDir=path.join(armDir,"task-"+i);
          const copy=graphs[i];
          const fx=F.graph(task,profile,srcs,{topology:"default",...(copy?copy.fixture:{})});
          const proof=await B.proveTask(fx.prepared.input,keys.joint,path.join(taskDir,"joint"));
          const packet=B.bundle(task,profile,fx.prepared,states,proof);
          const common={signals:packet.public_signals,source_checkpoints:packet.sources.map(x=>x.checkpoint),registry_checkpoint:packet.registry_checkpoint};
          if(copy)assert.deepEqual(common,copy.common,"Paired tasks use different public statements or checkpoints");
          else graphs[i]={common,fixture:{replayNodes:fx.registry.nodes,qSalt:fx.prepared.input.qSalt,lSalt:fx.prepared.input.lSalt}};
          const trust={...F.trust(profile,srcs,fx.registry),verification_only:true};
          const verified=await F.independentReceiver(task,packet,trust,keys,path.join(taskDir,"receiver"));
          assert.equal(verified.process.status,"PASS");
          assert.equal(verified.verified,true);
          assert.equal(verified.status,fx.answer.decision?"ALLOW":"DENY");
          assert.equal(verified.reason_code,fx.answer.reason);
          assert.equal(verified.action_authorized,false);
          const measurement={delta,rep,arm,task:i,task_ms:performance.now()-taskStart,joint_witness_ms:proof.witness_ms,joint_prove_ms:proof.prove_ms,receiver_ms:verified.wall_ms,packet_bytes:Buffer.byteLength(JSON.stringify(packet)),decision:verified.status,reason_code:verified.reason_code};
          append({stage:"task",...measurement});
          samples.push(measurement);
          console.log("TASK_VERIFIED",delta,rep,arm,i,measurement.task_ms.toFixed(1),"ms");
        }
        const replay_ms=samples.reduce((total,sample)=>total+sample.task_ms,0);
        const completed={...stateMetrics,first_task_with_update_ms:state_ready_ms+samples[0].task_ms,avg_task_including_update_ms:(state_ready_ms+replay_ms)/tasks,avg_task_after_update_ms:replay_ms/tasks};
        append({stage:"frontier_complete",...completed});
        byArm.push(completed);
        atomic(path.join(result,"progress.json"),{status:"RUNNING",completed_arms:byArm.length,expected_arms:deltas.length*repetitions*arms.length,latest:completed});
      }
    }
  }
  const metrics=["state_ready_ms","first_task_with_update_ms","avg_task_including_update_ms","avg_task_after_update_ms"];
  const summary=deltas.map(delta=>{
    const group=byArm.filter(x=>x.delta===delta);
    const summarized=Object.fromEntries(arms.map(arm=>[arm,Object.fromEntries(metrics.map(m=>[m,stats(group.filter(x=>x.arm===arm).map(x=>x[m]))]))]));
    const paired_speedup=Object.fromEntries(metrics.map(m=>[m,stats(Array.from({length:repetitions},(_,rep)=>group.find(x=>x.arm==="rebuild"&&x.rep===rep)[m]/group.find(x=>x.arm==="incremental"&&x.rep===rep)[m]))]));
    return {delta,arms:summarized,paired_speedup};
  });
  assert.equal(cli.revision(),revision);
  atomic(path.join(result,"results.json"),{status:"COMPLETE",completed_paired_frontiers:deltas.length*repetitions,total_verified_tasks:deltas.length*repetitions*arms.length*tasks,summary,raw:byArm});
}

async function main() {
  if(process.argv[2]==="--check") { fixture(); console.log("Preflight PASS: source revision, prior audit and three cached inputs"); return; }
  if(process.argv[2]==="--worker") { await worker(); return; }
  fs.mkdirSync(result,{recursive:true,mode:0o700});
  atomic(path.join(result,"status.json"),{status:"RUNNING",run_id:RUN_ID,result});
  console.log("RESULT_DIR",result);
  const {output,...execution}=await run(process.execPath,[__filename,"--worker"],{cwd:ROOT,log:path.join(result,"run.log"),timeout:6*60*60*1000});
  const complete=execution.status==="PASS"&&fs.existsSync(path.join(result,"results.json"));
  atomic(path.join(result,"status.json"),{status:complete?"COMPLETE":execution.status==="PASS"?"PARTIAL":execution.status,run_id:RUN_ID,execution});
  if(!complete)process.exitCode=1;
}

main().then(()=>process.exit(process.exitCode||0)).catch(error=>{console.error(error.stack);if(process.argv[2]!=="--check"&&process.argv[2]!=="--worker"&&fs.existsSync(result))atomic(path.join(result,"status.json"),{status:"FAIL",error:error.message});process.exit(1);});
