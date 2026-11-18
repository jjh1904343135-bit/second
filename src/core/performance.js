"use strict";
const fs=require("fs"),path=require("path");
const D=require("./data"),F=require("./fixtures"),B=require("./backend"),{ROOT,OUT,RUN_ID,run,save,beginExperiment}=require("./runtime");
const DIR=path.join(OUT,"experiment2");
function matrix() {
  const main=[3,16,16],base={capacity:main,history:64,lag:0,tasks:1,topology:"default",hits:4};
  return [
    ...D.CONFIG.profiles.map(c=>({...base,id:`capacity-${c.join("-")}`,scan:"capacity",capacity:c})),
    ...D.CONFIG.history_sizes.map(n=>({...base,id:`history-${n}`,scan:"history",history:n})),
    ...D.CONFIG.lag_sizes.map(n=>({...base,id:`lag-${n}`,scan:"lag",lag:n})),
    ...D.CONFIG.task_counts.map(n=>({...base,id:`tasks-${n}`,scan:"tasks",tasks:n})),
    ...D.CONFIG.graph_fixtures.map(n=>({...base,id:`graph-${n}`,scan:"graph",topology:n})),
    ...D.CONFIG.hit_counts.map(n=>({...base,id:`hits-${n}`,scan:"hits",hits:n,occupancy:16}))];
}
async function worker(config,dir,options={}) {
  const p=D.profile(...config.capacity),h=await D.hashing();const started=performance.now();
  const emit=row=>fs.appendFileSync(path.join(dir,"raw.jsonl"),JSON.stringify({...row,recorded_at:new Date().toISOString()})+"\n");
  const setupStart=performance.now(),psi=await B.psiKeys(p,h,dir),joint=await B.jointKeys(p,dir),keys={psi,joint};
  const offline_setup_ms=performance.now()-setupStart;
  const accounting=require("./accounting").account(joint.dir,joint.meta.constraints);
  emit({stage:"offline_setup",wall_ms:offline_setup_ms,psi_setup:psi.setup,joint_setup:joint.setup,compile_psi:psi.meta.compile,compile_joint:joint.meta.compile,cache:{psi:psi.meta.reused,joint:joint.meta.reused},accounting});
  save(path.join(dir,"verification_key.json"),joint.vk);
  const privateDir=path.join(OUT,"private",`experiment2-${RUN_ID}`,config.id);fs.mkdirSync(privateDir,{recursive:true,mode:0o700});
  // Shared immutable data for paired arms. Every measurement creates fresh actual proofs.
  const srcs=F.sources(p,h,{history:config.history,occupancy:config.occupancy||4,hits:config.hits});
  save(path.join(privateDir,"events.json"),srcs.map(s=>s.events.map(e=>({op:e.op,record:e.record}))));
  let maintained=[];const maintainedSources=[],frozenGraphs=new Map();const maintenanceStart=performance.now();
  // Preserve source identities when reconstructing each cached frontier.
  for(let i=0;i<srcs.length;i++) {
    const s=new D.Source(i+1,p,h);for(const e of srcs[i].events.slice(0,Math.max(0,srcs[i].events.length-config.lag)))s.apply(e.op,D.clone(e.record));
    maintainedSources.push(s);maintained.push(await B.proveState(s,psi,path.join(privateDir,`maintained-${i}`)));
  }
  const initial_maintenance_ms=performance.now()-maintenanceStart;
  emit({stage:"initial_maintenance",wall_ms:initial_maintenance_ms,states:maintained.map(s=>({fold_ms:s.fold_ms,export_ms:s.export_ms,witness_ms:s.witness_ms,proof_bytes:s.proof_bytes}))});
  const taskRun=async(arm,rep,warmup)=>{
    const wall=performance.now();let prior=maintained;const stages=[];
    for(let m=0;m<config.tasks;m++) {
      const at=performance.now();let states,state_index_ms=0;
      if(arm==="rebuild"||m===0&&config.lag>0) {
        const indexStart=performance.now();let workSources;
        if(arm==="rebuild")workSources=F.replay(p,h,srcs.map(s=>s.events.map(e=>({op:e.op,record:e.record}))));
        else workSources=maintainedSources.map((s,i)=>{const copy=s.fork();for(const e of srcs[i].events.slice(s.events.length))copy.apply(e.op,D.clone(e.record));return copy;});
        state_index_ms=performance.now()-indexStart;
        states=[];for(let i=0;i<srcs.length;i++)states.push(await B.proveState(workSources[i],psi,path.join(privateDir,`${arm}-${rep}-${m}-source-${i}`),{resume:arm==="reuse"?prior[i]:null}));
      } else states=prior;
      prior=states;const state_ms=performance.now()-at,task=D.task(p,`${config.id}-${rep}-${m}`,{psi_vk_id:psi.vk_id,task_vk_id:joint.vk_id,max_risk_score:5000+m});
      const refs=config.topology.endsWith("two")?[{source:1,id:1,version:srcs[0].current.get(1).version},{source:2,id:1,version:srcs[1].current.get(1).version}]:undefined;
      const graphKey=`${rep}-${m}`,wit=performance.now(),fx=F.graph(task,p,srcs,{topology:config.topology,rootRefs:refs,...(frozenGraphs.get(graphKey)||{})});const witness_prepare_ms=performance.now()-wit;
      if(!frozenGraphs.has(graphKey))frozenGraphs.set(graphKey,{replayNodes:fx.registry.nodes,qSalt:fx.prepared.input.qSalt,lSalt:fx.prepared.input.lSalt});
      const proof=await B.proveTask(fx.prepared.input,joint,path.join(privateDir,`${arm}-${rep}-${m}-joint`));
      const packet=B.bundle(task,p,fx.prepared,states,proof),b=await F.independentReceiver(task,packet,F.trust(p,srcs,fx.registry),keys,path.join(privateDir,`${arm}-${rep}-${m}-B`));
      D.check(b.verified&&b.status===(fx.answer.decision?"ALLOW":"DENY"),"BENCHMARK_CORRECTNESS");
      const graphNodes=fx.registry.nodes.filter(n=>fx.answer.visited.includes(n.seq)||n.op===6);
      const occurrences=(function count(n){return n.kind===1?1:n.parents.reduce((a,id)=>a+count(fx.registry.nodes[id-1]),0);})(fx.registry.nodes.at(-1));
      stages.push({state_online_ms:state_ms,state_index_ms,psi_witness_ms:states.reduce((a,s)=>a+(arm==="rebuild"||m===0&&config.lag?s.witness_ms||0:0),0),psi_fold_ms:states.reduce((a,s)=>a+(arm==="rebuild"||m===0&&config.lag?s.fold_ms||0:0),0),psi_export_ms:states.reduce((a,s)=>a+(arm==="rebuild"||m===0&&config.lag?s.export_ms||0:0),0),witness_prepare_ms,wtns_ms:proof.witness_ms,joint_prove_ms:proof.prove_ms,B_verify_ms:b.wall_ms,packet_bytes:Buffer.byteLength(JSON.stringify(packet)),constraints:joint.meta.constraints,graph_nodes:graphNodes.length,unique_roots:fx.answer.L.length,root_reference_occurrences:occurrences,duplicate_ratio:occurrences?1-fx.answer.L.length/occurrences:0,Q_hits:fx.answer.Q.length});
      save(path.join(dir,`${arm}-${rep}-${m}-bundle.json`),packet);
      emit({stage:"task_completed",measurement_stage:warmup?"warmup":"sample",arm,rep,task_index:m,metrics:stages.at(-1),elapsed_configuration_ms:performance.now()-started});
    }
    const result={stage:warmup?"warmup":"sample",arm,rep,tasks:config.tasks,wall_ms:performance.now()-wall,stages,elapsed_configuration_ms:performance.now()-started};
    emit(result);return result;
  };
  if(options.calibration) {
    const reuse=await taskRun("reuse","calibration",false);
    const rebuild=await taskRun("rebuild","calibration",false);
    const initialization_ms=offline_setup_ms+initial_maintenance_ms;
    const measured_pair_ms=reuse.wall_ms+rebuild.wall_ms;
    // A benchmark point includes its configured warm-up pair in the same wall
    // clock budget. Do not derive a deadline that silently excludes it.
    const measured_pairs=D.CONFIG.benchmark.warmups+D.CONFIG.benchmark.repetitions;
    const ten_pair_ms=measured_pairs*measured_pair_ms;
    const estimated_total_ms=initialization_ms+ten_pair_ms;
    const recommended_timeout_seconds=Math.ceil(estimated_total_ms*D.CONFIG.benchmark.budget_margin_ratio/1000);
    const calibration={status:"COMPLETE",profile:config.capacity,history:config.history,lag:config.lag,tasks:config.tasks,
      initialization_ms,offline_setup_ms,initial_maintenance_ms,reuse_one_run_ms:reuse.wall_ms,rebuild_one_run_ms:rebuild.wall_ms,
      warmups:D.CONFIG.benchmark.warmups,repetitions:D.CONFIG.benchmark.repetitions,measured_pairs,budget_margin_ratio:D.CONFIG.benchmark.budget_margin_ratio,
      pair_one_run_ms:measured_pair_ms,estimated_budget_ms:estimated_total_ms,recommended_configuration_timeout_seconds:recommended_timeout_seconds};
    save(path.join(dir,"calibration.json"),calibration);save(path.join(dir,"complete.json"),{status:"COMPLETE",wall_ms:performance.now()-started,calibration});return calibration;
  }
  for(let w=0;w<D.CONFIG.benchmark.warmups;w++)for(const arm of ["reuse","rebuild"])await taskRun(arm,`warmup-${w}`,true);
  for(let rep=0;rep<D.CONFIG.benchmark.repetitions;rep++)for(const arm of ["reuse","rebuild"])await taskRun(arm,rep,false);
  save(path.join(dir,"complete.json"),{status:"COMPLETE",wall_ms:performance.now()-started});
}
async function calibration() {
  const id="main-3-16-16",config={id,scan:"calibration",capacity:[3,16,16],history:64,lag:0,tasks:1,topology:"default",hits:4};
  const dir=beginExperiment("experiment2-calibration");
  save(path.join(dir,"input-manifest.json"),{run_id:RUN_ID,config:D.CONFIG,calibration_config:config,source_revision:require("./cli").revision(),method:"one actual reuse arm and one actual genesis-rebuild arm; recommendation = (initialization + repetitions × pair wall time) × margin"});
  const r=await run(process.execPath,[__filename,"--calibration-worker",JSON.stringify(config),dir],{quiet:true,timeout:D.CONFIG.benchmark.calibration_timeout_seconds*1000,log:path.join(dir,"full_run.log")});
  const complete=fs.existsSync(path.join(dir,"calibration.json"))?JSON.parse(fs.readFileSync(path.join(dir,"calibration.json"))):null;
  save(path.join(dir,"status.json"),{status:complete&&r.status==="PASS"?"COMPLETE":r.status,execution:{...r,output:undefined},calibration:complete});
  if(!complete||r.status!=="PASS")throw Object.assign(new Error("EXPERIMENT2_CALIBRATION_INCOMPLETE"),{execution:r});
  return complete;
}
async function main(options={}) {
  const experimentName=options.experimentName||"experiment2",outputDir=path.join(OUT,experimentName),configs=options.configs||matrix();
  beginExperiment(experimentName);save(path.join(outputDir,"input-manifest.json"),{run_id:RUN_ID,private_input_directory:path.join(OUT,"private",`${experimentName}-${RUN_ID}`),config:D.CONFIG,matrix:configs,source_revision:require("./cli").revision(),seed:D.CONFIG.security_seed_start,method:"single-variable scans; ten fresh proofs per arm after one warmup; hard configuration budget includes setup and maintenance"});
  const rows=[];let capacityBoundary=null;
  for(const c of configs) {
    const dir=path.join(outputDir,c.id);fs.mkdirSync(dir,{recursive:true});save(path.join(dir,"config.json"),c);
    if(capacityBoundary) {const r={id:c.id,status:"NOT_RUN",reason:`Resource boundary at ${capacityBoundary}; larger and main-profile scans require that profile`,completed_samples:0};save(path.join(dir,"status.json"),r);rows.push(r);continue;}
    console.log(`BENCHMARK ${c.id}: budget ${D.CONFIG.benchmark.configuration_timeout_seconds}s`);
    const r=await run(process.execPath,[__filename,"--worker",path.join(dir,"config.json"),dir],{quiet:true,timeout:D.CONFIG.benchmark.configuration_timeout_seconds*1000,log:path.join(dir,"full_run.log")});
    const raw=fs.existsSync(path.join(dir,"raw.jsonl"))?fs.readFileSync(path.join(dir,"raw.jsonl"),"utf8").trim().split("\n").filter(Boolean).map(JSON.parse):[];
    const samples=raw.filter(v=>v.stage==="sample"),done=fs.existsSync(path.join(dir,"complete.json"));
    const status=done&&r.status==="PASS"?"COMPLETE":r.status==="PASS"?"PARTIAL":r.status;
    const row={id:c.id,status,completed_samples:samples.length,expected_samples:20,execution:{...r,output:undefined}};save(path.join(dir,"status.json"),row);rows.push(row);
    const compiledProfile=D.profile(...c.capacity),keyFile=path.join(B.BUILD,`joint-${compiledProfile.id}-FULL/final.zkey`);
    if(c.scan==="capacity"&&(status==="RESOURCE_LIMIT"||status==="FAIL"||status==="TIMEOUT"&&!fs.existsSync(keyFile)))capacityBoundary=c.id;
    console.log(`BENCHMARK ${c.id}: ${status}, samples ${samples.length}/20`);
  }
  save(path.join(outputDir,"results.json"),{status:rows.every(v=>v.status==="COMPLETE")?"COMPLETE":"PARTIAL",rows});
  return rows;
}
async function mainOnly() {
  const config=matrix().find(c=>c.id==="capacity-3-16-16");
  D.check(config,"MAIN_BENCHMARK_CONFIGURATION_MISSING");
  return main({experimentName:"experiment2-main",configs:[config]});
}
if(require.main===module&&process.argv[2]==="--worker") {
  process.env.CORE_DEADLINE_MS=String(Date.now()+D.CONFIG.benchmark.configuration_timeout_seconds*1000);
  worker(JSON.parse(fs.readFileSync(process.argv[3])),process.argv[4]).then(()=>process.exit(0)).catch(e=>{console.error(e.stack);process.exit(1);});
}
if(require.main===module&&process.argv[2]==="--calibration-worker") {
  process.env.CORE_DEADLINE_MS=String(Date.now()+D.CONFIG.benchmark.calibration_timeout_seconds*1000);
  worker(JSON.parse(process.argv[3]),process.argv[4],{calibration:true}).then(()=>process.exit(0)).catch(e=>{console.error(e.stack);process.exit(1);});
}
module.exports={main,mainOnly,matrix,worker,calibration};
