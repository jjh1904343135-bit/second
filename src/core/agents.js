"use strict";
const fs=require("fs"),path=require("path"),http=require("http");
const D=require("./data"),B=require("./backend"),F=require("./fixtures"),P=require("./protocol"),{ROOT,OUT,RUN_ID,save,run,beginExperiment}=require("./runtime");
const DIR=path.join(OUT,"experiment3"),PRIVATE=path.join(OUT,"private",`experiment3-${RUN_ID}`);
function api(method,route,body) {
  return new Promise((resolve,reject)=>{
    const bytes=body?Buffer.from(JSON.stringify(body)):null;
    const req=http.request({hostname:"127.0.0.1",port:11434,path:route,method,headers:bytes?{"content-type":"application/json","content-length":bytes.length}:{}},r=>{
      let result="";r.on("data",c=>result+=c);r.on("end",()=>{try{if(r.statusCode!==200)throw new Error(`OLLAMA_HTTP_${r.statusCode}: ${result}`);resolve(JSON.parse(result));}catch(e){reject(e);}});
    });req.setTimeout(D.CONFIG.ollama.timeout_seconds*1000,()=>req.destroy(new Error("OLLAMA_TIMEOUT")));req.on("error",reject);if(bytes)req.write(bytes);req.end();
  });
}
function context(result) {
  D.check(result.verified,"UNVERIFIED_MODEL_CONTEXT");
  return {verified_assertions:{complete_query_checked:true,policy_conditions_satisfied:result.reason_code!==1,support_satisfied:result.reason_code===0},policy_result:{status:result.status,reason_code:result.reason_code}};
}
async function trajectory(name,ctx,origin) {
  const model=D.CONFIG.ollama,events=[];
  for(const [role,instruction] of [["A1","概述检索工具已验证的结果。"],["A2","将已验证的结论写成一句可供记忆转述的说明。"],["A3","简要说明结构化交接的策略结果。"]]) {
    const system="你是解释层 Agent。只能解释提供的已验证断言与策略结果。不得推测身份、信用、原始记录或依赖关系。不能执行 Action，也不能写入可信断言。请用一句简洁中文回答。";
    const input={model:model.model,stream:false,think:false,messages:[{role:"system",content:system},{role:"user",content:instruction+"\n"+JSON.stringify(ctx)}],options:{seed:model.seed,temperature:model.temperature,num_predict:model.num_predict,num_ctx:4096}};
    const start=performance.now(),response=await api("POST","/api/chat",input);
    D.check(typeof response.message?.content==="string"&&response.message.content.trim(),"EMPTY_MODEL_OUTPUT");
    events.push({role,actual_input:input,actual_response:response,wall_ms:performance.now()-start,origin_verified_bundle:origin});
    console.log(`OLLAMA ${name} ${role}: ${response.message.content.trim()}`);
  }
  const result={scenario:name,model,events,total_model_wall_ms:events.reduce((n,e)=>n+e.wall_ms,0),frozen_at:new Date().toISOString()};save(path.join(DIR,`${name}-trajectory.json`),result);return result;
}
async function binding(ctx,text) {
  const input={model:D.CONFIG.ollama.model,stream:false,think:false,format:"json",messages:[{role:"system",content:'你是独立事实一致性验证器。只使用给定断言和策略，不使用外部知识，不推测。逐一检查 Output 中每个事实是否获得支持。严格返回 JSON：{"supported":true或false,"claims":[{"text":"事实","status":"SUPPORTED或UNSUPPORTED"}]}。'},{role:"user",content:JSON.stringify({...ctx,output:text})}],options:{seed:D.CONFIG.ollama.seed,temperature:D.CONFIG.ollama.temperature,num_predict:256,num_ctx:4096}};
  const start=performance.now(),response=await api("POST","/api/chat",input),verdict=require("./receiver").strictJSON(response.message.content);
  D.check(typeof verdict.supported==="boolean"&&Array.isArray(verdict.claims)&&verdict.claims.length>0&&verdict.claims.every(c=>typeof c.text==="string"&&["SUPPORTED","UNSUPPORTED"].includes(c.status)),"VERIFIER_OUTPUT_SCHEMA");
  const result={actual_input:input,actual_response:response,verdict,wall_ms:performance.now()-start,result:verdict.supported&&verdict.claims.every(c=>c.status==="SUPPORTED")?"PASS":"FAIL"};save(path.join(DIR,"hallucination-binding.json"),result);return result;
}
async function statesFor(srcs,psi,label,{prior=null}={}) {
  const states=[];for(let i=0;i<srcs.length;i++)states.push(prior&&srcs[i].events.length===prior[i].statement.num_steps?prior[i]:await B.proveState(srcs[i],psi,path.join(PRIVATE,label,`source-${i}`),{resume:prior?.[i]||null}));return states;
}
function plainPacket(packet,prepared) {return {...D.clone(packet),proof:null,plaintext:D.clone(prepared.input)};}
async function replay(name,task,p,srcs,states,keys,trace,{rootRefs,timeout=false}={}) {
  const texts=trace.events.map(e=>e.actual_response.message.content),rows=[];let frozen=null,checkpointSet=null;
  for(const arm of ["RCPEH","PLAIN_COMPLETE"]) {
    const start=performance.now(),fetchStart=performance.now();
    if(timeout) {
      await new Promise(r=>setTimeout(r,D.CONFIG.source_timeout_seconds*1000));
      const result=await F.independentReceiver(task,{complete:false},{profile:p},keys,path.join(PRIVATE,name,arm,"B"));
      rows.push({scenario:name,arm,status:result.status,task_wall_ms:performance.now()-start,source_wait_ms:D.CONFIG.source_timeout_seconds*1000,model_wall_ms:trace.total_model_wall_ms,model_calls_online:0,witness_bytes:0,registration_bytes:0,handoff_bytes:0,actual:result});continue;
    }
    const input_bytes=srcs.reduce((n,s)=>n+Buffer.byteLength(JSON.stringify(s.bucket(task.object_id,task.evidence_type).records)),0),retrieval_ms=performance.now()-fetchStart;
    const registerStart=performance.now(),fx=F.graph(task,p,srcs,{rootRefs,texts,...(frozen||{})});const registration_ms=performance.now()-registerStart;
    if(!frozen){frozen={replayNodes:fx.registry.nodes,qSalt:fx.prepared.input.qSalt,lSalt:fx.prepared.input.lSalt};save(path.join(PRIVATE,name,"frozen-registration.json"),frozen);}
    const registration_bytes=fx.registry.communication.reduce((n,c)=>n+c.request_bytes+c.response_bytes,0),witnessWire=JSON.stringify(fx.prepared.input),witness_bytes=Buffer.byteLength(witnessWire);
    fx.prepared.input=JSON.parse(witnessWire);
    save(path.join(PRIVATE,name,arm,"registration-transcript.json"),fx.registry.communication);
    const trust=F.trust(p,srcs,fx.registry);let packet,proof={witness_ms:0,prove_ms:0};
    if(arm==="RCPEH") {
      proof=await B.proveTask(fx.prepared.input,keys.joint,path.join(PRIVATE,name,arm,"joint"));packet=B.bundle(task,p,fx.prepared,states,proof);
    } else {
      // A Groth16 object is not constructed or timed on the plaintext arm.
      const placeholder={publicSignals:P.publicSignals(fx.prepared.input),proof:{pi_a:[0,0],pi_b:[[0,0],[0,0]],pi_c:[0,0]}};
      packet=plainPacket(B.bundle(task,p,fx.prepared,states,placeholder),fx.prepared);trust.baseline_mode="PLAIN_COMPLETE";
    }
    const checked=await F.independentReceiver(task,packet,trust,keys,path.join(PRIVATE,name,arm,"B"));
    const checkpoints=JSON.stringify({sources:packet.sources,registry:packet.registry_checkpoint,commitments:packet.commitments});
    if(checkpointSet)D.check(checkpointSet===checkpoints,"REPLAY_CHECKPOINTS_DIFFER");else checkpointSet=checkpoints;
    D.check(checked.verified&&checked.status===(fx.answer.decision?"ALLOW":"DENY")&&checked.reason_code===fx.answer.reason,"AGENT_REPLAY_CORRECTNESS");
    const audit=F.auditPacket(packet,srcs,fx.registry);
    const actualLog=fs.readFileSync(path.join(PRIVATE,name,arm,"B/B.log"),"utf8");
    const responseAudit=F.auditPacket({response:checked,log:actualLog},srcs,fx.registry);
    const Bview=path.join(DIR,`${name}-${arm}-B-input.json`);fs.writeFileSync(Bview,JSON.stringify(packet));save(path.join(DIR,`${name}-${arm}-B-output.json`),checked);
    const row={scenario:name,arm,status:checked.status,reason_code:checked.reason_code,task_wall_ms:performance.now()-start,retrieval_ms,registration_ms,joint_witness_ms:proof.witness_ms,joint_prove_ms:proof.prove_ms,B_verify_ms:checked.wall_ms,model_wall_ms:trace.total_model_wall_ms,model_calls_online:0,checkpoint_set_sha256:D.SHA(Buffer.from(checkpoints)),tool_input_bytes:input_bytes,witness_bytes,registration_bytes,handoff_bytes:Buffer.byteLength(JSON.stringify(packet)),audit,response_and_log_audit:responseAudit,B_view:Bview,expected:{decision:fx.answer.decision,reason:fx.answer.reason},actual:checked};
    // The model cannot alter this structured packet; even a missed output-binding
    // check cannot grant a different action. Test the actual B verification again.
    if(arm==="RCPEH"&&name==="normal") {
      const injected="用户信用良好",before=D.SHA(Buffer.from(JSON.stringify(packet))),after=D.SHA(Buffer.from(JSON.stringify(packet)));
      const bindingResult=await binding(context(checked),injected);
      const repeat=await F.independentReceiver(task,packet,trust,keys,path.join(PRIVATE,name,"hallucination/B"));
      row.hallucination={injection_layer:"free-text explanation adapter",actual_model_outputs:texts,injected_output:injected,binding_result:bindingResult,assumed_binding_verdict_for_action_test:"PASS",packet_sha256_before:before,packet_sha256_after:after,B_result:repeat,pass:before===after&&repeat.status===checked.status&&repeat.action_token===checked.action_token};
      D.check(row.hallucination.pass,"HALLUCINATION_CHANGED_ACTION");
    }
    rows.push(row);
  }
  return rows;
}
async function privacyPair(p,h,keys,baseStates,baseSources,trace) {
  const rows=[];
  for(const [label,hits,topology] of [["sparse",1,"short"],["dense",4,"diamond_single"]]) {
    const srcs=F.sources(p,h,{history:4,occupancy:4,hits});
    const states=await statesFor(srcs,keys.psi,`pair-${label}`),task=D.task(p,"paired-same-task",{psi_vk_id:keys.psi.vk_id,task_vk_id:keys.joint.vk_id});
    const fx=F.graph(task,p,srcs,{topology,registryLength:12,texts:trace.events.map(e=>e.actual_response.message.content)}),proof=await B.proveTask(fx.prepared.input,keys.joint,path.join(PRIVATE,`pair-${label}/joint`));
    const packet=B.bundle(task,p,fx.prepared,states,proof),checked=await F.independentReceiver(task,packet,F.trust(p,srcs,fx.registry),keys,path.join(PRIVATE,`pair-${label}/B`));
    D.check(checked.status==="ALLOW","PRIVACY_PAIR_DECISION");const file=path.join(DIR,`pair-${label}-B-input.json`);fs.writeFileSync(file,JSON.stringify(packet));
    rows.push({label,Q_hits:fx.answer.Q.length,ancestor_nodes:fx.answer.visited.length+1,decision:checked.status,reason_code:checked.reason_code,bytes:Buffer.byteLength(JSON.stringify(packet)),attachments:packet.sources.length+1,fields:Object.keys(packet),source_checkpoint_lengths:packet.sources.map(v=>v.checkpoint.log_length),registry_length:packet.registry_checkpoint.registry_length,root_wire_bytes:64*2,audit:F.auditPacket(packet,srcs,fx.registry),file});
  }
  const result={rows,same_task:true,same_capacity:true,equal_bytes:rows[0].bytes===rows[1].bytes,equal_attachments:rows[0].attachments===rows[1].attachments,explanation:"Roots and commitments differ in content but use fixed-width field encoding. Public source and registry checkpoint lengths are reported separately. Audit is an engineering disclosure check, not a substitute for the ZK argument."};
  save(path.join(DIR,"privacy-pair.json"),result);return result;
}
async function worker() {
  fs.mkdirSync(DIR,{recursive:true});fs.mkdirSync(PRIVATE,{recursive:true,mode:0o700});
  const tags=await api("GET","/api/tags"),actual=tags.models.find(m=>m.name===D.CONFIG.ollama.model);D.check(actual&&actual.digest===D.CONFIG.ollama.digest,"MODEL_DIGEST_MISMATCH");
  save(path.join(DIR,"model-version.json"),{actual,version:await api("GET","/api/version"),parameters:D.CONFIG.ollama});
  const p=D.profile(3,16,16),h=await D.hashing(),psi=await B.psiKeys(p,h,DIR),joint=await B.jointKeys(p,DIR),keys={psi,joint};
  const srcs=F.sources(p,h,{history:4}),maintenance=performance.now(),states=await statesFor(srcs,psi,"initial");
  save(path.join(DIR,"initial-maintenance.json"),{wall_ms:performance.now()-maintenance,states:states.map(s=>({fold_ms:s.fold_ms,export_ms:s.export_ms,witness_ms:s.witness_ms,proof_bytes:s.proof_bytes}))});
  const all=[];let normalTrace;
  for(const name of ["normal","adverse_update","stale_memory","source_timeout"]) {
    let current=srcs,state=states,refs;
    if(name==="adverse_update"||name==="stale_memory") {
      current=F.replay(p,h,srcs.map(s=>s.events.map(e=>({op:e.op,record:e.record}))));
      const r=D.clone(current[0].current.get(1));r.version++;r.updated_at="1001";if(name==="adverse_update")r.business.risk_score=9999;current[0].apply(2,r);
      const chase=performance.now();state=await statesFor(current,psi,name,{prior:states});save(path.join(DIR,`${name}-catchup.json`),{wall_ms:performance.now()-chase,fold_ms:state[0].fold_ms,export_ms:state[0].export_ms,counted_in_online:true});
      if(name==="stale_memory")refs=[{source:1,id:1,version:1}];
    }
    const task=D.task(p,`agents-${name}`,{psi_vk_id:psi.vk_id,task_vk_id:joint.vk_id});let trace;
    if(name==="source_timeout"){trace={events:[],total_model_wall_ms:0,model_calls:0,note:"No verified assertions are available; no LLM call is made."};save(path.join(DIR,`${name}-trajectory.json`),trace);}
    else {
      const start=performance.now(),fx=F.graph(task,p,current,{rootRefs:refs}),proof=await B.proveTask(fx.prepared.input,joint,path.join(PRIVATE,name,"context-tool")),packet=B.bundle(task,p,fx.prepared,state,proof);
      const verified=await F.independentReceiver(task,packet,{...F.trust(p,current,fx.registry),verification_only:true},keys,path.join(PRIVATE,name,"context-tool/B"));
      trace=await trajectory(name,context(verified),D.SHA(Buffer.from(JSON.stringify(packet))));trace.offline_verification_tool_ms=performance.now()-start-trace.total_model_wall_ms;save(path.join(DIR,`${name}-trajectory.json`),trace);
    }
    if(name==="normal")normalTrace=trace;
    const rows=await replay(name,task,p,current,state,keys,trace,{rootRefs:refs,timeout:name==="source_timeout"});
    const chaseFile=path.join(DIR,`${name}-catchup.json`),catchup=fs.existsSync(chaseFile)?JSON.parse(fs.readFileSync(chaseFile)).wall_ms:0;
    for(const row of rows){row.catchup_ms=catchup;row.shared_catchup_measurement=catchup>0;row.task_wall_ms+=catchup;row.live_trajectory_plus_replay_ms=row.task_wall_ms+trace.total_model_wall_ms+(trace.offline_verification_tool_ms||0);all.push(row);fs.appendFileSync(path.join(DIR,"raw.jsonl"),JSON.stringify(row)+"\n");}
  }
  const pair=await privacyPair(p,h,keys,states,srcs,normalTrace);
  await run("ollama",["ps"],{quiet:true,log:path.join(DIR,"ollama-ps-after.log")});
  const modelsSafe=fs.readdirSync(DIR).filter(n=>n.endsWith("-trajectory.json")).every(n=>{const t=JSON.parse(fs.readFileSync(path.join(DIR,n)));return t.events.every(e=>Object.keys(JSON.parse(e.actual_input.messages[1].content.slice(e.actual_input.messages[1].content.indexOf("{")))).sort().join(",")==="policy_result,verified_assertions");});
  const result={status:"COMPLETE",rows:all,model_input_whitelist_pass:modelsSafe,privacy_pair:pair,hallucination_cannot_change_action:all.find(r=>r.hallucination)?.hallucination.pass};save(path.join(DIR,"results.json"),result);return result;
}
async function main() {
  beginExperiment("experiment3");save(path.join(DIR,"input-manifest.json"),{run_id:RUN_ID,private_input_directory:PRIVATE,config:D.CONFIG,scenarios:["normal","adverse_update","stale_memory","source_timeout"],source_revision:require("./cli").revision(),trace_policy:"Real model calls frozen before paired replays; no raw records, witness, paths or free text in RCPEH B packet."});
  const result=await run(process.execPath,[__filename,"--worker"],{quiet:true,timeout:12*3600000,log:path.join(DIR,"full_run.log")});
  if(result.status!=="PASS")save(path.join(DIR,"status.json"),{status:result.status,execution:{...result,output:undefined}});return result;
}
if(require.main===module&&process.argv[2]==="--worker")worker().then(()=>process.exit(0)).catch(e=>{console.error(e.stack);process.exit(1);});
module.exports={main,worker,api,context,trajectory,replay,privacyPair};
