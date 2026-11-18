"use strict";
const fs=require("fs"),path=require("path");
const {buildMimcSponge}=require("circomlibjs");
const snark=require("snarkjs");
const D=require("./data"),P=require("./protocol"),B=require("./backend"),F=require("./fixtures");
const {OUT,ROOT,save,run,jsonResult}=require("./runtime");
async function primitiveVectors(h,dir) {
  const m=await buildMimcSponge();
  const words=D.recordWords(D.record(1,1,0,{record_salt:"11".repeat(32),valid_until:"18446744073709551615"}));
  const inputs=[[2,[],0],[1,words,0],[7,[...h.hash(1,words),...h.hash(2)],47],[11,[...h.hash(10),...h.hash(10)],31]];
  const vectors={constants:m.cts.map(v=>m.F.toString(v)),vectors:inputs.map(([kind,words,level])=>({kind:String(kind),level:String(level),words:words.map(String),expected:h.hash(kind,words,level)}))};
  const file=path.join(dir,"hash-vectors.json");save(file,vectors);
  return jsonResult(await run(B.BIN,["hash-vectors",file],{quiet:true,log:path.join(dir,"hash-vectors.log")}));
}
async function rejectWitness(input,keys,mutate) {
  const bad=D.clone(input);mutate(bad);
  try {await snark.wtns.calculate(bad,keys.wasm,{type:"mem"});return {rejected:false};}
  catch(e){return {rejected:/Assert Failed/.test(e.message),error:e.message};}
}
async function main() {
  const frozenRevision=require("./cli").revision();
  const dir=path.join(OUT,"prerequisite"),priv=path.join(OUT,"private/prerequisite");
  fs.mkdirSync(dir,{recursive:true});fs.mkdirSync(priv,{recursive:true,mode:0o700});
  save(path.join(dir,"validation.json"),{status:"RUNNING",started_at:new Date().toISOString()});
  const h=await D.hashing(),p=D.profile();
  const vectors=await primitiveVectors(h,dir);
  const psi=await B.psiKeys(p,h,dir),joint=await B.jointKeys(p,dir),keys={psi,joint};
  let src;
  const oldEvents=path.join(OUT,"private/initial/events-6.json");
  if(fs.existsSync(oldEvents))src=F.replay(p,h,[JSON.parse(fs.readFileSync(oldEvents))])[0];
  else {
    src=F.sources(p,h)[0];
    const a=D.clone(src.current.get(1));a.version++;a.updated_at="100";src.apply(2,a);
    const b=D.clone(src.current.get(2));b.version++;b.updated_at="101";b.lifecycle=2;src.apply(3,b);
  }
  save(path.join(priv,"events.json"),src.events.map(e=>({op:e.op,record:e.record})));
  let state;
  const priorLog=path.join(dir,"nova_prove-6.log"),priorProof=path.join(dir,"psi-6.bin");
  if(fs.existsSync(priorLog)&&fs.existsSync(priorProof)) {
    const line=fs.readFileSync(priorLog,"utf8").split("\n").find(l=>l.startsWith("{"));
    if(line){const actual=JSON.parse(line);if(actual.status==="PASS"&&D.equal(actual.statement.output,src.state))state={...actual,file:priorProof,checkpoint:path.join(OUT,"private/initial/ivc-6.bin"),vk_id:psi.vk_id};}
  }
  const cached=path.join(priv,"state/result.json");
  if(!state&&fs.existsSync(cached)) {const previous=JSON.parse(fs.readFileSync(cached));if(previous.vk_id===psi.vk_id&&D.equal(previous.statement.output,src.state)&&fs.existsSync(previous.file)&&B.fileHash(previous.file)===previous.proof_sha256)state={...previous,reused_real_state_proof:true};}
  if(!state)state=await B.proveState(src,psi,path.join(priv,"state"));
  const cachedVerify=await require("./verifier").verify(psi,state.statement,state.file),wrongStatement=D.clone(state.statement);
  wrongStatement.output[2]=String(Number(wrongStatement.output[2])+1);
  const wrongVerify=await require("./verifier").verify(psi,wrongStatement,state.file);
  D.check(cachedVerify?.verified===true&&wrongVerify?.verified===false,"PRELOADED_KEY_REAL_VERIFICATION");
  const cases=[];let modelContext=null;
  for(const [index,name] of ["ALLOW","POLICY_DENY","INSUFFICIENT_SUPPORT"].entries()) {
    const task=D.task(p,`gate-${index}`,{psi_vk_id:psi.vk_id,task_vk_id:joint.vk_id,created_until:name==="POLICY_DENY"?100:11});
    const fixture=F.graph(task,p,[src],{rootRefs:[{source:1,id:1,version:name==="INSUFFICIENT_SUPPORT"?1:2}]});
    const proof=await B.proveTask(fixture.prepared.input,joint,path.join(priv,name));
    const packet=B.bundle(task,p,fixture.prepared,[state],proof),trust=F.trust(p,[src],fixture.registry);
    const checked=await F.independentReceiver(task,packet,trust,keys,path.join(priv,name,"receive"));
    const expected={status:name==="ALLOW"?"ALLOW":"DENY",reason:name==="ALLOW"?0:name==="POLICY_DENY"?1:2};
    const audit=F.auditPacket(packet,[src],fixture.registry);
    const record={name,expected,actual:checked,privacy:audit,pass:checked.status===expected.status&&checked.reason_code===expected.reason&&audit.pass};
    D.check(record.pass,`GATE_${name}`);
    const pub=path.join(dir,"public",name);fs.mkdirSync(pub,{recursive:true});
    save(path.join(pub,"task.json"),task);save(path.join(pub,"bundle.json"),packet);save(path.join(pub,"verification_key.json"),joint.vk);save(path.join(pub,"B-result.json"),checked);
    save(path.join(pub,"trust.json"),{...trust,action_key:undefined,verification_only:true});
    if(name==="ALLOW") {
      const replay=await F.independentReceiver(task,packet,trust,keys,path.join(priv,name,"receive"),{reuse:true});
      record.replay_blocked=replay.status==="INVALID_PROOF"&&!replay.action_authorized;
      D.check(record.replay_blocked,"ACTION_REPLAY");
      const actualLedger=JSON.parse(fs.readFileSync(path.join(priv,name,"receive/B/receiver-state.json")));
      try{require("./receiver").consumeAction(task,checked.action_token,actualLedger);record.action_double_consumption_blocked=false;}
      catch(e){record.action_double_consumption_blocked=e.code==="ACTION_ALREADY_CONSUMED";}
      D.check(record.action_double_consumption_blocked&&checked.action_execution?.executed,"ACTION_SINGLE_CONSUMPTION");
      const bad=D.clone(packet);bad.proof.a[0]="0".repeat(64);
      record.tampered_proof=await F.independentReceiver(task,bad,trust,keys,path.join(priv,name,"forged-proof"));
      D.check(record.tampered_proof.status==="INVALID_PROOF","GROTH16_FORGERY");
      record.interface_checks={};
      for(const field of ["max_risk_score","receiver_id","nonce"]) {
        const changed=D.clone(task);if(field==="nonce")changed.nonce=D.tagged("CHANGED_NONCE",task.nonce);else changed[field]++;
        const actual=await F.independentReceiver(changed,packet,trust,keys,path.join(priv,name,`changed-${field}`));
        record.interface_checks[field]=actual;D.check(actual.status==="INVALID_PROOF",`BINDING_${field}`);
      }
      const stale=D.clone(packet),advanced=new D.Source(1,p,h);for(const e of src.events)advanced.apply(e.op,D.clone(e.record));
      const changed=D.clone(advanced.current.get(1));changed.version++;changed.updated_at="200";advanced.apply(2,changed);
      stale.sources[0].checkpoint=B.wireCP(advanced.checkpoint(task));
      record.interface_checks.skipped_confirmed_update=await F.independentReceiver(task,stale,trust,keys,path.join(priv,name,"skipped-update"));
      D.check(record.interface_checks.skipped_confirmed_update.status==="INVALID_PROOF","STATE_CHECKPOINT_BINDING");
      const substituted=D.clone(packet),raw=Buffer.from(substituted.sources[0].proof,"base64");raw[Math.floor(raw.length/2)]^=1;substituted.sources[0].proof=raw.toString("base64");
      record.interface_checks.tampered_nova=await F.independentReceiver(task,substituted,trust,keys,path.join(priv,name,"tampered-nova"));
      D.check(record.interface_checks.tampered_nova.status==="INVALID_PROOF","NOVA_FORGERY");
      record.negative_constraints={
        forged_decision:await rejectWitness(fixture.prepared.input,joint,b=>b.decision=0),
        omitted_record:await rejectWitness(fixture.prepared.input,joint,b=>{b.selected[0][0]=0;b.qCommit=h.hash(18,[...b.taskDigest,...b.qSalt,...b.selected.flatMap((row,s)=>row.flatMap((hit,r)=>[hit,...h.hash(1,b.records[s][r]).map(v=>hit?v:"0")]))]);}),
        deleted_parent:await rejectWitness(fixture.prepared.input,joint,b=>b.parents[2][0]=1),
        forged_reason:await rejectWitness(fixture.prepared.input,joint,b=>b.reason=2),
      };
      modelContext={verified_assertions:{complete_query_satisfied:true,current_evidence_eligible:true,support_threshold_satisfied:true},policy_result:{decision:"APPROVED",reason_code:0},origin_bundle_sha256:D.SHA(Buffer.from(JSON.stringify(packet)))};
    } else {
      record.negative_constraints={forged_allow:await rejectWitness(fixture.prepared.input,joint,b=>{b.decision=1;b.reason=0;}),
        forged_reason:await rejectWitness(fixture.prepared.input,joint,b=>b.reason=name==="POLICY_DENY"?2:1)};
    }
    D.check(Object.values(record.negative_constraints).every(v=>v.rejected),"MISSING_JOINT_CONSTRAINT");cases.push(record);
    console.log(`CORE GATE ${name}: PASS`);
  }
  const transition=src.events.find(e=>e.op===2).input;
  const jumped=D.clone(transition);jumped.state[2]=String(Number(jumped.state[2])+1);
  const jumpWitness=path.join(priv,"jumped-state.wtns");await snark.wtns.calculate(jumped,psi.wasm,jumpWitness);
  const job={z0:src.genesis,witnesses:[jumpWitness],checkpoint_in:state.checkpoint,checkpoint_out:path.join(priv,"should-not-exist-ivc.bin"),proof_out:path.join(priv,"should-not-exist-proof.bin")};
  const jobFile=path.join(priv,"jumped-state-job.json");save(jobFile,job);
  const negativeNative=await run(B.BIN,["prove",psi.r1cs,psi.params,jobFile],{quiet:true,log:path.join(dir,"negative-recursive-chain.log")});
  const stepChecks={skipped_sequence:{rejected:negativeNative.exit_code!==0&&negativeNative.output.includes("STEP_CHAIN_BINDING"),layer:"Nova recursive public-state binding",standalone_step_satisfiable:true,execution:{...negativeNative,output:undefined}},
    version_rollback:await rejectWitness(transition,psi,b=>b.newRecord[3]=1),
    immutable_object:await rejectWitness(transition,psi,b=>b.newRecord[4]++),
    unknown_operation:await rejectWitness(transition,psi,b=>b.op=4)};
  const tombstone=src.current.get(2),resurrect=D.clone(tombstone);resurrect.version++;resurrect.lifecycle=1;resurrect.updated_at="200";
  const resurrection={state:src.state,op:2,oldCount:4,oldRecord:D.recordWords(tombstone),newRecord:D.recordWords(resurrect),slotSiblings:src.bucket().tree.opening(tombstone.slot_index),directorySiblings:src.directory.opening(BigInt(tombstone.object_id)*65536n+BigInt(tombstone.evidence_type)),logSiblings:src.log.opening(src.events.length)};
  stepChecks.tombstone_resurrection=await rejectWitness(resurrection,psi,()=>{});
  D.check(Object.values(stepChecks).every(v=>v.rejected),"MISSING_STATE_CONSTRAINT");
  save(path.join(priv,"model-context.json"),modelContext);
  D.check(require("./cli").revision()===frozenRevision,"SOURCE_CHANGED_DURING_PREREQUISITE");
  const result={status:cases.every(c=>c.pass)&&Object.values(stepChecks).every(v=>v.rejected)?"PASS":"FAIL",
    completed_at:new Date().toISOString(),source_revision:require("./cli").revision(),profile:p,hash_vectors:vectors,verifier_key_cache_checks:{valid:cachedVerify,wrong_public_statement:wrongVerify},cases,transition_checks:stepChecks,
    psi:{vk_id:psi.vk_id,r1cs_sha256:psi.meta.r1cs_sha256,statement:state.statement,fold_ms:state.fold_ms,export_ms:state.export_ms,proof_bytes:fs.statSync(state.file).size},
    joint:{vk_id:joint.vk_id,r1cs_sha256:joint.meta.r1cs_sha256,constraints:joint.meta.constraints},
    artifacts:{private_dir:priv,keys_file:path.join(priv,"keys.json"),source_events:path.join(priv,"events.json"),state_file:path.join(priv,"state-result.json")}};
  save(result.artifacts.keys_file,keys);save(result.artifacts.state_file,state);save(path.join(dir,"validation.json"),result);
  fs.writeFileSync(path.join(dir,"VALIDATION_REPORT.md"),`# Core prerequisite\n\nStatus: ${result.status}\n\nBackend: real Nova BN254/Grumpkin Pedersen/IPA + compressed zero-knowledge export; one Groth16 Gamma/Lambda circuit.\n\n${cases.map(c=>`- ${c.name}: ${c.actual.status}, reason ${c.actual.reason_code}; independent receiver verified=${c.actual.verified}`).join("\n")}\n\nState operations: CREATE, REVISE and REVOKE. Log depth 32; directory depth 48. Joint constraints: ${joint.meta.constraints}.\n\nPsi fold: ${state.fold_ms} ms; ZK export: ${state.export_ms} ms; serialized proof: ${result.psi.proof_bytes} bytes. Export and verification costs are real and must not be omitted. See validation.json for actual negative constraints, replay, privacy and proof-tampering outcomes. Private recursive IVC state is not an attachment.\n`);
  return result;
}
module.exports={main,primitiveVectors,rejectWitness};
