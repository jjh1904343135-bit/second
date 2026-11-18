"use strict";
const fs=require("fs"),path=require("path"),crypto=require("crypto"),snark=require("snarkjs");
const D=require("./data"),P=require("./protocol"),B=require("./backend");
const {save,run,jsonResult}=require("./runtime");
const exact=(value,keys)=>D.check(value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).sort().join(",")===[...keys].sort().join(","),"SCHEMA_WHITELIST");
function strictJSON(text) {
  let cursor=0;
  const white=()=>{while(/\s/.test(text[cursor]||"x"))cursor++;};
  const string=()=>{const start=cursor++;while(cursor<text.length){const c=text[cursor++];if(c==="\\")cursor++;else if(c==='"')return JSON.parse(text.slice(start,cursor));}throw new Error("JSON_STRING");};
  function value(depth=0) {
    D.check(depth<128,"JSON_DEPTH");white();
    if(text[cursor]==="{") {
      cursor++;white();const seen=new Set();if(text[cursor]==="}"){cursor++;return;}
      while(cursor<text.length) {
        white();D.check(text[cursor]==='"',"JSON_KEY");const key=string();D.check(!seen.has(key),"DUPLICATE_JSON_FIELD");seen.add(key);
        white();D.check(text[cursor++]===':',"JSON_COLON");value(depth+1);white();
        if(text[cursor]==="}"){cursor++;return;}D.check(text[cursor++]===",","JSON_COMMA");
      }
    } else if(text[cursor]==="[") {
      cursor++;white();if(text[cursor]==="]"){cursor++;return;}
      while(cursor<text.length){value(depth+1);white();if(text[cursor]==="]"){cursor++;return;}D.check(text[cursor++]===",","JSON_ARRAY_COMMA");}
    } else if(text[cursor]==='"')string();
    else {const start=cursor;while(cursor<text.length&&!/[\s,}\]]/.test(text[cursor]))cursor++;D.check(cursor>start,"JSON_TOKEN");}
  }
  value();white();D.check(cursor===text.length,"JSON_TRAILING");return JSON.parse(text);
}
function validateTask(task,p,keys) {
  exact(task,["protocol","profile_id","time_domain","receiver_id","nonce","issued_at","evaluation_time","deadline","object_id","evidence_type","registry_id","created_from","created_until","max_risk_score","purpose_bit","min_support_groups","require_each_source_nonempty","required_sources","source_groups","psi_vk_id","task_vk_id"]);
  D.check(task.protocol===D.CONFIG.protocol&&task.profile_id===p.id&&task.time_domain==="VIRTUAL_SECONDS","TASK_PROFILE");
  D.check(task.psi_vk_id===keys.psi.vk_id&&task.task_vk_id===keys.joint.vk_id,"TASK_KEY_IDS");
  D.check(/^[0-9a-f]{64}$/.test(task.nonce),"TASK_NONCE");
  for(const k of ["receiver_id","object_id","evidence_type","registry_id","max_risk_score","purpose_bit","min_support_groups"])
    D.check(Number.isSafeInteger(task[k])&&task[k]>=0&&task[k]<2**32,"TASK_INTEGER");
  D.check(task.registry_id===8001&&task.evidence_type<2**16&&task.purpose_bit<32&&task.min_support_groups>=1&&task.min_support_groups<=3&&task.max_risk_score<=10000,"TASK_RULES");
  for(const k of ["issued_at","evaluation_time","deadline","created_from","created_until"])D.limbs(task[k]);
  D.check(BigInt(task.issued_at)<=BigInt(task.evaluation_time)&&BigInt(task.evaluation_time)<=BigInt(task.deadline)&&BigInt(task.created_from)<BigInt(task.created_until),"TASK_TIMES");
  D.check(typeof task.require_each_source_nonempty==="boolean"&&task.required_sources.length===p.sources&&task.source_groups.length===p.sources,"TASK_SOURCES");
  task.required_sources.forEach((id,i)=>{D.check(Number.isInteger(id)&&id>0&&id<2**32&&(!i||id>task.required_sources[i-1]),"SOURCE_ORDER");
    exact(task.source_groups[i],["source_id","group_id"]);D.check(task.source_groups[i].source_id===id&&Number.isInteger(task.source_groups[i].group_id)&&task.source_groups[i].group_id>0,"SOURCE_GROUP");});
}
function consumeAction(task,token,state,now=task.issued_at+3) {
  const grant=state.grants?.[token];
  D.check(grant&&grant.task_digest===D.tagged("TASK",task),"ACTION_TASK_BINDING");
  D.check(!grant.consumed,"ACTION_ALREADY_CONSUMED");D.check(BigInt(now)<=BigInt(grant.deadline),"ACTION_EXPIRED");
  grant.consumed=true;return {executed:true,task_digest:grant.task_digest};
}
async function receive(task,packet,trust,keys,work,{removedBinding=null,state=null}={}) {
  const started=performance.now();let stage="TASK";const timings={};
  state=state||{used:[],marks:{}};
  try {
    validateTask(task,trust.profile,keys);const p=trust.profile;
    D.check(BigInt(task.deadline)>=BigInt(trust.now_virtual??task.issued_at+3),"TASK_EXPIRED");
    if(!packet||packet.complete===false)return {status:"UNAVAILABLE",stage:"MISSING_RESPONSE",action_authorized:false};
    D.check(!removedBinding||p.ablation==="NO_BINDING","LAB_ONLY_BINDING_ABLATION");
    const plain=trust.baseline_mode==="PLAIN_COMPLETE";
    exact(packet,["protocol","profile_id","complete","sources","registry_checkpoint","payload","commitments","public_signals","proof",...(plain?["plaintext"]:[])]);
    D.check(packet.protocol===D.CONFIG.protocol&&packet.profile_id===p.id&&packet.complete===true,"BUNDLE_PROFILE");
    const nonceKey=`${task.receiver_id}:${task.nonce}`;D.check(!state.used.includes(nonceKey),"NONCE_CONSUMED");
    D.check(B.fileHash(path.join(keys.psi.params,"vk.bin"))===keys.psi.vk_id&&B.fileHash(path.join(keys.joint.dir,"verification_key.json"))===keys.joint.vk_id,"TRUSTED_KEY_FILES");
    D.check(Array.isArray(packet.sources)&&packet.sources.length===p.sources,"SOURCE_COVERAGE");
    fs.mkdirSync(work,{recursive:true,mode:0o700});const h=await D.hashing();
    const verified=[],sourceCheckpoints=[];
    for(let i=0;i<p.sources;i++) {
      stage="SOURCE_SIGNATURE";
      const item=packet.sources[i];exact(item,["checkpoint","statement","proof"]);
      exact(item.checkpoint,["profile_id","source_id","key_epoch","log_length","log_root","confirmed_at","task_digest","receiver_id","nonce","signature"]);
      exact(item.statement,["profile_id","source_id","length","log_root","state_root"]);
      const cp=B.readCP(item.checkpoint),statement={...item.statement,log_root:B.rootRead(item.statement.log_root),state_root:B.rootRead(item.statement.state_root)};
      D.check(cp.source_id===task.required_sources[i]&&cp.profile_id===p.id&&cp.key_epoch===1,"SOURCE_ID");
      const {signature,...body}=cp;D.check(D.verify(trust.source_public_keys[i],D.tagged("SOURCE_CP",body),signature),"SOURCE_SIGNATURE");
      if(!["task","receiver_nonce"].includes(removedBinding))D.check(cp.task_digest===D.tagged("TASK",task),"SOURCE_TASK_BINDING");
      if(removedBinding!=="receiver_nonce")D.check(cp.receiver_id===task.receiver_id&&cp.nonce===task.nonce,"SOURCE_CHALLENGE_BINDING");
      D.check(cp.confirmed_at>=task.issued_at&&cp.confirmed_at<=task.issued_at+5,"CONFIRMATION_WINDOW");
      D.check(Number.isSafeInteger(cp.log_length)&&cp.log_length>=0&&cp.log_length<2**32&&(state.marks[cp.source_id]||0)<=cp.log_length,"SOURCE_FRONTIER");
      stage="PSI_CHECKPOINT_BINDING";
      D.check(statement.profile_id===p.psi_id&&statement.source_id===cp.source_id,"PSI_SOURCE_PROFILE");
      if(removedBinding!=="state_checkpoint")D.check(statement.length===cp.log_length&&D.equal(statement.log_root,cp.log_root),"PSI_CHECKPOINT_FRONTIER");
      const genesis=[String(p.psi_id),String(cp.source_id),"0",...new D.Tree(32,11,h.hash(10),h).root,...new D.Tree(48,7,h.hash(6),h).root];
      const publicState=[String(p.psi_id),String(cp.source_id),String(statement.length),...statement.log_root,...statement.state_root];
      const expected={num_steps:statement.length,z0:genesis,output:publicState};
      if(statement.length===0) {
        D.check(item.proof==="EMPTY_STATE"&&D.equal(publicState,genesis),"CANONICAL_EMPTY_STATE");
      } else {
        stage="NOVA_VERIFY";D.check(typeof item.proof==="string"&&item.proof.length<=65536&&/^[A-Za-z0-9+/]*={0,2}$/.test(item.proof),"NOVA_PROOF_ENCODING");
        const file=path.join(work,`psi-${i}.bin`),manifest=path.join(work,`psi-${i}.json`);fs.writeFileSync(file,Buffer.from(item.proof,"base64"));save(manifest,expected);
        const cached=await require("./verifier").verify(keys.psi,expected,file);
        if(cached){D.check(cached.verified,"NOVA_VERIFY");save(path.join(work,`verify-psi-${i}.json`),cached);timings[`psi_${i}_wall_ms`]=cached.wall_ms;}
        else {const execution=await run(B.BIN,["verify",keys.psi.params,manifest,file],{quiet:true,log:path.join(work,`verify-psi-${i}.log`)});
          const native=jsonResult(execution);D.check(native.verified,"NOVA_VERIFY");timings[`psi_${i}_wall_ms`]=execution.wall_ms;}
      }
      verified.push(statement);sourceCheckpoints.push(cp);
    }
    stage="REGISTRY_SIGNATURE";
    exact(packet.registry_checkpoint,["profile_id","registry_id","key_epoch","registry_length","registry_root","task_digest","receiver_id","nonce","confirmed_at","handoff_node_commit","handoff_content_commit","signature"]);
    const rcp=B.readCP(packet.registry_checkpoint),{signature,...body}=rcp;
    D.check(rcp.profile_id===p.id&&rcp.registry_id===task.registry_id&&rcp.key_epoch===1&&D.verify(trust.registry_public_key,D.tagged("REGISTRY_CP",body),signature),"REGISTRY_SIGNATURE");
    if(!["task","receiver_nonce"].includes(removedBinding))D.check(rcp.task_digest===D.tagged("TASK",task),"REGISTRY_TASK_BINDING");
    if(removedBinding!=="receiver_nonce")D.check(rcp.receiver_id===task.receiver_id&&rcp.nonce===task.nonce,"REGISTRY_CHALLENGE_BINDING");
    D.check(rcp.confirmed_at>=task.issued_at&&rcp.confirmed_at<=task.issued_at+5,"REGISTRY_CONFIRMATION");
    stage="PAYLOAD_BINDING";
    const value=packet.payload;exact(value,["schema_version","task_digest","receiver_id","object_id","decision","reason_code","deadline"]);
    if(!["task","receiver_nonce"].includes(removedBinding))D.check(value.task_digest===D.tagged("TASK",task),"PAYLOAD_TASK");
    if(removedBinding!=="task")D.check(value.object_id===task.object_id&&value.deadline===String(task.deadline),"PAYLOAD_OBJECT_DEADLINE");
    if(removedBinding!=="receiver_nonce")D.check(value.receiver_id===task.receiver_id,"PAYLOAD_RECEIVER");
    D.check(value.schema_version===1&&[0,1].includes(value.decision)&&[0,1,2].includes(value.reason_code),"PAYLOAD_RESULT");
    if(removedBinding!=="payload")D.check(D.equal(P.outputCommit(task,value,h),rcp.handoff_content_commit),"PAYLOAD_CONTENT");
    exact(packet.commitments,["q","l"]);
    const expected={profileId:p.id,sourceIds:task.required_sources,logLengths:sourceCheckpoints.map(c=>c.log_length),logRoots:sourceCheckpoints.map(c=>c.log_root),stateRoots:verified.map(s=>s.state_root),
      registryRoot:rcp.registry_root,registryLength:rcp.registry_length,handoffNode:rcp.handoff_node_commit,handoffCommit:rcp.handoff_content_commit,taskDigest:D.u32words(D.tagged("TASK",task)),
      objectId:task.object_id,evidenceType:task.evidence_type,lower:D.limbs(task.created_from),upper:D.limbs(task.created_until),evaluation:D.limbs(task.evaluation_time),deadline:D.limbs(task.deadline),
      maxRisk:task.max_risk_score,purposeBit:task.purpose_bit,minGroups:task.min_support_groups,requireEach:Number(task.require_each_source_nonempty),sourceGroups:task.source_groups.map(g=>g.group_id),
      qCommit:B.rootRead(packet.commitments.q),lCommit:B.rootRead(packet.commitments.l),decision:value.decision,reason:value.reason_code};
    const actual=packet.public_signals.map(v=>B.unhex(v));
    // Only LAB receivers can relax an interface. Pairing verification remains real.
    stage="PUBLIC_INPUT_BINDING";
    const fields=[];let offset=0;
    for(const name of P.PUBLIC) {const vals=[expected[name]].flat(4).map(String);fields.push({name,offset,vals});offset+=vals.length;}
    D.check(actual.length===offset,"PUBLIC_INPUT_COUNT");
    const relaxed={task:["taskDigest","objectId","evidenceType","lower","upper","evaluation","deadline","maxRisk","purposeBit","minGroups","requireEach","sourceGroups"],
      receiver_nonce:["taskDigest"],payload:["decision","reason","handoffCommit"],final_node:["handoffNode"],state_checkpoint:["logLengths","logRoots"]};
    for(const f of fields)if(!(relaxed[removedBinding]||[]).includes(f.name))D.check(D.equal(actual.slice(f.offset,f.offset+f.vals.length),f.vals),"PUBLIC_INPUT_BINDING");
    stage=plain?"PLAIN_COMPLETE_VERIFY":"GROTH16_VERIFY";let before=performance.now();
    const valid=plain?!!require("./plain").verify(task,packet.plaintext,p,h,actual):await snark.groth16.verify(keys.joint.vk,actual,B.readProof(packet.proof));timings[plain?"plaintext_verify_ms":"joint_verify_ms"]=performance.now()-before;
    D.check(valid,"GROTH16_VERIFY");
    state.used.push(nonceKey);for(const cp of sourceCheckpoints)state.marks[cp.source_id]=cp.log_length;
    const dField=fields.find(f=>f.name==="decision"),rField=fields.find(f=>f.name==="reason");
    const decision=Number(actual[dField.offset]),reason=Number(actual[rField.offset]);
    D.check(decision===0||reason===0,"DECISION_REASON");
    const token=decision&&!trust.verification_only?crypto.createHmac("sha256",trust.action_key).update(D.binary({task_digest:D.tagged("TASK",task),decision,reason,deadline:String(task.deadline)})).digest("hex"):null;
    let execution=null;
    if(token){state.grants=state.grants||{};D.check(!state.grants[token],"ACTION_DUPLICATE_GRANT");state.grants[token]={task_digest:D.tagged("TASK",task),deadline:String(task.deadline),consumed:false};execution=consumeAction(task,token,state,trust.now_virtual??task.issued_at+3);}
    return {status:decision?"ALLOW":"DENY",reason_code:reason,stage:"VERIFIED",action_authorized:!!token,action_token:token,
      action_execution:execution,verified:true,wall_ms:performance.now()-started,timings};
  } catch(e) {
    return {status:e.execution&&["TIMEOUT","RESOURCE_LIMIT"].includes(e.execution.status)?"UNAVAILABLE":"INVALID_PROOF",
      stage,error:e.code||e.message.split(":")[0],action_authorized:false,wall_ms:performance.now()-started,timings};
  }
}
module.exports={receive,strictJSON,validateTask,consumeAction};
if(require.main===module) {
  const [taskFile,packetFile,trustFile,keysFile,work]=process.argv.slice(2);
  (async()=>{
    if(process.env.CORE_SOURCE_REVISION)D.check(require("./cli").revision()===process.env.CORE_SOURCE_REVISION,"SOURCE_CHANGED_DURING_EXPERIMENT");
    const trust=strictJSON(fs.readFileSync(trustFile,"utf8")),keys=strictJSON(fs.readFileSync(keysFile,"utf8"));
    let result;const stateFile=path.join(work,"receiver-state.json");
    const state=fs.existsSync(stateFile)?strictJSON(fs.readFileSync(stateFile,"utf8")):{used:[],marks:{}};
    try {result=await receive(strictJSON(fs.readFileSync(taskFile,"utf8")),strictJSON(fs.readFileSync(packetFile,"utf8")),trust,keys,work,{state,removedBinding:trust.lab_removed_binding||null});}
    catch(e){result={status:"INVALID_PROOF",stage:"PARSING",error:e.message,action_authorized:false};}
    if(result.verified)save(stateFile,state);
    save(path.join(work,"result.json"),result);console.log(JSON.stringify(result));process.exit(result.verified?0:2);
  })().catch(e=>{console.error(e.message);process.exit(1);});
}
