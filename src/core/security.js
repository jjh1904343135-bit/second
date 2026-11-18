"use strict";
const fs=require("fs"),path=require("path"),crypto=require("crypto");
const D=require("./data"),P=require("./protocol"),B=require("./backend"),F=require("./fixtures"),{ROOT,OUT,RUN_ID,save,run,beginExperiment}=require("./runtime");
const DIR=path.join(OUT,"experiment1"),PRIVATE=path.join(OUT,"private",`experiment1-${RUN_ID}`);
const FAMILIES={
  omission:["missing_source","unfavorable_same_group","skipped_confirmed_update","late_published_in_window"],
  invalid_reuse:["old_version","revoked","expired","wrong_purpose"],
  lineage:["deleted_parent","impersonate_root","chain_echo","diamond_echo","true_two_groups"],
  substitution:["new_checkpoint_old_psi","policy","receiver","nonce","result","same_content_node"],
  reason:["insufficient_as_policy","both_fail_priority"]};
const PROFILES=["FULL","NO_QUERY","NO_VALIDITY","NO_LINEAGE","NO_BINDING"];
const read=f=>JSON.parse(fs.readFileSync(f));
function rng(seed){let x=seed>>>0;return()=>{x^=x<<13;x^=x>>>17;x^=x<<5;return x>>>0;};}
function plan() {
  const rows=[];
  for(const [family,types] of Object.entries(FAMILIES)) {
    for(const subtype of types)rows.push({id:`fixed-${family}-${subtype}`,family,subtype,phase:"fixed",seed:D.CONFIG.security_seed_start});
    const rand=rng(D.CONFIG.security_seed_start+Object.keys(FAMILIES).indexOf(family)),attacks=types.filter(t=>t!=="true_two_groups");
    for(let i=0;i<D.CONFIG.security_variants_per_category;i++)rows.push({id:`variant-${family}-${i}`,family,subtype:attacks[i%attacks.length],phase:"seeded",seed:rand(),index:i});
  }
  return rows;
}
function baseSources(p,h) {
  const srcs=Array.from({length:p.sources},(_,i)=>new D.Source(i+1,p,h));
  for(const s of srcs)for(let i=0;i<4;i++)s.apply(1,D.record(s.id,i+1,i,{created_at:String(i===1?5:10+i*10),updated_at:String(i===1?1000:10+i*10),valid_until:i===3?"20000":"1000000000",business:{assessment:1,risk_score:s.id===1&&i===1?9000:100,purpose_mask:1}}));
  const v=D.clone(srcs[0].current.get(1));v.version++;v.updated_at="1000";srcs[0].apply(2,v);
  const revoke=D.clone(srcs[0].current.get(3));revoke.version++;revoke.updated_at="1001";revoke.lifecycle=2;srcs[0].apply(3,revoke);
  return srcs;
}
function qCommit(input,h) {input.qCommit=h.hash(18,[...input.taskDigest,...input.qSalt,...input.selected.flatMap((row,s)=>row.flatMap((hit,r)=>[hit,...h.hash(1,input.records[s][r]).map(v=>hit?v:"0")]))]);}
function options(spec) {
  const t={created_from:10,created_until:11};let refs=[{source:1,id:1,version:2}],topology="default",decision=1,reason=0;
  if(["unfavorable_same_group","late_published_in_window","both_fail_priority"].includes(spec.subtype)){t.created_from=0;t.created_until=25;}
  if(spec.subtype==="old_version"||spec.subtype==="insufficient_as_policy")refs[0].version=1;
  if(spec.subtype==="revoked"){t.created_from=30;t.created_until=31;refs=[{source:1,id:3,version:2}];}
  if(spec.subtype==="expired"){t.created_from=40;t.created_until=41;t.issued_at=20000;t.evaluation_time=20001;t.deadline=20010;refs=[{source:1,id:4,version:1}];}
  if(spec.subtype==="wrong_purpose"){t.purpose_bit=1;}
  if(spec.subtype==="chain_echo"||spec.subtype==="diamond_echo"){t.min_support_groups=2;topology=spec.subtype==="chain_echo"?"chain_single":"diamond_single";}
  if(spec.subtype==="true_two_groups"){t.min_support_groups=2;topology="diamond_two";refs.push({source:2,id:1,version:1});}
  if(spec.subtype==="insufficient_as_policy"){decision=0;reason=1;}
  if(spec.subtype==="both_fail_priority"){refs[0].version=1;decision=0;reason=2;}
  return {t,refs,topology,decision,reason};
}
async function fixtureState(p,h,psi,dir) {
  const manifest=path.join(PRIVATE,"base.json");
  if(fs.existsSync(manifest)) {const c=read(manifest);if(c.vk_id===psi.vk_id&&c.states.every(s=>fs.existsSync(s.file)))return {srcs:F.replay(p,h,c.events),states:c.states};}
  const srcs=baseSources(p,h),states=[];
  for(let i=0;i<srcs.length;i++)states.push(await B.proveState(srcs[i],psi,path.join(PRIVATE,`base-source-${i}`)));
  const result={vk_id:psi.vk_id,events:srcs.map(s=>s.events.map(e=>({op:e.op,record:e.record}))),states};save(manifest,result);return {srcs,states};
}
async function worker(ablation,dir) {
  const p=D.profile(3,16,16,ablation),h=await D.hashing(),psi=await B.psiKeys(p,h,dir),joint=await B.jointKeys(p,dir),keys={psi,joint};
  save(path.join(dir,"profile.json"),{...p,lab_only:ablation!=="FULL",psi_vk_id:psi.vk_id,joint_vk_id:joint.vk_id});save(path.join(dir,"verification_key.json"),joint.vk);
  const {srcs,states}=await fixtureState(p,h,psi,dir);const pub=(name,v)=>save(path.join(dir,name),v);
  const task=D.task(p,`security-control-${ablation}`,{psi_vk_id:psi.vk_id,task_vk_id:joint.vk_id,created_from:10,created_until:11});
  const control=F.graph(task,p,srcs),cp=await B.proveTask(control.prepared.input,joint,path.join(PRIVATE,ablation,"control"));
  const packet=B.bundle(task,p,control.prepared,states,cp),trust=F.trust(p,srcs,control.registry);
  const checked=await F.independentReceiver(task,packet,trust,keys,path.join(PRIVATE,ablation,"control/B"));
  D.check(checked.status==="ALLOW","SECURITY_NORMAL_CONTROL");pub("normal-control.json",{id:`normal-${ablation}`,reference:"ALLOW",actual:checked,independent_samples:1});pub("normal-bundle.json",packet);
  const append=row=>fs.appendFileSync(path.join(dir,"raw.jsonl"),JSON.stringify(row)+"\n");
  let substitutionPool=null;
  for(const spec of plan()) {
    if(process.env.CORE_SOURCE_REVISION)D.check(require("./cli").revision()===process.env.CORE_SOURCE_REVISION,"SOURCE_CHANGED_DURING_EXPERIMENT");
    const work=path.join(PRIVATE,ablation,spec.id);let result;
    const wireAttack=["missing_source","skipped_confirmed_update","new_checkpoint_old_psi","policy","receiver","nonce","result","same_content_node"].includes(spec.subtype);
    const o=options(spec),t=wireAttack?D.clone(task):D.task(p,`${ablation}-${spec.id}-${spec.seed}`,{psi_vk_id:psi.vk_id,task_vk_id:joint.vk_id,...o.t,max_risk_score:5000+(spec.seed%500)});
    const fx=F.graph(t,p,srcs,{rootRefs:o.refs,topology:o.topology,forge:{decision:o.decision,reason:o.reason}}),input=fx.prepared.input;
    const attack={...spec,ablation,normal_control:`normal-${ablation}`,normal_proof_reused:true,expected:spec.subtype==="true_two_groups"?"ALLOW":"NO_UNAUTHORIZED_ACCEPTANCE",reference:{decision:fx.answer.decision,reason:fx.answer.reason,groups:fx.answer.groupCount,Q:fx.answer.Q.length,L:fx.answer.L.length},modified_factor:spec.subtype};
    if(wireAttack) {
      // Components are genuine proofs of a legal task; attack only their interface.
      const legal=control;let sent=D.clone(packet),receivingTask=D.clone(t),tr=D.clone(trust);attack.valid_component_proof_reused=true;
      if(spec.subtype==="missing_source")sent.sources.splice(spec.seed%p.sources,1);
      if(spec.subtype==="policy")receivingTask.max_risk_score=spec.seed%100;
      if(spec.subtype==="receiver")receivingTask.receiver_id+=1+spec.seed%1000;
      if(spec.subtype==="nonce")receivingTask.nonce=D.tagged("ATTACK_NONCE",[spec.seed,spec.id]);
      if(spec.subtype==="result"){sent.payload.decision=0;sent.payload.reason_code=1;}
      if(["skipped_confirmed_update","new_checkpoint_old_psi"].includes(spec.subtype)) {
        const s=new D.Source(1,p,h);for(const e of srcs[0].events)s.apply(e.op,D.clone(e.record));const r=D.clone(s.current.get(1));r.version++;r.updated_at=String(2000+spec.seed%1000);r.business.risk_score=9999;s.apply(2,r);
        sent.sources[0].checkpoint=B.wireCP(s.checkpoint(t));attack.reference={decision:0,reason:1};
      }
      if(spec.subtype==="same_content_node") {
        // Authenticated R has two distinct HANDOFF nodes with equal content. The
        // proof selects the first, while the signed checkpoint selects the second.
        if(!substitutionPool) {
          const pool=F.graph(t,p,srcs),r=pool.registry,old=r.nodes.at(-1),first=old.seq;
          for(let i=0;i<50;i++)r.add(103,6,old.parents,old.content);
          const prepared=P.prepare(t,p,srcs,r,pool.answer);
          prepared.input.handoffNode=old.leaf;prepared.input.nodes=pool.prepared.input.nodes;
          prepared.input.parents=pool.prepared.input.parents;prepared.input.parentSalts=pool.prepared.input.parentSalts;
          prepared.input.registryPaths=pool.prepared.input.nodes.map(n=>n[0]?r.tree.opening(n[3]-1):Array.from({length:32},()=>["0","0"]));
          const alternative=await B.proveTask(prepared.input,joint,path.join(PRIVATE,ablation,"handoff-pool"));
          substitutionPool={r,first,prepared,alternative};
        }
        const {r,first,prepared,alternative}=substitutionPool,target=first+1+spec.seed%50;
        sent=B.bundle(t,p,{...prepared,registry_checkpoint:r.checkpoint(t,target)},states,alternative);attack.distinct_handoff_nodes=[first,target];
      }
      const removed={policy:"task",receiver:"receiver_nonce",nonce:"receiver_nonce",result:"payload",same_content_node:"final_node",skipped_confirmed_update:"state_checkpoint",new_checkpoint_old_psi:"state_checkpoint"}[spec.subtype];
      if(ablation==="NO_BINDING")tr.lab_removed_binding=removed;
      result=await F.independentReceiver(receivingTask,sent,tr,keys,path.join(work,"B"));pub(`${spec.id}-input.json`,{task:receivingTask,bundle:sent});
      attack.outcome=result.status==="UNAVAILABLE"?"unavailable":result.status==="INVALID_PROOF"?"verification_rejection":result.status==="DENY"?"valid_deny":"accepted";
      attack.interface_accepted=result.verified===true;
    } else {
      if(["unfavorable_same_group","late_published_in_window"].includes(spec.subtype)){input.selected[0][1]=0;qCommit(input,h);}
      if(spec.subtype==="deleted_parent")input.parents[2][0]=input.parents[1][0];
      if(spec.subtype==="impersonate_root"){input.nodes[1][1]=1;input.nodes[1][2]=1;}
      const test=await require("./prerequisite").rejectWitness(input,joint,()=>{});
      if(test.rejected){result={status:"INVALID_PROOF",stage:"PROOF_CONSTRUCTION",error:test.error};attack.outcome="construction_failure";}
      else {
        const proof=await B.proveTask(input,joint,work),sent=B.bundle(t,p,fx.prepared,states,proof);
        result=await F.independentReceiver(t,sent,F.trust(p,srcs,fx.registry),keys,path.join(work,"B"));pub(`${spec.id}-input.json`,{task:t,bundle:sent});
        attack.outcome=result.status==="UNAVAILABLE"?"unavailable":result.status==="INVALID_PROOF"?"verification_rejection":result.status==="DENY"?"valid_deny":"accepted";
      }
    }
    attack.actual=result;attack.failure_checkpoint=result.stage;attack.actual_reason=result.reason_code??null;attack.attack_sample=spec.subtype!=="true_two_groups";
    const tamperReason=spec.family==="reason",positive=spec.subtype==="true_two_groups";
    attack.blocked=["construction_failure","verification_rejection"].includes(attack.outcome)||attack.outcome==="valid_deny"&&!tamperReason;
    attack.pass=positive?result.status==="ALLOW":attack.blocked;
    append(attack);console.log(`${ablation} ${spec.id}: ${attack.outcome}`);
  }
  // Explicit availability and scope controls never enter cryptographic success denominators.
  append({id:"source-timeout",phase:"availability_control",expected:"UNAVAILABLE",actual:await F.independentReceiver(task,{complete:false},trust,keys,path.join(PRIVATE,ablation,"timeout")),attack_sample:false});
  const later=new D.Source(1,p,h);for(const e of srcs[0].events)later.apply(e.op,D.clone(e.record));
  const after=D.clone(later.current.get(1));after.version++;after.updated_at="10020";after.business.risk_score=9999;later.apply(2,after);
  save(path.join(PRIVATE,ablation,"post-checkpoint-event.json"),{event:later.events.at(-1).record,old_frontier:srcs[0].events.length,new_frontier:later.events.length});
  append({id:"post-checkpoint-update",phase:"scope_control",scope:"OUTSIDE_CONFIRMED_FRONTIER",attack_sample:false,expected:"ALLOW",actual:await F.independentReceiver(task,packet,trust,keys,path.join(PRIVATE,ablation,"post-checkpoint/B")),explanation:"The real adverse event was appended after the authenticated checkpoint; B verifies the original confirmed snapshot. This is not counted as a blocked forgery."});
  save(path.join(dir,"complete.json"),{status:"COMPLETE",planned:plan().length});
}
async function main() {
  beginExperiment("experiment1");fs.mkdirSync(PRIVATE,{recursive:true,mode:0o700});save(path.join(DIR,"input-manifest.json"),{run_id:RUN_ID,private_input_directory:PRIVATE,config:D.CONFIG,profiles:PROFILES,attacks:plan(),source_revision:require("./cli").revision(),seed_algorithm:"xorshift32; seed per category recorded before execution"});
  const rows=[];
  for(const name of PROFILES) {
    const dir=path.join(DIR,name);fs.mkdirSync(dir,{recursive:true});
    const result=await run(process.execPath,[__filename,"--worker",name,dir],{quiet:true,timeout:12*3600000,log:path.join(dir,"full_run.log")});
    const samples=fs.existsSync(path.join(dir,"raw.jsonl"))?fs.readFileSync(path.join(dir,"raw.jsonl"),"utf8").trim().split("\n").filter(Boolean).map(JSON.parse):[];
    const row={profile:name,status:fs.existsSync(path.join(dir,"complete.json"))&&result.status==="PASS"?"COMPLETE":result.status,executed:samples.filter(r=>r.attack_sample!==false).length,planned:plan().length,execution:{...result,output:undefined}};
    save(path.join(dir,"status.json"),row);rows.push(row);
    if(name==="FULL"&&row.status!=="COMPLETE")break;
  }
  save(path.join(DIR,"results.json"),{coverage_complete:rows.length===PROFILES.length&&rows.every(r=>r.status==="COMPLETE"),rows});return rows;
}
if(require.main===module&&process.argv[2]==="--worker")worker(process.argv[3],process.argv[4]).then(()=>process.exit(0)).catch(e=>{console.error(e.stack);process.exit(1);});
module.exports={main,worker,plan,FAMILIES,PROFILES,baseSources,fixtureState};
