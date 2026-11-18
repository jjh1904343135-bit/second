"use strict";
const fs=require("fs"),path=require("path"),crypto=require("crypto");
const D=require("./data"),P=require("./protocol"),B=require("./backend");
const {ROOT,OUT,save,run}=require("./runtime");
function sources(p,h,{history=4,occupancy=4,hits=occupancy,seed=0}={}) {
  const result=[];
  for(let id=1;id<=p.sources;id++) {
    const src=new D.Source(id,p,h);
    for(let i=0;i<occupancy;i++)src.apply(1,D.record(id,i+1,i,{created_at:String(i<hits?10+i:200+i),updated_at:String(i<hits?10+i:200+i)}));
    for(let i=occupancy;i<history;i++) {
      const old=src.current.get(1+(i-occupancy)%occupancy),r=D.clone(old);
      r.version++;r.updated_at=String(1000+i);r.record_salt=crypto.randomBytes(32).toString("hex");src.apply(2,r);
    }
    result.push(src);
  }
  return result;
}
function replay(p,h,eventLists) {
  return eventLists.map((events,i)=>{const s=new D.Source(i+1,p,h);for(const e of events)s.apply(e.op,D.clone(e.record));return s;});
}
function graph(task,p,srcs,{rootRefs,empty=false,topology="default",texts=[],registryLength=0,forge=null,replayNodes=null,qSalt=null,lSalt=null}={}) {
  const h=srcs[0].h,r=new P.Registry(p,h,replayNodes);let parents=[];
  if(!empty) {
    const refs=rootRefs||[{source:1,id:1,version:srcs[0].current.get(1).version}];
    const roots=refs.map(ref=>r.import(srcs[ref.source-1],ref.id,ref.version));
    const make=(refs,index)=>r.derive(101+index%3,4,refs,texts[index]||`PRIVATE_MEMORY_${index}_${D.tagged("CANARY",[task.nonce,index])}`);
    if(topology==="default") {
      if(roots.length===1&&p.nodes>=4){const a=make(roots,0);parents=[make([a],1)];}
      else if(roots.length+2<=p.nodes)parents=[make(roots,0)];else parents=roots;
    } else if(topology==="chain_single") {
      let n=roots[0];const chain=[];while(r.nodes.length<7){n=make([n],r.nodes.length);chain.push(n);}parents=chain.slice(-3);
    } else if(topology==="chain_two") {
      let a=make([roots[0]],0),b=make([roots[1]],1);a=make([a],2);b=make([b],3);parents=[make([a,b],4)];
    } else if(topology==="diamond_single"||topology==="diamond_two") {
      const base=make(roots,0),a=make([base],1),b=make([base],2);let join=make([a,b],3);
      while(r.nodes.length<7)join=make([join],r.nodes.length);parents=[join];
    } else if(topology==="short")parents=[make(roots,0)];
  }
  const answer=P.reference(task,srcs,r.nodes,parents);
  const claim=forge?{...answer,...forge}:answer;
  while(r.nodes.length<registryLength-1)r.derive(199,5,[1],`UNRELATED_PRIVATE_CANARY_${r.nodes.length}`);
  r.add(103,6,parents,P.outputCommit(task,P.payload(task,claim),h));
  return {registry:r,answer,prepared:P.prepare(task,p,srcs,r,claim,{qSalt,lSalt})};
}
function trust(p,srcs,registry) {
  return {profile:p,source_public_keys:srcs.map(s=>D.publicKey(s.keys)),registry_public_key:D.publicKey(registry.keys),action_key:crypto.randomBytes(32).toString("hex")};
}
async function independentReceiver(task,packet,trustValue,keys,dir,{reuse=false}={}) {
  fs.mkdirSync(dir,{recursive:true,mode:0o700});
  for(const [name,value] of Object.entries({task,packet,trust:trustValue,keys})) {
    const file=path.join(dir,`${name}.json`);if(name==="packet")fs.writeFileSync(file,JSON.stringify(value));else save(file,value);
  }
  const stateDir=path.join(dir,"B");if(!reuse&&fs.existsSync(path.join(stateDir,"receiver-state.json")))fs.unlinkSync(path.join(stateDir,"receiver-state.json"));
  if(fs.existsSync(path.join(stateDir,"result.json")))fs.unlinkSync(path.join(stateDir,"result.json"));
  const result=await run(process.execPath,[path.join(ROOT,"src/core/receiver.js"),...["task","packet","trust","keys"].map(n=>path.join(dir,`${n}.json`)),stateDir],{quiet:true,log:path.join(dir,"B.log")});
  const record=fs.existsSync(path.join(stateDir,"result.json"))?JSON.parse(fs.readFileSync(path.join(stateDir,"result.json"))):{status:"UNAVAILABLE",stage:result.status,action_authorized:false};
  return {...record,process: {...result,output:undefined}};
}
function auditPacket(packet,privateSources,registry) {
  const text=JSON.stringify(packet);const forbiddenKeys=["records","raw_digest","record_salt","parents","parentSalts","rootRecords","directoryPaths","logPaths","private_text","text_salt","witness"];
  const present=forbiddenKeys.filter(k=>text.includes(`"${k}"`));
  const markers=[...privateSources.flatMap(s=>s.events.flatMap(e=>[e.record.raw_digest,e.record.record_salt])),...registry.nodes.map(n=>n.private_text).filter(Boolean)];
  const leaked=markers.filter(m=>text.includes(m)||/^[0-9a-f]{64}$/.test(m)&&text.includes(D.u32words(m).join(",")));
  return {forbidden_keys_found:present,private_markers_found:leaked.length,pass:present.length===0&&leaked.length===0,bytes:Buffer.byteLength(text)};
}
module.exports={sources,replay,graph,trust,independentReceiver,auditPacket};
