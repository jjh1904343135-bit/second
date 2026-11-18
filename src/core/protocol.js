"use strict";
const crypto=require("crypto");
const D=require("./data");
const {check,clone,tagged,u32words,recordWords,limbs,Tree,equal}=D;
const PUBLIC=["profileId","sourceIds","logLengths","logRoots","stateRoots","registryRoot","registryLength","handoffNode","handoffCommit","taskDigest","objectId","evidenceType","lower","upper","evaluation","deadline","maxRisk","purposeBit","minGroups","requireEach","sourceGroups","qCommit","lCommit","decision","reason"];
const MODES={FULL:0,NO_QUERY:1,NO_VALIDITY:2,NO_LINEAGE:3,NO_BINDING:0};
const randomWords=()=>u32words(crypto.randomBytes(32).toString("hex"));
const rootKey=r=>`${r.source_id}:${r.record_id}:${r.version}`;
const numericRootKey=r=>BigInt(r.source_id)*(1n<<64n)+BigInt(r.record_id)*(1n<<32n)+BigInt(r.version);
class Registry {
  constructor(p,h,replayNodes=null) {this.p=p;this.h=h;this.replayNodes=replayNodes;this.keys=D.keyPair("core-R");this.nodes=[];this.communication=[];this.tree=new Tree(32,17,h.hash(16),h);}
  add(actor,op,parents,content,root=null,at=10000) {
    const wire=JSON.stringify({actor,op,parents,content,root,at});
    ({actor,op,parents,content,root,at}=JSON.parse(wire));
    check(this.nodes.length<2**32-1,"REGISTRY_SEQUENCE_CAPACITY");
    const refs=[...parents].sort((a,b)=>a-b);
    check(refs.length<=4&&new Set(refs).size===refs.length&&refs.every(v=>v>0&&v<=this.nodes.length),"PARENT_LIST");
    check(op===1?refs.length===0&&root:op===6||refs.length>0,"NODE_OPERATION");
    const preset=this.replayNodes?.[this.nodes.length];
    const node={seq:this.nodes.length+1,actor,op,kind:op===1?1:2,parents:refs,content:clone(content),root:clone(root),operation:preset?.operation||randomWords(),salt:preset?.salt||randomWords(),registered:at};
    node.words=[1,node.kind,op,node.seq,actor,...node.operation,...node.content,node.parents.length,...limbs(at)];
    node.parentHash=this.h.hash(12,[refs.length,...refs,...Array(4-refs.length).fill(0),...node.salt]);
    const reference=root?[root.record.source_id,root.record.record_id,root.record.version,root.seq,...this.h.hash(1,recordWords(root.record))]:Array(6).fill(0);
    node.leaf=this.h.hash(13,[...node.words,...node.parentHash,...reference]);
    if(preset)check(equal(node.leaf,preset.leaf),"FROZEN_REGISTRATION_MISMATCH");
    this.nodes.push(node);this.tree.set(node.seq-1,node.leaf);
    const reply=JSON.stringify({seq:node.seq,commit:node.leaf});
    this.communication.push({request:wire,response:reply,request_bytes:Buffer.byteLength(wire),response_bytes:Buffer.byteLength(reply)});return JSON.parse(reply).seq;
  }
  import(source,id,version,actor=101) {
    const v=source.versions.get(`${id}:${version}`);check(v,"UNKNOWN_ROOT_VERSION");
    return this.add(actor,1,[],this.h.hash(1,recordWords(v.record)),v);
  }
  derive(actor,op,parents,text) {
    const bytes=Buffer.from(text),padding=(4-bytes.length%4)%4;
    const words=u32words(Buffer.concat([bytes,Buffer.alloc(padding)]).toString("hex"));
    const salt=this.replayNodes?.[this.nodes.length]?.text_salt||randomWords();const seq=this.add(actor,op,parents,this.h.hash(14,[bytes.length,...words,...salt]));
    this.nodes[seq-1].private_text=text;this.nodes[seq-1].text_salt=salt;return seq;
  }
  checkpoint(task,handoffSeq=this.nodes.length) {
    const last=this.nodes[handoffSeq-1];check(last&&last.op===6,"MISSING_HANDOFF");
    const body={profile_id:this.p.id,registry_id:8001,key_epoch:1,registry_length:this.nodes.length,registry_root:this.tree.root,
      task_digest:tagged("TASK",task),receiver_id:task.receiver_id,nonce:task.nonce,confirmed_at:task.issued_at+2,
      handoff_node_commit:last.leaf,handoff_content_commit:last.content};
    return {...body,signature:D.sign(this.keys.privateKey,tagged("REGISTRY_CP",body))};
  }
}

// Independent, raw-record reference model. Does not evaluate a circuit input.
function reference(task,sources,nodes,finalParents) {
  const Q=[];const historical=new Map();
  for(const src of sources) {
    const current=new Map();
    for(const event of src.events) {current.set(event.record.record_id,event.record);historical.set(rootKey(event.record),event.record);}
    for(const r of current.values())if(r.object_id===task.object_id&&r.evidence_type===task.evidence_type&&
      BigInt(r.created_at)>=BigInt(task.created_from)&&BigInt(r.created_at)<BigInt(task.created_until))Q.push(r);
  }
  const keys=new Set(),visited=new Set();
  function walk(seq) {
    if(visited.has(seq))return;visited.add(seq);
    const n=nodes.find(n=>n.seq===seq);check(n,"ORACLE_MISSING_PARENT");
    if(n.kind===1)keys.add(rootKey(n.root.record));else n.parents.forEach(walk);
  }
  finalParents.forEach(walk);
  const L=[...keys].map(k=>historical.get(k)).sort((a,b)=>numericRootKey(a)<numericRootKey(b)?-1:1);
  const valid=r=>r.lifecycle===1&&BigInt(r.valid_from)<=BigInt(task.evaluation_time)&&BigInt(task.deadline)<BigInt(r.valid_until)&&((r.business.purpose_mask>>>task.purpose_bit)&1)===1;
  const coverage=!task.require_each_source_nonempty||task.required_sources.every(id=>Q.some(r=>r.source_id===id));
  const recordsOK=Q.every(r=>valid(r)&&r.business.assessment===1&&r.business.risk_score<=task.max_risk_score);
  const qualified=L.filter(r=>valid(r)&&Q.some(q=>rootKey(q)===rootKey(r)));
  const supportOK=qualified.length===L.length;
  const groupCount=new Set(qualified.map(r=>task.source_groups.find(g=>g.source_id===r.source_id).group_id)).size;
  const p=coverage&&recordsOK,s=supportOK&&groupCount>=task.min_support_groups;
  return {Q,L,decision:Number(p&&s),reason:!p?1:!s?2:0,coverage,recordsOK,supportOK,groupCount,visited:[...visited]};
}
function payload(task,answer) {return {schema_version:1,task_digest:tagged("TASK",task),receiver_id:task.receiver_id,object_id:task.object_id,decision:answer.decision,reason_code:answer.reason,deadline:String(task.deadline)};}
function outputCommit(task,value,h) {
  return h.hash(15,[...u32words(value.task_digest),value.receiver_id,value.object_id,value.decision,value.reason_code,...limbs(value.deadline)]);
}
function prepare(task,p,sources,registry,answer,options={}) {
  const h=sources[0].h;
  const seen=new Set();
  function visit(seq){if(seen.has(seq))return;seen.add(seq);registry.nodes[seq-1].parents.forEach(visit);}
  visit(registry.nodes.at(-1).seq);
  const graph=registry.nodes.filter(n=>seen.has(n.seq));check(graph.length<=p.nodes,"GRAPH_CAPACITY");
  const zeroRecord=()=>Array(35).fill(0),qSalt=options.qSalt||randomWords(),lSalt=options.lSalt||randomWords();
  const records=sources.map(s=>Array.from({length:p.slots},(_,i)=>s.bucket(task.object_id,task.evidence_type).records[i]?recordWords(s.bucket(task.object_id,task.evidence_type).records[i]):zeroRecord()));
  const counts=sources.map(s=>s.bucket(task.object_id,task.evidence_type).records.length);
  const selected=records.map((row,s)=>row.map((w,r)=>Number(r<counts[s]&&BigInt(w[7])*4294967296n+BigInt(w[8])>=BigInt(task.created_from)&&BigInt(w[7])*4294967296n+BigInt(w[8])<BigInt(task.created_until))));
  if(options.selected)options.selected(selected);
  const taskDigest=u32words(tagged("TASK",task));
  const qWords=selected.flatMap((row,s)=>row.flatMap((hit,r)=>[hit,...h.hash(1,records[s][r]).map(v=>hit?v:"0")]));
  const qCommit=h.hash(18,[...taskDigest,...qSalt,...qWords]);
  const distinct=new Map();for(const n of graph)if(n.kind===1)distinct.set(rootKey(n.root.record),n.root.record);
  const roots=[...distinct.values()].sort((a,b)=>numericRootKey(a)<numericRootKey(b)?-1:1);
  const sortedRoots=Array.from({length:p.nodes},(_,i)=>roots[i]?[1,roots[i].source_id,roots[i].record_id,roots[i].version,...h.hash(1,recordWords(roots[i]))]:Array(6).fill(0));
  const lCommit=h.hash(19,[...taskDigest,...lSalt,...sortedRoots.flat()]);
  const emptyPath=()=>Array.from({length:32},()=>["0","0"]);
  const rootRecords=[],eventMeta=[],eventSeq=[],logPaths=[];
  for(let i=0;i<p.nodes;i++) {
    const n=graph[i];
    if(n?.kind===1) {
      const src=sources.find(s=>s.id===n.root.record.source_id),v=n.root;
      const event=src.events[v.seq-1];
      rootRecords.push(recordWords(v.record));eventSeq.push(v.seq);logPaths.push(src.log.opening(v.seq-1));
      eventMeta.push([event.op,event.previous?.version||0,...(event.previous?h.hash(1,recordWords(event.previous)):["0","0"])]);
    } else {rootRecords.push(zeroRecord());eventMeta.push([0,0,0,0]);eventSeq.push(0);logPaths.push(emptyPath());}
  }
  const rcp=registry.checkpoint(task);
  const input={profileId:p.id,sourceIds:task.required_sources,logLengths:sources.map(s=>s.events.length),logRoots:sources.map(s=>s.log.root),stateRoots:sources.map(s=>s.directory.root),
    registryRoot:registry.tree.root,registryLength:registry.nodes.length,handoffNode:rcp.handoff_node_commit,handoffCommit:rcp.handoff_content_commit,taskDigest,
    objectId:task.object_id,evidenceType:task.evidence_type,lower:limbs(task.created_from),upper:limbs(task.created_until),evaluation:limbs(task.evaluation_time),deadline:limbs(task.deadline),
    maxRisk:task.max_risk_score,purposeBit:task.purpose_bit,minGroups:task.min_support_groups,requireEach:Number(task.require_each_source_nonempty),sourceGroups:task.source_groups.map(v=>v.group_id),
    qCommit,lCommit,decision:answer.decision,reason:answer.reason,records,counts,
    directoryPaths:sources.map(s=>s.directory.opening(BigInt(task.object_id)*65536n+BigInt(task.evidence_type))),selected,qSalt,lSalt,
    nodes:Array.from({length:p.nodes},(_,i)=>graph[i]?.words||Array(18).fill(0)),
    parents:Array.from({length:p.nodes},(_,i)=>{const refs=graph[i]?.parents||[];return [...refs,...Array(4-refs.length).fill(0)];}),
    parentSalts:Array.from({length:p.nodes},(_,i)=>graph[i]?.salt||Array(8).fill(0)),
    registryPaths:Array.from({length:p.nodes},(_,i)=>graph[i]?registry.tree.opening(graph[i].seq-1):emptyPath()),
    rootRecords,eventMeta,eventSeq,logPaths,sortedRoots,claimedGroups:sources.map(()=>1),
  };
  return {input,source_checkpoints:sources.map(s=>s.checkpoint(task)),registry_checkpoint:rcp,payload:payload(task,answer)};
}
function publicSignals(input){return PUBLIC.flatMap(k=>[input[k]].flat(4)).map(String);}
module.exports={Registry,reference,payload,outputCommit,prepare,publicSignals,PUBLIC,MODES,rootKey};
