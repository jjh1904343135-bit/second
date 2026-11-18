"use strict";
const crypto=require("crypto");
const {buildMimcSponge}=require("circomlibjs");
const {encode,check,binary}=require("./codec");
const {keyPair,sign,verify}=require("./signatures");
const CONFIG=require("../../configs/core.json");
const ZERO=["0","0"];
const clone=value=>structuredClone(value);
const equal=(a,b)=>a.length===b.length&&a.every((v,i)=>String(v)===String(b[i]));
const SHA=bytes=>crypto.createHash("sha256").update(bytes).digest("hex");
const tagged=(tag,value)=>SHA(Buffer.concat([Buffer.from(`RCPEH_CORE/${tag}\0`),binary(value)]));
const u32words=hex=>Array.from({length:hex.length/8},(_,i)=>parseInt(hex.slice(i*8,i*8+8),16));
const limbs=value=>{const n=BigInt(value);check(n>=0n&&n<1n<<64n,"U64_RANGE");return [Number(n>>32n),Number(n&0xffffffffn)];};
function recordWords(r) {
  encode("record",r);
  return [r.schema_version,r.source_id,r.record_id,r.version,r.object_id,r.evidence_type,r.slot_index,
    ...limbs(r.created_at),...limbs(r.updated_at),...limbs(r.valid_from),...limbs(r.valid_until),
    r.lifecycle,r.business.assessment,r.business.risk_score,r.business.purpose_mask,
    ...u32words(r.raw_digest),...u32words(r.record_salt)];
}
function wordsRecord(w) {
  check(w.length===35,"RECORD_WORD_COUNT");
  const time=i=>(BigInt(w[i])*4294967296n+BigInt(w[i+1])).toString();
  const hex=(a,b)=>w.slice(a,b).map(v=>Number(v).toString(16).padStart(8,"0")).join("");
  return {schema_version:Number(w[0]),source_id:Number(w[1]),record_id:Number(w[2]),version:Number(w[3]),object_id:Number(w[4]),evidence_type:Number(w[5]),slot_index:Number(w[6]),
    created_at:time(7),updated_at:time(9),valid_from:time(11),valid_until:time(13),lifecycle:Number(w[15]),
    business:{assessment:Number(w[16]),risk_score:Number(w[17]),purpose_mask:Number(w[18])},raw_digest:hex(19,27),record_salt:hex(27,35)};
}
async function hashing() {
  const m=await buildMimcSponge(),cache=new Map();
  const hash=(kind,words=[],level=0)=>{
    const key=[kind,level,...words].join("/");if(cache.has(key))return cache.get(key);
    check(words.length<2**24&&level>=0&&level<2**24,"HASH_DOMAIN_RANGE");
    const domain=BigInt(CONFIG.hash.domain)+BigInt(kind)*281474976710656n+BigInt(level)*16777216n+BigInt(words.length);
    const result=m.multiHash(words.length?words:[0],domain.toString(),2).map(x=>m.F.toString(x));
    cache.set(key,result);return result;
  };
  return {hash,field:m.F};
}
class Tree {
  constructor(depth,kind,empty,h) {
    this.depth=depth;this.kind=kind;this.h=h;
    this.empty=[empty];for(let i=0;i<depth;i++)this.empty.push(h.hash(kind,[...this.empty[i],...this.empty[i]],i));
    this.levels=Array.from({length:depth+1},()=>new Map());
  }
  get root(){return this.levels[this.depth].get(0n)||this.empty[this.depth];}
  fork(){const t=Object.create(Tree.prototype);Object.assign(t,this,{levels:this.levels.map(level=>new Map(level))});return t;}
  opening(index) {
    let key=BigInt(index);check(key>=0n&&key<1n<<BigInt(this.depth),"TREE_INDEX");
    const result=[];
    for(let level=0;level<this.depth;level++) {result.push(this.levels[level].get(key^1n)||this.empty[level]);key>>=1n;}
    return clone(result);
  }
  set(index,leaf) {
    let key=BigInt(index);check(key>=0n&&key<1n<<BigInt(this.depth),"TREE_INDEX");
    this.levels[0].set(key,leaf);
    for(let level=0;level<this.depth;level++) {
      key>>=1n;
      const a=this.levels[level].get(key*2n)||this.empty[level],b=this.levels[level].get(key*2n+1n)||this.empty[level];
      this.levels[level+1].set(key,this.h.hash(this.kind,[...a,...b],level));
    }
  }
  verify(index,leaf,siblings,root) {
    if(siblings.length!==this.depth)return false;
    let key=BigInt(index),value=leaf;
    if(key<0n||key>=1n<<BigInt(this.depth))return false;
    for(let i=0;i<this.depth;i++) {value=this.h.hash(this.kind,key&1n?[...siblings[i],...value]:[...value,...siblings[i]],i);key>>=1n;}
    return equal(value,root);
  }
}
function profile(sources=1,slots=4,nodes=4,ablation="FULL") {
  check([1,2,3].includes(sources)&&[4,8,16].includes(slots)&&[4,8,16].includes(nodes),"PROFILE_CAPACITY");
  check(CONFIG.profiles.some(v=>v[0]===sources&&v[1]===slots&&v[2]===nodes),"UNREGISTERED_PROFILE");
  const modes=["FULL","NO_QUERY","NO_VALIDITY","NO_LINEAGE","NO_BINDING"];check(modes.includes(ablation),"UNKNOWN_LAB_PROFILE");
  const id=1000+sources*100+slots*2+nodes+modes.indexOf(ablation)*10000;
  return {protocol:CONFIG.protocol,id,psi_id:1100+slots*2+4,sources,slots,nodes,parents:4,log_depth:32,directory_depth:48,registry_depth:32,slot_depth:Math.log2(slots),ablation};
}
function record(source,id,slot,overrides={}) {
  const value={schema_version:1,source_id:source,record_id:id,version:1,object_id:7001,evidence_type:1,slot_index:slot,
    created_at:String(10+slot),updated_at:String(10+slot),valid_from:"0",valid_until:"1000000000",lifecycle:1,
    business:{assessment:1,risk_score:100+slot*17,purpose_mask:1},
    raw_digest:tagged("PRIVATE_ATTACHMENT",[source,id,slot,"PRIVATE_MARKER"]),record_salt:crypto.randomBytes(32).toString("hex"),...overrides};
  recordWords(value);return value;
}
class Source {
  constructor(id,p,h) {
    this.id=id;this.p=p;this.h=h;this.keys=keyPair(`core-demo-source-${id}`);
    this.log=new Tree(32,11,h.hash(10),h);this.directory=new Tree(48,7,h.hash(6),h);
    this.buckets=new Map();this.events=[];this.current=new Map();this.versions=new Map();
    this.genesis=[String(p.psi_id),String(id),"0",...this.log.root,...this.directory.root];
  }
  get state(){return [String(this.p.psi_id),String(this.id),String(this.events.length),...this.log.root,...this.directory.root];}
  fork() {
    const s=Object.create(Source.prototype);Object.assign(s,this,{log:this.log.fork(),directory:this.directory.fork(),events:this.events.slice(),current:new Map([...this.current].map(([k,v])=>[k,clone(v)])),versions:new Map(this.versions),buckets:new Map([...this.buckets].map(([k,b])=>[k,{records:clone(b.records),tree:b.tree.fork()}]))});return s;
  }
  apply(op,r) {
    const seq=this.events.length+1,key=`${r.object_id}:${r.evidence_type}`;
    let bucket=this.buckets.get(key);
    if(!bucket)bucket={records:[],tree:new Tree(this.p.slot_depth,4,this.h.hash(2),this.h)};
    const old=this.current.get(r.record_id),create=op===1;
    check(r.source_id===this.id&&[1,2,3].includes(op),"SOURCE_EVENT_ID");
    if(create)check(!old&&r.record_id===seq&&r.version===1&&r.lifecycle===1&&r.slot_index===bucket.records.length&&bucket.records.length<this.p.slots,"CREATE_RULES");
    else {
      check(old&&old.lifecycle===1&&r.version===old.version+1,"UPDATE_VERSION_OR_TOMBSTONE");
      for(const field of ["source_id","record_id","object_id","evidence_type","slot_index","created_at"])check(old[field]===r[field],"IMMUTABLE_FIELD");
      check(BigInt(r.updated_at)>=BigInt(old.updated_at)&&r.lifecycle===(op===3?2:1),"UPDATE_TIME_OR_LIFECYCLE");
    }
    const input={state:this.state,op,oldCount:bucket.records.length,
      oldRecord:old?recordWords(old):Array(35).fill(0),newRecord:recordWords(r),
      slotSiblings:bucket.tree.opening(r.slot_index),directorySiblings:this.directory.opening(BigInt(r.object_id)*65536n+BigInt(r.evidence_type)),logSiblings:this.log.opening(seq-1)};
    const newHash=this.h.hash(1,recordWords(r));
    const oldHash=old?this.h.hash(1,recordWords(old)):ZERO;
    const eventHash=this.h.hash(8,[op,old?.version||0,...oldHash,...newHash]);
    const logLeaf=this.h.hash(9,[seq,...eventHash]);
    bucket.tree.set(r.slot_index,this.h.hash(3,newHash));bucket.records[r.slot_index]=clone(r);
    this.buckets.set(key,bucket);
    this.directory.set(BigInt(r.object_id)*65536n+BigInt(r.evidence_type),this.h.hash(5,[r.object_id,r.evidence_type,bucket.records.length,...bucket.tree.root]));
    this.log.set(seq-1,logLeaf);this.current.set(r.record_id,clone(r));
    this.events.push({seq,op,record:clone(r),previous:clone(old||null),input});
    this.versions.set(`${r.record_id}:${r.version}`,{record:clone(r),seq,eventHash,logLeaf});
    return input;
  }
  checkpoint(task) {
    const body={profile_id:this.p.id,source_id:this.id,key_epoch:1,log_length:this.events.length,log_root:this.log.root,
      confirmed_at:task.issued_at+1,task_digest:tagged("TASK",task),receiver_id:task.receiver_id,nonce:task.nonce};
    return {...body,signature:sign(this.keys.privateKey,tagged("SOURCE_CP",body))};
  }
  bucket(object=7001,type=1) {
    return this.buckets.get(`${object}:${type}`)||{records:[],tree:new Tree(this.p.slot_depth,4,this.h.hash(2),this.h)};
  }
}
function task(p,seed=0,overrides={}) {
  return {protocol:CONFIG.protocol,profile_id:p.id,time_domain:"VIRTUAL_SECONDS",receiver_id:9001,nonce:tagged("NONCE",[seed]),issued_at:10000,evaluation_time:10001,deadline:10010,
    object_id:7001,evidence_type:1,registry_id:8001,created_from:0,created_until:100,max_risk_score:5000,purpose_bit:0,min_support_groups:1,require_each_source_nonempty:true,
    required_sources:Array.from({length:p.sources},(_,i)=>i+1),source_groups:Array.from({length:p.sources},(_,i)=>({source_id:i+1,group_id:i+1})),...overrides};
}
function publicKey(keys){return keys.publicKey.export({type:"spki",format:"pem"});}
module.exports={CONFIG,ZERO,clone,equal,SHA,tagged,u32words,limbs,recordWords,wordsRecord,hashing,Tree,profile,record,Source,task,publicKey,keyPair,sign,verify,binary,check};
