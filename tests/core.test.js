"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const D=require("../src/core/data"),P=require("../src/core/protocol"),F=require("../src/core/fixtures"),B=require("../src/core/backend"),R=require("../src/core/receiver");
test("canonical JSON rejects literal and escaped duplicate keys",()=>{
  assert.throws(()=>R.strictJSON('{"nonce":1,"n\\u006fnce":2}'),/DUPLICATE/);
  assert.throws(()=>R.strictJSON('{"nested":{"x":1,"x":2}}'),/DUPLICATE/);
  assert.deepEqual(R.strictJSON('{"s":"a\\\"b","nested":[{"x":1},null,true]}'),{s:'a"b',nested:[{x:1},null,true]});
});
test("scalar encoding rejects aliases, alternate casing and non-fixed width",()=>{
  assert.equal(B.unhex(B.hex(B.FR-1n)),(B.FR-1n).toString());
  assert.throws(()=>B.unhex(B.hex(B.FR)),/FIELD_ALIAS/);assert.throws(()=>B.unhex("01"),/ENCODING/);assert.throws(()=>B.unhex("A".repeat(64)),/ENCODING/);
});
test("complete records preserve all 64-bit timestamps",()=>{
  const r=D.record(1,1,0,{valid_until:"18446744073709551615"});assert.deepEqual(D.wordsRecord(D.recordWords(r)),r);
  assert.throws(()=>D.limbs("18446744073709551616"),/U64/);assert.throws(()=>D.limbs(-1),/U64/);
});
test("log sequence, immutable keys and tombstones reject invalid updates",async()=>{
  const h=await D.hashing(),p=D.profile(),s=new D.Source(1,p,h);s.apply(1,D.record(1,1,0));
  const r=D.clone(s.current.get(1));r.version=2;r.lifecycle=2;s.apply(3,r);
  const resurrect=D.clone(r);resurrect.version=3;resurrect.lifecycle=1;assert.throws(()=>s.apply(2,resurrect),/TOMBSTONE/);
  assert.throws(()=>s.apply(1,D.record(1,4,1)),/CREATE_RULES/);
});
test("independent reference deduplicates a diamond and distinguishes real groups",async()=>{
  const h=await D.hashing(),p=D.profile(3,16,16),srcs=F.sources(p,h),t=D.task(p,"test",{min_support_groups:2});
  const single=F.graph(t,p,srcs,{topology:"diamond_single"});assert.equal(single.answer.groupCount,1);assert.equal(single.answer.reason,2);
  const two=F.graph(t,p,srcs,{topology:"diamond_two",rootRefs:[{source:1,id:1,version:1},{source:2,id:1,version:1}]});assert.equal(two.answer.groupCount,2);assert.equal(two.answer.decision,1);
  const same=D.task(p,"same-group",{min_support_groups:2,source_groups:[{source_id:1,group_id:1},{source_id:2,group_id:1},{source_id:3,group_id:3}]});assert.equal(F.graph(same,p,srcs,{rootRefs:[{source:1,id:1,version:1},{source:2,id:1,version:1}]}).answer.reason,2);
});
test("seed manifest has fifty actual attacks per family, positive controls separate",()=>{
  const rows=require("../src/core/security").plan();for(const family of Object.keys(require("../src/core/security").FAMILIES))assert.equal(rows.filter(r=>r.family===family&&r.phase==="seeded"&&r.subtype!=="true_two_groups").length,50);
  assert.deepEqual(rows,require("../src/core/security").plan());
});
test("MiMC domain, path level and word count bind distinct statements",async()=>{
  const h=await D.hashing();assert.notDeepEqual(h.hash(2),h.hash(2,[0]));assert.notDeepEqual(h.hash(7,[1,2,3,4],0),h.hash(7,[1,2,3,4],1));
});
test("two replay arms consume the identical frozen registry and commitments",async()=>{
  const h=await D.hashing(),p=D.profile(3,16,16),srcs=F.sources(p,h),t=D.task(p,"frozen"),texts=["工具断言的检索解释","工具断言的记忆转述"];
  const a=F.graph(t,p,srcs,{texts}),b=F.graph(t,p,srcs,{texts,replayNodes:a.registry.nodes,qSalt:a.prepared.input.qSalt,lSalt:a.prepared.input.lSalt});
  assert.deepEqual(a.prepared,b.prepared);assert.deepEqual(a.registry.communication,b.registry.communication);
  assert.throws(()=>F.graph(t,p,srcs,{texts:["篡改记忆"],replayNodes:a.registry.nodes}),/FROZEN/);
});
test("incremental private-index snapshot equals actual genesis replay without changing its prefix",async()=>{
  const h=await D.hashing(),p=D.profile(),s=new D.Source(1,p,h);for(let i=0;i<4;i++)s.apply(1,D.record(1,i+1,i));
  const before=s.state,copy=s.fork(),r=D.clone(copy.current.get(1));r.version++;r.updated_at="100";copy.apply(2,r);
  assert.deepEqual(s.state,before);assert.notDeepEqual(copy.state,s.state);
  const rebuilt=F.replay(p,h,[copy.events.map(e=>({op:e.op,record:e.record}))])[0];assert.deepEqual(copy.state,rebuilt.state);assert.deepEqual(copy.events.at(-1).input,rebuilt.events.at(-1).input);
});
test("plain verifier agrees with the three real prerequisite proofs and rejects omissions",{skip:!require("fs").existsSync("results/core/private/prerequisite/ALLOW/input.json")},async()=>{
  const fs=require("fs"),h=await D.hashing(),p=D.profile();
  for(const name of ["ALLOW","POLICY_DENY","INSUFFICIENT_SUPPORT"]) {
    const w=JSON.parse(fs.readFileSync(`results/core/private/prerequisite/${name}/input.json`)),t=JSON.parse(fs.readFileSync(`results/core/prerequisite/public/${name}/task.json`));
    const actual=require("../src/core/plain").verify(t,w,p,h,P.publicSignals(w));assert.equal(actual.decision,name==="ALLOW"?1:0);assert.equal(actual.reason,name==="ALLOW"?0:name==="POLICY_DENY"?1:2);
    const omitted=D.clone(w);omitted.selected[0][0]=0;assert.throws(()=>require("../src/core/plain").verify(t,omitted,p,h,P.publicSignals(omitted)),/COMPLETENESS/);
    const parent=D.clone(w);parent.parents[2][0]=1;assert.throws(()=>require("../src/core/plain").verify(t,parent,p,h,P.publicSignals(parent)),/REGISTRY/);
  }
});
