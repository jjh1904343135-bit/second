"use strict";
const D=require("./data"),P=require("./protocol");
function verify(task,w,p,h,signals) {
  const {check,equal}=D;
  const validRecord=r=>check(r.schema_version===1&&[1,2].includes(r.lifecycle)&&[1,2,3].includes(r.business.assessment)&&r.business.risk_score<=10000&&BigInt(r.created_at)<=BigInt(r.updated_at)&&BigInt(r.valid_from)<BigInt(r.valid_until),"PLAIN_RECORD_RULES");
  check(equal(P.publicSignals(w),signals),"PLAIN_PUBLIC_BINDING");
  const current=[],selected=[];
  for(let s=0;s<p.sources;s++) {
    check(Number.isInteger(w.counts[s])&&w.counts[s]>=0&&w.counts[s]<=p.slots,"PLAIN_COUNT");
    const tree=new D.Tree(p.slot_depth,4,h.hash(2),h);
    for(let r=0;r<p.slots;r++) {
      if(r>=w.counts[s]){check(w.records[s][r].every(v=>BigInt(v)===0n),"PLAIN_PADDING");check(w.selected[s][r]===0,"PLAIN_PADDING_SELECTED");continue;}
      const rec=D.wordsRecord(w.records[s][r]);check(equal(D.recordWords(rec),w.records[s][r]),"PLAIN_RECORD_ENCODING");validRecord(rec);
      check(rec.source_id===task.required_sources[s]&&rec.slot_index===r&&rec.object_id===task.object_id&&rec.evidence_type===task.evidence_type,"PLAIN_RECORD_KEY");
      tree.set(r,h.hash(3,h.hash(1,w.records[s][r])));current.push(rec);
      const hit=BigInt(rec.created_at)>=BigInt(task.created_from)&&BigInt(rec.created_at)<BigInt(task.created_until);check(w.selected[s][r]===Number(hit),"PLAIN_COMPLETENESS");if(hit)selected.push(rec);
    }
    const leaf=w.counts[s]?h.hash(5,[task.object_id,task.evidence_type,w.counts[s],...tree.root]):h.hash(6);
    check(new D.Tree(48,7,h.hash(6),h).verify(BigInt(task.object_id)*65536n+BigInt(task.evidence_type),leaf,w.directoryPaths[s],w.stateRoots[s]),"PLAIN_CURRENT_ROOT");
  }
  const q=h.hash(18,[...w.taskDigest,...w.qSalt,...w.selected.flatMap((row,s)=>row.flatMap((hit,r)=>[hit,...h.hash(1,w.records[s][r]).map(v=>hit?v:"0")]))]);check(equal(q,w.qCommit),"PLAIN_Q_OPENING");
  const nodes=[],roots=new Map();let ended=false;
  for(let i=0;i<p.nodes;i++) {
    const n=w.nodes[i];if(!n[0]){ended=true;check(n.every(v=>BigInt(v)===0n),"PLAIN_NODE_PADDING");continue;}
    check(!ended&&n[0]===1&&[1,2].includes(n[1])&&[1,2,3,4,5,6].includes(n[2]),"PLAIN_NODE_KIND");
    for(const v of [...n.slice(0,13),...n.slice(15)])check(Number.isInteger(v)&&v>=0&&v<2**32,"PLAIN_NODE_WORD");
    check(n[3]>0&&n[3]<=w.registryLength&&(!nodes.length||n[3]>nodes.at(-1).seq),"PLAIN_NODE_ORDER");
    const parents=w.parents[i].slice(0,n[15]);check(n[15]<=4&&w.parents[i].slice(n[15]).every(v=>v===0),"PLAIN_PARENTS");
    check(parents.every((v,k)=>nodes.some(n=>n.seq===v)&&(!k||v>parents[k-1])),"PLAIN_PARENT_CLOSURE");
    check(n[1]===1?n[2]===1&&parents.length===0:n[2]!==1&&(n[2]===6||parents.length>0),"PLAIN_ROOT_OPERATION");
    const ph=h.hash(12,[parents.length,...w.parents[i],...w.parentSalts[i]]);let ref=Array(6).fill(0),record=null;
    if(n[1]===1) {
      record=D.wordsRecord(w.rootRecords[i]);check(equal(D.recordWords(record),w.rootRecords[i]),"PLAIN_ROOT_ENCODING");validRecord(record);
      const digest=h.hash(1,w.rootRecords[i]);check(equal(digest,n.slice(13,15)),"PLAIN_ROOT_CONTENT");
      ref=[record.source_id,record.record_id,record.version,w.eventSeq[i],...digest];
      const s=task.required_sources.indexOf(record.source_id),event=h.hash(8,[...w.eventMeta[i],...digest]),leaf=h.hash(9,[w.eventSeq[i],...event]);
      check(s>=0&&w.eventSeq[i]>0&&w.eventSeq[i]<=w.logLengths[s]&&new D.Tree(32,11,h.hash(10),h).verify(w.eventSeq[i]-1,leaf,w.logPaths[i],w.logRoots[s]),"PLAIN_ROOT_LOG");
      roots.set(P.rootKey(record),record);
    } else check(w.rootRecords[i].every(v=>BigInt(v)===0n)&&w.eventSeq[i]===0&&w.eventMeta[i].every(v=>v===0),"PLAIN_DERIVED_ROOT");
    const leaf=h.hash(13,[...n,...ph,...ref]);check(new D.Tree(32,17,h.hash(16),h).verify(n[3]-1,leaf,w.registryPaths[i],w.registryRoot),"PLAIN_REGISTRY_PATH");
    nodes.push({seq:n[3],kind:n[1],op:n[2],parents,leaf,content:n.slice(13,15),record});
  }
  const last=nodes.at(-1);check(last&&last.op===6&&equal(last.leaf,w.handoffNode)&&equal(last.content,w.handoffCommit),"PLAIN_HANDOFF");
  const seen=new Set();function walk(n){if(seen.has(n.seq))return;seen.add(n.seq);n.parents.forEach(id=>walk(nodes.find(n=>n.seq===id)));}walk(last);check(seen.size===nodes.length,"PLAIN_EXACT_ANCESTORS");
  const rootList=[...roots.values()].sort((a,b)=>a.source_id-b.source_id||a.record_id-b.record_id||a.version-b.version);
  const sorted=Array.from({length:p.nodes},(_,i)=>rootList[i]?[1,rootList[i].source_id,rootList[i].record_id,rootList[i].version,...h.hash(1,D.recordWords(rootList[i]))]:Array(6).fill(0));
  check(equal(sorted.flat(),w.sortedRoots.flat()),"PLAIN_ROOT_DEDUP");check(equal(h.hash(19,[...w.taskDigest,...w.lSalt,...sorted.flat()]),w.lCommit),"PLAIN_L_OPENING");
  const valid=r=>r.lifecycle===1&&BigInt(r.valid_from)<=BigInt(task.evaluation_time)&&BigInt(task.deadline)<BigInt(r.valid_until)&&((r.business.purpose_mask>>>task.purpose_bit)&1)===1;
  const business=(!task.require_each_source_nonempty||task.required_sources.every(s=>selected.some(r=>r.source_id===s)))&&selected.every(r=>valid(r)&&r.business.assessment===1&&r.business.risk_score<=task.max_risk_score);
  const support=rootList.filter(r=>valid(r)&&selected.some(c=>P.rootKey(c)===P.rootKey(r)&&equal(h.hash(1,D.recordWords(c)),h.hash(1,D.recordWords(r)))));
  const groups=new Set(support.map(r=>task.source_groups.find(g=>g.source_id===r.source_id).group_id));
  const ok=support.length===rootList.length&&groups.size>=task.min_support_groups,decision=Number(business&&ok),reason=!business?1:!ok?2:0;
  check(w.decision===decision&&w.reason===reason,"PLAIN_POLICY_REASON");return {decision,reason};
}
module.exports={verify};
