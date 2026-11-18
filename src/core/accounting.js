"use strict";
const fs=require("fs"),path=require("path");
const {save}=require("./runtime");
// Exclusive attribution of optimized R1CS rows by surviving wire namespaces.
// A row touching multiple categories belongs to shared_binding, never counted twice.
function category(name) {
  if(/^main\.(directory|slotTree|bucket|slotHash|regPath|logPath|eventHash|logLeaf|emptySlot|emptyDir)(\[|\.)/.test(name))return "authentication";
  if(/^main\.(rec|records|counts|count|exists|selected|lowerOK|upperOK|hitGate|coverage|sourceOK|qHash|qSalt)(\[|\.)/.test(name))return "complete_scan";
  if(/^main\.(life|assessment|risk|fromOK|untilOK|purpose|validity|businessOK|recordOK|effectiveValid|allCoverage|allRecords|enough|groups|hasGroup|sameGroup|firstGroup|supportOK|p|s)(\[|\.|$)/.test(name))return "policy";
  if(/^main\.(nodes|parents|parent|root|node|eventMeta|eventSeq|sorted|lHash|lSalt|claimedGroups|sourceRoot|qualified|supportFlag|allSupport|eligible|qualify|keyEq|hashEq|matches|firstRoot|sameKey|unique|edge|active|last|reached|reachable|unreachable|final|logTerms|lengthTerms|selectedLog|selectedLength|seqLimit|order|derivedEq|opEq)(\[|\.|[A-Z])/.test(name))return "lineage_dedup";
  return "shared_binding";
}
function account(dir,expected) {
  const kinds=["authentication","complete_scan","lineage_dedup","policy","shared_binding"],mask=new Map(kinds.map((k,i)=>[k,1<<i]));
  const wire=new Map();
  for(const line of fs.readFileSync(path.join(dir,"circuit.sym"),"utf8").split("\n")) {
    const f=line.split(","),id=Number(f[1]);if(f.length<4||id<1)continue;
    wire.set(id,(wire.get(id)||0)|mask.get(category(f[3])));
  }
  const buf=fs.readFileSync(path.join(dir,"circuit.r1cs"));let offset=12,body=0,size=0;
  const sections=buf.readUInt32LE(8);
  for(let i=0;i<sections;i++){const type=buf.readUInt32LE(offset),n=Number(buf.readBigUInt64LE(offset+4));offset+=12;if(type===2){body=offset;size=n;}offset+=n;}
  if(!body)throw new Error("R1CS_CONSTRAINT_SECTION");
  const counts=Object.fromEntries(kinds.map(k=>[k,0]));offset=body;let total=0;
  while(offset<body+size) {
    let seen=0;
    for(let part=0;part<3;part++) {const n=buf.readUInt32LE(offset);offset+=4;for(let term=0;term<n;term++){const id=buf.readUInt32LE(offset);if(id)seen|=wire.get(id)||16;offset+=36;}}
    const one=kinds.find(k=>mask.get(k)===seen);counts[one||"shared_binding"]++;total++;
  }
  if(total!==expected||offset!==body+size)throw new Error("CONSTRAINT_ACCOUNTING_MISMATCH");
  const result={method:"Exclusive attribution by surviving optimized R1CS wire namespaces; mixed rows assigned shared_binding. This is not separate subcircuit proving.",...counts,total,expected,balanced:total===expected};
  save(path.join(dir,"constraint-accounting.json"),result);return result;
}
module.exports={account};
