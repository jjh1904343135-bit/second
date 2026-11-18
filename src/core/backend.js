"use strict";
const fs=require("fs"),path=require("path"),crypto=require("crypto");
const snark=require("snarkjs");
const D=require("./data"),P=require("./protocol");
const {ROOT,OUT,save,run,jsonResult}=require("./runtime");
const BUILD=path.join(ROOT,"build/core"),BIN=path.join(BUILD,"rust/release/rcpeh-psi");
const CIRCOM=path.join(ROOT,"node_modules/.bin/circom2"),SNARK=path.join(ROOT,"node_modules/.bin/snarkjs");
const fileHash=f=>D.SHA(fs.readFileSync(f));
function must(result){D.check(result.status==="PASS",`PROCESS_${result.status}: ${result.output.slice(-1000)}`);return result;}
async function compile(source,dir,log) {
  fs.mkdirSync(dir,{recursive:true});const file=path.join(dir,"circuit.circom");
  const dependencies=source.includes("PsiStep(")?["common","psi"]:["common","joint"];
  const stamp=D.tagged("CIRCUIT_SOURCE",[source,...dependencies.map(n=>fileHash(path.join(ROOT,`circuits/core/${n}.circom`))),fileHash(path.join(ROOT,"node_modules/circomlib/circuits/mimcsponge.circom"))]);
  const marker=path.join(dir,"compiled.json");
  if(fs.existsSync(marker)) {
    const previous=JSON.parse(fs.readFileSync(marker));
    if(previous.stamp===stamp&&["circuit.r1cs","circuit_js/circuit.wasm"].every(f=>fs.existsSync(path.join(dir,f))))return {...previous,reused:true};
  }
  fs.writeFileSync(file,source);
  const result=must(await run(CIRCOM,[file,"--r1cs","--wasm","--sym","--O1","-l","node_modules","-o",dir],{log}));
  const info=await snark.r1cs.info(path.join(dir,"circuit.r1cs"));
  const metadata={stamp,constraints:info.nConstraints,public_inputs:info.nPubInputs,outputs:info.nOutputs,wires:info.nVars,compile:result,
    r1cs_sha256:fileHash(path.join(dir,"circuit.r1cs")),wasm_sha256:fileHash(path.join(dir,"circuit_js/circuit.wasm"))};
  delete metadata.compile.output;save(marker,metadata);return {...metadata,reused:false};
}
async function psiKeys(p,h,logDir) {
  const dir=path.join(BUILD,`psi-${p.slots}`);fs.mkdirSync(logDir,{recursive:true});
  const empty=new D.Tree(p.slot_depth,4,h.hash(2),h).root;
  const code=`pragma circom 2.1.6;\ninclude "../../../circuits/core/psi.circom";\ncomponent main {public [state]} = PsiStep(${p.slots},${p.psi_id},${empty[0]},${empty[1]});\n`;
  const meta=await compile(code,dir,path.join(logDir,`compile-psi-${p.slots}.log`));
  const params=path.join(dir,"nova"),marker=path.join(params,"r1cs.sha256");
  let setup=null;
  if(!fs.existsSync(marker)||fs.readFileSync(marker,"utf8")!==meta.r1cs_sha256)setup=jsonResult(await run(BIN,["setup",path.join(dir,"circuit.r1cs"),params],{log:path.join(logDir,`setup-psi-${p.slots}.log`)}));
  const vk_id=fileHash(path.join(params,"vk.bin"));
  const verifier_bootstrap=await require("./verifier").ensure(params,vk_id,logDir);
  return {dir,params,wasm:path.join(dir,"circuit_js/circuit.wasm"),r1cs:path.join(dir,"circuit.r1cs"),vk_id,meta,setup,verifier_bootstrap};
}
async function parameter(power,log) {
  const file=path.join(ROOT,`params/powersOfTau28_hez_final_${power}.ptau`);
  const readme=fs.readFileSync(path.join(ROOT,"node_modules/snarkjs/README.md"),"utf8");
  const expected=readme.split("\n").find(l=>l.includes(`hez_final_${power}.ptau`))?.match(/[a-f0-9]{128}/)?.[0];
  D.check(expected,"UNKNOWN_PARAMETER_DIGEST");
  if(!fs.existsSync(file)) {
    must(await run("python3",[path.join(ROOT,"scripts/download_ptau.py"),`https://circom.info/powersOfTau28_hez_final_${power}.ptau`,file+".part"],{log,timeout:7200000}));
  }
  const candidate=fs.existsSync(file)?file:file+".part";
  const sum=must(await run("b2sum",[candidate],{log,quiet:true})).output.trim().split(/\s/)[0];
  D.check(sum===expected,"PARAMETER_INTEGRITY");
  if(candidate!==file)fs.renameSync(candidate,file);
  save(file+".verified.json",{power,bytes:fs.statSync(file).size,blake2b:sum,expected,verified:sum===expected});return file;
}
async function jointKeys(p,logDir) {
  const dir=path.join(BUILD,`joint-${p.id}-${p.ablation}`);fs.mkdirSync(logDir,{recursive:true});
  const code=`pragma circom 2.1.6;\ninclude "../../../circuits/core/joint.circom";\ncomponent main {public [${P.PUBLIC.join(",")}]}=CoreJoint(${p.sources},${p.slots},${p.nodes},${p.id},${P.MODES[p.ablation]});\n`;
  const meta=await compile(code,dir,path.join(logDir,`compile-joint-${p.id}-${p.ablation}.log`));
  const key=path.join(dir,"final.zkey"),stamp=path.join(dir,"key-r1cs.sha256");
  let setup=null;
  if(!fs.existsSync(key)||!fs.existsSync(stamp)||fs.readFileSync(stamp,"utf8")!==meta.r1cs_sha256) {
    const started=performance.now();const power=Math.ceil(Math.log2(meta.constraints+meta.public_inputs+meta.outputs+1));
    const ptau=await parameter(power<=19?19:power<=21?21:power,path.join(logDir,`parameter-${power}.log`));
    must(await run(SNARK,["groth16","setup",path.join(dir,"circuit.r1cs"),ptau,path.join(dir,"initial.zkey")],{log:path.join(logDir,`setup-joint-${p.id}-${p.ablation}.log`)}));
    await snark.zKey.contribute(path.join(dir,"initial.zkey"),key,"core local research contribution",crypto.randomBytes(32).toString("hex"));
    fs.unlinkSync(path.join(dir,"initial.zkey"));fs.writeFileSync(stamp,meta.r1cs_sha256);
    setup={wall_ms:performance.now()-started,power,ceremony:"local research phase-2 contribution"};
  }
  const vk=await snark.zKey.exportVerificationKey(key);save(path.join(dir,"verification_key.json"),vk);
  return {dir,key,wasm:path.join(dir,"circuit_js/circuit.wasm"),vk,vk_id:fileHash(path.join(dir,"verification_key.json")),meta,setup};
}
async function proveState(source,keys,dir,{resume=null}={}) {
  fs.mkdirSync(dir,{recursive:true,mode:0o700});
  if(source.events.length===0)return {empty:true,status:"CANONICAL_EMPTY_STATE",statement:{num_steps:0,z0:source.genesis,output:source.genesis},vk_id:keys.vk_id,witness_ms:0};
  const witnesses=[];const from=resume?.statement.num_steps||0;
  if(resume)D.check(resume.statement.z0.every((v,i)=>v===source.genesis[i]),"RESUME_GENESIS");
  const prepared=performance.now();
  for(let i=from;i<source.events.length;i++) {
    const file=path.join(dir,`step-${i+1}.wtns`);
    save(path.join(dir,`step-${i+1}.json`),source.events[i].input);
    await snark.wtns.calculate(source.events[i].input,keys.wasm,file);witnesses.push(file);
  }
  const witness_ms=performance.now()-prepared;
  const job={z0:source.genesis,witnesses,checkpoint_in:resume?.checkpoint||null,checkpoint_out:path.join(dir,"ivc.bin"),proof_out:path.join(dir,"psi.bin")};
  save(path.join(dir,"job.json"),job);
  const execution=await run(BIN,["prove",keys.r1cs,keys.params,path.join(dir,"job.json")],{log:path.join(dir,"nova.log"),quiet:true});
  const result=jsonResult(execution);
  D.check(D.equal(result.statement.output,source.state),"NOVA_PUBLIC_STATE_AGREEMENT");
  const record={...result,witness_ms,execution:{...execution,output:undefined},checkpoint:job.checkpoint_out,file:job.proof_out,
    proof_sha256:fileHash(job.proof_out),vk_id:keys.vk_id};save(path.join(dir,"result.json"),record);return record;
}
async function proveTask(input,keys,dir) {
  fs.mkdirSync(dir,{recursive:true,mode:0o700});save(path.join(dir,"input.json"),input);
  const witness=path.join(dir,"witness.wtns");let started=performance.now();
  await snark.wtns.calculate(input,keys.wasm,witness);const witness_ms=performance.now()-started;
  started=performance.now();const output=await snark.groth16.prove(keys.key,witness);const prove_ms=performance.now()-started;
  D.check(D.equal(output.publicSignals,P.publicSignals(input)),"JOINT_PUBLIC_LAYOUT");
  started=performance.now();const verified=await snark.groth16.verify(keys.vk,output.publicSignals,output.proof);const verify_ms=performance.now()-started;
  D.check(verified,"JOINT_GROTH16_VERIFY");
  save(path.join(dir,"proof.json"),output.proof);save(path.join(dir,"public.json"),output.publicSignals);
  return {...output,witness_ms,prove_ms,verify_ms,verified};
}
const FR=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const FQ=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function hex(v){return BigInt(v).toString(16).padStart(64,"0");}
function unhex(v,mod=FR){D.check(typeof v==="string"&&/^[0-9a-f]{64}$/.test(v),"FIELD_WIRE_ENCODING");const n=BigInt("0x"+v);D.check(n<mod,"FIELD_ALIAS");return n.toString();}
const rootWire=v=>v.map(hex),rootRead=v=>{D.check(Array.isArray(v)&&v.length===2,"ROOT_SHAPE");return v.map(x=>unhex(x));};
function wireCP(cp) {const v=cloneCP(cp);for(const k of ["log_root","registry_root","handoff_node_commit","handoff_content_commit"])if(v[k])v[k]=rootWire(v[k]);return v;}
function readCP(cp){const v=cloneCP(cp);for(const k of ["log_root","registry_root","handoff_node_commit","handoff_content_commit"])if(v[k])v[k]=rootRead(v[k]);return v;}
function cloneCP(v){return structuredClone(v);}
function wireProof(proof){return {a:proof.pi_a.slice(0,2).map(hex),b:proof.pi_b.slice(0,2).map(row=>row.map(hex)),c:proof.pi_c.slice(0,2).map(hex)};}
function readProof(proof){D.check(Object.keys(proof).sort().join(",")==="a,b,c"&&[proof.a,proof.b,proof.c].every(v=>Array.isArray(v)&&v.length===2)&&proof.b.every(v=>Array.isArray(v)&&v.length===2),"GROTH16_WIRE_SCHEMA");return {protocol:"groth16",curve:"bn128",pi_a:[...proof.a.map(x=>unhex(x,FQ)),"1"],pi_b:[...proof.b.map(row=>row.map(x=>unhex(x,FQ))),["1","0"]],pi_c:[...proof.c.map(x=>unhex(x,FQ)),"1"]};}
function bundle(task,p,prepared,states,joint) {
  return {protocol:D.CONFIG.protocol,profile_id:p.id,complete:true,
    sources:prepared.source_checkpoints.map((cp,i)=>({checkpoint:wireCP(cp),
      statement:{profile_id:Number(states[i].statement.output[0]),source_id:Number(states[i].statement.output[1]),length:Number(states[i].statement.output[2]),
        log_root:rootWire(states[i].statement.output.slice(3,5)),state_root:rootWire(states[i].statement.output.slice(5))},
      proof:states[i].empty?"EMPTY_STATE":fs.readFileSync(states[i].file).toString("base64")})),
    registry_checkpoint:wireCP(prepared.registry_checkpoint),payload:prepared.payload,
    commitments:{q:rootWire(prepared.input.qCommit),l:rootWire(prepared.input.lCommit)},
    public_signals:joint.publicSignals.map(hex),proof:wireProof(joint.proof)};
}
module.exports={BUILD,BIN,psiKeys,jointKeys,proveState,proveTask,parameter,bundle,rootWire,rootRead,wireCP,readCP,wireProof,readProof,unhex,hex,fileHash,FR};
