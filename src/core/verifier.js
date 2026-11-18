"use strict";
const fs=require("fs"),path=require("path"),net=require("net"),crypto=require("crypto"),{spawn}=require("child_process");
const {ROOT,OUT,save}=require("./runtime");
const servers=new Map();
// Cache only the public verification key, never proof outcomes. Every request
// performs the official compressed Nova verification against the supplied state.
async function ensure(params,vk_id,logDir) {
  if(servers.has(vk_id))return servers.get(vk_id).ready;
  const socket=path.join(OUT,`private/nova-${process.pid}-${vk_id.slice(0,8)}.sock`);fs.mkdirSync(path.dirname(socket),{recursive:true,mode:0o700});if(fs.existsSync(socket))fs.unlinkSync(socket);
  const log=path.join(logDir,"nova-verifier-bootstrap.log"),started=performance.now();let output="";
  const child=spawn(path.join(ROOT,"build/core/rust/release/rcpeh-psi"),["serve",params,socket],{stdio:["ignore","pipe","pipe"],env:{...process.env,RAYON_NUM_THREADS:String(require("../../configs/core.json").benchmark.threads)}});
  const ready=new Promise((resolve,reject)=>{
    const clock=setTimeout(()=>{child.kill("SIGKILL");reject(new Error("VERIFIER_BOOTSTRAP_TIMEOUT"));},180000);
    child.stdout.on("data",c=>{fs.appendFileSync(log,c);output+=c;const line=output.split("\n").find(s=>s.startsWith("{"));if(line){try{const r=JSON.parse(line);if(r.ready&&r.vk_id===vk_id){clearTimeout(clock);const result={...r,socket,wall_ms:performance.now()-started};save(path.join(logDir,"nova-verifier-bootstrap.json"),result);resolve(result);}}catch{}}});
    child.stderr.on("data",c=>fs.appendFileSync(log,c));child.on("error",e=>{clearTimeout(clock);reject(e);});child.on("exit",code=>{clearTimeout(clock);reject(new Error(`VERIFIER_EXIT_${code}`));});
  });
  servers.set(vk_id,{child,ready,socket});process.once("exit",()=>{child.kill("SIGTERM");try{fs.unlinkSync(socket);}catch{}});
  const r=await ready;const env=JSON.parse(process.env.CORE_NOVA_VERIFIERS||"{}");env[vk_id]=socket;process.env.CORE_NOVA_VERIFIERS=JSON.stringify(env);return r;
}
async function verify(keys,expected,proofFile) {
  const socket=JSON.parse(process.env.CORE_NOVA_VERIFIERS||"{}")[keys.vk_id];if(!socket)return null;
  const id=crypto.randomBytes(16).toString("hex"),start=performance.now();
  const result=await new Promise((resolve,reject)=>{
    const connection=net.createConnection(socket),data={id,statement:expected,proof_hex:fs.readFileSync(proofFile).toString("hex")};let text="";
    connection.setTimeout(120000,()=>connection.destroy(new Error("NOVA_VERIFY_TIMEOUT")));
    connection.on("connect",()=>connection.write(JSON.stringify(data)+"\n"));connection.on("data",c=>text+=c);connection.on("end",()=>{try{resolve(JSON.parse(text));}catch(e){reject(e);}});connection.on("error",reject);
  });
  if(result.vk_id!==keys.vk_id||result.verified&&result.id!==id)throw new Error("VERIFIER_RESPONSE_BINDING");
  return {...result,wall_ms:performance.now()-start,key_cache:"preloaded public key; proof verification not cached"};
}
module.exports={ensure,verify};
