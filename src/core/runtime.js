"use strict";
const fs=require("fs"),path=require("path"),{spawn}=require("child_process");
const ROOT=path.resolve(__dirname,"../..");
const OUT=path.join(ROOT,"results/core");
const TMP=path.join(ROOT,"build/core/tmp");
const cfg=require("../../configs/core.json");
const RUN_ID=process.env.CORE_RUN_ID||(process.env.CORE_RUN_ID=new Date().toISOString().replace(/[:.]/g,"-")+"-"+process.pid);
function save(file,data){fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,JSON.stringify(data,null,2)+"\n");}
function rss(pid) {
  try {
    const status=fs.readFileSync(`/proc/${pid}/status`,"utf8");
    let total=Number(status.match(/^VmRSS:\s+(\d+)/m)?.[1]||0)*1024;
    const kids=fs.readFileSync(`/proc/${pid}/task/${pid}/children`,"utf8").trim().split(/\s+/).filter(Boolean);
    for(const child of kids)total+=rss(Number(child));return total;
  }catch{return 0;}
}
function run(command,args,{log,timeout=cfg.benchmark.configuration_timeout_seconds*1000,quiet=false,cwd=ROOT}={}) {
  fs.mkdirSync(TMP,{recursive:true});if(log)fs.mkdirSync(path.dirname(log),{recursive:true});
  const started=performance.now();let peak=0,reason=null,text="";
  return new Promise((resolve,reject)=>{
    const child=spawn(command,args,{cwd,detached:true,env:{...process.env,TMPDIR:TMP,
      PATH:`/mnt/user-data/zjh/.cargo/bin:${process.env.PATH}`,RAYON_NUM_THREADS:String(cfg.benchmark.threads),
      CARGO_TARGET_DIR:path.join(ROOT,"build/core/rust"),NODE_OPTIONS:`--max-old-space-size=${cfg.benchmark.node_heap_mib}`},stdio:["ignore","pipe","pipe"]});
    const append=chunk=>{if(log)fs.appendFileSync(log,chunk);if(!quiet)process.stdout.write(chunk);else if(process.env.CORE_RUN_LOG)fs.appendFileSync(process.env.CORE_RUN_LOG,chunk);text=(text+chunk.toString()).slice(-1048576);};
    child.stdout.on("data",append);child.stderr.on("data",append);
    const kill=why=>{if(reason)return;reason=why;killTree(child.pid);};
    const remaining=process.env.CORE_DEADLINE_MS?Number(process.env.CORE_DEADLINE_MS)-Date.now():Infinity;
    const clock=setTimeout(()=>kill("TIMEOUT"),Math.max(1,Math.min(timeout,remaining)));
    const monitor=setInterval(()=>{peak=Math.max(peak,rss(child.pid));if(peak>cfg.benchmark.memory_limit_gib*1024**3)kill("RESOURCE_LIMIT");},100);
    child.on("error",e=>{clearTimeout(clock);clearInterval(monitor);reject(e);});
    child.on("close",(code,signal)=>{
      clearTimeout(clock);clearInterval(monitor);
      const result={exit_code:code,signal,status:reason||(code===0?"PASS":"FAIL"),wall_ms:performance.now()-started,sampled_process_tree_peak_rss_bytes:peak,output:text};
      if(log)save(log+".execution.json",{...result,output:undefined,command:[command,...args]});
      resolve(result);
    });
  });
}
function killTree(pid) {
  try {for(const p of fs.readFileSync(`/proc/${pid}/task/${pid}/children`,"utf8").trim().split(/\s+/).filter(Boolean))killTree(Number(p));}catch{}
  try{process.kill(-pid,"SIGKILL");}catch{try{process.kill(pid,"SIGKILL");}catch{}}
}
function jsonResult(result) {
  if(result.status!=="PASS")throw Object.assign(new Error(`SUBPROCESS_${result.status}: ${result.output.slice(-2000)}`),{execution:result});
  const line=result.output.trim().split("\n").filter(s=>s.startsWith("{")).at(-1);
  if(!line)throw new Error("MISSING_JSON_SUBPROCESS_RESULT");return JSON.parse(line);
}
function beginExperiment(name) {
  const dir=path.join(OUT,name);
  if(fs.existsSync(path.join(dir,"input-manifest.json"))) {
    const archive=path.join(OUT,"attempts",`${name}-${RUN_ID}`);fs.mkdirSync(path.dirname(archive),{recursive:true});fs.renameSync(dir,archive);
  }
  fs.mkdirSync(dir,{recursive:true});return dir;
}
module.exports={ROOT,OUT,TMP,RUN_ID,save,run,jsonResult,beginExperiment};
