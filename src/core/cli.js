"use strict";
const fs=require("fs"),path=require("path"),os=require("os"),crypto=require("crypto");
const D=require("./data"),B=require("./backend"),{ROOT,OUT,save,run}=require("./runtime");
function gate() {
  const file=path.join(OUT,"prerequisite/validation.json");
  D.check(fs.existsSync(file),"RUN_CORE_CHECK_FIRST");const g=JSON.parse(fs.readFileSync(file));
  D.check(g.status==="PASS","PREREQUISITE_NOT_PASS");
  const keys=JSON.parse(fs.readFileSync(g.artifacts.keys_file));
  D.check(B.fileHash(keys.psi.r1cs)===g.psi.r1cs_sha256&&B.fileHash(path.join(keys.joint.dir,"circuit.r1cs"))===g.joint.r1cs_sha256,"STALE_GATE_ARTIFACTS");
  D.check(g.source_revision===revision(),"SOURCE_CHANGED_RERUN_CHECK");return g;
}
function revision() {
  const names=["configs/core.json",...fs.readdirSync(path.join(ROOT,"circuits/core")).map(x=>"circuits/core/"+x),...fs.readdirSync(path.join(ROOT,"src/core")).filter(x=>x.endsWith(".js")).map(x=>"src/core/"+x),"rust/psi/src/main.rs","rust/psi/Cargo.lock"];
  const hash=crypto.createHash("sha256");for(const n of names.sort())hash.update(n).update(fs.readFileSync(path.join(ROOT,n)));return hash.digest("hex");
}
async function metadata() {
  const commands={node:[process.execPath,["--version"]],rust:["rustc",["--version"]],cargo:["cargo",["--version"]],circom:[path.join(ROOT,"node_modules/.bin/circom2"),["--version"]],snarkjs:[path.join(ROOT,"node_modules/.bin/snarkjs"),["--version"]],gpu:["nvidia-smi",[]],ollama:["ollama",["--version"]],models:["ollama",["list"]],ollama_ps:["ollama",["ps"]]};
  const actual={date:new Date().toISOString(),os:{type:os.type(),release:os.release(),arch:os.arch()},cpu:os.cpus()[0]?.model,logical_cpus:os.cpus().length,total_memory_bytes:os.totalmem(),config:D.CONFIG,source_revision:revision(),commands:{}};
  for(const [name,[cmd,args]] of Object.entries(commands))try{actual.commands[name]=await run(cmd,args,{quiet:true,timeout:30000,log:path.join(OUT,`environment/${name}.log`)});}catch(e){actual.commands[name]={error:e.message};}
  save(path.join(OUT,"manifest.json"),actual);return actual;
}
async function main(command="all") {
  D.check(process.argv.length<=3,"EXTRA_ARGUMENTS_USE_CONFIGS_CORE_JSON");
  D.check(["all","check","experiment1","experiment2","experiment2-calibrate","experiment2-main","experiment3","report"].includes(command),"UNKNOWN_CORE_COMMAND");
  if(command==="report")return require("./report").main();
  await metadata();
  if(["all","check"].includes(command)) {
    try {const r=await require("./prerequisite").main();r.source_revision=revision();save(path.join(OUT,"prerequisite/validation.json"),r);}
    catch(e){save(path.join(OUT,"prerequisite/validation.json"),{status:"FAIL",error:e.message,execution:e.execution,source_revision:revision(),failed_at:new Date().toISOString()});throw e;}
  }
  gate();
  const tests=await run(process.execPath,["--test","tests/core.test.js"],{quiet:true,log:path.join(OUT,"tests.log")});
  save(path.join(OUT,"tests.json"),{status:tests.status,execution:{...tests,output:undefined}});D.check(tests.status==="PASS","MANDATORY_TESTS_FAILED");
  if(command==="experiment2-calibrate")return require("./performance").calibration();
  if(command==="experiment2-main")return require("./performance").mainOnly();
  for(const [name,module] of [["experiment1","security"],["experiment2","performance"],["experiment3","agents"]])if(command==="all"||command===name) {
    const frozen=revision();process.env.CORE_SOURCE_REVISION=frozen;
    console.log(`START ${name}`);await require(`./${module}`).main();D.check(revision()===frozen,"SOURCE_CHANGED_DURING_EXPERIMENT");
  }
  return require("./report").main();
}
if(require.main===module)main(process.argv[2]||"all").then(r=>process.exit((process.argv[2]||"all")==="all"&&r.functional_status!=="PASS"?1:0)).catch(async e=>{console.error(`CORE STOPPED: ${e.message}`);try{await require("./report").main();}catch(reportError){console.error(reportError.message);}process.exit(1);});
module.exports={main,gate,revision,metadata};
