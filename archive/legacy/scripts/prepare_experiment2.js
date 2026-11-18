"use strict";
const fs=require("fs"),path=require("path");
const {spawnSync}=require("child_process");
const root=path.resolve(__dirname,"..");
fs.mkdirSync(path.join(root,"params"),{recursive:true});
const readme=fs.readFileSync(path.join(root,"node_modules/snarkjs/README.md"),"utf8");
const records=[];
for(const power of [19,21]) {
  const name=`powersOfTau28_hez_final_${power}.ptau`;
  const expected=readme.split("\n").find(line=>line.includes(name)).match(/[a-f0-9]{128}/)[0];
  const file=path.join(root,"params",name);
  if(!fs.existsSync(file)) {
    const part=file+".part";
    // Mirror fallback; actual bytes must match the official snarkjs digest.
    const url=`https://circom.info/${name}`;
    const r=spawnSync("curl",["--fail","--location","--retry","2","--silent","--show-error","-o",part,url],{stdio:"inherit"});
    if(r.status!==0)throw new Error(`PARAMETER_DOWNLOAD_FAILED: ${name}`);
    fs.renameSync(part,file);
  }
  const r=spawnSync("b2sum",[file],{encoding:"utf8"});
  const actual=r.stdout.trim().split(/\s/)[0];
  if(r.status!==0||actual!==expected)throw new Error(`PARAMETER_DIGEST_MISMATCH: ${name}`);
  console.log(`Parameters ${name}: BLAKE2b PASS`);
  records.push({file:name,bytes:fs.statSync(file).size,expected_blake2b:expected,actual_blake2b:actual,verified:actual===expected});
}
fs.mkdirSync(path.join(root,"results/experiment2"),{recursive:true});
fs.writeFileSync(path.join(root,"results/experiment2/parameters.json"),JSON.stringify({checked_at:new Date().toISOString(),source:"node_modules/snarkjs/README.md",files:records},null,2)+"\n");
