"use strict";
const crypto=require("crypto");
// Reproducible local research authority keys; not production key management.
function keyPair(seed) {
  const privateKey=crypto.createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),crypto.createHash("sha256").update(seed).digest()]),format:"der",type:"pkcs8"});
  return {privateKey,publicKey:crypto.createPublicKey(privateKey)};
}
const sign=(key,hash)=>crypto.sign(null,Buffer.from(hash,"hex"),key).toString("hex");
function verify(key,hash,signature) {
  try{return typeof signature==="string"&&/^[a-f0-9]{128}$/.test(signature)&&crypto.verify(null,Buffer.from(hash,"hex"),key,Buffer.from(signature,"hex"));}catch{return false;}
}
module.exports={keyPair,sign,verify};
