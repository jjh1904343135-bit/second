"use strict";
function check(ok,code){if(!ok)throw Object.assign(new Error(code),{code});}
function integer(value,width) {
  if(width===8)check(typeof value==="string"&&/^(0|[1-9][0-9]*)$/.test(value),"U64_REQUIRES_DECIMAL_STRING");else check(Number.isSafeInteger(value),"INVALID_INTEGER");
  let n=BigInt(value);check(n>=0n&&n<1n<<BigInt(width*8),"INTEGER_OUT_OF_RANGE");const out=Buffer.alloc(width);
  for(let i=width-1;i>=0;i--){out[i]=Number(n&255n);n>>=8n;}return out;
}
const S={business:[["assessment","u8"],["risk_score","u16"],["purpose_mask","u32"]],record:[["schema_version","u16"],["source_id","u32"],["record_id","u32"],["version","u32"],["object_id","u32"],["evidence_type","u16"],["slot_index","u8"],["created_at","u64"],["updated_at","u64"],["valid_from","u64"],["valid_until","u64"],["lifecycle","u8"],["business","business"],["raw_digest","bytes32"],["record_salt","bytes32"]]};
function encode(name,v) {
  const schema=S[name];check(v&&typeof v==="object"&&schema&&Object.keys(v).length===schema.length&&schema.every(([k])=>Object.hasOwn(v,k)),`SCHEMA_FIELDS_${name}`);
  return Buffer.concat(schema.map(([key,type])=>{const x=v[key];if(/^u/.test(type))return integer(x,Number(type.slice(1))/8);if(type==="bytes32"){check(typeof x==="string"&&/^[0-9a-f]{64}$/.test(x),"INVALID_HEX");return Buffer.from(x,"hex");}return encode(type,x);}));
}
function binary(value) {
  if(value===null)return Buffer.from([0]);
  if(typeof value==="boolean")return Buffer.from([1,Number(value)]);
  if(typeof value==="number"){check(Number.isSafeInteger(value)&&value>=0,"BINARY_NUMBER");return Buffer.concat([Buffer.from([2]),integer(String(value),8)]);}
  if(typeof value==="string"){const b=Buffer.from(value);return Buffer.concat([Buffer.from([3]),integer(b.length,4),b]);}
  if(Array.isArray(value))return Buffer.concat([Buffer.from([4]),integer(value.length,4),...value.map(binary)]);
  check(value&&typeof value==="object","BINARY_TYPE");const keys=Object.keys(value).sort();return Buffer.concat([Buffer.from([5]),integer(keys.length,4),...keys.flatMap(k=>[binary(k),binary(value[k])])]);
}
module.exports={check,integer,encode,binary};
