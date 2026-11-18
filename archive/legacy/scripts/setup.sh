#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build params
circuit="circuits/real_experiment1.circom"
ptau="params/powersOfTau28_hez_final_19.ptau"
expected="bca9d8b04242f175189872c42ceaa21e2951e0f0f272a0cc54fc37193ff6648600eaf1c555c70cdedfaf9fb74927de7aa1d33dc1e2a7f1a50619484989da0887"
./node_modules/.bin/circom2 "$circuit" --r1cs --wasm --sym --O1 -l node_modules -o build
if [[ ! -f "$ptau" ]]; then
  curl --fail --location --retry 2 -o "$ptau" https://circom.info/powersOfTau28_hez_final_19.ptau
fi
actual=$(b2sum "$ptau")
if [[ "${actual%% *}" != "$expected" ]]; then
  echo "Powers of tau integrity mismatch; incomplete or invalid parameter file." >&2
  exit 1
fi
node - <<'NODE'
const fs=require('fs'),snark=require('snarkjs');
snark.r1cs.info('build/real_experiment1.r1cs').then(info=>{
  if(info.nConstraints+info.nPubInputs+info.nOutputs>=2**19)throw new Error('Powers of tau capacity exceeded');
  const metadata={constraints:info.nConstraints,wires:info.nVars,public_inputs:info.nPubInputs,private_inputs:info.nPrvInputs,power:19,hash:'MiMCSponge-220-BN254',parameter_url:'https://circom.info/powersOfTau28_hez_final_19.ptau',setup:'single local research contribution'};
  fs.writeFileSync('build/metadata.json',JSON.stringify(metadata,null,2)+'\n');
  console.log(JSON.stringify(metadata));process.exit(0);
}).catch(e=>{console.error(e);process.exit(1)});
NODE
./node_modules/.bin/snarkjs groth16 setup build/real_experiment1.r1cs "$ptau" build/task_0000.zkey
task_entropy=$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')
./node_modules/.bin/snarkjs zkey contribute build/task_0000.zkey build/task_final.zkey --name="local research contribution" -e="$task_entropy"
unset task_entropy
./node_modules/.bin/snarkjs zkey verify build/real_experiment1.r1cs "$ptau" build/task_final.zkey
./node_modules/.bin/snarkjs zkey export verificationkey build/task_final.zkey build/verification_key.json
node - <<'NODE'
const fs=require('fs'),crypto=require('crypto');
fs.writeFileSync('build/circuit.sha256',crypto.createHash('sha256').update(fs.readFileSync('circuits/real_experiment1.circom')).digest('hex')+'\n');
fs.unlinkSync('build/task_0000.zkey');
NODE
