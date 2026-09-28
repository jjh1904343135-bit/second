#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p build
./node_modules/.bin/circom2 circuits/generic_assertions.circom \
  --r1cs --wasm --sym -o build -l node_modules

if [[ ! -f build/pot14_final.ptau ]]; then
  ./node_modules/.bin/snarkjs powersoftau new bn128 14 build/pot14_0000.ptau
  ./node_modules/.bin/snarkjs powersoftau contribute build/pot14_0000.ptau build/pot14_0001.ptau \
    --name="demo contribution" -e="fixed demo entropy; not for production"
  ./node_modules/.bin/snarkjs powersoftau prepare phase2 build/pot14_0001.ptau build/pot14_final.ptau
  rm -f build/pot14_0000.ptau build/pot14_0001.ptau
fi

./node_modules/.bin/snarkjs groth16 setup build/generic_assertions.r1cs build/pot14_final.ptau build/generic_assertions_0000.zkey
./node_modules/.bin/snarkjs zkey contribute build/generic_assertions_0000.zkey build/generic_assertions_final.zkey \
  --name="demo circuit contribution" -e="fixed circuit entropy; not for production"
./node_modules/.bin/snarkjs zkey export verificationkey build/generic_assertions_final.zkey build/generic_verification_key.json
rm -f build/generic_assertions_0000.zkey

echo "Setup complete. Artifacts are in build/."
