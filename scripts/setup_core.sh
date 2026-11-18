#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/core/tmp results/core
export TMPDIR="$PWD/build/core/tmp"
export PATH="/mnt/user-data/zjh/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$PWD/build/core/rust"
if ! command -v rustup >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$TMPDIR/rustup-init.sh"
  bash "$TMPDIR/rustup-init.sh" -y --no-modify-path --profile minimal --default-toolchain 1.88.0
fi
rustup toolchain install 1.88.0 --profile minimal
npm ci
cargo build --release --locked --manifest-path rust/psi/Cargo.toml
