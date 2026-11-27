#!/usr/bin/env bash
# Builds the release CLI for Linux x64. Build paths are remapped so the
# executable does not reveal the build machine.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}

# Cargo treats these as separate values, so paths with spaces stay intact.
separator=$'\x1f'
unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$root=/leonida-forge${separator}--remap-path-prefix=$cargo_home=/cargo${separator}--remap-path-prefix=$rustup_home=/rustup"

cargo build --release --locked --target x86_64-unknown-linux-gnu -p lforge-cli
