#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir/.."
# Optional existing alias; the benchmark runner separately enforces rustc 1.93.0.
toolchain="${LRDAS_TOOLCHAIN:-1.93.0}"
cargo "+$toolchain" fmt --all -- --check
cargo "+$toolchain" clippy --locked --workspace --all-targets -- -D warnings
cargo "+$toolchain" test --locked --workspace
cargo "+$toolchain" test --locked --workspace --release
cargo "+$toolchain" test --locked --workspace --doc
cargo "+$toolchain" doc --locked --workspace --no-deps
python3 -m unittest discover -s scripts -p 'test_*.py'
