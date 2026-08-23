#!/usr/bin/env bash
#
# run_bench.sh -- Criterion bench runner for the Rust binding.
# Builds libitb.so + the crate via build.sh, points ITB_LIBITB_PATH
# at the freshly-built shared library, then runs both bench binaries
# (bench_message + bench_stream). Positional arguments are forwarded
# to the Criterion harness (e.g. `./run_bench.sh --measurement-time 2`).

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

cargo bench --bench bench_message -- "$@"
cargo bench --bench bench_stream -- "$@"
