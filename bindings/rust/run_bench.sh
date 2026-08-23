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

# Bench-hostile Go runtime defaults are capped at libitb load time
# via env vars so a bench crash before the benches' own
# set_memory_limit / set_gc_percent calls still runs under a bounded
# heap. The benches themselves reassert these via the API for
# self-contained reproducibility.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

cargo bench --bench bench_message -- "$@"
cargo bench --bench bench_stream -- "$@"
