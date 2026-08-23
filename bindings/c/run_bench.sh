#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the C binding. Builds
# libitb.so + the C library via build.sh, then compiles and runs the
# benches/bench_*.c binaries (make bench): EncryptMessage and
# encrypt_stream_pump throughput at 1 KiB / 64 KiB / 1 MiB / 16 MiB.
#
# Usage:
#   ./run_bench.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench mains
# apply the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

make bench
