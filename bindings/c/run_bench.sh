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

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# Encrypt3x{128,256,512}Cfg baseline. Override any of these before
# calling the script to change the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-128}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

make bench
