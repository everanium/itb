#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the Ada binding. Runs
# the binaries built by itb_bench.gpr (see build.sh):
# obj-bench/bench_message (Single Message shape) and
# obj-bench/bench_stream (incremental stream-pump shape) at
# 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"

for bin in obj-bench/bench_message obj-bench/bench_stream; do
    if [ ! -x "$bin" ]; then
        echo "error: $bin not found -- run ./build.sh first" >&2
        exit 2
    fi
done

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench mains
# apply the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# baseline. Override any of these before calling the script to
# change the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

./obj-bench/bench_message
./obj-bench/bench_stream
