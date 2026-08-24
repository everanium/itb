#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the D binding. Builds
# libitb.so + the binding via build.sh, then compiles and runs the
# benches/bench_*.d binaries: encryptMessage and encryptStreamPump
# throughput at 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh
#   ITB_BENCH_MIN_SEC=1 ./run_bench.sh    # smoke run
#   COMPILER=ldc2 ./run_bench.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench mains
# apply the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# baseline. Override any of these before calling the script to change
# the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

COMPILER="${COMPILER:-ldc2}"
BUILD_DIR="benches/build"
mkdir -p "$BUILD_DIR"

for bench in bench_message bench_stream; do
    echo "==> compiling $bench"
    # DMD accepts `-inline`; LDC2 inlines under `-O` and rejects the
    # DMD-only flag. Split the two compilers' flag lines.
    case "$COMPILER" in
        ldc2) OPT_FLAGS="-O3 -release" ;;
        *)    OPT_FLAGS="-O -inline -release" ;;
    esac
    "$COMPILER" -w $OPT_FLAGS -I=source -I=benches \
        -of="$BUILD_DIR/$bench" "benches/$bench.d" benches/bench_util.d \
        source/itb/*.d \
        -L-L"$DIST_DIR" -L-litb "-L-rpath=$DIST_DIR"
done

for bench in bench_message bench_stream; do
    echo
    echo "==> running $bench (ITB_BENCH_MIN_SEC=$ITB_BENCH_MIN_SEC)"
    "./$BUILD_DIR/$bench"
done
