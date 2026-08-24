#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the C# / .NET binding.
# Builds libitb.so + the solution via build.sh, points
# ITB_LIBITB_PATH at the freshly-built shared library, then runs the
# Itb.Bench binary: EncryptMessage and stream-pump throughput at
# 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh             # both shapes
#   ./run_bench.sh message     # Single Message shape only
#   ./run_bench.sh stream      # stream-pump shape only

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench main
# applies the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# Encrypt3x{128,256,512}Cfg baseline. Override any of these before
# calling the script to change the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

exec dotnet run -c Release --no-build --project Itb.Bench -- "${1:-all}"
