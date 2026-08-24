#!/usr/bin/env bash
#
# run_bench.sh -- bench runner for the Java binding. Builds
# libitb.so + the binding via build.sh, then runs both bench mains
# (BenchMessage + BenchStream). Positional arguments select the shape:
# `message`, `stream`, or `all` (default).

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

export ITB_JNI_PATH="$PWD/build/jni/libitb_jni.so"

# Bench-hostile Go runtime defaults are capped at libitb load time
# via env vars so a bench crash before the benches' own
# setMemoryLimit / setGCPercent calls still runs under a bounded
# heap. The benches themselves reassert these via the API for
# self-contained reproducibility.
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

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

SHAPE="${1:-all}"

case "$SHAPE" in
    message)
        export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
        java -cp build/libs/bench.jar com.everanium.itb.bench.BenchMessage
        ;;
    stream)
        export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
        java -cp build/libs/bench.jar com.everanium.itb.bench.BenchStream
        ;;
    all)
        export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
        java -cp build/libs/bench.jar com.everanium.itb.bench.BenchMessage
        export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
        java -cp build/libs/bench.jar com.everanium.itb.bench.BenchStream
        ;;
    *)
        echo "usage: $0 [message|stream|all]" >&2
        exit 2
        ;;
esac
