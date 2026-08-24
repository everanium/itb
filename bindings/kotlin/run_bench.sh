#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the Kotlin binding.
# Builds everything via build.sh, then runs the bench main:
# encryptMessage and stream-pump throughput at 1 MiB / 16 MiB /
# 64 MiB.
#
# Usage:
#   ./run_bench.sh             # both shapes
#   ./run_bench.sh message     # Single Message shape only
#   ./run_bench.sh stream      # stream-pump shape only

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

export ITB_JNI_PATH="${ITB_JNI_PATH:-$PWD/../java/build/jni/libitb_jni.so}"

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

# Split at the shell layer so each shape carries its own ITB_PROFILE
# in a single script pass (the Gradle runBench task handles
# "message", "stream", and "all" arguments individually).
case "${1:-all}" in
    message)
        export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
        exec ./gradlew --console=plain runBench --args=message
        ;;
    stream)
        export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
        exec ./gradlew --console=plain runBench --args=stream
        ;;
    all)
        # --no-daemon forces a fresh Gradle process for each invocation
        # so the second runBench call does not inherit the first call's
        # cached task state (Gradle's args= discriminator is not part of
        # the task input hash and would otherwise mark the second call
        # UP-TO-DATE).
        export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
        ./gradlew --no-daemon --console=plain runBench --args=message
        export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
        exec ./gradlew --no-daemon --console=plain runBench --args=stream
        ;;
    *)
        echo "usage: $0 [message|stream|all]" >&2
        exit 2
        ;;
esac
