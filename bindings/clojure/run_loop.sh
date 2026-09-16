#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Clojure
# binding: execs the utility with every argument passed through.
# libitb3.so, the JNI shim and the Java binding layer are assumed
# built by build.sh, which also compiles the utility's namespaces and
# warms the classpath cache the Clojure CLI reads here.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

JNI="$PWD/../java/build/jni/libitb3_jni.so"
if [ ! -f "$JNI" ]; then
    echo "run_loop.sh: JNI shim missing, run ./build.sh first: $JNI" >&2
    exit 1
fi

export ITB_JNI_PATH="${ITB_JNI_PATH:-$JNI}"

# The Clojure CLI execs the JVM in place, so a termination signal sent
# to this script reaches the utility itself and its graceful stop runs.
exec clojure -M:loop -m io.github.everanium.itb3.clojure.loop.main "$@"
