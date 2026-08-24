#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Clojure binding.
# Builds libitb.so + the JNI shim + the Java binding jars + the
# Clojure compile check via build.sh, then invokes the clojure.test
# suite. Positional arguments narrow the run to the named test
# namespaces (e.g. `./run_tests.sh smoke-test errors-test`).

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

export ITB_JNI_PATH="${ITB_JNI_PATH:-$PWD/../java/build/jni/libitb_jni.so}"

exec clojure -M:test -m dev.everanium.itb.clojure.test-runner "$@"
