#!/usr/bin/env bash
#
# One-step test runner for the Clojure binding. Builds libitb3.so +
# the JNI shim + the Java binding jars + the Clojure compile check via
# build.sh, then invokes the clojure.test suite. Positional arguments
# narrow the run to the named test namespaces (e.g. `./run_tests.sh
# smoke-test errors-test`).
#
# build.sh wipes the compiled target directory and the Clojure CLI
# classpath cache, and delegates the Java layer to
# bindings/java/build.sh, which cleans its own, so the namespaces
# exercised here always resolve against the jar this invocation built.
# Set ITB_SKIP_CLEAN=1 to keep the existing artefacts and build
# incrementally instead.

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

export ITB_JNI_PATH="${ITB_JNI_PATH:-$PWD/../java/build/jni/libitb3_jni.so}"

exec clojure -M:test -m io.github.everanium.itb3.clojure.test-runner "$@"
