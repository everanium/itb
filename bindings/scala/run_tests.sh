#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Scala binding. Builds
# the Java binding (libitb.so + JNI shim + jars) and the sbt projects
# via build.sh, points ITB_JNI_PATH at the freshly-built JNI shim,
# then invokes `sbt test`. A positional argument narrows the run to a
# testOnly glob.
#
# Usage:
#   ./run_tests.sh                        # all suites
#   ./run_tests.sh '*SmokeSuite'          # testOnly glob

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

./build.sh

export ITB_JNI_PATH="$REPO_ROOT/bindings/java/build/jni/libitb_jni.so"

if [ "$#" -gt 0 ]; then
    exec sbt --batch "testOnly $*"
fi
exec sbt --batch test
