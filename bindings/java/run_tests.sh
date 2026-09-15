#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Java binding.
# Builds libitb3.so + the JNI shim + jars via build.sh, then invokes
# the JUnit 5 suite through Gradle. Positional arguments are forwarded
# straight to Gradle (e.g. `./run_tests.sh --tests '*SmokeTest'`).
#
# build.sh wipes the whole build tree before it builds, so the test
# classes exercised here are always compiled by this invocation. Set
# ITB_SKIP_CLEAN=1 to keep the existing artefacts and compile
# incrementally instead.

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

exec ./gradlew --console=plain cleanTest test "$@"
