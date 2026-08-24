#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Java binding.
# Builds libitb.so + the JNI shim + jars via build.sh, then invokes
# the JUnit 5 suite through Gradle. Positional arguments are forwarded
# straight to Gradle (e.g. `./run_tests.sh --tests '*SmokeTest'`).

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

exec ./gradlew --console=plain cleanTest test "$@"
