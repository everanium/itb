#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Groovy binding.
# Builds libitb.so + the JNI shim + the Java binding jar + the
# Groovy classes via build.sh, then invokes the JUnit 5 suite
# through Gradle. Positional arguments are forwarded straight to
# Gradle (e.g. `./run_tests.sh --tests '*SmokeTest'`).

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

export ITB_JNI_PATH="${ITB_JNI_PATH:-$PWD/../java/build/jni/libitb_jni.so}"

exec ./gradlew --console=plain cleanTest test "$@"
