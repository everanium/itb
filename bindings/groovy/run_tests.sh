#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Groovy binding.
# Builds libitb3.so + the JNI shim + the Java binding jar + the
# Groovy classes via build.sh, then invokes the JUnit 5 suite
# through Gradle. Positional arguments are forwarded straight to
# Gradle (e.g. `./run_tests.sh --tests '*SmokeTest'`).
#
# build.sh wipes this binding's build tree and delegates the Java
# layer to bindings/java/build.sh, which cleans its own, so the classes
# exercised here are always compiled by this invocation. Set
# ITB_SKIP_CLEAN=1 to keep the existing artefacts and compile
# incrementally instead.

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

export ITB_JNI_PATH="${ITB_JNI_PATH:-$PWD/../java/build/jni/libitb3_jni.so}"

exec ./gradlew --console=plain cleanTest test "$@"
