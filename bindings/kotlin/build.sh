#!/usr/bin/env bash
#
# build.sh -- one-step build for the Kotlin binding: libitb.so + JNI
# shim + Java binding jar (via the sibling bindings/java/build.sh),
# then the Kotlin classes + eitb jar via Gradle. Prerequisites (Go,
# JDK 17+, Gradle, Kotlin, gcc) must be installed separately; see
# README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm

set -eu
set -o pipefail

cd "$(dirname "$0")"

echo "==> building Java binding layer (libitb.so + JNI shim + jar)"
../java/build.sh "$@"

echo "==> building Kotlin binding (gradle assemble)"
./gradlew --console=plain assemble

echo "==> ready: ./run_tests.sh"
