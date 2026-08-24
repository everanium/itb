#!/usr/bin/env bash
#
# build.sh -- one-step build for the Clojure binding: libitb.so + JNI
# shim + Java binding jars (via the sibling bindings/java/build.sh),
# then a classpath prepare + compile check of the Clojure namespaces
# with reflection warnings treated as errors. Prerequisites (Go,
# JDK 17+, Gradle, Clojure CLI, gcc) must be installed separately;
# see README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm

set -eu
set -o pipefail

cd "$(dirname "$0")"

echo "==> building Java binding layer (libitb.so + JNI shim + jars)"
../java/build.sh "$@"

echo "==> preparing Clojure classpath"
clojure -Sforce -P -M:test:bench:eitb

echo "==> compile check (reflection warnings are errors)"
export ITB_JNI_PATH="${ITB_JNI_PATH:-$PWD/../java/build/jni/libitb_jni.so}"
out="$(clojure -M:test:bench -e "
(set! *warn-on-reflection* true)
(require 'dev.everanium.itb.clojure.status
         'dev.everanium.itb.clojure.error
         'dev.everanium.itb.clojure.opts
         'dev.everanium.itb.clojure.runtime
         'dev.everanium.itb.clojure.stream
         'dev.everanium.itb.clojure.core
         'dev.everanium.itb.clojure.test-runner
         'dev.everanium.itb.clojure.bench-util
         'dev.everanium.itb.clojure.bench-message
         'dev.everanium.itb.clojure.bench-stream)
(println :compiled-ok)" 2>&1)"
echo "$out"
if grep -q "Reflection warning" <<<"$out"; then
    echo "build.sh: reflection warnings found — treat as errors" >&2
    exit 1
fi
grep -q ":compiled-ok" <<<"$out"

echo "==> ready: ./run_tests.sh"
