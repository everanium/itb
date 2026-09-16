#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Kotlin binding:
# builds the utility jar with Gradle (a no-op when it is up to date;
# libitb3.so, the JNI shim and the Java binding layer are assumed built
# by build.sh) and execs it with every argument passed through.
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

./gradlew --console=plain -q loopJar >/dev/null

JAR="$PWD/build/libs/loop.jar"
if [ ! -f "$JAR" ]; then
    echo "run_loop.sh: expected the loop jar, found none: $JAR" >&2
    exit 1
fi

export ITB_JNI_PATH="${ITB_JNI_PATH:-$JNI}"
exec java -jar "$JAR" "$@"
