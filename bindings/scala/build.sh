#!/usr/bin/env bash
#
# build.sh -- one-step build for the Scala binding. The binding is a
# thin proxy over the Java binding (JVM bytecode interop, no FFI hop
# of its own), so the Java binding is built first (libitb.so + JNI
# shim + jars via bindings/java/build.sh), then sbt compiles the
# Scala library, tests, bench, and eitb. Prerequisites (Go, JDK 17+,
# Gradle, gcc, sbt) must be installed separately; see README.md
# "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

echo "==> building Java binding (libitb.so + JNI shim + jars)"
bash "$REPO_ROOT/bindings/java/build.sh"

# Re-run the libitb build when a tag opt-out is requested — the Java
# driver builds the default (full asm) shared library; the JNI shim
# resolves dist/linux-amd64/libitb.so by RPATH, so overwriting the
# file in place retargets it.
if [ "${#TAGS[@]}" -gt 0 ]; then
    cd "$REPO_ROOT"
    echo "==> rebuilding libitb.so (with ${TAGS[*]})"
    go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
        -o dist/linux-amd64/libitb.so ./cmd/cshared
fi

cd "$REPO_ROOT/bindings/scala"
echo "==> building Scala binding (sbt compile)"
sbt --batch compile Test/compile bench/Compile/compile eitb/Compile/compile

echo "==> refreshing eitb launcher classpath cache"
sbt --batch --error "export eitb/Runtime/fullClasspath" | tail -n 1 > eitb/.classpath

echo "==> ready: ./run_tests.sh"
