#!/usr/bin/env bash
#
# build.sh -- one-step build for the Java binding: libitb3.so + JNI
# shim + jars via Gradle. Prerequisites (Go, JDK 17+, Gradle, gcc)
# must be installed separately; see README.md "Prerequisites" section.
#
# The build starts from an empty tree: every artefact this binding
# owns -- the Gradle build directory, the project-local Gradle cache,
# stray class / archive output outside the build tree -- is removed
# first, so no output can survive from an earlier invocation.
#
# The wipe has to be total because build/ is shared: the JNI shim
# (build/jni/libitb3_jni.so) and the library jar (build/libs) are what
# the Kotlin, Groovy, Scala and Clojure bindings consume. Scala and the
# two Gradle consumers resolve the library through a
# `libitb3-java-*.jar` glob and Clojure through an exact version-bearing
# path, so a jar left behind by a different version either lands first
# on a consumer's classpath or shadows the path Clojure pins -- in both
# cases the consumer compiles and runs against the wrong library with no
# build error.
#
# Set ITB_SKIP_CLEAN=1 to keep the existing artefacts and let Gradle
# build incrementally. With no environment set the wipe always runs.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels

set -eu
set -o pipefail

cd "$(dirname "$0")"
BINDING_DIR="$(pwd -P)"
REPO_ROOT="$(cd ../.. && pwd -P)"
START_EPOCH="$(date +%s)"
SKIP_CLEAN="${ITB_SKIP_CLEAN:-0}"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# clean_under <root> <relative-path>...
#
# Removes each relative path under <root>. A target is removed only
# when it is a literal relative path (no leading slash, no ".."), it
# exists, and it still resolves inside <root> after symlinks are
# followed -- so a target can never escape the tree it belongs to.
# Every removal is logged before it happens, and a failing rm aborts
# the script rather than being swallowed.
clean_under() {
    local root="$1"; shift
    local rel abs
    root="$(realpath -e "$root")"
    for rel in "$@"; do
        case "$rel" in
            "" | /* | *..*)
                echo "clean: refusing suspicious target '$rel'" >&2
                exit 1
                ;;
        esac
        abs="$root/$rel"
        if [ ! -e "$abs" ] && [ ! -L "$abs" ]; then
            echo "[clean] (absent) $abs"
            continue
        fi
        abs="$(realpath -e "$abs")"
        case "$abs/" in
            "$root"/?*) ;;
            *)
                echo "clean: refusing to remove '$abs' -- outside $root" >&2
                exit 1
                ;;
        esac
        echo "[clean] rm -rf $abs"
        rm -rf "$abs"
    done
}

# require_built <path>
#
# Asserts that a build artefact exists and, when the clean stage ran,
# that it was written by this invocation rather than inherited from an
# earlier one.
require_built() {
    local f="$1"
    if [ ! -f "$f" ]; then
        echo "build.sh: expected artefact was not produced: $f" >&2
        exit 1
    fi
    if [ "$SKIP_CLEAN" != "1" ] && [ "$(stat -c %Y "$f")" -lt "$START_EPOCH" ]; then
        echo "build.sh: artefact predates this invocation: $f" >&2
        exit 1
    fi
}

if [ "$SKIP_CLEAN" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 — keeping existing artefacts"
else
    echo "==> cleaning Java binding artefacts"
    clean_under "$BINDING_DIR" build .gradle bin out .classpath .project .settings
fi

cd "$REPO_ROOT"
echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared

cd "$BINDING_DIR"
# assemble covers the library jar, the JNI shim, the bench jar and the
# eitb jar (see build.gradle.kts: tasks.assemble dependsOn compileJni,
# eitbJar, benchJar).
echo "==> building Java binding (gradlew assemble)"
./gradlew --console=plain assemble

require_built "$BINDING_DIR/build/jni/libitb3_jni.so"
require_built "$BINDING_DIR/build/libs/eitb.jar"
require_built "$BINDING_DIR/build/libs/bench.jar"

echo "==> ready: ./run_tests.sh"
