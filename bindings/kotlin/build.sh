#!/usr/bin/env bash
#
# One-step build for the Kotlin binding: libitb3.so + JNI shim + Java
# binding jar (via the sibling bindings/java/build.sh), then the Kotlin
# classes + eitb jar via Gradle. Prerequisites (Go, JDK 17+, Gradle,
# Kotlin, gcc) must be installed separately; see README.md
# "Prerequisites" section.
#
# The build starts from an empty tree: the Gradle build directory, the
# project-local Gradle and Kotlin caches and stray class output are
# removed first, so no output can survive from an earlier invocation.
#
# The Java binding layer is a shared producer, not something this
# binding owns, so it is never deleted from here: bindings/java/build.sh
# is invoked instead and performs its own clean, which is what
# guarantees the JNI shim and the `libitb3-java-*.jar` this binding
# resolves are both current. Running that producer build first also
# means the shim is in place before any Kotlin code loads it.
#
# Set ITB_SKIP_CLEAN=1 to keep the existing artefacts and build
# incrementally; it propagates to the Java layer as well. With no
# environment set the wipe always runs.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels

set -eu
set -o pipefail

cd "$(dirname "$0")"
BINDING_DIR="$(pwd -P)"
START_EPOCH="$(date +%s)"
SKIP_CLEAN="${ITB_SKIP_CLEAN:-0}"

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
    echo "==> cleaning Kotlin binding artefacts"
    clean_under "$BINDING_DIR" build .gradle .kotlin out
fi

echo "==> building Java binding layer (libitb3.so + JNI shim + jar)"
../java/build.sh "$@"

# assemble covers the library jar, the bench classes and the eitb jar
# (see build.gradle.kts: tasks.assemble dependsOn benchClasses,
# eitbClasses, eitbJar).
echo "==> building Kotlin binding (gradle assemble)"
./gradlew --console=plain assemble

require_built "$BINDING_DIR/build/libs/eitb.jar"

echo "==> ready: ./run_tests.sh"
