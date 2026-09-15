#!/usr/bin/env bash
#
# One-step build for the Clojure binding: libitb3.so + JNI shim + Java
# binding jars (via the sibling bindings/java/build.sh), then a
# classpath prepare + compile check of the Clojure namespaces with
# reflection warnings treated as errors. Prerequisites (Go, JDK 17+,
# Gradle, Clojure CLI, gcc) must be installed separately; see README.md
# "Prerequisites" section.
#
# The build starts from an empty tree: the compiled target directory
# and the Clojure CLI's project-local classpath cache are removed
# first, so no output can survive from an earlier invocation.
#
# .cpcache is the artefact that matters most here. deps.edn resolves
# the Java binding through an exact version-bearing path, and the cache
# records the resolved classpath keyed on the deps.edn timestamp, so a
# cache written against a jar that no longer exists is what surfaces as
# NoClassDefFoundError at run time rather than as a build failure.
#
# The Java binding layer is a shared producer, not something this
# binding owns, so it is never deleted from here: bindings/java/build.sh
# is invoked instead and performs its own clean, which is what
# guarantees the jar deps.edn names is the current one. Running that
# producer build first also means neither the eitb launcher nor a test
# run can trigger a Java-layer rebuild of its own mid-run.
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

if [ "$SKIP_CLEAN" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 — keeping existing artefacts"
else
    echo "==> cleaning Clojure binding artefacts"
    clean_under "$BINDING_DIR" target .cpcache .nrepl-port
fi

echo "==> building Java binding layer (libitb3.so + JNI shim + jars)"
../java/build.sh "$@"

echo "==> preparing Clojure classpath"
clojure -Sforce -P -M:test:bench:eitb

echo "==> compile check (reflection warnings are errors)"
export ITB_JNI_PATH="${ITB_JNI_PATH:-$PWD/../java/build/jni/libitb3_jni.so}"
out="$(clojure -M:test:bench -e "
(set! *warn-on-reflection* true)
(require 'io.github.everanium.itb3.clojure.status
         'io.github.everanium.itb3.clojure.error
         'io.github.everanium.itb3.clojure.opts
         'io.github.everanium.itb3.clojure.runtime
         'io.github.everanium.itb3.clojure.stream
         'io.github.everanium.itb3.clojure.core
         'io.github.everanium.itb3.clojure.test-runner
         'io.github.everanium.itb3.clojure.bench-util
         'io.github.everanium.itb3.clojure.bench-message
         'io.github.everanium.itb3.clojure.bench-stream
         'io.github.everanium.itb3.clojure.bench-stream-one-shot)
(println :compiled-ok)" 2>&1)"
echo "$out"
if grep -q "Reflection warning" <<<"$out"; then
    echo "build.sh: reflection warnings found — treat as errors" >&2
    exit 1
fi
grep -q ":compiled-ok" <<<"$out"

# eitb/main.clj is a clojure.main script rather than a namespace on the
# classpath, so the compile check above cannot reach it. Running the
# `version` subcommand loads and exercises the whole script under the
# :eitb alias, which is the equivalent guarantee that eitb is built and
# usable at the end of every invocation.
echo "==> compile check (eitb script)"
clojure -M:eitb eitb/main.clj version

echo "==> ready: ./run_tests.sh"
