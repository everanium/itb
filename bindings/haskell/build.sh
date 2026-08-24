#!/usr/bin/env bash
#
# build.sh -- one-step build for the Haskell binding: libitb.so
# (only when absent — set ITB_REBUILD_LIBITB=1 to force a Go rebuild)
# plus the cabal package (library, tests, bench, eitb executable).
# Prerequisites (Go, ghc, cabal-install) must be installed separately;
# see README.md "Prerequisites".
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

if [[ ! -f "$DIST_DIR/libitb.so" || "${ITB_REBUILD_LIBITB:-0}" == "1" || ${#TAGS[@]} -gt 0 ]]; then
    echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
    (cd "$REPO_ROOT" && go build -trimpath ${TAGS[@]+"${TAGS[@]}"} \
        -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared)
fi

# Pin the link and run-time search paths to the freshly-built dist
# directory. cabal.project.local is generated (gitignored) so the
# absolute path never lands in a committed file.
cat > cabal.project.local <<EOF
package itb
    extra-lib-dirs: $DIST_DIR
    ghc-options: -optl-Wl,-rpath,$DIST_DIR
EOF

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

echo "==> building Haskell binding (cabal build)"
cabal build all --enable-tests --enable-benchmarks

echo "==> ready: ./run_tests.sh"
