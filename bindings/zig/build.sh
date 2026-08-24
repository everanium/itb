#!/usr/bin/env bash
#
# build.sh -- one-step build for the Zig binding: libitb.so + the C
# binding static archive + the Zig library / eitb / bench binaries.
# Prerequisites (Go, a C11 compiler, GNU make, Zig 0.16+) must be
# installed separately; see README.md "Prerequisites".
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

echo "==> building C binding static archive (make, CC=${CC:-cc})"
make -C "$SCRIPT_DIR/../c" build/libitb_c.a

cd "$SCRIPT_DIR"
echo "==> building Zig binding (zig build)"
zig build

echo "==> ready: ./run_tests.sh"
