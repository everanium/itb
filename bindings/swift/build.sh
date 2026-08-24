#!/usr/bin/env bash
#
# build.sh -- one-step build for the Swift binding: libitb.so + the C
# binding library (the bridged layer) + the Swift package in release
# configuration. Prerequisites (Go, a C11 compiler, GNU make, Swift
# 6+) must be installed separately; see README.md "Prerequisites".
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

echo "==> building the C binding library (libitb_c)"
make -C bindings/c build/libitb_c.a build/libitb_c.so

cd "$SCRIPT_DIR"
echo "==> building Swift package (swift build -c release)"
swift build -c release

echo "==> ready: ./run_tests.sh"
