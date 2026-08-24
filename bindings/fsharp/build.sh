#!/usr/bin/env bash
#
# build.sh -- one-step build for the F# binding: libitb.so + dotnet
# build. The binding is a thin proxy over the C# binding (CLR
# bytecode interop, no FFI hop of its own); the C# Itb library
# project is a solution member, so one dotnet build covers both
# layers. Prerequisites (Go, dotnet-sdk) must be installed
# separately; see README.md "Prerequisites" section.
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

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

cd "$REPO_ROOT/bindings/fsharp"
echo "==> building F# binding (dotnet build -c Release)"
dotnet build EveraniumItb.FSharp.sln -c Release

echo "==> ready: ./run_tests.sh"
