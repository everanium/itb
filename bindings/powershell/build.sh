#!/usr/bin/env bash
#
# build.sh -- one-step build for the PowerShell binding. The binding
# itself has no compilation step (script module); this driver builds
# the C# peer it proxies (libitb.so + Itb.dll via ../csharp/build.sh)
# and then verifies the module imports cleanly under pwsh.
# Prerequisites (Go, dotnet-sdk, pwsh 7.4+) must be installed
# separately; see README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

case "${1:-}" in
    --noitbasm) CSHARP_ARGS=(--noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         CSHARP_ARGS=();;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

echo "==> building C# peer (libitb.so + Itb.dll)"
../csharp/build.sh "${CSHARP_ARGS[@]:+${CSHARP_ARGS[@]}}"

echo "==> verifying module import (pwsh)"
ITB_LIBITB_PATH="$REPO_ROOT/dist/linux-amd64/libitb.so" \
pwsh -NoProfile -Command '
    Import-Module ./Itb/Itb.psd1 -Force
    $v = Get-ItbVersion
    Write-Host ("libitb {0} / itb-csharp {1} / module {2}" -f `
        $v.Library, $v.CSharpBinding, $v.Module)
'

echo "==> ready: ./run_tests.sh"
