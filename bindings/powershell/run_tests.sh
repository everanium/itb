#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the PowerShell binding.
# Builds the C# peer via build.sh, points ITB_LIBITB_PATH at the
# freshly-built shared library, then invokes Pester over
# Tests/Itb.Tests. Positional arguments narrow the run to matching
# test files (e.g. `./run_tests.sh Smoke StreamPump`).
#
# Usage:
#   ./run_tests.sh          # all tests
#   ./run_tests.sh Smoke    # only Tests/Itb.Tests/Smoke.Tests.ps1

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"
export ITB_PWSH_TEST_FILTERS="$*"

exec pwsh -NoProfile -Command '
    $filters = @($env:ITB_PWSH_TEST_FILTERS -split "\s+" | Where-Object { $_ })
    $path = if ($filters.Count -gt 0) {
        $filters | ForEach-Object { "Tests/Itb.Tests/$_.Tests.ps1" }
    } else {
        "Tests/Itb.Tests"
    }
    $config = New-PesterConfiguration
    $config.Run.Path = $path
    $config.Run.Exit = $true
    $config.Output.Verbosity = "Detailed"
    Invoke-Pester -Configuration $config
'
