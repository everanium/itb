#!/usr/bin/env bash
#
# run_tests.sh -- Build libitb3.so + the C binding library, then run
# the Swift test suite (XCTest via swift test). Positional arguments
# are forwarded to swift test (e.g. ./run_tests.sh --filter Smoke).
#
# Exit code is 0 when the whole suite passes.

set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd -P)"

./build.sh

# The SwiftPM manifest lives at the repository root.
swift test --package-path "$REPO_ROOT" "$@"
