#!/usr/bin/env bash
# One-shot runner for the v0.3.0 nonce-reuse adversarial re-verification
# probes. Runs the Go test suite; the tests emit JSON records under
# tmp/redteam/nonce_reuse/ that aggregate.py then summarises.
#
# The script exits non-zero only on Go test failures; the emitted
# statistics are read from JSON, not from the test exit code (each
# probe passes as long as it completed without panic).
#
# Attacker-realism discipline (see README.md) is enforced in the test
# file itself. The runner does not toggle any lab-peek switch —
# everything is baked into the Go tests.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$repo_root"

echo "==> Running nonce-reuse re-verification probes"
echo "    (repo root: $repo_root)"
echo

go test -run TestRedTeamNonceReuse -v ./

echo
echo "==> Emitted JSON records"
ls -la tmp/redteam/nonce_reuse/ 2>/dev/null || {
    echo "    (no output directory — did the tests run?)"
    exit 1
}

echo
echo "==> Aggregating per-layer summary"
python3 scripts/redteam/itb/nonce_reuse/aggregate.py
