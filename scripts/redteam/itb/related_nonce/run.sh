#!/usr/bin/env bash
# One-shot runner for the related-nonce differential adversarial
# re-verification probes. Runs the Go test suite; the tests emit JSON
# records under ~/scratch/redteam/related_nonce/ (override via
# REDTEAM_RELATED_NONCE_OUTPUT_DIR) that aggregate.py summarises as a
# structural analysis (Δ pattern ranking / plaintext-kind sensitivity /
# primitive contrast / excess-over-no-Δ-floor).
#
# Runtime: ~3 minutes wall clock at 512 KiB plaintext per cell
# (48 encrypts under Encrypt3x128Cfg for the matrix + 4 encrypts under
# Encrypt3x128Cfg for the no-Δ floor probe).
#
# Attacker-realism discipline (see README.md) is enforced in the test
# file itself. The runner does not toggle any lab-peek switch —
# everything is baked into the Go tests.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$repo_root"

echo "==> Running related-nonce differential re-verification probes"
echo "    (repo root: $repo_root)"
echo

go test -tags redteam -run TestRedTeamRelatedNonce -v -timeout 1800s ./

echo
echo "==> Emitted JSON records"
ls -la "${REDTEAM_RELATED_NONCE_OUTPUT_DIR:-${HOME}/scratch/redteam/related_nonce}/" 2>/dev/null || {
    echo "    (no output directory — did the tests run?)"
    exit 1
}

echo
echo "==> Aggregating structural analysis"
python3 scripts/redteam/itb/related_nonce/aggregate.py
