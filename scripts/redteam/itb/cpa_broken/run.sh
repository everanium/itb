#!/usr/bin/env bash
# One-shot runner for the v0.3.0 fresh-nonce CPA broken-primitive
# re-verification probe. Runs the Go test suite; the test emits a JSON
# record under ~/scratch/redteam/cpa_broken/ (override via
# REDTEAM_CPA_BROKEN_OUTPUT_DIR) that aggregate.py summarises as a
# structural analysis (per-cell body chi² / pair byte-equal rate /
# two-sample homogeneity chi² between FNV-1a and BLAKE3 arms).
#
# Runtime: ~25-30 minutes wall clock at 512-byte plaintext × 28,000
# encryptions total (2 primitive arms × 7 plaintext kinds × N=2000
# messages per cell), Encrypt3x128Cfg parallelised across
# runtime.NumCPU(). Override N via ITB_CPA_N.
#
# Attacker-realism discipline (see README.md) is enforced in the test
# file itself. The runner does not toggle any lab-peek switch —
# everything is baked into the Go test.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$repo_root"

echo "==> Running fresh-nonce CPA broken-primitive re-verification probe"
echo "    (repo root: $repo_root)"
echo "    (sample size per cell: ${ITB_CPA_N:-2000} — override via ITB_CPA_N)"
echo

go test -tags redteam -run TestRedTeamCPABroken -v -timeout 7200s ./

echo
echo "==> Emitted JSON records"
ls -la "${REDTEAM_CPA_BROKEN_OUTPUT_DIR:-${HOME}/scratch/redteam/cpa_broken}/" 2>/dev/null || {
    echo "    (no output directory — did the test run?)"
    exit 1
}

echo
echo "==> Aggregating structural analysis"
python3 scripts/redteam/itb/cpa_broken/aggregate.py
