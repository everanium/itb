#!/usr/bin/env bash
# One-shot runner for the v0.3.0 related-seed differential adversarial
# re-verification probes. Runs the Go test suite; the tests emit JSON
# records under ~/scratch/redteam/related_seed/ (override via
# REDTEAM_RELATED_SEED_OUTPUT_DIR) that aggregate.py summarises as a
# 4-D structural analysis (axis dominance / Δ pattern / plaintext kind
# / primitive contrast).
#
# Runtime: ~10 minutes wall clock at 512 KiB plaintext per cell
# (192 encrypts under Encrypt3x128Cfg + 4 encrypts under process128Cfg
# for the positive control + 4 encrypts under Encrypt3x128Cfg for the
# no-Δ floor probe).
#
# Attacker-realism discipline (see README.md) is enforced in the test
# file itself. The runner does not toggle any lab-peek switch —
# everything is baked into the Go tests.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$repo_root"

echo "==> Running related-seed differential re-verification probes"
echo "    (repo root: $repo_root)"
echo

go test -tags redteam -run TestRedTeamRelatedSeed -v -timeout 1800s ./

echo
echo "==> Emitted JSON records"
ls -la "${REDTEAM_RELATED_SEED_OUTPUT_DIR:-${HOME}/scratch/redteam/related_seed}/" 2>/dev/null || {
    echo "    (no output directory — did the tests run?)"
    exit 1
}

echo
echo "==> Aggregating 4-D structural analysis"
python3 scripts/redteam/itb/related_seed/aggregate.py
