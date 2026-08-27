#!/usr/bin/env bash
# One-shot runner for the v0.3.0 fresh-nonce cross-message near-identical
# distinguisher re-verification probe. Runs the Go test; the test emits
# a JSON record under tmp/redteam/near_identical_fresh/ that aggregate.py
# summarises as a structural analysis (per-cell byte-XOR chi² + byte-
# equal floor ratio, two-sample homogeneity chi² between the near-
# identical and independent-pair categories at every (size, delta)).
#
# Runtime: ~15-25 min wall-clock at N=80 pairs per cell (default);
# 4 sizes × 6 delta positions × 2 categories = 48 cells × 2 × 80 =
# 7680 Encrypt3x128Cfg calls; Encrypt3x128Cfg parallelises across
# runtime.NumCPU(). Override N via ITB_NIF_N.
#
# Attacker-realism discipline (see README.md) is enforced in the test
# file itself. The runner does not toggle any lab-peek switch —
# everything is baked into the Go test.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$repo_root"

echo "==> Running fresh-nonce near-identical cross-message distinguisher probe"
echo "    (repo root: $repo_root)"
echo "    (sample pairs per cell: ${ITB_NIF_N:-80} — override via ITB_NIF_N)"
echo

go test -run TestRedTeamNearIdenticalFreshNonce -v -timeout 3600s ./

echo
echo "==> Emitted JSON records"
ls -la tmp/redteam/near_identical_fresh/ 2>/dev/null || {
    echo "    (no output directory — did the test run?)"
    exit 1
}

echo
echo "==> Aggregating structural analysis"
python3 scripts/redteam/itb/near_identical_fresh/aggregate.py
