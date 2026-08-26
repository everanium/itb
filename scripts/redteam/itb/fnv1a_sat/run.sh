#!/usr/bin/env bash
# One-shot runner for the v0.3.0 FNV-1a lo-lane SAT re-verification
# probes. Runs the Go test suite; the tests emit JSON records under
# tmp/redteam/fnv1a_sat/ that the companion Python SAT probe and the
# aggregate summariser then consume.
#
# The script exits non-zero on Go test failures; the emitted
# statistics are read from JSON, not from the test exit code.
#
# Attacker-realism discipline (see README.md) is enforced in the test
# file itself. The runner does not toggle any lab-peek switch —
# every peek is tagged in-source and consumed as documented.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$repo_root"

echo "==> Running FNV-1a lo-lane SAT re-verification Go probes"
echo "    (repo root: $repo_root)"
echo

go test -run TestRedTeamBrokenFNV1a -v ./

echo
echo "==> Emitted JSON records"
ls -la tmp/redteam/fnv1a_sat/ 2>/dev/null || {
    echo "    (no output directory — did the tests run?)"
    exit 1
}

echo
echo "==> Optional Bitwuzla SAT probe (only if Bitwuzla is installed)"
if command -v bitwuzla >/dev/null 2>&1 && python3 -c 'import bitwuzla' 2>/dev/null; then
    n_pixels="${ITB_FNV1A_SAT_N:-2}"
    timeout="${ITB_FNV1A_SAT_TIMEOUT:-600}"
    cap="${ITB_FNV1A_SAT_CAP:-4}"
    ITB_FNV1A_SAT_CAP="${cap}" python3 scripts/redteam/itb/fnv1a_sat/sat_probe.py \
        --n-crib-pixels "${n_pixels}" \
        --timeout-sec "${timeout}" \
        --regime true_npr \
        --json-report tmp/redteam/fnv1a_sat/sat_probe.json
else
    echo "    Bitwuzla not available — skipping (install: yay -S bitwuzla)"
fi

echo
echo "==> Aggregating per-layer summary"
python3 scripts/redteam/itb/fnv1a_sat/aggregate.py
