#!/usr/bin/env bash
#
# prefetch_sweep.sh — cross-host PrefetchDistance sweep bench for
# process_pixels.c. Portable: reads repo path from env var (default
# ~/go/src/itb), writes results to $ITB_SWEEP_RESULT_ROOT (default
# ~/scratch/prefetch-sweep/<UTC-stamp>).
#
# Sweeps PrefetchDistance ∈ {8, 16, 32, 64, 128} through
# BenchmarkExtProductionMessage_(Encrypt|Decrypt)_(1|16|64)MB at
# canonical config (areion512 / 512-bit key / no MAC / no overlays).
# 5s benchtime × 3 counts per config × 5 configs × 6 sub-benches
# ≈ 10-15 min wall.
#
# Automatically backs up the source file, applies the const change via
# sed, and restores the original after all sweep configs run — no git
# operations, no persistent code changes.
#
# Usage:
#   ~/scripts/prefetch_sweep.sh
#
# Env overrides:
#   ITB_REPO                 (default /home/andrew/go/src/itb)
#   ITB_SWEEP_RESULT_ROOT    (default ~/scratch/prefetch-sweep)
#   BENCH_TIME               (default 5s)
#   BENCH_COUNT              (default 3)
#   SWEEP_VALUES             (default "8 16 32 64 128" — space-separated)

set -uo pipefail

REPO="${ITB_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
RESULT_ROOT="${ITB_SWEEP_RESULT_ROOT:-$HOME/scratch/prefetch-sweep}"
BENCH_TIME="${BENCH_TIME:-5s}"
BENCH_COUNT="${BENCH_COUNT:-3}"
SWEEP_VALUES="${SWEEP_VALUES:-8 16 32 64 128}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_ROOT="$RESULT_ROOT/$STAMP"
mkdir -p "$LOG_ROOT"

PROC_FILE="$REPO/process_pixels.c"
if [ ! -f "$PROC_FILE" ]; then
    echo "process_pixels.c not found at $PROC_FILE" >&2
    exit 1
fi

# Canonical bench-shape env (fastest single-core measurement)
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-512}"
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_WITH_MAC="${ITB_WITH_MAC:-false}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-1GiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

echo "=== ITB PrefetchDistance sweep ==="
echo "timestamp:  $STAMP"
echo "host:       $(uname -n) / $(uname -m) / $(nproc) cores"
echo "cpu:        $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo "repo:       $REPO"
echo "results:    $LOG_ROOT"
echo "sweep:      $SWEEP_VALUES"
echo "bench time: $BENCH_TIME × $BENCH_COUNT counts"
echo ""

# Backup original
cp "$PROC_FILE" "$LOG_ROOT/process_pixels.c.original"

cd "$REPO"

RESTORED=0
restore_original() {
    if [ $RESTORED -eq 0 ]; then
        cp "$LOG_ROOT/process_pixels.c.original" "$PROC_FILE"
        RESTORED=1
        echo "Restored original process_pixels.c"
    fi
}
trap restore_original EXIT

for DISTANCE in $SWEEP_VALUES; do
    echo "--- PrefetchDistance = $DISTANCE ---"
    sed -i "s/const int PrefetchDistance = [0-9]*;/const int PrefetchDistance = $DISTANCE;/g" "$PROC_FILE"
    CURRENT="$(grep 'const int PrefetchDistance' "$PROC_FILE" | head -1 | tr -s ' ')"
    echo "  applied: $CURRENT"
    go clean -testcache 2>/dev/null || true
    LOG="$LOG_ROOT/prefetch_${DISTANCE}.log"
    start=$(date +%s)
    go test -run '^$' \
        -bench '^BenchmarkExtProductionMessage_(Encrypt|Decrypt)_(1|16|64)MB$' \
        -benchtime="$BENCH_TIME" -count="$BENCH_COUNT" -timeout=1200s . \
        > "$LOG" 2>&1
    rc=$?
    end=$(date +%s)
    dur=$((end - start))
    if [ $rc -eq 0 ]; then
        printf "  OK %ds — median MB/s per size:\n" "$dur"
        # Extract per-benchmark median across 3 counts
        for BENCH in \
            "BenchmarkExtProductionMessage_Encrypt_1MB" \
            "BenchmarkExtProductionMessage_Encrypt_16MB" \
            "BenchmarkExtProductionMessage_Encrypt_64MB" \
            "BenchmarkExtProductionMessage_Decrypt_1MB" \
            "BenchmarkExtProductionMessage_Decrypt_16MB" \
            "BenchmarkExtProductionMessage_Decrypt_64MB"; do
            # Extract 3 MB/s values, compute median
            MBS=$(grep -oE "${BENCH}-[0-9]+\s+[0-9]+\s+[0-9]+\s+ns/op\s+[0-9]+\.[0-9]+" "$LOG" | grep -oE "[0-9]+\.[0-9]+$" | sort -n | awk 'NR==2')
            printf "    %-45s %s MB/s\n" "$BENCH" "${MBS:-?}"
        done
    else
        printf "  FAIL rc=%d %ds — see %s\n" "$rc" "$dur" "$LOG"
    fi
    echo ""
done

restore_original

echo "=== Result dir: $LOG_ROOT ==="
echo ""
echo "For portability across hosts (e.g. Zen 5 EPYC):"
echo "  scp -r ~/scripts/prefetch_sweep.sh <target-host>:~/scripts/"
echo "  ssh <target-host> 'ITB_REPO=/path/to/itb ~/scripts/prefetch_sweep.sh'"
