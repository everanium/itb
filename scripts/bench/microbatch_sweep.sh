#!/usr/bin/env bash
#
# microbatch_sweep.sh — cross-host microBatchSize const sweep bench
# for process_cgo.go. Portable: reads repo path from env var
# (default: script's ../..). Writes results to
# $ITB_SWEEP_RESULT_ROOT (default ~/scratch/microbatch-sweep/<UTC-stamp>).
#
# Sweeps microBatchSize ∈ {512, 1024, 2048, 4096, 8192} through
# BenchmarkExtProductionMessage_(Encrypt|Decrypt)_(1|16|64)MB at
# canonical config (areion512 / 512-bit key / no MAC / no overlays).
#
# Memory footprint per config (hash arrays = size × 2 × 8 bytes):
#   512  →  8 KiB  (L1)
#   1024 → 16 KiB  (L1)
#   2048 → 32 KiB  (L1 edge — Intel 32 KiB, Zen 5 48 KiB)
#   4096 → 64 KiB  (L1 miss → L2)
#   8192 → 128 KiB (L2 hit)
#
# Trade: larger batch = fewer CGO crossings (~2×/4×/8×/16× fewer
# relative to 512) at the cost of L1 pressure. This sweep measures
# whether the CGO crossing savings compensate any L1-miss cost.
#
# Wall-time budget: 5 s × 3 counts × 6 sub-benches × 5 configs
# ≈ 10-15 min on a warm cgo cache. Cold-start adds ~30-60 s per config.
#
# The script backs up the source file, applies the const change via
# sed, runs bench, restores the original on exit (trap EXIT) — no git
# operations, no persistent code changes.
#
# Usage:
#   cd path/to/itb
#   bash scripts/bench/microbatch_sweep.sh
#
# Env overrides:
#   ITB_REPO                 (default: script's ../..)
#   ITB_SWEEP_RESULT_ROOT    (default ~/scratch/microbatch-sweep)
#   BENCH_TIME               (default 5s)
#   BENCH_COUNT              (default 3)
#   SWEEP_VALUES             (default "512 1024 2048 4096 8192")
#   ITB_INNER_HASH / ITB_KEY_BITS / etc. — canonical bench shape

set -uo pipefail

REPO="${ITB_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
RESULT_ROOT="${ITB_SWEEP_RESULT_ROOT:-$HOME/scratch/microbatch-sweep}"
BENCH_TIME="${BENCH_TIME:-5s}"
BENCH_COUNT="${BENCH_COUNT:-3}"
SWEEP_VALUES="${SWEEP_VALUES:-512 1024 2048 4096 8192}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_ROOT="$RESULT_ROOT/$STAMP"
mkdir -p "$LOG_ROOT"

SRC_FILE="$REPO/process_cgo.go"
if [ ! -f "$SRC_FILE" ]; then
    echo "process_cgo.go not found at $SRC_FILE" >&2
    exit 1
fi

export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-512}"
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_WITH_MAC="${ITB_WITH_MAC:-false}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-1GiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

echo "=== ITB microBatchSize sweep ==="
echo "timestamp:  $STAMP"
echo "host:       $(uname -n) / $(uname -m) / $(nproc) cores"
echo "cpu:        $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo "repo:       $REPO"
echo "results:    $LOG_ROOT"
echo "sweep:      $SWEEP_VALUES"
echo "bench time: $BENCH_TIME × $BENCH_COUNT counts"
echo ""

cp "$SRC_FILE" "$LOG_ROOT/process_cgo.go.original"

cd "$REPO"

RESTORED=0
restore_original() {
    if [ $RESTORED -eq 0 ]; then
        cp "$LOG_ROOT/process_cgo.go.original" "$SRC_FILE"
        RESTORED=1
        echo "Restored original process_cgo.go"
    fi
}
trap restore_original EXIT

for BATCH in $SWEEP_VALUES; do
    echo "--- microBatchSize = $BATCH ---"
    sed -i "s/const microBatchSize = [0-9]*/const microBatchSize = $BATCH/g" "$SRC_FILE"
    CURRENT="$(grep 'const microBatchSize' "$SRC_FILE" | head -1 | tr -s ' ')"
    echo "  applied: $CURRENT"
    go clean -testcache 2>/dev/null || true
    LOG="$LOG_ROOT/microbatch_${BATCH}.log"
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
        for BENCH in \
            "BenchmarkExtProductionMessage_Encrypt_1MB" \
            "BenchmarkExtProductionMessage_Encrypt_16MB" \
            "BenchmarkExtProductionMessage_Encrypt_64MB" \
            "BenchmarkExtProductionMessage_Decrypt_1MB" \
            "BenchmarkExtProductionMessage_Decrypt_16MB" \
            "BenchmarkExtProductionMessage_Decrypt_64MB"; do
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
