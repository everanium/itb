#!/usr/bin/env bash
#
# sweep.sh — unified cross-host const sweep for two pixel-encoder
# hot-path knobs: PrefetchDistance in process_pixels.c and
# microBatchSize in process_cgo.go. Sweeps either or both
# independently, or their Cartesian product for interaction studies.
#
# Portable: reads repo path from ITB_REPO (default: script's ../..).
# Writes results to $ITB_SWEEP_RESULT_ROOT (default
# ~/scratch/sweep/<UTC-stamp>).
#
# Sweep values are space-separated lists via env vars. A single value
# holds that knob at baseline. Cartesian product runs when BOTH lists
# are multi-valued.
#
# Wall-time budget: per-config ≈ 2 min on a warm cgo cache. Cartesian
# 6 × 5 = 30 configs ≈ 60 min. Cold-start builds add per-config
# rebuild time.
#
# The script backs up both source files, applies const changes via
# sed, runs the canonical bench, and restores originals on exit
# (trap EXIT) — no git operations, no persistent code changes.
#
# Usage:
#   cd path/to/itb
#
#   # baseline single point (no sweep):
#   bash scripts/bench/sweep.sh
#
#   # PrefetchDistance sweep only (microbatch stays 512):
#   SWEEP_PREFETCH="32 64 128 256 512 1024" bash scripts/bench/sweep.sh
#
#   # microBatchSize sweep only (prefetch stays 8):
#   SWEEP_MICROBATCH="4096 8192 16384 32768 65536" bash scripts/bench/sweep.sh
#
#   # Cartesian product interaction study:
#   SWEEP_PREFETCH="32 128 512" \
#   SWEEP_MICROBATCH="1024 4096 16384" \
#     bash scripts/bench/sweep.sh
#
# Env overrides:
#   ITB_REPO                 (default: script's ../..)
#   ITB_SWEEP_RESULT_ROOT    (default ~/scratch/sweep)
#   BENCH_TIME               (default 5s)
#   BENCH_COUNT              (default 3)
#   SWEEP_PREFETCH           (default "8" — no sweep on this knob)
#   SWEEP_MICROBATCH         (default "512" — no sweep on this knob)
#   ITB_INNER_HASH / ITB_KEY_BITS / etc. — canonical bench shape

set -uo pipefail

REPO="${ITB_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
RESULT_ROOT="${ITB_SWEEP_RESULT_ROOT:-$HOME/scratch/sweep}"
BENCH_TIME="${BENCH_TIME:-5s}"
BENCH_COUNT="${BENCH_COUNT:-3}"
SWEEP_PREFETCH="${SWEEP_PREFETCH:-8}"
SWEEP_MICROBATCH="${SWEEP_MICROBATCH:-512}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_ROOT="$RESULT_ROOT/$STAMP"
mkdir -p "$LOG_ROOT"

PIXELS_C="$REPO/process_pixels.c"
CGO_GO="$REPO/process_cgo.go"
[ -f "$PIXELS_C" ] || { echo "process_pixels.c not found at $PIXELS_C" >&2; exit 1; }
[ -f "$CGO_GO" ] || { echo "process_cgo.go not found at $CGO_GO" >&2; exit 1; }

export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-512}"
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_WITH_MAC="${ITB_WITH_MAC:-false}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-1GiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

N_PREFETCH=$(echo "$SWEEP_PREFETCH" | wc -w)
N_MICROBATCH=$(echo "$SWEEP_MICROBATCH" | wc -w)
TOTAL=$((N_PREFETCH * N_MICROBATCH))

echo "=== ITB unified sweep ==="
echo "timestamp:  $STAMP"
echo "host:       $(uname -n) / $(uname -m) / $(nproc) cores"
echo "cpu:        $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo "repo:       $REPO"
echo "results:    $LOG_ROOT"
echo "PrefetchDistance:  $SWEEP_PREFETCH   ($N_PREFETCH values)"
echo "microBatchSize:    $SWEEP_MICROBATCH ($N_MICROBATCH values)"
echo "configs:    $TOTAL (Cartesian product)"
echo "bench time: $BENCH_TIME × $BENCH_COUNT counts"
echo ""

cp "$PIXELS_C" "$LOG_ROOT/process_pixels.c.original"
cp "$CGO_GO" "$LOG_ROOT/process_cgo.go.original"

cd "$REPO"

RESTORED=0
restore_original() {
    if [ $RESTORED -eq 0 ]; then
        cp "$LOG_ROOT/process_pixels.c.original" "$PIXELS_C"
        cp "$LOG_ROOT/process_cgo.go.original" "$CGO_GO"
        RESTORED=1
        echo "Restored originals: process_pixels.c + process_cgo.go"
    fi
}
trap restore_original EXIT

CONFIG_IDX=0
for PD in $SWEEP_PREFETCH; do
    for MB in $SWEEP_MICROBATCH; do
        CONFIG_IDX=$((CONFIG_IDX + 1))
        LABEL="pd${PD}_mb${MB}"
        echo "--- [$CONFIG_IDX/$TOTAL] PrefetchDistance=$PD  microBatchSize=$MB ---"
        sed -i "s/const int PrefetchDistance = [0-9]*;/const int PrefetchDistance = $PD;/g" "$PIXELS_C"
        sed -i "s/const microBatchSize = [0-9]*/const microBatchSize = $MB/g" "$CGO_GO"
        CUR_PD="$(grep 'const int PrefetchDistance' "$PIXELS_C" | head -1 | tr -s ' ')"
        CUR_MB="$(grep 'const microBatchSize' "$CGO_GO" | head -1 | tr -s ' ')"
        echo "  applied PD: $CUR_PD"
        echo "  applied MB: $CUR_MB"
        go clean -testcache 2>/dev/null || true
        LOG="$LOG_ROOT/${LABEL}.log"
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
done

restore_original

echo "=== Result dir: $LOG_ROOT ==="
