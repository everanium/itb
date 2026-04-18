#!/bin/bash
# Partial KPA matrix driver — parallel orchestrator scheduler.
#
# Launches up to $PARALLEL orchestrator invocations concurrently (default 4).
# Each invocation processes one (size, kind) slot with both BLAKE3 + FNV-1a
# hashes inside its own corpus subdirectory, so concurrent runs do not
# collide on disk.
#
# Sizing for 16-core host: each invocation internally uses up to 8 goroutines
# for Go corpus generation (SetMaxWorkers(8)) plus a single Python demask
# worker. With PARALLEL=4:
#   - Corpus-gen phase: 4 × 8 = 32 goroutines on 16 cores (oversubscribed
#     → ~2-3× effective Go speedup, not 4×).
#   - Demask phase: 4 Python workers on 16 cores (idle capacity).
# Net speedup on the original sequential matrix: ~2.5-3× observed.
#
# Usage:
#   bash scripts/redteam/partial_kpa_matrix.sh            # default 4 workers
#   PARALLEL=3 bash scripts/redteam/partial_kpa_matrix.sh # custom
#
# Aggregate afterwards:
#   python3 scripts/redteam/aggregate_partial_kpa_matrix.py
set -u

SIZES=(4096 16384 65536 131072 524288 1048576 2097152 4194304)
KINDS=(
    json_structured_80 json_structured_50 json_structured_25
    html_structured_80 html_structured_50 html_structured_25
)
HASHES="blake3,fnv1a"
PARALLEL=${PARALLEL:-4}
OUTDIR="tmp/attack/nonce_reuse/results"
LOG="${OUTDIR}/matrix_driver.log"

mkdir -p "$OUTDIR"
{
    echo "Starting Partial-KPA matrix (parallel) at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Parallel workers: $PARALLEL"
    echo "Sizes: ${SIZES[*]}"
    echo "Kinds: ${KINDS[*]}"
    echo "Hashes: $HASHES"
} > "$LOG"

# One-time pre-wipe — the orchestrator's own pre-wipe is bypassed via
# --no-pre-wipe on each invocation so parallel runs do not wipe each other's
# in-flight corpus directories.
{
    echo "[prewipe] (once, before workers launch)"
    rm -rf tmp/attack/nonce_reuse/corpus 2>/dev/null
    rm -rf tmp/attack/nonce_reuse/reconstructed 2>/dev/null
    mkdir -p tmp/attack/nonce_reuse/corpus tmp/attack/nonce_reuse/reconstructed
} >> "$LOG"

run_one() {
    local size="$1" kind="$2"
    local tag="matrix_${size}_${kind}"
    local tstart
    tstart=$(date +%s)
    echo "[$(date -u +%H:%M:%S)]  START  size=$size kind=$kind" >> "$LOG"
    python3 scripts/redteam/run_attack_nonce_reuse.py \
        --plaintext-size "$size" \
        --hashes "$HASHES" \
        --collision-counts 2 \
        --attacker-modes partial \
        --plaintext-kind "$kind" \
        --validate \
        --cleanup-ciphertexts-after-emission \
        --continue-on-error \
        --no-pre-wipe \
        --results-tag "$tag" \
        > "/tmp/partial_kpa_${tag}.out" 2>&1
    local rc=$?
    local tend
    tend=$(date +%s)
    local elapsed=$((tend - tstart))
    if [ "$rc" -eq 0 ]; then
        echo "[$(date -u +%H:%M:%S)]  DONE   size=$size kind=$kind  elapsed=${elapsed}s" >> "$LOG"
    else
        echo "[$(date -u +%H:%M:%S)]  FAIL   size=$size kind=$kind  rc=$rc elapsed=${elapsed}s" >> "$LOG"
    fi
}

total=0
for size in "${SIZES[@]}"; do
    for kind in "${KINDS[@]}"; do
        total=$((total + 1))
    done
done

launched=0
for size in "${SIZES[@]}"; do
    for kind in "${KINDS[@]}"; do
        # Throttle to PARALLEL concurrent workers.
        while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do
            sleep 0.5
        done
        run_one "$size" "$kind" &
        launched=$((launched + 1))
        echo "[$(date -u +%H:%M:%S)]  LAUNCH $launched/$total  size=$size kind=$kind  (workers in flight: $(($(jobs -rp | wc -l))))" >> "$LOG"
    done
done

wait
echo "Matrix complete at $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG"
