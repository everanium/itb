#!/usr/bin/env bash
# Phase 2a extension — CRC128 compound-key seed-inversion matrix (parallel).
#
# Iterates {sizes} × {coverages} × {kinds} for a Partial-KPA nonce-reuse
# attack against the test-only CRC128 primitive (ChainHash<CRC128> is
# GF(2)-linear end-to-end at 1024-bit key, collapsing the 512-bit ECMA-
# side dataSeed to a 64-bit compound key — 56 bits observable via
# channelXOR). For every cell: corpus generator → demasker (Layer 1 +
# Layer 2) → seed_invert_crc128.py (compound-key recovery with brute-
# force period-shift search + lab-ground-truth shadow-K filter).
#
# PARALLEL defaults to 8 on a 16-core host. Every cell is independent
# (unique `mode_seg` under corpus/reconstructed dirs, unique results
# tag) so parallel execution is safe without locking. The matrix
# driver does a single up-front wipe then passes --no-pre-wipe to
# every worker.
#
# Usage:
#   bash scripts/redteam/crc128_seed_invert_matrix.sh
#
# Env vars:
#   SIZES COVERAGES KINDS BRUTE_FORCE_SHIFT RESULTS_TAG PARALLEL
set -euo pipefail

SIZES=${SIZES:-"4096 16384 65536 131072 524288 1048576"}
COVERAGES=${COVERAGES:-"25 50 80"}
KINDS=${KINDS:-"random_masked json_structured html_structured"}
BRUTE_FORCE_SHIFT=${BRUTE_FORCE_SHIFT:-200000}
RESULTS_TAG=${RESULTS_TAG:-"crc128_seed_invert_matrix"}
PARALLEL=${PARALLEL:-8}

PROJ_DIR=$(cd "$(dirname "$0")/../.." && pwd)
cd "$PROJ_DIR"

RESULTS_ROOT="tmp/attack/nonce_reuse/results/${RESULTS_TAG}"
mkdir -p "$RESULTS_ROOT"
MATRIX_SUMMARY="${RESULTS_ROOT}/matrix_summary.jsonl"
PROGRESS_LOG="${RESULTS_ROOT}/matrix_progress.log"
DRIVER_LOG="${RESULTS_ROOT}/matrix.log"
: > "$MATRIX_SUMMARY"
: > "$PROGRESS_LOG"
: > "$DRIVER_LOG"

echo "==========================================================================="
echo "CRC128 seed-inversion matrix (parallel=$PARALLEL)"
echo "==========================================================================="
echo "  sizes             : $SIZES"
echo "  coverages         : $COVERAGES"
echo "  kinds             : $KINDS"
echo "  brute-force shift : [0, $BRUTE_FORCE_SHIFT)"
echo "  results tag       : $RESULTS_TAG"
echo "  aggregate summary : $MATRIX_SUMMARY"
echo "  progress log      : $PROGRESS_LOG"
echo "==========================================================================="
echo

# Build flat cell list.
cells_file=$(mktemp)
total_cells=0
for size in $SIZES; do
    for cov in $COVERAGES; do
        for kind in $KINDS; do
            echo "$size $cov $kind" >> "$cells_file"
            total_cells=$((total_cells + 1))
        done
    done
done
echo "Cell count: $total_cells"

echo "Pre-wipe (once, up-front)..."
for d in tmp/attack/nonce_reuse/corpus tmp/attack/nonce_reuse/reconstructed; do
    if [ -d "$d" ]; then
        rm -rf "$d"
        echo "  [cleanup] $d"
    fi
done
echo

# Worker: runs one cell, emits one JSON line to matrix_summary + one
# human-readable line to progress log. Called via xargs -P.
worker_script=$(mktemp)
cat > "$worker_script" <<'OUTER_EOF'
#!/usr/bin/env bash
set -u
triple="$1"
size=$(echo "$triple" | cut -d' ' -f1)
cov=$(echo  "$triple" | cut -d' ' -f2)
kind=$(echo "$triple" | cut -d' ' -f3)
full_kind="${kind}_${cov}"
cell_tag="${CELL_TAG_PREFIX}_${size}_${full_kind}"
cell_dir="tmp/attack/nonce_reuse/results/${cell_tag}"
rm -rf "$cell_dir"
set +e
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size "$size" \
    --hashes crc128 \
    --barrier-fill 1 \
    --collision-counts 2 \
    --attacker-modes partial \
    --plaintext-kind "$full_kind" \
    --seed-invert \
    --seed-invert-brute-force-shift "$BRUTE_FORCE_SHIFT" \
    --validate \
    --continue-on-error \
    --no-pre-wipe \
    --results-tag "$cell_tag" \
    >>"$DRIVER_LOG" 2>&1
rc=$?
set -e
if [ -f "${cell_dir}/summary.jsonl" ]; then
    python3 scripts/redteam/_matrix_cell_emit.py \
        "$cell_dir/summary.jsonl" "$size" "$cov" "$kind" "$rc" \
        "$MATRIX_SUMMARY" "$PROGRESS_LOG"
else
    echo "MISSING size=$size cov=${cov}% kind=$kind (orchestrator produced no summary)" \
         >> "$PROGRESS_LOG"
fi
OUTER_EOF
chmod +x "$worker_script"

# Python helper that atomically appends one line per cell to the
# aggregate files. flock-guarded so parallel workers don't interleave
# half-written JSON.
cat > scripts/redteam/_matrix_cell_emit.py <<'PYEOF'
#!/usr/bin/env python3
"""Matrix cell emitter — one-shot helper invoked per cell by the parallel
driver. Reads the cell's summary.jsonl, stamps matrix_{size,coverage,
kind,exit_code} fields onto each entry, and appends to the aggregate
matrix_summary.jsonl + human-readable progress log under flock so
parallel workers don't interleave output."""
import fcntl
import json
import sys
from pathlib import Path


def main() -> int:
    (src, size, cov, kind, rc, matrix_summary, progress_log) = sys.argv[1:]
    src_path = Path(src)
    entries = []
    with open(src_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            entry["matrix_size"] = int(size)
            entry["matrix_coverage"] = int(cov)
            entry["matrix_kind"] = kind
            entry["matrix_exit_code"] = int(rc)
            entries.append(entry)
    # Compact one-liner for the progress log (uses first entry).
    first = entries[0] if entries else {}
    demask = "OK" if first.get("demask_ok") else "FAIL"
    si_ok = first.get("seed_invert_ok")
    si = "OK" if si_ok is True else ("FAIL" if si_ok is False else "—")
    cand = first.get("seed_invert_brute_candidates", "—")
    cor = first.get("seed_invert_n_correct", "—")
    sha = first.get("seed_invert_n_shadow", "—")
    chm = first.get("seed_invert_channels_matched", "—")
    cht = first.get("seed_invert_channels_total", "—")
    shift = first.get("seed_invert_chosen_shift", "—")
    wall = first.get("seed_invert_elapsed_s", "—")
    human = (f"size={size:>7} cov={cov}% kind={kind:<16} demask={demask:<4} "
             f"si={si:<4} cands={cand:>3} correct={cor} shadow={sha:>3} "
             f"shift={shift} pred={chm}/{cht} wall={wall}s")

    with open(matrix_summary, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    with open(progress_log, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write(human + "\n")
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    print(human, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF
chmod +x scripts/redteam/_matrix_cell_emit.py

# Export env for worker_script (bash doesn't propagate non-exported
# by default).
export PROJ_DIR BRUTE_FORCE_SHIFT DRIVER_LOG MATRIX_SUMMARY PROGRESS_LOG
export CELL_TAG_PREFIX="$RESULTS_TAG"

start_ts=$(date +%s)
<"$cells_file" xargs -I{} -P "$PARALLEL" bash "$worker_script" "{}"
elapsed=$(($(date +%s) - start_ts))
rm -f "$worker_script" "$cells_file"

echo
echo "==========================================================================="
echo "Matrix complete in ${elapsed}s"
echo "==========================================================================="
echo "  matrix_summary.jsonl : $MATRIX_SUMMARY"
echo "  progress log         : $PROGRESS_LOG"
echo "  per-cell driver logs : $RESULTS_ROOT/"
echo
echo "Render markdown table:"
echo "  python3 scripts/redteam/aggregate_crc128_matrix.py --input $MATRIX_SUMMARY > crc128_matrix.md"
