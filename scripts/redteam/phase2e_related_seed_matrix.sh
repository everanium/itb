#!/usr/bin/env bash
# Phase 2e — related-seed differential matrix.
#
# Runs the Go harness TestRedTeamGenerateRelatedSeedPair across every
# (primitive × axis × delta_kind × plaintext_kind) combination, then
# analyses each cell with related_seed_diff_analyze.py.
#
# Default matrix = 11 primitives × 3 axes × 7 delta kinds × 2 pt kinds
#                = 462 cells; disk cost ≈ 540 MB at 512 KB plaintext
#                (2 ciphertexts × ~595 KB per cell × 462).
#
# Runtime scales with primitive + plaintext size. Expect ~30-60 min
# wall-clock at PARALLEL=8 on a 16-core box for the default 512 KB.
#
# Env overrides:
#   PRIMITIVES   default: "crc128 fnv1a md5 aescmac siphash24 chacha20 areion256 blake2s blake3 blake2b areion512"
#   AXES         default: "noise data start"
#   DELTA_KINDS  default: "bit0 bit_mid512 bit_high1023 rand_1 rand_2 rand_3 zero_low_half"
#   PT_KINDS     default: "random ascii"
#   SIZE         default: 524288   (512 KB)
#   NONCE_SEED   default: 0xA17B1CE
#   PARALLEL     default: 8
#   RESULTS_TAG  default: "phase2e_related_seed"
#
# Output:
#   tmp/attack/related_seed_diff/corpus/<primitive>/<axis>/<delta>/<pt>/
#     ct_0.bin, ct_1.bin, plaintext.bin, cell.meta.json, stats.json
#   tmp/attack/related_seed_diff/results/<RESULTS_TAG>/
#     matrix_summary.jsonl  — one stats row per cell
#     matrix_progress.log   — human-readable per-cell progress
set -euo pipefail

PRIMITIVES=${PRIMITIVES:-"crc128 fnv1a md5 aescmac siphash24 chacha20 areion256 blake2s blake2b256 blake3 blake2b areion512"}
AXES=${AXES:-"noise data start"}
DELTA_KINDS=${DELTA_KINDS:-"bit0 bit_mid512 bit_high1023 rand_1 rand_2 rand_3 zero_low_half"}
PT_KINDS=${PT_KINDS:-"random ascii"}
BFS=${BFS:-"1 32"}
SIZE=${SIZE:-524288}
NONCE_SEED=${NONCE_SEED:-0xA17B1CE}
PARALLEL=${PARALLEL:-8}
RESULTS_TAG=${RESULTS_TAG:-"phase2e_related_seed"}

PROJ_DIR=$(cd "$(dirname "$0")/../.." && pwd)
cd "$PROJ_DIR"

CORPUS_ROOT="tmp/attack/related_seed_diff/corpus"
RESULTS_ROOT="tmp/attack/related_seed_diff/results/${RESULTS_TAG}"
mkdir -p "$CORPUS_ROOT" "$RESULTS_ROOT"

MATRIX_SUMMARY="${RESULTS_ROOT}/matrix_summary.jsonl"
PROGRESS_LOG="${RESULTS_ROOT}/matrix_progress.log"
DRIVER_LOG="${RESULTS_ROOT}/matrix.log"
: > "$MATRIX_SUMMARY"
: > "$PROGRESS_LOG"
: > "$DRIVER_LOG"

echo "==========================================================================="
echo "Phase 2e — related-seed differential matrix (parallel=$PARALLEL)"
echo "==========================================================================="
echo "  primitives   : $PRIMITIVES"
echo "  axes         : $AXES"
echo "  delta kinds  : $DELTA_KINDS"
echo "  pt kinds     : $PT_KINDS"
echo "  size         : $SIZE bytes"
echo "  nonce seed   : $NONCE_SEED"
echo "  corpus root  : $CORPUS_ROOT"
echo "  results root : $RESULTS_ROOT"
echo "==========================================================================="
echo

cells_file=$(mktemp)
total=0
for primitive in $PRIMITIVES; do
    for axis in $AXES; do
        for delta in $DELTA_KINDS; do
            for pt in $PT_KINDS; do
                for bf in $BFS; do
                    echo "$primitive $axis $delta $pt $bf" >> "$cells_file"
                    total=$((total + 1))
                done
            done
        done
    done
done
echo "Total cells: $total"
echo

worker=$(mktemp)
cat > "$worker" <<'OUTER_EOF'
#!/usr/bin/env bash
set -u
tuple="$1"
primitive=$(echo "$tuple" | cut -d' ' -f1)
axis=$(echo "$tuple" | cut -d' ' -f2)
delta=$(echo "$tuple" | cut -d' ' -f3)
pt=$(echo "$tuple" | cut -d' ' -f4)
bf=$(echo "$tuple" | cut -d' ' -f5)

cell_dir="${CORPUS_ROOT}/${primitive}/BF${bf}/${axis}/${delta}/${pt}"
mkdir -p "$cell_dir"

# 1) Go corpus generation (2 ciphertexts + meta)
ITB_REDTEAM=1 \
  ITB_REL_HASH="$primitive" \
  ITB_REL_AXIS="$axis" \
  ITB_REL_DELTA_KIND="$delta" \
  ITB_REL_PT_KIND="$pt" \
  ITB_REL_SIZE="$SIZE" \
  ITB_REL_NONCE_SEED="$NONCE_SEED" \
  ITB_REL_BF="$bf" \
  ITB_REL_CELL_DIR="$cell_dir" \
  go test -run TestRedTeamGenerateRelatedSeedPair -v -timeout 600s \
  >>"$DRIVER_LOG" 2>&1

# 2) Python analysis — emits stats.json + one-line JSON on stdout
line=$(python3 scripts/redteam/phase2_theory/related_seed_diff_analyze.py \
        --cell-dir "$cell_dir" --stdout-json 2>>"$DRIVER_LOG")

# 3) Append to summary + progress (flock-guarded)
(
    flock -x 9
    echo "$line" >> "$MATRIX_SUMMARY"
    # Brief human-readable one-liner for progress log
    printf "%-10s %-6s %-15s %-7s\n" "$primitive" "$axis" "$delta" "$pt" >> "$PROGRESS_LOG"
) 9>>"$MATRIX_SUMMARY.lock"
OUTER_EOF
chmod +x "$worker"

export PROJ_DIR CORPUS_ROOT MATRIX_SUMMARY PROGRESS_LOG DRIVER_LOG SIZE NONCE_SEED

start_ts=$(date +%s)
<"$cells_file" xargs -I{} -P "$PARALLEL" bash "$worker" "{}"
elapsed=$(($(date +%s) - start_ts))
rm -f "$worker" "$cells_file"

echo
echo "==========================================================================="
echo "Matrix complete in ${elapsed}s"
echo "==========================================================================="
echo "  matrix_summary.jsonl : $MATRIX_SUMMARY"
echo "  progress log         : $PROGRESS_LOG"
echo "  driver log           : $DRIVER_LOG"
echo
echo "Aggregate:"
echo "  python3 scripts/redteam/phase2_theory/aggregate_related_seed_diff.py \\"
echo "    --input $MATRIX_SUMMARY > phase2e_matrix.md"
