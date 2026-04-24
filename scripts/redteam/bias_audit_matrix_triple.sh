#!/usr/bin/env bash
# Phase 2a extension — Triple Ouroboros bit-soup bias-neutralization audit.
#
# Sibling of bias_audit_matrix.sh. Generates Triple Ouroboros nonce-reuse
# corpora via TestRedTeamGenerateNonceReuseTriple and runs the existing
# raw_mode_bias_probe.py on them unchanged (no Triple-region splitter —
# per attacker-realism, the analyzer does not know the Triple partition).
#
# Default scope: CRC128 + FNV-1a only, two sizes (512 KB + 1 MB). These
# are the primitives for which the bit-soup input-distribution-flattening
# effect is expected to be measurable. Run once without ITB_BITSOUP (byte-
# level baseline), once with ITB_BITSOUP=1 (bit-soup arm); RESULTS_TAG
# auto-suffixes with _bitsoup when ITB_BITSOUP is non-zero so the two
# runs write to separate directories.
#
# Usage:
#   bash scripts/redteam/bias_audit_matrix_triple.sh                   # byte-level
#   ITB_BITSOUP=1 bash scripts/redteam/bias_audit_matrix_triple.sh     # bit-soup
#
# Environment overrides:
#   PRIMITIVES  default: "crc128 fnv1a"
#   SIZES       default: "524288 1048576"  (512 KB + 1 MB)
#   PROBE_SIZE  default: auto
#   RESULTS_TAG default: "bias_audit_matrix_triple" (suffix _bitsoup added
#                        automatically when ITB_BITSOUP is non-zero)
#   PARALLEL    default: 4
#
# Aggregate: scripts/redteam/aggregate_bias_audit.py reads the
# matrix_summary.jsonl produced here unchanged.
set -euo pipefail

PRIMITIVES=${PRIMITIVES:-"crc128 fnv1a"}
SIZES=${SIZES:-"524288 1048576"}
PROBE_SIZE=${PROBE_SIZE:-auto}
RESULTS_TAG=${RESULTS_TAG:-"bias_audit_matrix_triple"}
if [[ "${ITB_BITSOUP:-0}" != "0" ]]; then
    RESULTS_TAG="${RESULTS_TAG}_bitsoup"
fi
PARALLEL=${PARALLEL:-4}

PROJ_DIR=$(cd "$(dirname "$0")/../.." && pwd)
cd "$PROJ_DIR"

RESULTS_ROOT="tmp/attack/triple_nonce_reuse/results/${RESULTS_TAG}"
mkdir -p "$RESULTS_ROOT"
MATRIX_SUMMARY="${RESULTS_ROOT}/matrix_summary.jsonl"
PROGRESS_LOG="${RESULTS_ROOT}/matrix_progress.log"
DRIVER_LOG="${RESULTS_ROOT}/matrix.log"
: > "$MATRIX_SUMMARY"
: > "$PROGRESS_LOG"
: > "$DRIVER_LOG"

echo "==========================================================================="
echo "Triple Ouroboros bit-soup bias-neutralization audit (parallel=$PARALLEL)"
echo "==========================================================================="
echo "  primitives        : $PRIMITIVES"
echo "  sizes             : $SIZES"
echo "  probe size        : $PROBE_SIZE"
echo "  ITB_BITSOUP       : ${ITB_BITSOUP:-0}"
echo "  results tag       : $RESULTS_TAG"
echo "  aggregate summary : $MATRIX_SUMMARY"
echo "==========================================================================="
echo

cells_file=$(mktemp)
total_cells=0
for primitive in $PRIMITIVES; do
    for size in $SIZES; do
        echo "$primitive $size" >> "$cells_file"
        total_cells=$((total_cells + 1))
    done
done
echo "Cell count: $total_cells"
echo

worker_script=$(mktemp)
cat > "$worker_script" <<'OUTER_EOF'
#!/usr/bin/env bash
set -u
pair="$1"
primitive=$(echo "$pair" | cut -d' ' -f1)
size=$(echo      "$pair" | cut -d' ' -f2)
cell_dir="tmp/attack/triple_nonce_reuse/corpus/${primitive}/BF1/N2/known_ascii/size_${size}"
probe_log="${RESULTS_ROOT}/probe_${primitive}_${size}.log"
# 1. Generate Triple corpus (ITB_BITSOUP inherits from parent env; TestMain
#    in bitsoup_test.go flips SetBitSoup(1) before the test body runs).
ITB_REDTEAM=1 ITB_BARRIER_FILL=1 \
  ITB_TRIPLE_NONCE_REUSE_HASH="$primitive" \
  ITB_TRIPLE_NONCE_REUSE_SIZE="$size" \
  go test -run TestRedTeamGenerateNonceReuseTriple -v -timeout 180s \
  >>"$DRIVER_LOG" 2>&1
# 2. Bias probe — same analyzer as the Single-Ouroboros audit, zero
#    Triple-awareness. Measures snake 0's bias signature via the
#    data_seed / start_pixel written into cell.meta.json.
set +e
python3 scripts/redteam/phase2_theory/raw_mode_bias_probe.py \
  --cell-dir "$cell_dir" \
  --hash-module "chainhashes.${primitive}" \
  --probe-size "$PROBE_SIZE" \
  --top-n 5 \
  > "$probe_log" 2>&1
rc=$?
set -e
python3 scripts/redteam/_bias_cell_emit.py \
  "$cell_dir/cell.meta.json" "$probe_log" \
  "$primitive" "$size" "ascii" "$rc" \
  "$MATRIX_SUMMARY" "$PROGRESS_LOG"
OUTER_EOF
chmod +x "$worker_script"

export PROJ_DIR PROBE_SIZE DRIVER_LOG MATRIX_SUMMARY PROGRESS_LOG RESULTS_ROOT
export ITB_BITSOUP=${ITB_BITSOUP:-0}

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
echo "  per-probe logs       : $RESULTS_ROOT/probe_*.log"
echo
echo "Render markdown:"
echo "  python3 scripts/redteam/aggregate_bias_audit.py --input $MATRIX_SUMMARY > bias_audit_triple.md"
