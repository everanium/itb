#!/usr/bin/env bash
# Phase 2a extension — hash-agnostic bias-neutralization audit matrix.
#
# Iterates {primitives} × {sizes} × {formats} under the clean
# ITB_NONCE_REUSE_MODE=known_ascii corpus (Full KPA, printable-ASCII
# plaintext, no Partial-KPA sidecar). For every cell:
#
#   1. Go corpus generator with the requested hash + size + N=2
#      collisions + BF=1. For blake3 the generator also emits
#      `blake3_key_hex` into cell.meta.json.
#   2. Python `raw_mode_bias_probe.py` with the matching
#      `chainhashes.<primitive>` module — scans every pixel_shift in
#      [0, total_pixels) using the numpy fast-path, reports the full
#      conflict-rate distribution + plateau size + true-shift rank
#      (the true shift is lab-accessible only; the probe tags it for
#      the human reading the output).
#
# Expected per-primitive fingerprint:
#
#   * CRC128 (GF(2)-linear, test-only): min conflict clearly < 50 %,
#     small plateau (tens of shifts), TRUE shift ranks near minimum.
#     Audit FAILS — Proof 7 precondition violated.
#
#   * FNV-1a (Z/2^64 multiply, carry chains): min conflict ≈ 50 % up
#     to binomial noise, wide plateau, TRUE shift randomly positioned.
#     Audit PASSES — carry nonlinearity is sufficient to neutralize
#     the ASCII bit-7 bias through ITB's masking.
#
#   * BLAKE3 (PRF): same fingerprint as FNV-1a but from a different
#     mechanism — output is by assumption pseudorandom. Audit PASSES.
#
# Usage:
#   bash scripts/redteam/bias_audit_matrix.sh
#
# Environment overrides:
#   PRIMITIVES  default: "crc128 fnv1a blake3"
#   SIZES       default: "524288 1048576"  (512 KB + 1 MB)
#   FORMATS     default: "ascii"           (from known_ascii mode; "json"
#                                           / "html" variants are not
#                                           produced by this mode)
#   BRUTE_FORCE_SHIFT default: matches total_pixels per cell (implicit)
#   PROBE_SIZE  default: 4000
#   RESULTS_TAG default: "bias_audit_matrix"
#   PARALLEL    default: 8
#
# Aggregate matrix_summary.jsonl via scripts/redteam/aggregate_bias_audit.py.
set -euo pipefail

PRIMITIVES=${PRIMITIVES:-"crc128 fnv1a blake3"}
SIZES=${SIZES:-"524288 1048576"}
FORMATS=${FORMATS:-"ascii"}
PROBE_SIZE=${PROBE_SIZE:-auto}
RESULTS_TAG=${RESULTS_TAG:-"bias_audit_matrix"}
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
echo "Hash-agnostic bias-neutralization audit matrix (parallel=$PARALLEL)"
echo "==========================================================================="
echo "  primitives        : $PRIMITIVES"
echo "  sizes             : $SIZES"
echo "  formats           : $FORMATS  (Full-KPA; ascii | json_structured | html_structured)"
echo "  probe size        : $PROBE_SIZE"
echo "  results tag       : $RESULTS_TAG"
echo "  aggregate summary : $MATRIX_SUMMARY"
echo "  progress log      : $PROGRESS_LOG"
echo "==========================================================================="
echo

cells_file=$(mktemp)
total_cells=0
for primitive in $PRIMITIVES; do
    for size in $SIZES; do
        for fmt in $FORMATS; do
            echo "$primitive $size $fmt" >> "$cells_file"
            total_cells=$((total_cells + 1))
        done
    done
done
echo "Cell count: $total_cells"
echo

worker_script=$(mktemp)
cat > "$worker_script" <<'OUTER_EOF'
#!/usr/bin/env bash
set -u
triple="$1"
primitive=$(echo "$triple" | cut -d' ' -f1)
size=$(echo     "$triple" | cut -d' ' -f2)
fmt=$(echo      "$triple" | cut -d' ' -f3)
# Map bias-audit format label → ITB_NONCE_REUSE_MODE (Full-KPA corpus
# mode with corresponding plaintext shape).
case "$fmt" in
  ascii)           nonce_reuse_mode="known_ascii" ;;
  json_structured) nonce_reuse_mode="known_json_structured" ;;
  html_structured) nonce_reuse_mode="known_html_structured" ;;
  *) echo "unknown fmt: $fmt" >&2; exit 2 ;;
esac
cell_dir="tmp/attack/nonce_reuse/corpus/${primitive}/BF1/N2/${nonce_reuse_mode}"
probe_log="${RESULTS_ROOT}/probe_${primitive}_${size}_${fmt}.log"
# 1. Generate corpus
ITB_REDTEAM=1 ITB_BARRIER_FILL=1 \
  ITB_NONCE_REUSE_HASH="$primitive" ITB_NONCE_REUSE_N=2 \
  ITB_NONCE_REUSE_MODE="$nonce_reuse_mode" ITB_NONCE_REUSE_SIZE="$size" \
  go test -run TestRedTeamGenerateNonceReuse -v -timeout 180s \
  >>"$DRIVER_LOG" 2>&1
# 2. Bias probe
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
  "$primitive" "$size" "$fmt" "$rc" \
  "$MATRIX_SUMMARY" "$PROGRESS_LOG"
OUTER_EOF
chmod +x "$worker_script"

export PROJ_DIR PROBE_SIZE DRIVER_LOG MATRIX_SUMMARY PROGRESS_LOG RESULTS_ROOT

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
echo "  python3 scripts/redteam/aggregate_bias_audit.py --input $MATRIX_SUMMARY > bias_audit.md"
