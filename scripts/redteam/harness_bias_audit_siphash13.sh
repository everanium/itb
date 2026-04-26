#!/usr/bin/env bash
# HARNESS.md § 4.1 siphash13 (reduced-round PRF boundary) — Axis B ITB-wrapped bias audit.
#
# Single-primitive driver that generates ITB corpora under known_ascii
# plaintext mode with siphash13 wrapped into ChainHash128 (via the parallel
# two-lane adapter siphash13Hash128 defined in harness_test.go), then
# runs the existing raw-mode bias probe against each corpus.
#
# Kept SEPARATE from scripts/redteam/bias_audit_matrix.sh to preserve the
# existing 4-primitive matrix boundary (crc128 / fnv1a / blake3 / md5) that
# REDTEAM.md reproduction commands assume. This harness runs only siphash13
# as part of the HARNESS.md shelf work; the Phase 2a extension main
# matrix is untouched.
#
# Corpus generation uses a dedicated Go test entry point —
# TestRedTeamHarnessGenerateSiphash13NonceReuse in
# harness_test.go — which delegates to the same
# runNonceReuse128 body as the Phase 2a extension tests, so encryption,
# cell.meta.json schema, config.truth.json, and summary.json are identical
# across the two tracks. The bias probe also reuses the existing
# scripts/redteam/phase2_theory/raw_mode_bias_probe.py — the only new
# surface is the chainhashes/siphash13.py mirror, already parity-validated
# against the Go reference.
#
# Usage:
#   bash scripts/redteam/harness_bias_audit_siphash13.sh
#
# Env overrides:
#   SIZES       default: "524288 1048576"
#               (512 KB + 1 MB, matching the Phase 2a extension main
#               matrix baseline; add 4194304 for a 4 MB stress cell
#               parallel to the MD5 4 MB stress cell)
#   PROBE_SIZE  default: "auto"  (scales with corpus size)
#   RESULTS_TAG default: "harness_bias_audit_siphash13"
#   TIMEOUT_S   default: 600     (per-cell Go generator timeout)
#
# Output:
#   tmp/attack/siphash13stress/corpus/size_<N>_ascii/          — generated corpora
#   tmp/attack/siphash13stress/<RESULTS_TAG>/matrix_summary.jsonl
#   tmp/attack/siphash13stress/<RESULTS_TAG>/matrix.log
#   tmp/attack/siphash13stress/<RESULTS_TAG>/probe_siphash13_<N>_ascii.log

set -euo pipefail

SIZES=${SIZES:-"524288 1048576"}
PROBE_SIZE=${PROBE_SIZE:-"auto"}
RESULTS_TAG=${RESULTS_TAG:-"harness_bias_audit_siphash13"}
TIMEOUT_S=${TIMEOUT_S:-600}

PROJ_DIR=$(cd "$(dirname "$0")/../.." && pwd)
cd "$PROJ_DIR"

CORPUS_ROOT="tmp/attack/siphash13stress/corpus"
RESULTS_ROOT="tmp/attack/siphash13stress/${RESULTS_TAG}"
mkdir -p "$CORPUS_ROOT" "$RESULTS_ROOT"

MATRIX_SUMMARY="${RESULTS_ROOT}/matrix_summary.jsonl"
DRIVER_LOG="${RESULTS_ROOT}/matrix.log"
: > "$MATRIX_SUMMARY"
: > "$DRIVER_LOG"

echo "==========================================================================="
echo "siphash13 harness bias-neutralization audit (HARNESS.md § 4.1, Axis B)"
echo "==========================================================================="
echo "  primitive    : siphash13 (harness track; not in Phase 2a matrix)"
echo "  sizes        : $SIZES"
echo "  mode         : known_ascii (Full KPA; strongest per-byte bit-7=0 bias)"
echo "  probe size   : $PROBE_SIZE"
echo "  results tag  : $RESULTS_TAG"
echo "  matrix sum   : $MATRIX_SUMMARY"
echo "  driver log   : $DRIVER_LOG"
echo "==========================================================================="
echo

for size in $SIZES; do
    cell_dir="${CORPUS_ROOT}/size_${size}_ascii"
    cell_log="${RESULTS_ROOT}/probe_siphash13_${size}_ascii.log"

    echo "[${size}B ascii] generating corpus → ${cell_dir}"
    echo "[${size}B ascii] generating corpus → ${cell_dir}" >> "$DRIVER_LOG"

    # Go corpus generator — new harness entry point. cell.meta.json + ct_*.bin
    # emitted with the same schema as the Phase 2a extension corpora.
    ITB_HARNESS_SIPHASH13_MODE=known_ascii \
    ITB_HARNESS_SIPHASH13_SIZE="$size" \
    ITB_HARNESS_SIPHASH13_OUT="$cell_dir" \
    go test -run TestRedTeamHarnessGenerateSiphash13NonceReuse \
        -count=1 -v -timeout "${TIMEOUT_S}s" >> "$DRIVER_LOG" 2>&1

    echo "[${size}B ascii] running bias probe → ${cell_log}"
    echo "[${size}B ascii] running bias probe → ${cell_log}" >> "$DRIVER_LOG"

    # Reuse the existing raw_mode_bias_probe.py; point it at chainhashes.siphash13
    # (Python mirror bit-exact-verified against the Go siphash13 reference
    # via scripts/redteam/phase2_theory/chainhashes/_parity_test.py).
    python3 scripts/redteam/phase2_theory/raw_mode_bias_probe.py \
        --cell-dir "$cell_dir" \
        --hash-module chainhashes.siphash13 \
        --probe-size "$PROBE_SIZE" \
        --top-n 5 > "$cell_log" 2>&1

    # Parse the probe output into a single-row matrix summary. Uses a heredoc
    # Python invocation to keep everything in one file; no new dependencies.
    python3 - "$cell_log" "$size" "$cell_dir" >> "$MATRIX_SUMMARY" <<'PY'
import json
import re
import sys
from pathlib import Path

log_path, size_str, cell_dir = sys.argv[1], sys.argv[2], sys.argv[3]
size = int(size_str)
text = Path(log_path).read_text()

def _find(pattern, group=1, cast=None):
    m = re.search(pattern, text)
    if not m:
        return None
    v = m.group(group)
    return cast(v) if cast else v

# Read meta for nonce + total_pixels so the summary row cross-references cleanly.
meta = json.loads(Path(cell_dir + "/cell.meta.json").read_text())

row = {
    "primitive": "siphash13",
    "hash_display": meta.get("hash_display", "siphash13"),
    "hash_width": meta.get("hash_width", 128),
    "size_bytes": size,
    "format": "ascii",
    "total_pixels": meta.get("total_pixels"),
    "start_pixel": meta.get("start_pixel"),
    "min_conflict_pct": _find(r"min:\s+([\d.]+)%", cast=float),
    "p01_conflict_pct": _find(r"p01:\s+([\d.]+)%", cast=float),
    "p05_conflict_pct": _find(r"p05:\s+([\d.]+)%", cast=float),
    "median_conflict_pct": _find(r"median:\s+([\d.]+)%", cast=float),
    "p95_conflict_pct": _find(r"p95:\s+([\d.]+)%", cast=float),
    "p99_conflict_pct": _find(r"p99:\s+([\d.]+)%", cast=float),
    "max_conflict_pct": _find(r"max:\s+([\d.]+)%", cast=float),
    "true_shift_rank": _find(r"TRUE shift \d+: rank (\d+)/(\d+)", cast=int),
    "total_shifts": _find(r"TRUE shift \d+: rank \d+/(\d+)", cast=int),
    "plateau_size": _find(r"plateau \(≤ same conflict\) = (\d+) shift", cast=int),
    "pred_min_bits_pct": _find(
        r"at min-conflict shift \d+:\s*\n\s*bits matched\s*:\s*\d+/\d+ = ([\d.]+)%",
        cast=float),
    "pred_true_bits_pct": _find(
        r"at TRUE shift \d+  \(lab-only\):\s*\n\s*bits matched\s*:\s*\d+/\d+ = ([\d.]+)%",
        cast=float),
}
print(json.dumps(row))
PY

    echo "[${size}B ascii] done"
    echo >> "$DRIVER_LOG"
done

echo
echo "==========================================================================="
echo "Done."
echo "  Matrix summary: $MATRIX_SUMMARY"
echo "  Driver log    : $DRIVER_LOG"
echo "==========================================================================="
echo
echo "Summary rows:"
cat "$MATRIX_SUMMARY"
