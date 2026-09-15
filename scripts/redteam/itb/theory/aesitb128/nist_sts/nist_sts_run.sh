#!/usr/bin/env bash
# Non-interactive driver for NIST STS 2.1.2 (/usr/bin/nist-sts).
#
# Usage: nist_sts_run.sh <input-binary-file> <output-dir> [<bit-count>] [<streams>]
#
# Feeds the interactive prompts:
#   0                        -- Generator: Input File
#   <input-binary-file>      -- File path (absolute)
#   1                        -- Choose ALL 15 tests
#   0                        -- Accept default parameters for the parameter-tuned tests
#   <streams>                -- Number of bit streams (default 10)
#   1                        -- Data format: binary
#
# After completion, moves experiments/AlgorithmTesting/finalAnalysisReport.txt
# and every experiments/AlgorithmTesting/<TestName>/results.txt beneath it
# to <output-dir>/.
#
# Runs `nist-sts-create-experiment.sh` in a per-invocation temp cwd so
# repeated runs do not stomp each other's experiments/ layout.
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <input-binary-file> <output-dir> [<bit-count>] [<streams>]" >&2
    exit 2
fi

INPUT="$(readlink -f "$1")"
OUTDIR="$2"
BITS="${3:-1000000}"
STREAMS="${4:-10}"

if [[ ! -f "$INPUT" ]]; then
    echo "error: input file not found: $INPUT" >&2
    exit 1
fi

# Sanity check on stream size (STREAMS * BITS bits <= input file bits)
INPUT_BITS=$(( $(stat -c %s "$INPUT") * 8 ))
NEED_BITS=$(( BITS * STREAMS ))
if (( INPUT_BITS < NEED_BITS )); then
    echo "error: input has $INPUT_BITS bits, need $NEED_BITS ($BITS x $STREAMS)" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
OUTDIR="$(readlink -f "$OUTDIR")"

# Per-invocation experiment cwd (nist-sts writes relative to cwd).
WORK="$(mktemp -d -t nist-sts-XXXXXX)"
KEEP_WORK="${KEEP_WORK:-0}"
if [[ "$KEEP_WORK" != "1" ]]; then
    trap 'rm -rf "$WORK"' EXIT
fi

cd "$WORK"
/usr/bin/nist-sts-create-experiment.sh >/dev/null

# The NonOverlappingTemplate test reads `templates/template<m>` relative to
# cwd. The Arch package ships only /usr/bin/nist-sts + create-experiment.sh
# (no template files), so a fresh WORK dir would ABORT the NonOverlapping
# Template rows and emit constant-value dataN.txt files. Fetch the templates
# once from the NIST STS 2.1.2 source drop into a local cache, then
# symlink into every WORK dir.
TEMPLATES_CACHE="${NIST_STS_TEMPLATES:-$HOME/.local/share/nist-sts/templates}"
if [[ ! -f "$TEMPLATES_CACHE/template9" ]]; then
    echo "error: template file $TEMPLATES_CACHE/template9 missing." >&2
    echo "       download sts-2_1_2.zip from csrc.nist.gov and extract" >&2
    echo "       sts-2.1.2/templates/ to $TEMPLATES_CACHE/ ." >&2
    exit 1
fi
ln -s "$TEMPLATES_CACHE" "$WORK/templates"

# Drive interactively via stdin.
#   0 = Input File, path, 1 = all 15 tests, 0 = default params,
#   STREAMS = num substreams, 1 = binary format.
# Feed via a stdin file so printf SIGPIPE cannot break `set -e -o pipefail`.
STDIN_FILE="$WORK/nist-sts.stdin"
printf '0\n%s\n1\n0\n%s\n1\n' "$INPUT" "$STREAMS" > "$STDIN_FILE"
set +e
/usr/bin/nist-sts "$BITS" < "$STDIN_FILE" > "$OUTDIR/nist-sts.stdout.log" 2> "$OUTDIR/nist-sts.stderr.log"
NIST_RC=$?
set -e
if (( NIST_RC != 0 )); then
    echo "warning: nist-sts exit=$NIST_RC (some builds return non-zero even on success)" >&2
fi

REPORT="$WORK/experiments/AlgorithmTesting/finalAnalysisReport.txt"
if [[ ! -f "$REPORT" ]]; then
    echo "error: finalAnalysisReport.txt not produced. stdout log:" >&2
    tail -80 "$OUTDIR/nist-sts.stdout.log" >&2
    exit 1
fi

cp "$REPORT" "$OUTDIR/finalAnalysisReport.txt"
# Optional: preserve per-test results
mkdir -p "$OUTDIR/AlgorithmTesting"
cp -r "$WORK/experiments/AlgorithmTesting/." "$OUTDIR/AlgorithmTesting/" 2>/dev/null || true

echo "$OUTDIR/finalAnalysisReport.txt"
