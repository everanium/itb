#!/usr/bin/env bash
# loop_policy_sweep.sh — steady-state encoder-policy sweep via tools/loop.
#
# Runs one tools/loop cell per line of a cell-spec file, each under its
# own ITB_MICROBATCH_TIERS / ITB_HASHPOOL_STARTERS / GOGC environment, and
# stores the per-cell JSON summary (the --json-output trailing line) in
# an output directory for loop_policy_aggregate.py to tabulate.
#
# Cell-spec line format (pipe-delimited; "-" or empty = default):
#
#   label|tiers|pools|gogc|hash|payload|extra loop flags
#
#   label    free-form cell name (used as the JSON file stem)
#   tiers    ITB_MICROBATCH_TIERS value, or - for the shipped ladder
#   pools    ITB_HASHPOOL_STARTERS value, or - for the shipped ladder
#   gogc     GOGC value (85, 100, off ...), or - for LOOP_GOGC (default 85)
#   hash     inner hash name, or - for LOOP_HASH (default aesitb128)
#   payload  --payload-size value (4KB, 1MB, 64MB ...)
#   extra    additional tools/loop flags appended verbatim (optional)
#
# Lines starting with # and blank lines are ignored.
#
# Fixed knobs (override through LOOP_COMMON): the production Streaming
# AEAD shape tools/loop defaults to — --shape stream, --mac hmac-blake3,
# --parallax on, --wrapper on, --key-bits 1024, --goroutines 3 — with
# GOMEMLIMIT and --memlimit both at LOOP_MEMLIMIT (default 2GiB) and
# --duration LOOP_DURATION (default 90s).
#
# These figures are steady-state Streaming AEAD numbers from a
# long-lived pipeline and are NOT comparable with the cold-start
# Single Message rows sweep.sh produces from `go test -bench`.
#
# Usage:
#   bash scripts/bench/loop_policy_sweep.sh CELLS_FILE OUT_DIR
#   python3 scripts/bench/loop_policy_aggregate.py OUT_DIR

set -uo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 CELLS_FILE OUT_DIR" >&2
    exit 2
fi
CELLS="$1"
OUT="$2"

REPO="${ITB_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
LOOP_DURATION="${LOOP_DURATION:-90s}"
LOOP_MEMLIMIT="${LOOP_MEMLIMIT:-2GiB}"
LOOP_GOGC="${LOOP_GOGC:-85}"
LOOP_HASH="${LOOP_HASH:-aesitb128}"
LOOP_COMMON="${LOOP_COMMON:---shape stream --mac hmac-blake3 --parallax on --wrapper on --key-bits 1024 --goroutines 3}"

mkdir -p "$OUT"

# Build the loop binary once unless the caller supplies one.
if [ -z "${LOOP_BIN:-}" ]; then
    LOOP_BIN="$OUT/loop"
    (cd "$REPO" && go build -o "$LOOP_BIN" ./tools/loop) || exit 1
fi

echo "sweep: cells=$CELLS out=$OUT duration=$LOOP_DURATION memlimit=$LOOP_MEMLIMIT bin=$LOOP_BIN"
echo "sweep: common flags: $LOOP_COMMON"

while IFS='|' read -r label tiers pools gogc hash payload extra; do
    case "$label" in ''|'#'*) continue ;; esac
    [ "$tiers" = "-" ] && tiers=""
    [ "$pools" = "-" ] && pools=""
    { [ -z "$gogc" ] || [ "$gogc" = "-" ]; } && gogc="$LOOP_GOGC"
    { [ -z "$hash" ] || [ "$hash" = "-" ]; } && hash="$LOOP_HASH"
    [ "${extra:-}" = "-" ] && extra=""
    stem="$OUT/$label"
    echo "=== $(date +%T) cell $label hash=$hash payload=$payload gogc=$gogc tiers=${tiers:-default} pools=${pools:-default} extra=${extra:-}"
    # shellcheck disable=SC2086
    env ITB_MICROBATCH_TIERS="$tiers" ITB_HASHPOOL_STARTERS="$pools" \
        GOGC="$gogc" GOMEMLIMIT="$LOOP_MEMLIMIT" \
        "$LOOP_BIN" $LOOP_COMMON --hash "$hash" --payload-size "$payload" \
        --duration "$LOOP_DURATION" --memlimit "$LOOP_MEMLIMIT" \
        --json-output $extra > "$stem.log" 2>&1
    rc=$?
    tail -1 "$stem.log" > "$stem.json"
    echo "exit=$rc"
done < "$CELLS"
echo "=== $(date +%T) sweep done"
