#!/usr/bin/env bash
# tier_matrix_bench.sh — AES-ITB-128 dispatch-tier matrix benchmark.
#
# Crosses the two aesitbasm forcing variables and reports encrypt /
# decrypt throughput of the Triple 512-bit AES-ITB-128 cell for every
# combination the host silicon can execute:
#
#   rows    ITB_FORCE_HASH_TIER (per-round x4 + fused cascade family):
#           natural (variable unset), aesni, vaesavx2, avx512, avx512x4,
#           scalar — avx512x4 is ITB_FORCE_HASH_TIER=avx512 with
#           ITB_FORCE_CHAINHASH_X4=1, the ZMM tier with the eight-lane
#           fused ChainHash kernels disarmed (four-lane ZMM kernels and
#           the four-pixel stride), so the avx512 / avx512x4 pair isolates
#           the eight-lane arm
#   columns ITB_FORCE_INTERLOCK_PRF_FILL_TIER (batch-16 interlock fill):
#           aesni, vex, vaesavx2, avx512, scalar
#
# On arm64 the matrix is {natural, scalar} × {neon, scalar}: the amd64
# tier tokens are rejected there, and "natural" rows leave the variable
# unset. The hash-tier "scalar" row disarms the batch-16 family as well;
# the column variable, applied afterwards, re-arms the named batch-16
# tier, so every cell measures exactly the named pair.
#
# Cells whose tier the host cannot execute report "n/a": the library
# emits an "itb: forcetier: ... keeping auto-dispatch" note on stderr
# when a forced arm is unsupported, and the harness treats that note as
# a skip rather than reporting the auto-dispatch numbers under the
# wrong label.
#
# Each cell runs the encrypt and decrypt benchmarks BENCH_COUNT times
# and reports the median MB/s (lower-middle element for an even count).
# The benchmark functions exercise the same seed wiring the Triple
# pipeline installs (single, batched, fused-cascade and batch-16 hooks);
# the decrypt benchmark verifies its round trip once before timing.
# Cross-tier wire parity is pinned by the Go test suite, not by this
# harness.
#
# Output: a Markdown table on stdout; per-cell raw benchmark logs under
# LOG_DIR.
#
# Usage:
#   bash scripts/diag/tier_matrix_bench.sh
#   BENCH_TIME=5s BENCH_COUNT=5 PAYLOAD=16MB bash scripts/diag/tier_matrix_bench.sh

set -uo pipefail

if [ -f /etc/profile.d/golang.sh ]; then . /etc/profile.d/golang.sh; fi

REPO="${ITB_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BENCH_TIME="${BENCH_TIME:-3s}"
BENCH_COUNT="${BENCH_COUNT:-3}"
PAYLOAD="${PAYLOAD:-64MB}"
LOG_DIR="${LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/itb-tier-matrix.XXXXXX")}"
BINARY="${ITB_TEST_BINARY:-$LOG_DIR/itb.test}"

mkdir -p "$LOG_DIR"

# Always rebuild: the test binary must reflect the working tree.
if ! (cd "$REPO" && go test -c -o "$BINARY" github.com/everanium/itb); then
    echo "tier_matrix_bench: go test -c failed" >&2
    exit 1
fi

MODEL=$(awk -F': +' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
[ -n "$MODEL" ] || MODEL="unknown"
THREADS=$(nproc 2>/dev/null || echo "?")
ARCH=$(uname -m)

echo "tier_matrix_bench on $ARCH: $MODEL (${THREADS}t)"
echo "payload=$PAYLOAD  bench_time=$BENCH_TIME  count=$BENCH_COUNT  (median MB/s, encrypt/decrypt)"
echo ""

BENCH_ENC="BenchmarkExtTripleAESITB128_512bit_Encrypt_${PAYLOAD}"
BENCH_DEC="BenchmarkExtTripleAESITB128_512bit_Decrypt_${PAYLOAD}"
COMMON_ENV="ITB_GOMEMLIMIT=2GiB ITB_GOGC=20"

# median prints the lower-middle element of the newline-separated
# numbers on stdin, or nothing for empty input.
median() {
    sort -n | awk '{a[NR]=$1} END{if (NR) print a[int((NR+1)/2)]}'
}

# run_bench <hash_tier> <prf_fill_tier> prints "enc/dec" median MB/s,
# "n/a" when the host cannot execute the requested pair, or "ERR" when
# the benchmark binary failed.
run_bench() {
    local hash_tier="$1" prf_fill_tier="$2"
    local env_vars="$COMMON_ENV"
    case "$hash_tier" in
        natural) ;;
        avx512x4) env_vars="$env_vars ITB_FORCE_HASH_TIER=avx512 ITB_FORCE_CHAINHASH_X4=1" ;;
        *) env_vars="$env_vars ITB_FORCE_HASH_TIER=$hash_tier" ;;
    esac
    env_vars="$env_vars ITB_FORCE_INTERLOCK_PRF_FILL_TIER=$prf_fill_tier"

    local log_file="$LOG_DIR/tier_${hash_tier}_${prf_fill_tier}.log"
    local out status
    out=$(env $env_vars "$BINARY" -test.run='^$' \
        -test.bench="^(${BENCH_ENC}|${BENCH_DEC})\$" \
        -test.benchtime="$BENCH_TIME" -test.count="$BENCH_COUNT" 2>&1)
    status=$?
    printf '%s\n' "$out" > "$log_file"

    if printf '%s\n' "$out" | grep -q "keeping auto-dispatch"; then
        echo "n/a"
        return 0
    fi
    if [ "$status" -ne 0 ] || printf '%s\n' "$out" | grep -qE "^(FAIL|panic:)"; then
        echo "ERR"
        return 1
    fi

    # Benchmark lines: <name>-<procs> <N> <ns/op> ns/op <MB/s> MB/s ...
    local enc_median dec_median
    enc_median=$(printf '%s\n' "$out" | awk -v n="$BENCH_ENC" 'index($1, n "-") == 1 && $6 == "MB/s" {print $5}' | median)
    dec_median=$(printf '%s\n' "$out" | awk -v n="$BENCH_DEC" 'index($1, n "-") == 1 && $6 == "MB/s" {print $5}' | median)
    if [ -z "$enc_median" ] || [ -z "$dec_median" ]; then
        echo "ERR"
        return 1
    fi
    printf "%.0f/%.0f" "$enc_median" "$dec_median"
}

if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    hash_tiers=("natural" "scalar")
    prf_fill_tiers=("neon" "scalar")
else
    hash_tiers=("natural" "aesni" "vaesavx2" "avx512" "avx512x4" "scalar")
    prf_fill_tiers=("aesni" "vex" "vaesavx2" "avx512" "scalar")
fi

CELL=12
printf "| %-10s |" "hash \\ x16"
for prf in "${prf_fill_tiers[@]}"; do
    printf " %${CELL}s |" "$prf"
done
echo ""
printf "|:%s:|" "$(printf '%.0s-' $(seq 1 10))"
for prf in "${prf_fill_tiers[@]}"; do
    printf "%s:|" "$(printf '%.0s-' $(seq 1 $((CELL + 1))))"
done
echo ""
for hash in "${hash_tiers[@]}"; do
    printf "| %-10s |" "$hash"
    for prf in "${prf_fill_tiers[@]}"; do
        printf " %${CELL}s |" "$(run_bench "$hash" "$prf")"
    done
    echo ""
done

echo ""
echo "logs: $LOG_DIR/"
echo "done: $(date -Iseconds)"
