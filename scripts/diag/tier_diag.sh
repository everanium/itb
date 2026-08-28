#!/usr/bin/env bash
# tier_diag.sh — force each ITB dispatch tier and report throughput.
#
# Runs a short single-thread bench (default: 4 MiB payload, 300 ms
# per direction) at natural dispatch and then under every documented
# forced-tier value for the three dispatch axes:
#
#   ITB_FORCE_INTERLOCK_TIER = avx512 | avx2 | scalar
#   ITB_FORCE_HASH_TIER      = avx512 | vaesavx2 | avx2 | aesni | scalar
#   ITB_FORCE_PIXEL_TIER     = A | A_NOGFNI | B | B_NOGFNI | C
#
# Purpose: identify a slow tier on a given CPU by comparison — natural
# dispatch throughput vs each forced arm. When natural dispatch is
# significantly slower than one of the forced arms, the auto-selected
# tier has a silicon-specific regression on this host and belongs
# either in the SKU blacklist at
# `internal/interlock/interlock_sku_blacklist_amd64.go` (interlock
# axis) or in an equivalent site for the hash / pixel axes.
#
# Usage:
#   bash scripts/diag/tier_diag.sh                     # defaults
#   PAYLOAD=1MB BENCH_TIME=1s bash scripts/diag/tier_diag.sh
#   ITB_TEST_BINARY=/tmp/itb.test bash scripts/diag/tier_diag.sh
#
# Prereq: a Go bench binary must exist. If not present, this script
# builds one at ITB_TEST_BINARY (default /tmp/itb.test) via `go test -c`.

set -uo pipefail

if [ -f /etc/profile.d/golang.sh ]; then . /etc/profile.d/golang.sh; fi

REPO="${ITB_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BINARY="${ITB_TEST_BINARY:-/tmp/itb.test}"
PAYLOAD="${PAYLOAD:-4MB}"
BENCH_TIME="${BENCH_TIME:-300ms}"
BENCH_COUNT="${BENCH_COUNT:-3}"

if [ ! -x "$BINARY" ] || [ "$REPO" -nt "$BINARY" ]; then
    ( cd "$REPO" && go test -c -o "$BINARY" github.com/everanium/itb ) 2>&1 | tail -3
fi

model=$(awk -F': +' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)
threads=$(nproc 2>/dev/null || echo "?")
echo "tier_diag: CPU=$model ${threads}t"
echo "  payload=$PAYLOAD  bench_time=$BENCH_TIME  bench_count=$BENCH_COUNT"
echo ""

BENCH_REGEX="^BenchmarkExtProductionMessage_(Encrypt|Decrypt)_${PAYLOAD}\$"
COMMON_ENV="ITB_INNER_HASH=areion512 ITB_KEY_BITS=512 ITB_NONCE_BITS=512 ITB_WITH_MAC=false ITB_WITH_PARALLAX=false ITB_WITH_WRAPPER=false ITB_GOMEMLIMIT=1GiB ITB_GOGC=20"

run_bench() {
    local label="$1"
    shift
    printf "%-30s" "$label"
    local out
    out=$(env $COMMON_ENV "$@" "$BINARY" -test.run='^$' \
            -test.bench="$BENCH_REGEX" \
            -test.benchtime="$BENCH_TIME" -test.count="$BENCH_COUNT" 2>&1)
    local enc dec
    enc=$(echo "$out" | awk '/^BenchmarkExtProductionMessage_Encrypt_/ {s+=$5; n++} END {if(n) printf "%.1f", s/n}')
    dec=$(echo "$out" | awk '/^BenchmarkExtProductionMessage_Decrypt_/ {s+=$5; n++} END {if(n) printf "%.1f", s/n}')
    printf "  E=%8s MB/s  D=%8s MB/s\n" "${enc:-N/A}" "${dec:-N/A}"
}

echo "=== Natural dispatch ==="
run_bench "natural"
echo ""

echo "=== Forced interlock tier ==="
for t in avx512 avx2 scalar; do
    run_bench "INTERLOCK=$t" ITB_FORCE_INTERLOCK_TIER=$t
done
echo ""

echo "=== Forced hash tier ==="
for t in avx512 vaesavx2 avx2 aesni scalar; do
    run_bench "HASH=$t" ITB_FORCE_HASH_TIER=$t
done
echo ""

echo "=== Forced pixel tier ==="
for t in A A_NOGFNI B B_NOGFNI C; do
    run_bench "PIXEL=$t" ITB_FORCE_PIXEL_TIER=$t
done
echo ""

echo "done: $(date -Iseconds)"
