#!/usr/bin/env bash
# hash_diag.sh — 9-hash x 3-nonce-width throughput matrix at fixed
# tier configuration.
#
# Purpose: detect hash-specific or nonce-width-specific regressions on
# a given CPU. Compares the same 27 cells across CPUs (or across tier
# forcings on the same CPU). A uniform host-vs-host ratio across all
# 27 cells indicates general silicon performance difference; an
# outlier cell indicates a hash-specific dispatch bug or kernel
# regression on the affected silicon.
#
# Usage:
#   bash scripts/diag/hash_diag.sh                           # defaults
#   INTERLOCK_TIER=avx512 bash scripts/diag/hash_diag.sh     # compare interlock arms
#   PIXEL_TIER=A_NOGFNI bash scripts/diag/hash_diag.sh       # different pixel arm
#   HASH_TIER=avx2 bash scripts/diag/hash_diag.sh            # force hash arm
#   PAYLOAD=1MB BENCH_TIME=1s bash scripts/diag/hash_diag.sh # bigger sample
#
# Env inputs (all optional):
#   INTERLOCK_TIER  = natural | avx512 | avx2 | scalar             (default: avx2)
#   PIXEL_TIER      = natural | A | A_NOGFNI | B | B_NOGFNI | C    (default: natural)
#   HASH_TIER       = natural | avx512 | vaesavx2 | avx2 | aesni | scalar  (default: natural)
#   PAYLOAD         = 4KB..64MB from ExtProductionMessage ladder   (default: 4MB)
#   BENCH_TIME      = Go bench duration                            (default: 300ms)
#   BENCH_COUNT     = Go bench -count (samples averaged in output) (default: 3)
#   ITB_KEY_BITS    = 128 | 256 | 512 | 1024 | 2048                (default: 512)

set -uo pipefail

if [ -f /etc/profile.d/golang.sh ]; then . /etc/profile.d/golang.sh; fi

REPO="${ITB_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BINARY="${ITB_TEST_BINARY:-/tmp/itb.test}"

if [ ! -x "$BINARY" ] || [ "$REPO" -nt "$BINARY" ]; then
    ( cd "$REPO" && go test -c -o "$BINARY" github.com/everanium/itb ) 2>&1 | tail -3
fi

INTERLOCK_TIER="${INTERLOCK_TIER:-avx2}"
PIXEL_TIER="${PIXEL_TIER:-natural}"
HASH_TIER="${HASH_TIER:-natural}"
PAYLOAD="${PAYLOAD:-4MB}"
BENCH_TIME="${BENCH_TIME:-300ms}"
BENCH_COUNT="${BENCH_COUNT:-3}"
KEY_BITS="${ITB_KEY_BITS:-512}"

HASHES="areion256 areion512 blake2b256 blake2b512 blake2s blake3 aescmac siphash24 chacha20"
NONCE_WIDTHS="128 256 512"

tier_env=""
[ "$INTERLOCK_TIER" != "natural" ] && tier_env="$tier_env ITB_FORCE_INTERLOCK_TIER=$INTERLOCK_TIER"
[ "$PIXEL_TIER"     != "natural" ] && tier_env="$tier_env ITB_FORCE_PIXEL_TIER=$PIXEL_TIER"
[ "$HASH_TIER"      != "natural" ] && tier_env="$tier_env ITB_FORCE_HASH_TIER=$HASH_TIER"

model=$(awk -F': +' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)
threads=$(nproc 2>/dev/null || echo "?")
echo "hash_diag: CPU=$model ${threads}t"
echo "  KEY_BITS=$KEY_BITS  PAYLOAD=$PAYLOAD  BENCH_TIME=$BENCH_TIME  BENCH_COUNT=$BENCH_COUNT"
echo "  INTERLOCK_TIER=$INTERLOCK_TIER  PIXEL_TIER=$PIXEL_TIER  HASH_TIER=$HASH_TIER"
echo ""

echo "=== Encrypt MB/s  (rows = hash, cols = nonce bits) ==="
printf "  %-12s | %8s | %8s | %8s\n" hash 128 256 512
printf "  %-12s-+-%8s-+-%8s-+-%8s\n" ------------ -------- -------- --------

for hash in $HASHES; do
    line="  $(printf '%-12s' $hash) |"
    for n in $NONCE_WIDTHS; do
        mbps=$(env ITB_INNER_HASH=$hash ITB_KEY_BITS=$KEY_BITS ITB_NONCE_BITS=$n \
            ITB_WITH_MAC=false ITB_WITH_PARALLAX=false ITB_WITH_WRAPPER=false \
            ITB_GOMEMLIMIT=1GiB ITB_GOGC=20 $tier_env \
            "$BINARY" -test.run='^$' \
            -test.bench="^BenchmarkExtProductionMessage_Encrypt_${PAYLOAD}\$" \
            -test.benchtime=${BENCH_TIME} -test.count=${BENCH_COUNT} 2>&1 | \
            awk '/^BenchmarkExtProductionMessage_/ {a[NR]=$5} END {n=NR; if(n==0){print "N/A"; exit} for(i=1;i<=n;i++)s+=a[i]; printf "%.1f", s/n}')
        line="${line} $(printf '%8s' ${mbps:-N/A}) |"
    done
    echo "$line"
done

echo ""
echo "=== Decrypt MB/s  (rows = hash, cols = nonce bits) ==="
printf "  %-12s | %8s | %8s | %8s\n" hash 128 256 512
printf "  %-12s-+-%8s-+-%8s-+-%8s\n" ------------ -------- -------- --------

for hash in $HASHES; do
    line="  $(printf '%-12s' $hash) |"
    for n in $NONCE_WIDTHS; do
        mbps=$(env ITB_INNER_HASH=$hash ITB_KEY_BITS=$KEY_BITS ITB_NONCE_BITS=$n \
            ITB_WITH_MAC=false ITB_WITH_PARALLAX=false ITB_WITH_WRAPPER=false \
            ITB_GOMEMLIMIT=1GiB ITB_GOGC=20 $tier_env \
            "$BINARY" -test.run='^$' \
            -test.bench="^BenchmarkExtProductionMessage_Decrypt_${PAYLOAD}\$" \
            -test.benchtime=${BENCH_TIME} -test.count=${BENCH_COUNT} 2>&1 | \
            awk '/^BenchmarkExtProductionMessage_/ {a[NR]=$5} END {n=NR; if(n==0){print "N/A"; exit} for(i=1;i<=n;i++)s+=a[i]; printf "%.1f", s/n}')
        line="${line} $(printf '%8s' ${mbps:-N/A}) |"
    done
    echo "$line"
done

echo ""
echo "done: $(date -Iseconds)"
