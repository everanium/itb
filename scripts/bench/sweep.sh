#!/usr/bin/env bash
# sweep.sh — single-policy microBatch bench with compact output.
#
# Runs the canonical BenchmarkExtProductionMessage_(Encrypt|Decrypt) cohort
# at 1s x count=1 with -benchmem, parses each result line into a compact
# three-number row (allocs/op, ns/op, MB/s), and prefixes the run with the
# CPU model, core/thread count, and the active tier + pool policy.
#
# Policy is set through two ITB env vars read by the shipped binary at
# init(); no source edits required.
#
#   ITB_MICROBATCH_TIERS  = "upper:batch,upper:batch,-1:batch"
#   ITB_HASHPOOL_STARTERS = "s1,s2,s3"
#
# Both default to the shipped ladder when unset. See README.md for policy
# recipes worth sweeping and the interpretation of the compact output.

set -uo pipefail

REPO="${ITB_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$REPO"

POLICY_NAME="${POLICY_NAME:-default}"
BENCH_TIME="${BENCH_TIME:-1s}"
BENCH_COUNT="${BENCH_COUNT:-1}"

# Canonical bench profile — matches the pre-adaptive sweep configuration
# so cross-run comparability holds. Every knob below is set only when the
# caller has not already exported an override.
: "${ITB_INNER_HASH:=areion512}"
: "${ITB_KEY_BITS:=512}"
: "${ITB_NONCE_BITS:=512}"
: "${ITB_WITH_MAC:=false}"
: "${ITB_WITH_PARALLAX:=false}"
: "${ITB_WITH_WRAPPER:=false}"
: "${ITB_GOMEMLIMIT:=1GiB}"
: "${ITB_GOGC:=20}"
export ITB_INNER_HASH ITB_KEY_BITS ITB_NONCE_BITS \
    ITB_WITH_MAC ITB_WITH_PARALLAX ITB_WITH_WRAPPER \
    ITB_GOMEMLIMIT ITB_GOGC

BENCH_REGEX='^BenchmarkExtProductionMessage_(Encrypt|Decrypt)_(4KB|64KB|512KB|1MB|4MB|8MB|16MB|32MB|48MB|64MB)$'

# Compact CPU model line.
cpu_line() {
    local model cores threads
    model=$(awk -F': +' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
    [ -z "$model" ] && model="unknown"
    # Physical cores per socket × sockets = total physical cores.
    local sockets phys_per_sock
    sockets=$(awk -F': +' '/^physical id/{print $2}' /proc/cpuinfo 2>/dev/null | sort -u | wc -l)
    phys_per_sock=$(awk -F': +' '/^cpu cores/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
    if [ -n "$sockets" ] && [ "$sockets" -gt 0 ] && [ -n "$phys_per_sock" ]; then
        cores=$((sockets * phys_per_sock))
    else
        cores="?"
    fi
    threads=$(nproc 2>/dev/null || echo "?")
    echo "CPU: ${model} ${cores}c/${threads}t"
}

# Header (compact — never touched by the parser).
cpu_line
echo "Policy: ${POLICY_NAME}"
if [ -n "${ITB_MICROBATCH_TIERS:-}" ]; then
    echo "  tiers=${ITB_MICROBATCH_TIERS}"
else
    echo "  tiers=default"
fi
if [ -n "${ITB_HASHPOOL_STARTERS:-}" ]; then
    echo "  pools=${ITB_HASHPOOL_STARTERS}"
else
    echo "  pools=default"
fi

# Force a fresh test cache so a prior run at the same benchtime does not
# short-circuit — sweep runs must actually measure, not replay.
go clean -testcache >/dev/null 2>&1 || true

go test -run='^$' \
        -bench="${BENCH_REGEX}" \
        -benchmem \
        -benchtime="${BENCH_TIME}" \
        -count="${BENCH_COUNT}" \
        github.com/everanium/itb 2>&1 | \
awk '
/^BenchmarkExtProductionMessage_(Encrypt|Decrypt)_/ {
    # Field layout with -benchmem and SetBytes:
    #   $1 name-cpus  $2 iters  $3 ns/op  $4 "ns/op"
    #   $5 MB/s       $6 "MB/s" $7 B/op   $8 "B/op"
    #   $9 allocs/op  $10 "allocs/op"
    name = $1
    if (name ~ /_Encrypt_/) { dir = "E" } else { dir = "D" }
    n = split(name, parts, "_")
    size = parts[n]
    sub(/-[0-9]+$/, "", size)
    printf "%s %-5s %6s %10s %8s\n", dir, size, $9, $3, $5
}
'
