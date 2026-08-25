#!/usr/bin/env bash
# cross-build-parity.sh -- cross-build C ↔ pure-Go pixel parity harness.
#
# Builds two arms of the tools/parity helper (CGO_ENABLED=1 dispatches
# into process_pixels.c Tier A / B / C; CGO_ENABLED=0 runs the pure-Go
# pixel path), then for every shipped PRF-grade hash × every fixture
# size runs both cross-build encrypt→decrypt directions and cross-checks
# the recovered plaintext against the source via sha256sum. A same-build
# round-trip proves only self-inversion (a C tier applying permutation Q
# with its own inverse Q⁻¹ passes even when Q differs from the Go-specified
# permutation P); the cross matrix forces the two implementations to agree
# on the sampled mapping.
#
# Fixture matrix reuses the standard edge-case set:
#   1  6  7  56  1024  65535  1048576  16777231
# — bytes that exercise the sub-pixel, single-pixel, single-8-pixel-batch,
# non-8-multiple, single-chunk (< 16 MiB), and multi-chunk (16 MiB + 15 B)
# handoffs.
#
# Working directory tmp/parity/ is under the repo's gitignored tmp/ tree;
# nothing produced by this script lands in the tracked working set.

set -eu
set -o pipefail

REPO="/home/andrew/go/src/itb"
cd "$REPO"

# Build both arms — always fresh so a stale binary cannot mask a
# just-landed pixel-kernel edit. A third arm carries the parity-only
# tier-forcing knob: process_pixels.c reads ITB_FORCE_PIXEL_TIER when
# built with -DITB_PARITY_TIER_OVERRIDE and masks its cached
# support-flag to downgrade the selected tier (A→B→C). Production
# builds compile the knob out entirely.
CGO_ENABLED=1 go build -o tools/parity/parity-cgo         ./tools/parity
CGO_ENABLED=0 go build -o tools/parity/parity-nocgo       ./tools/parity
CGO_ENABLED=1 CGO_CFLAGS="-DITB_PARITY_TIER_OVERRIDE" \
    go build -o tools/parity/parity-cgo-tiered            ./tools/parity

# Fixture matrix. Covers sub-pixel (1), single-pixel (6, 7), single-8-pixel
# batch boundary (56), and multi-chunk transitions (65535, 1048576,
# 16777231). 16777231 = 16 MiB + 15 B — one full chunk (DefaultChunkSize
# = 16 MiB) plus a short remainder chunk.
SIZES=(1 6 7 56 1024 65535 1048576 16777231)

WORKDIR="$REPO/tmp/parity"
mkdir -p "$WORKDIR"

# Canonical PRF-grade hash roster. Order matches
# github.com/everanium/itb/hashes.Registry so the sweep visits every
# primitive a §3 asm micro or §4 pixel-kernel change can touch.
HASHES=(areion256 areion512 blake2b256 blake2b512 blake2s blake3 aescmac siphash24 chacha20)

FAIL=0

for HASH in "${HASHES[@]}"; do
    PROFILE="parity-${HASH}-v1"
    SEED="$WORKDIR/seed-${HASH}.blob"

    # Init once — either arm produces a functionally identical envelope
    # (crypto/rand entropy is the only source of variance and the blob
    # is then read verbatim by every subsequent invocation on either
    # arm). Use the cgo arm arbitrarily.
    ./tools/parity/parity-cgo -mode=init \
        -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED"

    for SIZE in "${SIZES[@]}"; do
        PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
        head -c "$SIZE" /dev/urandom > "$PLAIN"
        PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

        # Direction 1: encrypt=cgo, decrypt=nocgo.
        WIRE1="$WORKDIR/wire-${HASH}-${SIZE}-cgo.bin"
        BACK1="$WORKDIR/back-${HASH}-${SIZE}-nocgo.bin"
        ./tools/parity/parity-cgo   -mode=encrypt \
            -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" \
            -in="$PLAIN" -out="$WIRE1"
        ./tools/parity/parity-nocgo -mode=decrypt \
            -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" \
            -in="$WIRE1" -out="$BACK1"
        BACK1_HASH=$(sha256sum "$BACK1" | awk '{print $1}')
        if [ "$BACK1_HASH" != "$PLAIN_HASH" ]; then
            echo "FAIL: encrypt=cgo decrypt=nocgo hash=$HASH size=$SIZE"
            FAIL=$((FAIL + 1))
        fi

        # Direction 2: encrypt=nocgo, decrypt=cgo.
        WIRE2="$WORKDIR/wire-${HASH}-${SIZE}-nocgo.bin"
        BACK2="$WORKDIR/back-${HASH}-${SIZE}-cgo.bin"
        ./tools/parity/parity-nocgo -mode=encrypt \
            -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" \
            -in="$PLAIN" -out="$WIRE2"
        ./tools/parity/parity-cgo   -mode=decrypt \
            -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" \
            -in="$WIRE2" -out="$BACK2"
        BACK2_HASH=$(sha256sum "$BACK2" | awk '{print $1}')
        if [ "$BACK2_HASH" != "$PLAIN_HASH" ]; then
            echo "FAIL: encrypt=nocgo decrypt=cgo hash=$HASH size=$SIZE"
            FAIL=$((FAIL + 1))
        fi
    done
done

CELLS=$(( ${#HASHES[@]} * ${#SIZES[@]} * 2 ))

# Tier-forcing matrix. Sweeps ITB_FORCE_PIXEL_TIER=A|B|C on the tiered
# cgo arm to exercise all three C dispatch paths on one host regardless
# of the host CPU's natural tier. Downgrade-only: forcing to B on a
# Tier C-only host has no effect; forcing to A on an actual Tier A host
# is a no-op vs the plain cgo arm and re-runs it as sanity coverage.
TIER_MATRIX=(A B C)
TIER_CELLS=$(( ${#TIER_MATRIX[@]} * ${#HASHES[@]} * ${#SIZES[@]} * 2 ))

for TIER in "${TIER_MATRIX[@]}"; do
    for HASH in "${HASHES[@]}"; do
        PROFILE="parity-${HASH}-v1"
        SEED="$WORKDIR/seed-${HASH}.blob"

        for SIZE in "${SIZES[@]}"; do
            PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
            PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

            WIRE1="$WORKDIR/wire-${HASH}-${SIZE}-tier${TIER}.bin"
            BACK1="$WORKDIR/back-${HASH}-${SIZE}-tier${TIER}-nocgo.bin"
            ITB_FORCE_PIXEL_TIER="$TIER" ./tools/parity/parity-cgo-tiered -mode=encrypt \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" \
                -in="$PLAIN" -out="$WIRE1"
            ./tools/parity/parity-nocgo -mode=decrypt \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" \
                -in="$WIRE1" -out="$BACK1"
            if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                echo "FAIL: tier=$TIER encrypt=cgo decrypt=nocgo hash=$HASH size=$SIZE"
                FAIL=$((FAIL + 1))
            fi

            WIRE2="$WORKDIR/wire-${HASH}-${SIZE}-nocgo-vs-tier${TIER}.bin"
            BACK2="$WORKDIR/back-${HASH}-${SIZE}-nocgo-vs-tier${TIER}-cgo.bin"
            ./tools/parity/parity-nocgo -mode=encrypt \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" \
                -in="$PLAIN" -out="$WIRE2"
            ITB_FORCE_PIXEL_TIER="$TIER" ./tools/parity/parity-cgo-tiered -mode=decrypt \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" \
                -in="$WIRE2" -out="$BACK2"
            if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                echo "FAIL: tier=$TIER encrypt=nocgo decrypt=cgo hash=$HASH size=$SIZE"
                FAIL=$((FAIL + 1))
            fi
        done
    done
done

echo "---"
TOTAL=$(( CELLS + TIER_CELLS ))
if [ "$FAIL" -eq 0 ]; then
    echo "PASS: $CELLS host-tier + $TIER_CELLS forced-tier = $TOTAL cells"
    exit 0
fi
echo "FAIL: $FAIL of $TOTAL cells failed"
exit 1
