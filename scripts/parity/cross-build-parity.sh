#!/usr/bin/env bash
# cross-build-parity.sh -- cross-build C ↔ pure-Go pixel parity harness.
#
# Builds two arms of the tools/parity helper (CGO_ENABLED=1 dispatches
# into process_pixels.c Tier A / B / C; CGO_ENABLED=0 runs the pure-Go
# pixel path), then for every shipped PRF-grade hash × every fixture
# size × every on-wire nonce width runs both cross-build
# encrypt→decrypt directions and cross-checks the recovered plaintext
# against the source via sha256sum. A same-build round-trip proves only
# self-inversion (a C tier applying permutation Q with its own inverse
# Q⁻¹ passes even when Q differs from the Go-specified permutation P);
# the cross matrix forces the two implementations to agree on the
# sampled mapping.
#
# Fixture matrix reuses the standard edge-case set:
#   1  6  7  56  1024  65535  1048576  16777231
# — bytes that exercise the sub-pixel, single-pixel, single-8-pixel-batch,
# non-8-multiple, single-chunk (< 16 MiB), and multi-chunk (16 MiB + 15 B)
# handoffs.
#
# Nonce-width axis: the nonce width determines the per-pixel buf shape
# the inner hash absorbs (nonce bytes + 4 → 20 / 36 / 68 bytes), so the
# 128 / 256 / 512 sweep drives every chain-absorb kernel width through
# the cross-build matrix (the 13-byte width fires on every run via the
# interlock overlay's batched PRF fill whenever the primitive exposes a
# batched arm).
#
# Hash-arm axis: ITB_FORCE_HASH_TIER (read by the Go-side asm packages
# via internal/forcetier) forces a specific dispatch arm so kernels the
# host would never auto-select (AVX2 / AES-NI arms on an AVX-512 host)
# are validated end-to-end. Each forced arm is crossed against the
# opposite build with the scalar reference forced, so a
# self-consistent-but-wrong kernel cannot pass. Non-existent
# (hash, arm) pairs are skipped explicitly and audited — never silently
# passed as green.
#
# Interlock-tier axis: ITB_FORCE_INTERLOCK_TIER sweeps the 48-bit
# interlock rank-mask / apply kernel tiers on one canonical hash.
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
# builds compile the knob out entirely. The Go-side hash / interlock
# forcing env vars (ITB_FORCE_HASH_TIER / ITB_FORCE_INTERLOCK_TIER)
# are always-on library behaviour, so every arm consumes them without
# build flags.
CGO_ENABLED=1 go build -o tools/parity/parity-cgo         ./tools/parity
CGO_ENABLED=0 go build -o tools/parity/parity-nocgo       ./tools/parity
CGO_ENABLED=1 CGO_CFLAGS="-DITB_PARITY_TIER_OVERRIDE" \
    go build -o tools/parity/parity-cgo-tiered            ./tools/parity
# Fourth arm: pure-Go pixels AND scalar hash/MAC kernels (-tags noitbasm).
# Used by the KMAC256 MAC section to force tag agreement across the
# vendored AVX-512 Keccak-f[1600] tier and the scalar tier.
CGO_ENABLED=0 go build -tags noitbasm \
    -o tools/parity/parity-nocgo-noasm                    ./tools/parity

# Fixture matrix. Covers sub-pixel (1), single-pixel (6, 7), single-8-pixel
# batch boundary (56), and multi-chunk transitions (65535, 1048576,
# 16777231). 16777231 = 16 MiB + 15 B — one full chunk (DefaultChunkSize
# = 16 MiB) plus a short remainder chunk.
SIZES=(1 6 7 56 1024 65535 1048576 16777231)

# Nonce-width matrix. 128 / 256 / 512 bits map to the 20- / 36- /
# 68-byte per-pixel buf shapes, exercising every specialised
# chain-absorb kernel width.
NONCEBITS=(128 256 512)

WORKDIR="$REPO/tmp/parity"
mkdir -p "$WORKDIR"

# Canonical PRF-grade hash roster. Order matches
# github.com/everanium/itb/hashes.Registry so the sweep visits every
# primitive a §3 asm micro or §4 pixel-kernel change can touch.
HASHES=(areion256 areion512 blake2b256 blake2b512 blake2s blake3 aescmac siphash24 chacha20)

FAIL=0

# ---------------------------------------------------------------------------
# Section 1 — host-tier cross-build matrix × nonce widths.
# ---------------------------------------------------------------------------
for NB in "${NONCEBITS[@]}"; do
    for HASH in "${HASHES[@]}"; do
        PROFILE="parity-${HASH}-v1"
        SEED="$WORKDIR/seed-${HASH}-nb${NB}.blob"

        # Init once per (hash, nonce width) — either arm produces a
        # functionally identical envelope (crypto/rand entropy is the only
        # source of variance and the blob is then read verbatim by every
        # subsequent invocation on either arm). Use the cgo arm arbitrarily.
        ./tools/parity/parity-cgo -mode=init \
            -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB"

        for SIZE in "${SIZES[@]}"; do
            PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
            head -c "$SIZE" /dev/urandom > "$PLAIN"
            PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

            # Direction 1: encrypt=cgo, decrypt=nocgo.
            WIRE1="$WORKDIR/wire-${HASH}-${SIZE}-nb${NB}-cgo.bin"
            BACK1="$WORKDIR/back-${HASH}-${SIZE}-nb${NB}-nocgo.bin"
            ./tools/parity/parity-cgo   -mode=encrypt \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$PLAIN" -out="$WIRE1"
            ./tools/parity/parity-nocgo -mode=decrypt \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$WIRE1" -out="$BACK1"
            BACK1_HASH=$(sha256sum "$BACK1" | awk '{print $1}')
            if [ "$BACK1_HASH" != "$PLAIN_HASH" ]; then
                echo "FAIL: encrypt=cgo decrypt=nocgo hash=$HASH size=$SIZE nb=$NB"
                FAIL=$((FAIL + 1))
            fi

            # Direction 2: encrypt=nocgo, decrypt=cgo.
            WIRE2="$WORKDIR/wire-${HASH}-${SIZE}-nb${NB}-nocgo.bin"
            BACK2="$WORKDIR/back-${HASH}-${SIZE}-nb${NB}-cgo.bin"
            ./tools/parity/parity-nocgo -mode=encrypt \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$PLAIN" -out="$WIRE2"
            ./tools/parity/parity-cgo   -mode=decrypt \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$WIRE2" -out="$BACK2"
            BACK2_HASH=$(sha256sum "$BACK2" | awk '{print $1}')
            if [ "$BACK2_HASH" != "$PLAIN_HASH" ]; then
                echo "FAIL: encrypt=nocgo decrypt=cgo hash=$HASH size=$SIZE nb=$NB"
                FAIL=$((FAIL + 1))
            fi
        done
    done
done

CELLS=$(( ${#NONCEBITS[@]} * ${#HASHES[@]} * ${#SIZES[@]} * 2 ))

# ---------------------------------------------------------------------------
# Section 2 — forced pixel-tier matrix × nonce widths.
# Sweeps ITB_FORCE_PIXEL_TIER=A|B|C on the tiered cgo arm to exercise
# all three C dispatch paths on one host regardless of the host CPU's
# natural tier. Downgrade-only: forcing to B on a Tier C-only host has
# no effect; forcing to A on an actual Tier A host is a no-op vs the
# plain cgo arm and re-runs it as sanity coverage.
# ---------------------------------------------------------------------------
TIER_MATRIX=(A B C)
TIER_CELLS=$(( ${#TIER_MATRIX[@]} * ${#NONCEBITS[@]} * ${#HASHES[@]} * ${#SIZES[@]} * 2 ))

for TIER in "${TIER_MATRIX[@]}"; do
    for NB in "${NONCEBITS[@]}"; do
        for HASH in "${HASHES[@]}"; do
            PROFILE="parity-${HASH}-v1"
            SEED="$WORKDIR/seed-${HASH}-nb${NB}.blob"

            for SIZE in "${SIZES[@]}"; do
                PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
                PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

                WIRE1="$WORKDIR/wire-${HASH}-${SIZE}-nb${NB}-tier${TIER}.bin"
                BACK1="$WORKDIR/back-${HASH}-${SIZE}-nb${NB}-tier${TIER}-nocgo.bin"
                ITB_FORCE_PIXEL_TIER="$TIER" ./tools/parity/parity-cgo-tiered -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE1"
                ./tools/parity/parity-nocgo -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE1" -out="$BACK1"
                if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: tier=$TIER encrypt=cgo decrypt=nocgo hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi

                WIRE2="$WORKDIR/wire-${HASH}-${SIZE}-nb${NB}-nocgo-vs-tier${TIER}.bin"
                BACK2="$WORKDIR/back-${HASH}-${SIZE}-nb${NB}-nocgo-vs-tier${TIER}-cgo.bin"
                ./tools/parity/parity-nocgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE2"
                ITB_FORCE_PIXEL_TIER="$TIER" ./tools/parity/parity-cgo-tiered -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE2" -out="$BACK2"
                if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: tier=$TIER encrypt=nocgo decrypt=cgo hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
            done
        done
    done
done

# ---------------------------------------------------------------------------
# Section 3 — hash-arm sweep × nonce widths.
# For every applicable (hash, arm) pair the forced arm runs on one
# build against the scalar-forced opposite build, both directions —
# cross-arm AND cross-build, so the forced kernel's output is always
# checked against the independent scalar reference implementation.
# Non-existent pairs are skipped with an audit line.
# ---------------------------------------------------------------------------
HASHARMS=(avx512 avx2 aesni scalar)

# arm_applicable HASH ARM — succeeds when the (hash, arm) pair names a
# real dispatch arm. Skip rules:
#   * aesni: only the AES-based primitives carry AES-NI XMM chain
#     kernels (areion256 / areion512 / aescmac).
#   * avx2: aescmac deliberately has no YMM tier (see
#     hashes/internal/aescmacasm/aescmacasm_amd64.go); areion256 /
#     areion512 run their VAES-on-YMM general-chain arm
#     (Areion*Permutex4Avx2) rather than width-specialised kernels —
#     a real shipped arm (AMD Zen 3 class), so the pair is applicable.
#   * avx512 / scalar: every primitive has both.
arm_applicable() {
    case "$2" in
        avx512|scalar) return 0 ;;
        avx2)
            case "$1" in
                aescmac) return 1 ;;
                *) return 0 ;;
            esac ;;
        aesni)
            case "$1" in
                areion256|areion512|aescmac) return 0 ;;
                *) return 1 ;;
            esac ;;
    esac
    return 1
}

ARM_CELLS=0
SKIPPED_PAIRS=0
SKIPPED_CELLS=0
CELLS_PER_PAIR=$(( ${#NONCEBITS[@]} * ${#SIZES[@]} * 2 ))

for ARM in "${HASHARMS[@]}"; do
    for HASH in "${HASHES[@]}"; do
        if ! arm_applicable "$HASH" "$ARM"; then
            echo "SKIP: hash=$HASH arm=$ARM (no such arm; $CELLS_PER_PAIR cells skipped)"
            SKIPPED_PAIRS=$((SKIPPED_PAIRS + 1))
            SKIPPED_CELLS=$((SKIPPED_CELLS + CELLS_PER_PAIR))
            continue
        fi
        PROFILE="parity-${HASH}-v1"

        for NB in "${NONCEBITS[@]}"; do
            SEED="$WORKDIR/seed-${HASH}-nb${NB}.blob"

            for SIZE in "${SIZES[@]}"; do
                PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
                PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

                # Direction 1: encrypt=cgo+forced arm, decrypt=nocgo+scalar.
                WIRE1="$WORKDIR/wire-${HASH}-${SIZE}-nb${NB}-arm${ARM}.bin"
                BACK1="$WORKDIR/back-${HASH}-${SIZE}-nb${NB}-arm${ARM}-nocgo.bin"
                ITB_FORCE_HASH_TIER="$ARM" ./tools/parity/parity-cgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE1"
                ITB_FORCE_HASH_TIER=scalar ./tools/parity/parity-nocgo -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE1" -out="$BACK1"
                if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: arm=$ARM encrypt=cgo decrypt=nocgo-scalar hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
                ARM_CELLS=$((ARM_CELLS + 1))

                # Direction 2: encrypt=nocgo+scalar, decrypt=cgo+forced arm.
                WIRE2="$WORKDIR/wire-${HASH}-${SIZE}-nb${NB}-scalar-vs-arm${ARM}.bin"
                BACK2="$WORKDIR/back-${HASH}-${SIZE}-nb${NB}-arm${ARM}-cgo.bin"
                ITB_FORCE_HASH_TIER=scalar ./tools/parity/parity-nocgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE2"
                ITB_FORCE_HASH_TIER="$ARM" ./tools/parity/parity-cgo -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE2" -out="$BACK2"
                if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: arm=$ARM encrypt=nocgo-scalar decrypt=cgo hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
                ARM_CELLS=$((ARM_CELLS + 1))
            done
        done
    done
done

# ---------------------------------------------------------------------------
# Section 4 — interlock-tier sweep × nonce widths, canonical hash.
# Forces the 48-bit interlock rank-mask tier on the cgo arm against the
# scalar-forced nocgo arm, both directions. Expand ILTIERS to
# (avx512 avx2 scalar) when Phase B.5's interlock AVX2 kernel lands —
# currently 2 tiers × 48 = 96 cells, will grow to 3 tiers × 48 = 144
# cells.
# ---------------------------------------------------------------------------
ILTIERS=(avx512 scalar)
ILHASH="areion512"
ILPROFILE="parity-${ILHASH}-v1"
IL_CELLS=$(( ${#ILTIERS[@]} * ${#NONCEBITS[@]} * ${#SIZES[@]} * 2 ))

for ILT in "${ILTIERS[@]}"; do
    for NB in "${NONCEBITS[@]}"; do
        SEED="$WORKDIR/seed-${ILHASH}-nb${NB}.blob"

        for SIZE in "${SIZES[@]}"; do
            PLAIN="$WORKDIR/plain-${ILHASH}-${SIZE}.bin"
            PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

            WIRE1="$WORKDIR/wire-il-${SIZE}-nb${NB}-${ILT}.bin"
            BACK1="$WORKDIR/back-il-${SIZE}-nb${NB}-${ILT}-nocgo.bin"
            ITB_FORCE_INTERLOCK_TIER="$ILT" ./tools/parity/parity-cgo -mode=encrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$PLAIN" -out="$WIRE1"
            ITB_FORCE_INTERLOCK_TIER=scalar ./tools/parity/parity-nocgo -mode=decrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$WIRE1" -out="$BACK1"
            if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                echo "FAIL: iltier=$ILT encrypt=cgo decrypt=nocgo-scalar size=$SIZE nb=$NB"
                FAIL=$((FAIL + 1))
            fi

            WIRE2="$WORKDIR/wire-il-${SIZE}-nb${NB}-scalar-vs-${ILT}.bin"
            BACK2="$WORKDIR/back-il-${SIZE}-nb${NB}-${ILT}-cgo.bin"
            ITB_FORCE_INTERLOCK_TIER=scalar ./tools/parity/parity-nocgo -mode=encrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$PLAIN" -out="$WIRE2"
            ITB_FORCE_INTERLOCK_TIER="$ILT" ./tools/parity/parity-cgo -mode=decrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$WIRE2" -out="$BACK2"
            if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                echo "FAIL: iltier=$ILT encrypt=nocgo-scalar decrypt=cgo size=$SIZE nb=$NB"
                FAIL=$((FAIL + 1))
            fi
        done
    done
done

# ---------------------------------------------------------------------------
# Section 5 — KMAC256 MAC Authenticated matrix. One canonical inner
# hash (areion512) under the parity-mac-* profile (MAC pinned to
# kmac256); two arm pairings per size:
#   (1) cgo (AVX-512 Keccak tier on capable hosts) <-> nocgo-noasm
#       (scalar tier) — forces asm/scalar tag agreement both ways;
#   (2) cgo <-> nocgo (both natural-tier) — MAC'd wire across the
#       C / pure-Go pixel arms.
# Runs at the default nonce width.
# ---------------------------------------------------------------------------
MAC_HASH="areion512"
MAC_PROFILE="parity-mac-${MAC_HASH}-v1"
MAC_SEED="$WORKDIR/seed-mac-${MAC_HASH}.blob"
MAC_CELLS=$(( ${#SIZES[@]} * 4 ))

./tools/parity/parity-cgo -mode=init \
    -profile="$MAC_PROFILE" -hash="$MAC_HASH" -seed-file="$MAC_SEED"

for SIZE in "${SIZES[@]}"; do
    PLAIN="$WORKDIR/plain-mac-${SIZE}.bin"
    head -c "$SIZE" /dev/urandom > "$PLAIN"
    PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

    for PAIR in "parity-cgo:parity-nocgo-noasm" "parity-cgo:parity-nocgo"; do
        ENC_ARM="${PAIR%%:*}"
        DEC_ARM="${PAIR##*:}"

        WIRE1="$WORKDIR/wire-mac-${SIZE}-${ENC_ARM}.bin"
        BACK1="$WORKDIR/back-mac-${SIZE}-${DEC_ARM}.bin"
        ./tools/parity/$ENC_ARM -mode=encrypt \
            -profile="$MAC_PROFILE" -hash="$MAC_HASH" -seed-file="$MAC_SEED" \
            -in="$PLAIN" -out="$WIRE1"
        ./tools/parity/$DEC_ARM -mode=decrypt \
            -profile="$MAC_PROFILE" -hash="$MAC_HASH" -seed-file="$MAC_SEED" \
            -in="$WIRE1" -out="$BACK1"
        if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
            echo "FAIL: kmac encrypt=$ENC_ARM decrypt=$DEC_ARM size=$SIZE"
            FAIL=$((FAIL + 1))
        fi

        WIRE2="$WORKDIR/wire-mac-${SIZE}-${DEC_ARM}.bin"
        BACK2="$WORKDIR/back-mac-${SIZE}-${ENC_ARM}.bin"
        ./tools/parity/$DEC_ARM -mode=encrypt \
            -profile="$MAC_PROFILE" -hash="$MAC_HASH" -seed-file="$MAC_SEED" \
            -in="$PLAIN" -out="$WIRE2"
        ./tools/parity/$ENC_ARM -mode=decrypt \
            -profile="$MAC_PROFILE" -hash="$MAC_HASH" -seed-file="$MAC_SEED" \
            -in="$WIRE2" -out="$BACK2"
        if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
            echo "FAIL: kmac encrypt=$DEC_ARM decrypt=$ENC_ARM size=$SIZE"
            FAIL=$((FAIL + 1))
        fi
    done
done

echo "---"
echo "skipped: $SKIPPED_PAIRS (hash, arm) pairs / $SKIPPED_CELLS cells (no such arm — see SKIP lines)"
TOTAL=$(( CELLS + TIER_CELLS + ARM_CELLS + IL_CELLS + MAC_CELLS ))
if [ "$FAIL" -eq 0 ]; then
    echo "PASS: $CELLS host-tier + $TIER_CELLS forced-pixel-tier + $ARM_CELLS forced-hash-arm + $IL_CELLS interlock-tier + $MAC_CELLS kmac-mac = $TOTAL cells"
    exit 0
fi
echo "FAIL: $FAIL of $TOTAL cells failed"
exit 1
