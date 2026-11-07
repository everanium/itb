#!/usr/bin/env bash
# Cross-build C ↔ pure-Go pixel parity harness.
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
# Fixture matrix reuses the compact edge-case set:
#   1  56  1024  65535  524288  1048576
# — bytes that exercise the sub-pixel (1), single-8-pixel-batch (56),
# tier-1 microBatch (1024), non-8-multiple / tier-2 microBatch transition
# (65535), 512 KiB (524288), and 1 MiB multi-microBatch (1048576) handoffs
# without multi-gigabyte disk write amplification. (Sub-chunk and single-chunk
# boundaries 6, 20, 21, 22, 41, 42, 43, 63, 64 are covered by Section 4b and
# tools/parity selftest).
#
# Nonce-width axis: the nonce width determines the per-pixel buf shape
# the inner hash absorbs (nonce bytes + 4 → 20 / 36 / 68 bytes, the
# same size the wire header happens to be), so the
# 128 / 256 / 512 sweep drives every fused cascade kernel shape through
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
# passed as green. The pseudo-arms avx512x4, vaesavx2x4, avx2x4, vexx4 and
# aesnix4 (the ITB_FORCE_HASH_TIER token plus ITB_FORCE_CHAINHASH_X4=1)
# pin the four-lane fused ChainHash kernels of a tier whose arm
# otherwise runs the eight-lane kernels, so both fused arms of every
# tier are crossed against the scalar reference.
#
# Interlock-tier axis: ITB_FORCE_INTERLOCK_TIER sweeps the 48-bit
# interlock rank-mask / apply kernel tiers on two lockSeed widths
# (areion512 for the x4 fill, aesitb128 for the batch-16 fill that
# reaches the 16-lane unrank pass), and the 168-bit interlock tiers on
# areion512 and blake2b512 (Section 4b).
#
# Working directory defaults to ${TMPDIR:-/tmp}/itb-parity (overridable via
# PARITY_WORK_DIR) so transient ciphertexts live in tmpfs rather than wearing
# the repository's backing SSD, and nothing lands in the tracked working set.

set -eu
set -o pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
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
CGO_ENABLED=1 go build -o tools/parity/parity             ./tools/parity
CGO_ENABLED=1 go build -o tools/parity/parity-cgo         ./tools/parity
CGO_ENABLED=0 go build -o tools/parity/parity-nocgo       ./tools/parity
CGO_ENABLED=1 CGO_CFLAGS="-DITB_PARITY_TIER_OVERRIDE" \
    go build -o tools/parity/parity-cgo-tiered            ./tools/parity
# Fourth arm: pure-Go pixels AND scalar hash/MAC kernels (-tags noitbasm).
# Used by the KMAC256 MAC section to force tag agreement across the
# vendored AVX-512 Keccak-f[1600] tier and the scalar tier.
CGO_ENABLED=0 go build -tags noitbasm \
    -o tools/parity/parity-nocgo-noasm                    ./tools/parity

# Fixture matrix. Covers sub-pixel (1), single-8-pixel batch boundary (56),
# tier-1 microBatch (1024), odd 64 KiB - 1 tail & tier-2 microBatch transition
# (65535), 512 KiB (524288), and 1 MiB multi-microBatch (1048576).
SIZES=(1 56 1024 65535 524288 1048576)

# Nonce-width matrix. 128 / 256 / 512 bits map to the 20- / 36- /
# 68-byte per-pixel buf shapes, exercising every specialised
# fused cascade kernel shape.
NONCEBITS=(128 256 512)

WORKDIR="${PARITY_WORK_DIR:-${TMPDIR:-/tmp}/itb-parity}"
mkdir -p "$WORKDIR"
WIRE1="$WORKDIR/wire1.bin"
BACK1="$WORKDIR/back1.bin"
WIRE2="$WORKDIR/wire2.bin"
BACK2="$WORKDIR/back2.bin"

# Canonical PRF-grade hash roster. Order matches
# github.com/everanium/itb/hashes.Registry so the sweep visits every
# primitive a §3 asm micro or §4 pixel-kernel change can touch.
HASHES=(aesitb128 areion256 areion512 blake2b256 blake2b512 blake2s blake3 aescmac siphash24 chacha20)

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
            if [ ! -f "$PLAIN" ]; then
                head -c "$SIZE" /dev/urandom > "$PLAIN"
            fi
            PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

            # Direction 1: encrypt=cgo, decrypt=nocgo.
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
# Sweeps ITB_FORCE_PIXEL_TIER on the tiered cgo arm to exercise every C
# dispatch path on one host regardless of the host CPU's natural tier.
# Each tag simulates a real fleet CPU class via a feature-suppression
# mask rather than capping a ladder, so leftover sub-batch pixels route
# exactly as they would on the simulated silicon:
#   A        — full AVX-512 + GFNI ZMM (Zen 5 / Rocket Lake)
#   A_NOGFNI — AVX-512 F+BW+VL, GFNI suppressed (Cascade Lake); 4-7-pixel
#              leftovers fall to the B_NOGFNI 4-pixel path, as on silicon
#   B        — AVX2 + GFNI YMM (AVX-512 suppressed)
#   B_NOGFNI — AVX2 only, GFNI suppressed (Zen 3 / Haswell)
#   C        — plain-C path (all SIMD tiers suppressed)
# Downgrade-only: a forced tag can only remove features the host has, so
# forcing A_NOGFNI on a GFNI-less host is a no-op and re-runs coverage.
# ---------------------------------------------------------------------------
TIER_MATRIX=(A A_NOGFNI B B_NOGFNI C)
TIER_CELLS=$(( ${#TIER_MATRIX[@]} * ${#NONCEBITS[@]} * ${#HASHES[@]} * ${#SIZES[@]} * 2 ))

for TIER in "${TIER_MATRIX[@]}"; do
    for NB in "${NONCEBITS[@]}"; do
        for HASH in "${HASHES[@]}"; do
            PROFILE="parity-${HASH}-v1"
            SEED="$WORKDIR/seed-${HASH}-nb${NB}.blob"

            for SIZE in "${SIZES[@]}"; do
                PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
                PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

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
HASHARMS=(avx512 avx512x4 vaesavx2 vaesavx2x4 avx2 avx2x4 vex vexx4 aesni aesnix4 gpr scalar)

# arm_env ARM — prints the forcing environment of an arm: the
# ITB_FORCE_HASH_TIER token, plus ITB_FORCE_CHAINHASH_X4=1 for the x4
# pseudo-arms (the tier with its eight-lane fused ChainHash arm
# disarmed).
arm_env() {
    case "$1" in
        *x4) echo "ITB_FORCE_HASH_TIER=${1%x4} ITB_FORCE_CHAINHASH_X4=1" ;;
        *) echo "ITB_FORCE_HASH_TIER=$1" ;;
    esac
}

# arm_applicable HASH ARM — succeeds when the (hash, arm) pair names a
# real dispatch arm. Skip rules:
#   * avx512x4: every shipped primitive carries eight-lane fused
#     ChainHash kernels (x8 at the nonce-buf shapes) on its AVX-512
#     tier — aesitb128 (internal/aesitbasm), areion256 / areion512
#     (internal/areionasm), blake2b256 / blake2b512
#     (hashes/internal/blake2basm), blake2s (hashes/internal/blake2sasm),
#     blake3 (hashes/internal/blake3asm), aescmac
#     (hashes/internal/aescmacasm), siphash24
#     (hashes/internal/siphashasm) and chacha20
#     (hashes/internal/chacha20asm) — so the pseudo-arm applies to all.
#   * vaesavx2x4 / avx2x4 / aesnix4: every tier below AVX-512 carries an
#     eight-lane fused ChainHash arm of its own (eight-lane kernels, or
#     two four-lane calls where the register file holds no eight-lane
#     plan), so each x4 pseudo-arm applies exactly where its tier does.
#   * vex / vexx4: aesitb128, areion256, areion512 and aescmac carry VEX
#     XMM fused cascade kernels (four and eight lanes); every other
#     primitive is skipped.
#   * aesni: only the AES-based primitives carry AES-NI XMM fused
#     cascade kernels (aesitb128 / areion256 / areion512 / aescmac).
#   * vaesavx2: aesitb128, areion256, areion512 and aescmac carry VAES
#     YMM fused cascade kernels; every other primitive is skipped.
#   * avx2: aesitb128 and aescmac map the avx2 token to their VAES YMM
#     tier; areion256 / areion512 run their VAES-on-YMM batched
#     permutation with the fused cascade off (the arms-only probe on
#     the AMD Zen 3 class), so the pair is applicable; blake2b256 /
#     blake2b512, blake2s, blake3 and chacha20 run their AVX2 fused
#     cascade kernels.
#   * gpr: blake2b256 / blake2b512, blake2s, blake3, siphash24 and
#     chacha20 carry single-lane general-purpose-register kernels as the
#     arm below their SIMD tiers; the token pins them as the only arm.
#   * avx512 / scalar: every primitive has both.
arm_applicable() {
    case "$2" in
        avx512|scalar|avx2|avx2x4) return 0 ;;
        avx512x4) return 0 ;;
        vex|vexx4)
            case "$1" in
                aesitb128|areion256|areion512|aescmac) return 0 ;;
                *) return 1 ;;
            esac ;;
        vaesavx2x4|aesnix4)
            case "$1" in
                aesitb128|areion256|areion512|aescmac) return 0 ;;
                *) return 1 ;;
            esac ;;
        vaesavx2)
            case "$1" in
                aesitb128|areion256|areion512|aescmac) return 0 ;;
                *) return 1 ;;
            esac ;;
        aesni)
            case "$1" in
                aesitb128|areion256|areion512|aescmac) return 0 ;;
                *) return 1 ;;
            esac ;;
        gpr)
            case "$1" in
                blake2b256|blake2b512|blake2s|blake3|siphash24|chacha20) return 0 ;;
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
                env $(arm_env "$ARM") ./tools/parity/parity-cgo -mode=encrypt \
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
                ITB_FORCE_HASH_TIER=scalar ./tools/parity/parity-nocgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE2"
                env $(arm_env "$ARM") ./tools/parity/parity-cgo -mode=decrypt \
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
# Section 4 — interlock-tier sweep × nonce widths, two lockSeed widths.
# Forces the 48-bit interlock rank-mask tier on the cgo arm against the
# scalar-forced nocgo arm, both directions. 8 tiers × 2 hashes × 48 =
# 768 cells. areion512 drives the 512-bit lockSeed (x4 fill, 8-lane
# unrank passes); aesitb128 drives the 128-bit lockSeed whose batch-16
# fill runs the 16-chunk unrank pass — the only shape that reaches the
# 16-lane AVX-512 kernel. avx512x8 keeps the AVX-512 kernel but runs
# each 16-chunk batch as two 8-lane passes, so the x8×2 wire geometry
# is validated against the 16-lane pass on the same host.
# ---------------------------------------------------------------------------
ILTIERS=(avx512 avx512x8 avx2 bmi2 sve2 sve neon scalar)
ILHASHES=(aesitb128 areion512)
IL_CELLS=$(( ${#ILTIERS[@]} * ${#ILHASHES[@]} * ${#NONCEBITS[@]} * ${#SIZES[@]} * 2 ))

for ILHASH in "${ILHASHES[@]}"; do
ILPROFILE="parity-${ILHASH}-v1"
for ILT in "${ILTIERS[@]}"; do
    for NB in "${NONCEBITS[@]}"; do
        SEED="$WORKDIR/seed-${ILHASH}-nb${NB}.blob"

        for SIZE in "${SIZES[@]}"; do
            PLAIN="$WORKDIR/plain-${ILHASH}-${SIZE}.bin"
            PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

            ITB_FORCE_INTERLOCK_TIER="$ILT" ./tools/parity/parity-cgo -mode=encrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$PLAIN" -out="$WIRE1"
            ITB_FORCE_INTERLOCK_TIER=scalar ./tools/parity/parity-nocgo -mode=decrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$WIRE1" -out="$BACK1"
            if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                echo "FAIL: iltier=$ILT hash=$ILHASH encrypt=cgo decrypt=nocgo-scalar size=$SIZE nb=$NB"
                FAIL=$((FAIL + 1))
            fi

            ITB_FORCE_INTERLOCK_TIER=scalar ./tools/parity/parity-nocgo -mode=encrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$PLAIN" -out="$WIRE2"
            ITB_FORCE_INTERLOCK_TIER="$ILT" ./tools/parity/parity-cgo -mode=decrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" \
                -in="$WIRE2" -out="$BACK2"
            if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                echo "FAIL: iltier=$ILT hash=$ILHASH encrypt=nocgo-scalar decrypt=cgo size=$SIZE nb=$NB"
                FAIL=$((FAIL + 1))
            fi
        done
    done
done
done

# ---------------------------------------------------------------------------
# Section 4b — 168-bit interlock-tier sweep × nonce widths on 512-bit hashes.
# Forces the 168-bit interlock rank-mask / chunk168 tier on the cgo arm
# against the scalar-forced nocgo arm, both directions, across areion512,
# blake2b512, and mixed 512-bit constellations (areion512,blake2b512,areion512),
# including non-21-byte-multiple tail sizes (1, 6, 20, 21, 22, 41, 42, 43,
# 63, 64, 1024).
# ---------------------------------------------------------------------------
IL168HASHES=(areion512 blake2b512)
IL168_TAIL_SIZES=(1 6 20 21 22 41 42 43 63 64 1024)
IL168_TAIL_SPECS=("areion512:areion512" "blake2b512:blake2b512" "mixed512:areion512,blake2b512,areion512")
IL168_CELLS=$(( ${#ILTIERS[@]} * ${#IL168HASHES[@]} * ${#NONCEBITS[@]} * ${#SIZES[@]} * 2 + ${#ILTIERS[@]} * ${#IL168_TAIL_SPECS[@]} * ${#IL168_TAIL_SIZES[@]} * 2 ))

for ILHASH in "${IL168HASHES[@]}"; do
    ILPROFILE="parity-${ILHASH}-v1"
    for NB in "${NONCEBITS[@]}"; do
        SEED="$WORKDIR/seed-${ILHASH}-il168-nb${NB}.blob"
        ./tools/parity/parity-cgo -mode=init \
            -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" -interlock=168
    done
    for ILT in "${ILTIERS[@]}"; do
        for NB in "${NONCEBITS[@]}"; do
            SEED="$WORKDIR/seed-${ILHASH}-il168-nb${NB}.blob"

            for SIZE in "${SIZES[@]}"; do
                PLAIN="$WORKDIR/plain-${ILHASH}-${SIZE}.bin"
                PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

                ITB_FORCE_INTERLOCK_TIER="$ILT" ./tools/parity/parity-cgo -mode=encrypt \
                    -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" -interlock=168 \
                    -in="$PLAIN" -out="$WIRE1"
                ITB_FORCE_INTERLOCK_TIER=scalar ./tools/parity/parity-nocgo -mode=decrypt \
                    -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" -interlock=168 \
                    -in="$WIRE1" -out="$BACK1"
                if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: il168 iltier=$ILT hash=$ILHASH encrypt=cgo decrypt=nocgo-scalar size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi

                ITB_FORCE_INTERLOCK_TIER=scalar ./tools/parity/parity-nocgo -mode=encrypt \
                    -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" -interlock=168 \
                    -in="$PLAIN" -out="$WIRE2"
                ITB_FORCE_INTERLOCK_TIER="$ILT" ./tools/parity/parity-cgo -mode=decrypt \
                    -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits="$NB" -interlock=168 \
                    -in="$WIRE2" -out="$BACK2"
                if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: il168 iltier=$ILT hash=$ILHASH encrypt=nocgo-scalar decrypt=cgo size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
            done
        done
    done
done

for SPEC in "${IL168_TAIL_SPECS[@]}"; do
    TAG="${SPEC%%:*}"
    ILHASH="${SPEC#*:}"
    ILPROFILE="parity-${TAG}-il168-v1"
    SEED="$WORKDIR/seed-${TAG}-il168-tail.blob"
    ./tools/parity/parity-cgo -mode=init \
        -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits=512 -interlock=168

    for SIZE in "${IL168_TAIL_SIZES[@]}"; do
        PLAIN="$WORKDIR/plain-il168-tail-${SIZE}.bin"
        if [ ! -f "$PLAIN" ]; then
            head -c "$SIZE" /dev/urandom > "$PLAIN"
        fi
        PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

        for ILT in "${ILTIERS[@]}"; do
            ITB_FORCE_INTERLOCK_TIER="$ILT" ./tools/parity/parity-cgo -mode=encrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits=512 -interlock=168 \
                -in="$PLAIN" -out="$WIRE1"
            ITB_FORCE_INTERLOCK_TIER=scalar ./tools/parity/parity-nocgo -mode=decrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits=512 -interlock=168 \
                -in="$WIRE1" -out="$BACK1"
            if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                echo "FAIL: il168-tail iltier=$ILT spec=$TAG encrypt=cgo decrypt=nocgo-scalar size=$SIZE"
                FAIL=$((FAIL + 1))
            fi

            ITB_FORCE_INTERLOCK_TIER=scalar ./tools/parity/parity-nocgo -mode=encrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits=512 -interlock=168 \
                -in="$PLAIN" -out="$WIRE2"
            ITB_FORCE_INTERLOCK_TIER="$ILT" ./tools/parity/parity-cgo -mode=decrypt \
                -profile="$ILPROFILE" -hash="$ILHASH" -seed-file="$SEED" -nonce-bits=512 -interlock=168 \
                -in="$WIRE2" -out="$BACK2"
            if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                echo "FAIL: il168-tail iltier=$ILT spec=$TAG encrypt=nocgo-scalar decrypt=cgo size=$SIZE"
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

# ---------------------------------------------------------------------------
# Section 6 — batch-16 interlock PRF fill dispatch matrix × nonce widths.
# Exercises the fill-ladder rung disarm knobs and the fill-tier axis
# separately from the ChainHash arm sweep of Section 3, so every
# dispatch state of the Interlocked Barrier's batch-16 fill hook is
# reached end-to-end. Two primitives cover the two hook families the
# ladder resolves against:
#   * aesitb128  — AES-family fill (aesni / vex / vaesavx2 / avx512 tiers)
#   * blake2b512 — ARX-family fill (gpr / avx2 / avx512 tiers)
# Both sit on the widened batch-32 rung at width 512, so the whole
# four-rung ladder (batch-32 top → batch-16 → four-lane → single-lane)
# is reachable through the four disarm knobs.
#
# Rung sweep: for every rung disarm knob and every applicable tier
# token, the forced side runs on the cgo build against the
# scalar-forced (HASH+PRF-FILL) opposite build, both directions.
# ---------------------------------------------------------------------------
FILLHASHES=(aesitb128 blake2b512)
FILLRUNGS=(seq x1 x4 x16)

# fill_tier_applicable HASH TIER — succeeds when the (hash, PRF-fill
# tier) pair names a real batch-16 fill kernel on this build.
#   * avx512 / scalar — every primitive has both
#   * vaesavx2 / vex / aesni — AES-family only (aesitb128 / areion256 /
#     areion512 / aescmac)
#   * avx2 — non-AES ARX family (blake2b / blake2s / blake3 /
#     siphash24 / chacha20)
#   * gpr — ARX family (blake2b / blake2s / blake3 / siphash24 /
#     chacha20), single-lane general-purpose-register kernels
#   * neon — arm64 only, all primitives (skipped here — the amd64
#     forcetier init rejects the token with a stderr note)
fill_tier_applicable() {
    case "$2" in
        avx512|scalar) return 0 ;;
        vaesavx2|vex|aesni)
            case "$1" in
                aesitb128|areion256|areion512|aescmac) return 0 ;;
                *) return 1 ;;
            esac ;;
        avx2|gpr)
            case "$1" in
                blake2b256|blake2b512|blake2s|blake3|siphash24|chacha20) return 0 ;;
                *) return 1 ;;
            esac ;;
    esac
    return 1
}

# rung_env RUNG — prints the environment for a fill-rung disarm knob.
rung_env() {
    case "$1" in
        seq) echo "ITB_FORCE_INTERLOCK_PRF_FILL_SEQ=1" ;;
        x1)  echo "ITB_FORCE_INTERLOCK_PRF_FILL_X1=1"  ;;
        x4)  echo "ITB_FORCE_INTERLOCK_PRF_FILL_X4=1"  ;;
        x16) echo "ITB_FORCE_INTERLOCK_PRF_FILL_X16=1" ;;
    esac
}

FILL_CELLS=0
FILL_SKIPPED_PAIRS=0
FILL_SKIPPED_CELLS=0

# Sub-section 6a — fill-rung disarm sweep.
for RUNG in "${FILLRUNGS[@]}"; do
    for HASH in "${FILLHASHES[@]}"; do
        PROFILE="parity-${HASH}-v1"
        for NB in "${NONCEBITS[@]}"; do
            SEED="$WORKDIR/seed-${HASH}-nb${NB}.blob"

            for SIZE in "${SIZES[@]}"; do
                PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
                PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

                # Direction 1: encrypt cgo + rung disarmed, decrypt nocgo + scalar.
                env $(rung_env "$RUNG") ./tools/parity/parity-cgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE1"
                ITB_FORCE_HASH_TIER=scalar ITB_FORCE_INTERLOCK_PRF_FILL_TIER=scalar \
                    ./tools/parity/parity-nocgo -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE1" -out="$BACK1"
                if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: rung=$RUNG encrypt=cgo decrypt=nocgo-scalar hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
                FILL_CELLS=$((FILL_CELLS + 1))

                # Direction 2: encrypt nocgo + scalar, decrypt cgo + rung disarmed.
                ITB_FORCE_HASH_TIER=scalar ITB_FORCE_INTERLOCK_PRF_FILL_TIER=scalar \
                    ./tools/parity/parity-nocgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE2"
                env $(rung_env "$RUNG") ./tools/parity/parity-cgo -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE2" -out="$BACK2"
                if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: rung=$RUNG encrypt=nocgo-scalar decrypt=cgo hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
                FILL_CELLS=$((FILL_CELLS + 1))
            done
        done
    done
done

# Sub-section 6b — PRF-fill tier sweep.
FILLTIERS=(avx512 vaesavx2 avx2 vex aesni gpr scalar)
FILL_CELLS_PER_PAIR=$(( ${#NONCEBITS[@]} * ${#SIZES[@]} * 2 ))

for FT in "${FILLTIERS[@]}"; do
    for HASH in "${FILLHASHES[@]}"; do
        if ! fill_tier_applicable "$HASH" "$FT"; then
            echo "SKIP: hash=$HASH fill-tier=$FT (no such kernel; $FILL_CELLS_PER_PAIR cells skipped)"
            FILL_SKIPPED_PAIRS=$((FILL_SKIPPED_PAIRS + 1))
            FILL_SKIPPED_CELLS=$((FILL_SKIPPED_CELLS + FILL_CELLS_PER_PAIR))
            continue
        fi
        PROFILE="parity-${HASH}-v1"

        for NB in "${NONCEBITS[@]}"; do
            SEED="$WORKDIR/seed-${HASH}-nb${NB}.blob"

            for SIZE in "${SIZES[@]}"; do
                PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
                PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

                # Direction 1: encrypt cgo + forced fill-tier, decrypt nocgo + scalar.
                ITB_FORCE_INTERLOCK_PRF_FILL_TIER="$FT" ./tools/parity/parity-cgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE1"
                ITB_FORCE_HASH_TIER=scalar ITB_FORCE_INTERLOCK_PRF_FILL_TIER=scalar \
                    ./tools/parity/parity-nocgo -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE1" -out="$BACK1"
                if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: fill-tier=$FT encrypt=cgo decrypt=nocgo-scalar hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
                FILL_CELLS=$((FILL_CELLS + 1))

                # Direction 2: encrypt nocgo + scalar, decrypt cgo + forced fill-tier.
                ITB_FORCE_HASH_TIER=scalar ITB_FORCE_INTERLOCK_PRF_FILL_TIER=scalar \
                    ./tools/parity/parity-nocgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE2"
                ITB_FORCE_INTERLOCK_PRF_FILL_TIER="$FT" ./tools/parity/parity-cgo -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE2" -out="$BACK2"
                if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: fill-tier=$FT encrypt=nocgo-scalar decrypt=cgo hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
                FILL_CELLS=$((FILL_CELLS + 1))
            done
        done
    done
done

# ---------------------------------------------------------------------------
# Section 7 — Mode 3 (Gauss-Posit) cross-build & cross-tier matrix.
# Exercises the 56x28 = 1568-pixel (6272-byte) Posit(16,1)/Quire(256)
# container floor across all three hash widths (aesitb128, areion256,
# areion512), both initialization paths (-container-mode=3 via Opts.Mode=3
# and ITB_CONTAINER_MODE=3 environment variable), all five C pixel tiers
# (A / A_NOGFNI / B / B_NOGFNI / C) against pure-Go scalar, 168-bit
# interlock on 512-bit primitives, and KMAC256 MAC authentication across
# parity-cgo <-> parity-nocgo-noasm.
# Uses the full SIZES ladder (1 56 1024 65535 524288 1048576) so both the
# 56x28 floor (sizes <= 1024) and the above-floor multi-microBatch regimes
# are verified end-to-end.
# ---------------------------------------------------------------------------
M3_SIZES=("${SIZES[@]}")
M3_CELLS=0

# Sub-section 7a — 3 hash widths × 3 nonce widths × 5 C pixel tiers vs scalar,
# testing both -container-mode=3 (Opts.Mode=3) and ITB_CONTAINER_MODE=3 env.
M3_SPECS=(
    "aesitb128:flag"
    "areion256:env"
    "areion512:flag"
    "areion512:env"
)

for SPEC in "${M3_SPECS[@]}"; do
    HASH="${SPEC%%:*}"
    INIT_VIA="${SPEC##*:}"
    PROFILE="parity-${HASH}-v1"

    for NB in "${NONCEBITS[@]}"; do
        SEED="$WORKDIR/seed-m3-${HASH}-${INIT_VIA}-nb${NB}.blob"
        if [ "$INIT_VIA" = "env" ]; then
            ITB_CONTAINER_MODE=3 ./tools/parity/parity-cgo -mode=init \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB"
        else
            ./tools/parity/parity-cgo -mode=init \
                -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" -container-mode=3
        fi
        WANT_FLOOR=$(( 6272 + 32 + 4 + NB / 8 ))

        for TIER in "${TIER_MATRIX[@]}"; do
            for SIZE in "${M3_SIZES[@]}"; do
                PLAIN="$WORKDIR/plain-${HASH}-${SIZE}.bin"
                PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

                # Direction 1: encrypt cgo-tiered, decrypt nocgo scalar (with ITB_CONTAINER_MODE unset).
                ITB_FORCE_PIXEL_TIER="$TIER" ./tools/parity/parity-cgo-tiered -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE1"
                if [ "$SIZE" -le 1024 ]; then
                    GOT_LEN=$(wc -c < "$WIRE1" | tr -d ' ')
                    if [ "$GOT_LEN" -ne "$WANT_FLOOR" ]; then
                        echo "FAIL: mode3 wire floor len=$GOT_LEN want=$WANT_FLOOR hash=$HASH via=$INIT_VIA size=$SIZE nb=$NB"
                        FAIL=$((FAIL + 1))
                    fi
                fi
                ITB_FORCE_HASH_TIER=scalar ITB_FORCE_INTERLOCK_TIER=scalar \
                    ./tools/parity/parity-nocgo -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE1" -out="$BACK1"
                if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: mode3 tier=$TIER via=$INIT_VIA encrypt=cgo decrypt=nocgo-scalar hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
                M3_CELLS=$((M3_CELLS + 1))

                # Direction 2: encrypt nocgo scalar, decrypt cgo-tiered.
                ITB_FORCE_HASH_TIER=scalar ITB_FORCE_INTERLOCK_TIER=scalar \
                    ./tools/parity/parity-nocgo -mode=encrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$PLAIN" -out="$WIRE2"
                if [ "$SIZE" -le 1024 ]; then
                    GOT_LEN=$(wc -c < "$WIRE2" | tr -d ' ')
                    if [ "$GOT_LEN" -ne "$WANT_FLOOR" ]; then
                        echo "FAIL: mode3 nocgo wire floor len=$GOT_LEN want=$WANT_FLOOR hash=$HASH via=$INIT_VIA size=$SIZE nb=$NB"
                        FAIL=$((FAIL + 1))
                    fi
                fi
                ITB_FORCE_PIXEL_TIER="$TIER" ./tools/parity/parity-cgo-tiered -mode=decrypt \
                    -profile="$PROFILE" -hash="$HASH" -seed-file="$SEED" -nonce-bits="$NB" \
                    -in="$WIRE2" -out="$BACK2"
                if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
                    echo "FAIL: mode3 tier=$TIER via=$INIT_VIA encrypt=nocgo-scalar decrypt=cgo hash=$HASH size=$SIZE nb=$NB"
                    FAIL=$((FAIL + 1))
                fi
                M3_CELLS=$((M3_CELLS + 1))
            done
        done
    done
done

# Sub-section 7b — Mode 3 + 168-bit interlock & KMAC256 MAC across parity-cgo <-> parity-nocgo-noasm.
M3_EXTRA_SPECS=(
    "parity-areion512-il168-v1:areion512:168:flag"
    "parity-blake2b512-il168-v1:blake2b512:168:env"
    "parity-mac-areion512-v1:areion512:48:flag"
    "parity-mac-areion512-v1:areion512:48:env"
)

for ESPEC in "${M3_EXTRA_SPECS[@]}"; do
    IFS=':' read -r EPROF EHASH EIL EVIA <<< "$ESPEC"
    ESEED="$WORKDIR/seed-m3-extra-${EPROF}-${EIL}-${EVIA}.blob"
    if [ "$EVIA" = "env" ]; then
        ITB_CONTAINER_MODE=3 ./tools/parity/parity-cgo -mode=init \
            -profile="$EPROF" -hash="$EHASH" -seed-file="$ESEED" -nonce-bits=512 -interlock="$EIL"
    else
        ./tools/parity/parity-cgo -mode=init \
            -profile="$EPROF" -hash="$EHASH" -seed-file="$ESEED" -nonce-bits=512 -interlock="$EIL" -container-mode=3
    fi

    for SIZE in "${M3_SIZES[@]}"; do
        PLAIN="$WORKDIR/plain-${EHASH}-${SIZE}.bin"
        PLAIN_HASH=$(sha256sum "$PLAIN" | awk '{print $1}')

        ./tools/parity/parity-cgo -mode=encrypt \
            -profile="$EPROF" -hash="$EHASH" -seed-file="$ESEED" -nonce-bits=512 -interlock="$EIL" \
            -in="$PLAIN" -out="$WIRE1"
        if [ "$SIZE" -le 1024 ]; then
            GOT_LEN=$(wc -c < "$WIRE1" | tr -d ' ')
            if [ "$GOT_LEN" -ne 6372 ]; then
                echo "FAIL: mode3 extra wire floor len=$GOT_LEN want=6372 prof=$EPROF via=$EVIA size=$SIZE"
                FAIL=$((FAIL + 1))
            fi
        fi
        ./tools/parity/parity-nocgo-noasm -mode=decrypt \
            -profile="$EPROF" -hash="$EHASH" -seed-file="$ESEED" -nonce-bits=512 -interlock="$EIL" \
            -in="$WIRE1" -out="$BACK1"
        if [ "$(sha256sum "$BACK1" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
            echo "FAIL: mode3 extra prof=$EPROF il=$EIL via=$EVIA encrypt=cgo decrypt=nocgo-noasm size=$SIZE"
            FAIL=$((FAIL + 1))
        fi
        M3_CELLS=$((M3_CELLS + 1))

        ./tools/parity/parity-nocgo-noasm -mode=encrypt \
            -profile="$EPROF" -hash="$EHASH" -seed-file="$ESEED" -nonce-bits=512 -interlock="$EIL" \
            -in="$PLAIN" -out="$WIRE2"
        ./tools/parity/parity-cgo -mode=decrypt \
            -profile="$EPROF" -hash="$EHASH" -seed-file="$ESEED" -nonce-bits=512 -interlock="$EIL" \
            -in="$WIRE2" -out="$BACK2"
        if [ "$(sha256sum "$BACK2" | awk '{print $1}')" != "$PLAIN_HASH" ]; then
            echo "FAIL: mode3 extra prof=$EPROF il=$EIL via=$EVIA encrypt=nocgo-noasm decrypt=cgo size=$SIZE"
            FAIL=$((FAIL + 1))
        fi
        M3_CELLS=$((M3_CELLS + 1))
    done
done

echo "---"
echo "skipped: $SKIPPED_PAIRS (hash, arm) pairs / $SKIPPED_CELLS cells (no such arm — see SKIP lines)"
echo "skipped: $FILL_SKIPPED_PAIRS (hash, fill-tier) pairs / $FILL_SKIPPED_CELLS cells (no such kernel — see SKIP lines)"
TOTAL=$(( CELLS + TIER_CELLS + ARM_CELLS + IL_CELLS + IL168_CELLS + MAC_CELLS + FILL_CELLS + M3_CELLS ))
if [ "$FAIL" -eq 0 ]; then
    echo "PASS: $CELLS host-tier + $TIER_CELLS forced-pixel-tier + $ARM_CELLS forced-hash-arm + $IL_CELLS interlock-tier + $IL168_CELLS interlock168-tier + $MAC_CELLS kmac-mac + $FILL_CELLS batch-16-fill + $M3_CELLS mode3-posit = $TOTAL cells"
    exit 0
fi
echo "FAIL: $FAIL of $TOTAL cells failed"
exit 1
