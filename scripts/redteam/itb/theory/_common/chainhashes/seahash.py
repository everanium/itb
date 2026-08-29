"""SeaHash 128-bit pluggable ChainHash — Ticki's 4-lane ARX hash
(Redox OS / tfs project) adapted to ITB's 128-bit primitive interface
via parallel two-lane construction.

Mirrors `seahash64` in `harness_test.go` bit-for-bit. Canonical reference:
https://github.com/ticki/tfs/tree/master/seahash/src (reference.rs +
helper.rs).

Native primitive produces a 64-bit output. For ITB's ChainHash128 wrapping
we use the same parallel two-lane construction as t1ha1: lo lane =
seahash64 under seed_lo, hi lane = seahash64 under seed_hi.

Expected HARNESS.md Axis A signature: PerlinNoise catastrophic
(rurban/smhasher seahash.txt: 2.2 × 10¹² × over-expected collisions on
coordinate-structured input). That bias signature is the primary
reason SeaHash is the second priority target in HARNESS.md § 4.1 —
ITB's per-pixel envelope mixes pixel coordinates into every hash call,
so validating absorption on coordinate-structured input is directly
architectural. Axis A' structural bias test complements by measuring
schema-repetition bias under the ITB-realistic fixed-seed model; Axis B
measures whether the ITB wrap absorbs any surviving bias into the
attacker-observable ciphertext surface.
"""

from __future__ import annotations

from typing import Sequence

MASK64 = (1 << 64) - 1

SEAHASH_PRIME = 0x6EED0E9DA4D94A4F

SEAHASH_INIT_A = 0x16F11FE89B0D677C
SEAHASH_INIT_B = 0xB480A793D8E6C86C
SEAHASH_INIT_C = 0x6FE2E5AAF078EBC9
SEAHASH_INIT_D = 0x14F994A4C5259381

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit wrap


def _diffuse(x: int) -> int:
    """Canonical PCG-style diffusion mixer: x *= PRIME; x ^= (x >> 32)
    >> (x >> 60); x *= PRIME."""
    x = (x * SEAHASH_PRIME) & MASK64
    x ^= (x >> 32) >> (x >> 60)
    x = (x * SEAHASH_PRIME) & MASK64
    return x


def _read_tail(buf: bytes) -> int:
    """Read a 1..7-byte LE remainder as a uint64 zero-padded to the high
    side. Matches the buffer-pad convention in ticki/tfs seahash."""
    x = 0
    for i, b in enumerate(buf):
        x |= b << (8 * i)
    return x & MASK64


def seahash64(data: bytes, seed: int) -> int:
    """Pure-Python port of ticki/tfs seahash `hash_seeded` with seed
    applied per the canonical spec: "each of the initial state component
    are modularly multiplied by the seed". seed == 0 preserves the
    canonical unseeded case (test vector `hash("to be or not to be") =
    1988685042348123509` exercised by the Go self-check)."""
    seed &= MASK64
    a = SEAHASH_INIT_A
    b = SEAHASH_INIT_B
    c = SEAHASH_INIT_C
    d = SEAHASH_INIT_D
    if seed != 0:
        a = (a * seed) & MASK64
        b = (b * seed) & MASK64
        c = (c * seed) & MASK64
        d = (d * seed) & MASK64

    pos = 0
    length = len(data)
    while pos + 8 <= length:
        n = int.from_bytes(data[pos:pos + 8], "little")
        # (a, b, c, d) = (b, c, d, diffuse(a ^ n))
        a, b, c, d = b, c, d, _diffuse(a ^ n)
        pos += 8

    if pos < length:
        n = _read_tail(data[pos:])
        a, b, c, d = b, c, d, _diffuse(a ^ n)

    return _diffuse(a ^ b ^ c ^ d ^ length) & MASK64


def _seahash_128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """Parallel two-lane adapter matching seahashHash128 in the Go
    harness."""
    lo = seahash64(data, seed_lo & MASK64)
    hi = seahash64(data, seed_hi & MASK64)
    return lo, hi


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of `ChainHash128(data, seed)` with SeaHash as the inner
    primitive at keyBits=1024 (16 seed components). Standard ChainHash
    XOR-keying between rounds; output is `h[0]` (low uint64) of the
    final round."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"seahash 128 ChainHash expects {N_SEED_COMPONENTS} seed "
        f"components, got {len(seed_components)}"
    )
    h_lo, h_hi = _seahash_128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _seahash_128(data, k_lo, k_hi)
    return h_lo
