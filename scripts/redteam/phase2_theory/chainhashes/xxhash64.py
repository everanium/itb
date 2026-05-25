"""XXH64 (xxHash, 64-bit) pluggable ChainHash — Yann Collet's
non-cryptographic hash (BSD-2) adapted to ITB's two-lane primitive interface
for the SAT-free avalanche / differential pre-screen.

RESEARCH primitive for the pre-screen only; NOT wired into ITB's Go harness
and NOT exported to any public API. XXH64 is an accumulator design (four
64-bit lanes for long inputs, a single-lane tail mixer for short ones) built
from multiply / rotate steps — a structurally different non-crypto shape
from the multiply-xorshift mixers (mx3, murmur3, splitmix64), included so
the screen covers more than one mixing topology. Like MurmurHash3 it has
excellent avalanche and documented seed/multicollision weaknesses, never a
MAC.

Reference: the canonical XXH64 (Cyan4973/xxHash). Parity is checked against
the empty-input vector XXH64("", 0) = 0xEF46DB3751D8E999 in the __main__
self-check, and — when the `xxhash` reference library is installed —
bit-for-bit against it across random inputs and seeds.
"""

from __future__ import annotations

from typing import Sequence

MASK64 = (1 << 64) - 1

P1 = 0x9E3779B185EBCA87
P2 = 0xC2B2AE3D27D4EB4F
P3 = 0x165667B19E3779F9
P4 = 0x85EBCA77C2B2AE63
P5 = 0x27D4EB2F165667C5

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit wrap

# INVERTIBLE is left undeclared (-> "?" in the screen). XXH64 is a by-design
# one-way accumulator hash with no documented solver-exploitable algebraic
# shortcut, so the screen makes no invertibility claim — unlike splitmix64 /
# fnv1a (flagged Y for their cheap per-step / triangular inverse). Mere
# bijectivity of the seed map for a fixed short input is not the property
# that helps a solver; a cheap structural inverse is.


def _rotl64(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & MASK64


def _round(acc: int, inp: int) -> int:
    acc = (acc + (inp * P2)) & MASK64
    acc = _rotl64(acc, 31)
    acc = (acc * P1) & MASK64
    return acc


def _merge_round(acc: int, val: int) -> int:
    val = _round(0, val)
    acc ^= val
    acc = (acc * P1 + P4) & MASK64
    return acc


def xxh64(data: bytes, seed: int) -> int:
    """Canonical XXH64 over `data` with 64-bit `seed`."""
    seed &= MASK64
    length = len(data)
    p = 0

    if length >= 32:
        v1 = (seed + P1 + P2) & MASK64
        v2 = (seed + P2) & MASK64
        v3 = seed & MASK64
        v4 = (seed - P1) & MASK64
        limit = length - 32
        while p <= limit:
            v1 = _round(v1, int.from_bytes(data[p:p + 8], "little")); p += 8
            v2 = _round(v2, int.from_bytes(data[p:p + 8], "little")); p += 8
            v3 = _round(v3, int.from_bytes(data[p:p + 8], "little")); p += 8
            v4 = _round(v4, int.from_bytes(data[p:p + 8], "little")); p += 8
        h = (_rotl64(v1, 1) + _rotl64(v2, 7) + _rotl64(v3, 12) + _rotl64(v4, 18)) & MASK64
        h = _merge_round(h, v1)
        h = _merge_round(h, v2)
        h = _merge_round(h, v3)
        h = _merge_round(h, v4)
    else:
        h = (seed + P5) & MASK64

    h = (h + length) & MASK64

    while p + 8 <= length:
        k1 = _round(0, int.from_bytes(data[p:p + 8], "little"))
        h ^= k1
        h = (_rotl64(h, 27) * P1 + P4) & MASK64
        p += 8
    if p + 4 <= length:
        h ^= (int.from_bytes(data[p:p + 4], "little") * P1) & MASK64
        h = (_rotl64(h, 23) * P2 + P3) & MASK64
        p += 4
    while p < length:
        h ^= (data[p] * P5) & MASK64
        h = (_rotl64(h, 11) * P1) & MASK64
        p += 1

    h ^= h >> 33
    h = (h * P2) & MASK64
    h ^= h >> 29
    h = (h * P3) & MASK64
    h ^= h >> 32
    return h & MASK64


def _xxhash64_128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """Two-lane adapter: independent XXH64 hashes keyed by each lane seed."""
    return xxh64(data, seed_lo & MASK64), xxh64(data, seed_hi & MASK64)


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of the two-lane ChainHash with XXH64 as the inner
    primitive at keyBits=1024 (16 seed components)."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"xxhash64 128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = _xxhash64_128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _xxhash64_128(data, k_lo, k_hi)
    return h_lo


def _selfcheck() -> None:
    assert xxh64(b"", 0) == 0xEF46DB3751D8E999, (
        f"xxh64 empty-input vector fail: {xxh64(b'', 0):#018x}")
    a = xxh64(b"itb", 1)
    assert a == xxh64(b"itb", 1), "xxh64 not deterministic"
    assert a != xxh64(b"itb", 2), "xxh64 seed-insensitive"
    try:
        import xxhash  # type: ignore
    except ImportError:
        print("xxhash64: empty-vector (0xEF46DB3751D8E999) + seed-sensitivity OK "
              "(xxhash not installed — skipped bit-exact cross-check)")
        return
    import random
    rng = random.Random(20260524)
    for _ in range(2000):
        n = rng.randint(0, 80)  # span the <32 tail path and the >=32 accumulator
        buf = bytes(rng.getrandbits(8) for _ in range(n))
        seed = rng.getrandbits(64)
        got = xxh64(buf, seed)
        ref = xxhash.xxh64(buf, seed=seed).intdigest()
        assert got == ref, f"xxh64 mismatch len={n} seed={seed:#x}: {got:#x} != {ref:#x}"
    print("xxhash64: bit-for-bit parity vs xxhash over 2000 random inputs OK")


if __name__ == "__main__":
    _selfcheck()
