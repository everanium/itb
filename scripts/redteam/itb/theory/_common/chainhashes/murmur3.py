"""MurmurHash3 (x64, 128-bit) pluggable ChainHash — Austin Appleby's
non-cryptographic hash (public domain) adapted to ITB's two-lane primitive
interface for the SAT-free avalanche / differential pre-screen.

RESEARCH primitive for the pre-screen only; NOT wired into ITB's Go harness
and NOT exported to any public API. MurmurHash3 is the canonical "fast hash
table mixer, never a MAC" primitive: a multiply / rotate / xorshift body
with a strong finalizer (fmix64). Its avalanche is excellent, which is why
it is a fair stress case for the screen's "good avalanche does not imply
SAT-hardness" caveat — MurmurHash3 has documented seed-independence and
related-key weaknesses that a structure-aware solver can target even though
the diffusion columns read clean.

Reference: the canonical MurmurHash3_x64_128 (smhasher). Parity is checked
against the empty-input vector (which is (0, 0) for seed 0 by construction)
in the __main__ self-check, and — when the `mmh3` reference library is
installed — bit-for-bit against it across random inputs and seeds.
"""

from __future__ import annotations

from typing import Sequence

MASK64 = (1 << 64) - 1

C1 = 0x87C37B91114253D5
C2 = 0x4CF5AD432745937F

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit wrap

# INVERTIBLE is left undeclared (-> "?" in the screen). MurmurHash3 is a
# by-design one-way table mixer: it carries no documented solver-exploitable
# algebraic shortcut (no T-function triangularity, not a published invertible
# mixer), so the screen makes no invertibility claim — unlike splitmix64 /
# fnv1a, which are flagged Y because their structure DOES hand a solver a
# cheap per-step / triangular inverse. (For a fixed short input the seed map
# may happen to be a bijection, but mere bijectivity is not the property that
# helps a solver — a cheap structural inverse is.)


def _rotl64(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & MASK64


def _fmix64(k: int) -> int:
    """MurmurHash3 64-bit finalizer (a bijection in isolation)."""
    k &= MASK64
    k ^= k >> 33
    k = (k * 0xFF51AFD7ED558CCD) & MASK64
    k ^= k >> 33
    k = (k * 0xC4CEB9FE1A85EC53) & MASK64
    k ^= k >> 33
    return k & MASK64


def murmur3_x64_128(data: bytes, seed: int) -> tuple[int, int]:
    """Canonical MurmurHash3_x64_128. Returns (h1, h2) — the low and high
    64-bit halves of the 128-bit digest."""
    length = len(data)
    nblocks = length // 16
    h1 = seed & MASK64
    h2 = seed & MASK64

    for i in range(nblocks):
        base = i * 16
        k1 = int.from_bytes(data[base:base + 8], "little")
        k2 = int.from_bytes(data[base + 8:base + 16], "little")

        k1 = (k1 * C1) & MASK64
        k1 = _rotl64(k1, 31)
        k1 = (k1 * C2) & MASK64
        h1 ^= k1
        h1 = _rotl64(h1, 27)
        h1 = (h1 + h2) & MASK64
        h1 = (h1 * 5 + 0x52DCE729) & MASK64

        k2 = (k2 * C2) & MASK64
        k2 = _rotl64(k2, 33)
        k2 = (k2 * C1) & MASK64
        h2 ^= k2
        h2 = _rotl64(h2, 31)
        h2 = (h2 + h1) & MASK64
        h2 = (h2 * 5 + 0x38495AB5) & MASK64

    tail = data[nblocks * 16:]
    tl = len(tail)
    k1 = 0
    k2 = 0
    if tl >= 15:
        k2 ^= tail[14] << 48
    if tl >= 14:
        k2 ^= tail[13] << 40
    if tl >= 13:
        k2 ^= tail[12] << 32
    if tl >= 12:
        k2 ^= tail[11] << 24
    if tl >= 11:
        k2 ^= tail[10] << 16
    if tl >= 10:
        k2 ^= tail[9] << 8
    if tl >= 9:
        k2 ^= tail[8]
        k2 = (k2 * C2) & MASK64
        k2 = _rotl64(k2, 33)
        k2 = (k2 * C1) & MASK64
        h2 ^= k2
    if tl >= 8:
        k1 ^= tail[7] << 56
    if tl >= 7:
        k1 ^= tail[6] << 48
    if tl >= 6:
        k1 ^= tail[5] << 40
    if tl >= 5:
        k1 ^= tail[4] << 32
    if tl >= 4:
        k1 ^= tail[3] << 24
    if tl >= 3:
        k1 ^= tail[2] << 16
    if tl >= 2:
        k1 ^= tail[1] << 8
    if tl >= 1:
        k1 ^= tail[0]
        k1 = (k1 * C1) & MASK64
        k1 = _rotl64(k1, 31)
        k1 = (k1 * C2) & MASK64
        h1 ^= k1

    h1 ^= length
    h2 ^= length
    h1 = (h1 + h2) & MASK64
    h2 = (h2 + h1) & MASK64
    h1 = _fmix64(h1)
    h2 = _fmix64(h2)
    h1 = (h1 + h2) & MASK64
    h2 = (h2 + h1) & MASK64
    return h1, h2


def _murmur3_128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """Two-lane adapter: independent MurmurHash3_x64_128 low halves keyed by
    each lane seed, matching the lo/hi shape the screen and ChainHash use."""
    lo, _ = murmur3_x64_128(data, seed_lo & MASK64)
    hi, _ = murmur3_x64_128(data, seed_hi & MASK64)
    return lo, hi


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of the two-lane ChainHash with MurmurHash3 as the inner
    primitive at keyBits=1024 (16 seed components)."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"murmur3 128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = _murmur3_128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _murmur3_128(data, k_lo, k_hi)
    return h_lo


def _selfcheck() -> None:
    # Empty input with seed 0 collapses to (0, 0) by construction.
    assert murmur3_x64_128(b"", 0) == (0, 0), "murmur3 empty-input vector fail"
    # Determinism + seed sensitivity.
    a = murmur3_x64_128(b"itb", 1)
    assert a == murmur3_x64_128(b"itb", 1), "murmur3 not deterministic"
    assert a != murmur3_x64_128(b"itb", 2), "murmur3 seed-insensitive"
    # Bit-for-bit parity against the reference library, when present.
    try:
        import mmh3  # type: ignore
    except ImportError:
        print("murmur3: empty-vector + seed-sensitivity OK "
              "(mmh3 not installed — skipped bit-exact cross-check)")
        return
    import random
    rng = random.Random(20260524)
    for _ in range(2000):
        n = rng.randint(0, 40)
        buf = bytes(rng.getrandbits(8) for _ in range(n))
        seed = rng.getrandbits(32)  # mmh3 takes a 32-bit seed
        lo, hi = murmur3_x64_128(buf, seed)
        ref = mmh3.hash128(buf, seed, signed=False)  # 128-bit int, little-endian halves
        ref_lo = ref & MASK64
        ref_hi = (ref >> 64) & MASK64
        assert (lo, hi) == (ref_lo, ref_hi), (
            f"murmur3 mismatch len={n} seed={seed}: "
            f"{(lo, hi)} != {(ref_lo, ref_hi)}")
    print("murmur3: bit-for-bit parity vs mmh3 over 2000 random inputs OK")


if __name__ == "__main__":
    _selfcheck()
