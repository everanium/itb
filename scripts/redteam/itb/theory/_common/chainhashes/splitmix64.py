"""SplitMix64 128-bit pluggable ChainHash — Sebastiano Vigna's SplitMix64
finalizer (public domain) adapted to ITB's two-lane primitive interface.

This is a RESEARCH primitive for the SAT-free avalanche / differential
pre-screen only; it is NOT wired into ITB's Go harness (harness_test.go) and
NOT exported to any public API. Its purpose is to make the screen's central
caveat concrete: SplitMix64's mix64 is a BIJECTION on the 64-bit word (each
step — an xorshift and a multiply by an odd constant — is individually
invertible), so the data-absorbing chain built from it is invertible in the
seed for any fixed data. It therefore reads "ideal" on every avalanche /
SAC / algebraic-degree column yet is round-by-round invertible by a solver,
exactly the FNV-1a lesson in a different algebra (xorshift-multiply rather
than a carry-chain multiply). High degree and perfect diffusion do not imply
SAT-hardness when the round map is a bijection with a cheap inverse.

Reference: http://prng.di.unimi.it/splitmix64.c (Vigna). The mix64 below is
the SplitMix64 output stage; parity is established against the canonical
seed-0 output sequence in the __main__ self-check, not against a Go
reference (this primitive has no Go-harness counterpart).
"""

from __future__ import annotations

from typing import Sequence

MASK64 = (1 << 64) - 1

# SplitMix64 increment (golden-ratio odd constant) and the two finalizer
# multipliers. All three are odd, so every multiply is invertible mod 2^64.
GAMMA = 0x9E3779B97F4A7C15
M1 = 0xBF58476D1CE4E5B9
M2 = 0x94D049BB133111EB

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit wrap

# INVERTIBLE flags the structural property the avalanche screen cannot see
# statistically: the seed -> output map is a bijection for any fixed data.
INVERTIBLE = True


def mix64(z: int) -> int:
    """SplitMix64 output mixer. A bijection on 64 bits (two invertible
    xorshift-multiply stages plus a final invertible xorshift)."""
    z &= MASK64
    z = ((z ^ (z >> 30)) * M1) & MASK64
    z = ((z ^ (z >> 27)) * M2) & MASK64
    z = z ^ (z >> 31)
    return z & MASK64


def splitmix64_hash(data: bytes, seed: int) -> int:
    """Data-absorbing 64-bit hash keyed by seed. h starts at the seed and
    each byte is folded through the bijective mixer, so for any fixed data
    the map seed -> output is a composition of bijections (hence invertible).
    The length is absorbed last to separate distinct-length inputs."""
    h = seed & MASK64
    for b in data:
        h = mix64(h ^ b)
    h = mix64(h ^ (len(data) & MASK64))
    return h & MASK64


def _splitmix64_128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """Parallel two-lane adapter: independent SplitMix64 hashes on each lane,
    matching the lo/hi shape the avalanche screen and ChainHash expect."""
    return splitmix64_hash(data, seed_lo & MASK64), splitmix64_hash(data, seed_hi & MASK64)


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of the two-lane ChainHash with SplitMix64 as the inner
    primitive at keyBits=1024 (16 seed components). Mirrors the chain shape
    of the sibling chainhashes.<name> modules."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"splitmix64 128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = _splitmix64_128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _splitmix64_128(data, k_lo, k_hi)
    return h_lo


def _selfcheck() -> None:
    """Parity against the canonical SplitMix64 seed-0 output sequence.

    The generator next() does state += GAMMA then mix64(state); starting from
    state 0 the first outputs are the well-known SplitMix64 vectors."""
    expected = [
        0xE220A8397B1DCDAF,
        0x6E789E6AA1B965F4,
        0x06C45D188009454F,
        0xF88BB8A8724C81EC,
        0x1B39896A51A8749B,
    ]
    state = 0
    for want in expected:
        state = (state + GAMMA) & MASK64
        got = mix64(state)
        assert got == want, f"splitmix64 parity fail: {got:#018x} != {want:#018x}"
    # mix64 is a bijection: it must have no fixed-point collision on a small
    # injective spot-check (sanity, not a proof).
    seen = set()
    for x in range(4096):
        y = mix64(x * GAMMA & MASK64)
        assert y not in seen, "mix64 collision on injective probe"
        seen.add(y)


if __name__ == "__main__":
    _selfcheck()
    print("splitmix64: canonical seed-0 vectors OK; mix64 injective spot-check OK")
