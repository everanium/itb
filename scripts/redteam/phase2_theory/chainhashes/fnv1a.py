"""FNV-1a 128-bit pluggable ChainHash — the borderline-invertible primitive
ITB uses as a non-PRF below-spec control.

Mirrors `fnv1a128` in `redteam_test.go` bit-for-bit:

    state = seed_hi_64 || seed_lo_64      (128-bit, hi in top)
    for b in data:
        state ^= b
        state = (state * 0x01000000000000000000013B) mod 2^128
    output 16 bytes big-endian → (hi = first 8 BE, lo = last 8 BE)

Inside ITB's ChainHash128 at 1024-bit key, 16 uint64 seed components are
consumed two at a time across 8 rounds with the standard XOR-keying between
rounds. Each round's `(seed0, seed1)` initializes the 128-bit state.

Unlike CRC128, FNV-1a's per-byte step includes a multiplication modulo
2^64 (well, 2^128 here), and that multiplication has carry chains that
are NOT GF(2)-linear — AND-combinations between bit positions accumulate.
End result: no pixel-independent compound key K exists for FNV-1a, so
the raw-mode bias probe should show flat ~50 % conflict across all shifts
(no plateau, no structural hook).
"""

from __future__ import annotations

from typing import Sequence

MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1
FNV_PRIME_128 = 0x01000000000000000000013B

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit hash width


def _fnv1a128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """One primitive-level FNV-1a 128-bit computation matching the Go
    reference. Returns `(lo, hi)` as two uint64 halves, big-endian output
    convention (hi = upper 64 bits of state, lo = lower)."""
    state = ((seed_hi & MASK64) << 64) | (seed_lo & MASK64)
    for b in data:
        state ^= b
        state = (state * FNV_PRIME_128) & MASK128
    hi = (state >> 64) & MASK64
    lo = state & MASK64
    return lo, hi


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of `Seed128.ChainHash128(data)` at 1024-bit key under
    FNV-1a 128-bit primitive. Standard ChainHash XOR-keying between
    rounds; output is `h[0]` of the final round."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"FNV-1a 128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = _fnv1a128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _fnv1a128(data, k_lo, k_hi)
    return h_lo
