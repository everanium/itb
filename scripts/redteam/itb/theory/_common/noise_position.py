"""Per-pixel noise bit position, mirrored from the ITB encoder.

The encoder derives the noise bit position of every pixel from words 0
and 1 of noiseSeed's ChainHash over `LE32(c) || mainNonce`:

    noisePos = noise_fold3(noise_mix(h_word0, h_word1))
    noise_mix(w0, w1) = (w0 + rotl64(w1, 1)) mod 2^64

For 128-bit primitives the two words are the lo and hi lanes of
`Seed128.ChainHash128`; for 256- and 512-bit primitives they are output
words [0] and [1].

The noise hash runs ONE counter across the whole container. Region i of
a Triple container (i in {0, 1, 2}, `third = total_pixels // 3`) hashes
the counter `c = noise_counter_base(i, third) + p` at its per-region
stream step p, so the three regions read disjoint stretches of a single
position sequence. A single-region control encode keeps `c = p`
(counter base 0). The data hash is not affected: each region's dataSeed
is hashed at its own per-region counter p starting at 0.

`noise_fold3` is GF(2)-linear — `noise_fold3(a ^ b) == noise_fold3(a) ^
noise_fold3(b)` — but `noise_mix` is not: the carries of the integer
addition couple the two words. A primitive whose two words are related
by identity, complement or a constant XOR therefore does not cancel to a
constant or to a reduced set of positions, and for a primitive whose
ChainHash is affine in the seed per lane (CRC128) the position does not
split into a seed-only 3-bit key plus a public per-counter constant:
`noise_fold3(mix(K_lo ^ c_lo, K_hi ^ c_hi))` is a carry-coupled function
of all 128 seed-only bits and the counter. `precompute_noise_const3`
keeps the public constant of a GF(2)-linear word-mix model for the
scripts built on that model; see its docstring.
"""

from __future__ import annotations

import struct
from typing import Callable, Sequence, Tuple

import numpy as np

MASK64 = (1 << 64) - 1


def rotl64(w: int, r: int) -> int:
    """Rotate a 64-bit word left by `r` bits."""
    w &= MASK64
    r %= 64
    return ((w << r) | (w >> (64 - r))) & MASK64


def noise_fold3(w: int) -> int:
    """Reduce a 64-bit word to a 3-bit noise position — the ITB encoder's
    fold: every input bit reaches exactly one output bit."""
    w &= MASK64
    w ^= w >> 32
    w ^= w >> 16
    w ^= w >> 8
    w ^= w >> 4
    n = w & 15
    return (n ^ (n >> 3)) & 7


def noise_mix(word0: int, word1: int) -> int:
    """The 64-bit word `noise_fold3` reduces: word 0 plus word 1 rotated
    left by one bit, modulo 2^64 — the ITB encoder's `noiseMix`."""
    return (word0 + rotl64(word1, 1)) & MASK64


def noise_position(word0: int, word1: int) -> int:
    """Noise bit position from noise-hash words 0 and 1."""
    return noise_fold3(noise_mix(word0, word1))


def noise_counter_base(region: int, third: int) -> int:
    """Noise-hash counter offset of region `region` in a Triple container
    (`third = total_pixels // 3`). A single-region encode uses base 0."""
    return region * third


def noise_counter_data(counter: int, nonce: bytes) -> bytes:
    """Noise-hash input `LE32(counter) || nonce` at one counter value."""
    return struct.pack("<I", counter & 0xFFFFFFFF) + nonce


def precompute_noise_const3(
    n_pixels: int,
    nonce: bytes,
    chainhash_lohi_fn: Callable[[bytes, Sequence[int]], Tuple[int, int]],
    n_seed_components: int,
    counter_base: int = 0,
) -> np.ndarray:
    """Public per-pixel noise constant of a GF(2)-linear word-mix model.

    For stream step p in [0, n_pixels) returns
    `noise_fold3(c_lo(c) ^ c_hi(c))` at the noise counter
    `c = counter_base + p`, where `(c_lo, c_hi)` is the chain output under
    an all-zero seed. In a model where the two noise-hash words are
    combined by XOR and the chain is affine per lane, the noise position
    is

        noisePos(p) = k3 ^ const3[p],   k3 = noise_fold3(K_lo ^ K_hi)

    with `(K_lo, K_hi)` the seed-only compound keys of the two lanes.

    The shipped encoder combines the two words by integer addition
    (`noise_mix`), whose carries couple the seed-only and public parts,
    so this identity does NOT hold against shipped output: no seed-only
    3-bit key exists there, and `k3 ^ const3[p]` is not the shipped
    position. The helper serves the CRC128 scripts written on the
    XOR-mix model (`theory/crc128/crib_crc128_kpa_full.py`,
    `theory/crc128/crib_crc128_decrypt_full.py`); it is not a mirror of
    the shipped derivation, which `noise_position` is.
    Attacker-computable: the primitive and the nonce are public.
    """
    zero_seed = [0] * n_seed_components
    out = np.zeros(n_pixels, dtype=np.uint8)
    for p in range(n_pixels):
        lo, hi = chainhash_lohi_fn(noise_counter_data(counter_base + p, nonce), zero_seed)
        out[p] = noise_fold3((lo ^ hi) & MASK64)
    return out
