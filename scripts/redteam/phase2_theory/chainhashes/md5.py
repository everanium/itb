"""MD5 128-bit pluggable ChainHash — broken cryptographic primitive included
in the bias audit as a cross-validation datapoint against Phase 2b
NIST-STS (which already reported MD5 ITB-wrapped output indistinguishable
from random noise on its own statistical framework).

Mirrors `md5Hash128` in `redteam_test.go`:

    key[0:8]  = seed0 little-endian
    key[8:16] = seed1 little-endian
    digest    = MD5(key || data)                           (16 bytes)
    lo, hi    = first 8 bytes LE, last 8 bytes LE          (uint64 each)

Inside ITB's ChainHash128 at 1024-bit key, 16 uint64 seed components are
consumed two at a time across 8 rounds with the standard XOR-keying
between rounds — same wrapping as FNV-1a / CRC128 (128-bit hash family).

Expected bias-probe outcome: MD5 has compression + non-linear F/G/H/I
rounds with carry chains; no pixel-independent compound key K exists for
it, so the raw-mode probe should show `neutralized ✓` across every
tested format (ascii / json_structured / html_structured).
"""

from __future__ import annotations

import hashlib
import struct
from typing import Sequence

MASK64 = (1 << 64) - 1

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit hash width


def _md5_128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """One primitive-level MD5 128-bit computation matching the Go
    reference. Returns `(lo, hi)` as two uint64 halves, LE output."""
    key = struct.pack("<QQ", seed_lo & MASK64, seed_hi & MASK64)
    digest = hashlib.md5(key + data).digest()
    lo = int.from_bytes(digest[:8], "little")
    hi = int.from_bytes(digest[8:], "little")
    return lo, hi


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of `Seed128.ChainHash128(data)` at 1024-bit key under
    MD5 128-bit primitive. Standard ChainHash XOR-keying between rounds;
    output is `h[0]` (low uint64) of the final round."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"MD5 128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = _md5_128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _md5_128(data, k_lo, k_hi)
    return h_lo
