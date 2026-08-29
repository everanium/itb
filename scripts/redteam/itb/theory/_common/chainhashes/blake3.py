"""BLAKE3 pluggable ChainHash — PRF-grade 256-bit primitive used by ITB.

Mirrors `makeBlake3Hash256` in `itb_test.go`: a fresh 32-byte BLAKE3 key is
drawn at test init and reused across all hash calls of one encryption
session. Each primitive call XORs `seed[0..3]` (4 × uint64 = 32 bytes) into
the first 32 bytes of the data before feeding it through the keyed BLAKE3
hasher, truncates to 32 bytes, and returns as 4 × uint64 little-endian.

For ITB's 1024-bit key under a 256-bit hash, `Seed256.ChainHash256` uses
16 / 4 = 4 rounds, consuming 4 seed components per round. The usual
ChainHash XOR-keying between rounds XORs the 4-uint64 previous output
into the next round's 4 seed components.

Only `h[0]` (the low uint64 of the 4-uint64 output) is observable through
ITB's encoding. This mirror returns that value.

**Pre-condition**: `init_from_meta(meta)` must be called before the first
`chainhash_lo` — the BLAKE3 key is in `meta["blake3_key_hex"]`, emitted by
the corpus generator when `ITB_REDTEAM=1` is set (otherwise absent and
this module raises on first call).
"""

from __future__ import annotations

import struct
from typing import Optional, Sequence

from blake3 import blake3

# Number of uint64 components of the ChainHash seed consumed across all
# rounds at 1024-bit key. 4 rounds × 4 uint64 per round = 16.
N_SEED_COMPONENTS = 16
_COMPONENTS_PER_ROUND = 4
_N_ROUNDS = N_SEED_COMPONENTS // _COMPONENTS_PER_ROUND  # = 4

MASK64 = (1 << 64) - 1
_BLAKE3_KEY: Optional[bytes] = None


def init_from_meta(meta: dict) -> None:
    """Initialize the module-level BLAKE3 key from a cell.meta.json dict.

    Looks for `meta["blake3_key_hex"]` (32 bytes as 64 hex chars). The
    corpus generator emits this under ITB_REDTEAM=1 when hash=blake3.
    Raises if absent — BLAKE3 bias audit is not possible without the
    per-corpus key."""
    global _BLAKE3_KEY
    key_hex = meta.get("blake3_key_hex")
    if key_hex is None:
        raise RuntimeError(
            "BLAKE3 bias audit requires `blake3_key_hex` in cell.meta.json. "
            "Regenerate the corpus with the REDTEAM-mode generator that emits "
            "this field (the public-API hash registration does not expose its "
            "internal BLAKE3 key; we need the lab-emitted value)."
        )
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        raise RuntimeError(f"blake3_key_hex must decode to 32 bytes; got {len(key)}")
    _BLAKE3_KEY = key


def _blake3_256(data: bytes, seed4: Sequence[int]) -> tuple[int, int, int, int]:
    """One primitive-level BLAKE3-keyed call matching the Go reference.

    `seed4` is 4 × uint64. XOR each component little-endian into the first
    32 bytes of `data`, then keyed_hash with the per-session BLAKE3 key,
    truncate to 32 bytes, return as `(h0, h1, h2, h3)` = little-endian
    uint64 pair."""
    if _BLAKE3_KEY is None:
        raise RuntimeError(
            "BLAKE3 chainhash_lo called before init_from_meta(); "
            "pass cell.meta.json to the module before any hash call."
        )
    buf = bytearray(data)
    # Overlay XOR of seed4 into first 32 bytes of buf, little-endian u64.
    # If data is shorter than 32 bytes (shouldn't happen for ITB pixel+nonce
    # inputs), only XOR what fits.
    for i in range(4):
        off = i * 8
        if off + 8 > len(buf):
            break
        prev = struct.unpack_from("<Q", buf, off)[0]
        struct.pack_into("<Q", buf, off, (prev ^ (seed4[i] & MASK64)))
    h = blake3(bytes(buf), key=_BLAKE3_KEY).digest()[:32]
    return struct.unpack("<QQQQ", h)


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of `Seed256.ChainHash256(data)` at 1024-bit key under
    BLAKE3. Round i consumes components[i*4:(i+1)*4]; subsequent rounds
    XOR the 4-uint64 previous output into their 4 seed components before
    feeding to the primitive."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"BLAKE3 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h = _blake3_256(data, seed_components[0:4])
    for r in range(1, _N_ROUNDS):
        k = tuple(
            (seed_components[r * 4 + j] ^ h[j]) & MASK64 for j in range(4)
        )
        h = _blake3_256(data, k)
    return h[0]
