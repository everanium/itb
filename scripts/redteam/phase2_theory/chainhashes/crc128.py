"""CRC128 pluggable ChainHash — two keyed CRC64 computations (ECMA + ISO
polynomials) concatenated to 128 bits, wrapped in ITB's 8-round ChainHash128
at 1024-bit key.

Mirrors the test-only primitive defined in `redteam_lab_test.go`
bit-for-bit. Corpus side uses a custom Sarwate update loop WITHOUT the
entry/exit complementation that Go stdlib `hash/crc64.Update` applies;
this module matches that custom loop.

Every operation in the chain is GF(2)-linear, so the 512-bit ECMA-side of
the dataSeed collapses to a pixel-independent 64-bit compound key K; 56
of those bits are observable through ITB's channelXOR encoding.

See REDTEAM.md Phase 2a extension for the full empirical treatment.
"""

from __future__ import annotations

from typing import Sequence

CRC64_ECMA_POLY = 0xC96C5795D7870F42
CRC64_ISO_POLY = 0xD800000000000000
MASK64 = (1 << 64) - 1

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit hash width


def _build_crc64_table(poly: int) -> list[int]:
    table = [0] * 256
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        table[i] = crc
    return table


_TABLE_ECMA = _build_crc64_table(CRC64_ECMA_POLY)
_TABLE_ISO = _build_crc64_table(CRC64_ISO_POLY)


def _crc64_keyed(table: list[int], data: bytes, seed: int) -> int:
    """No-complement keyed CRC64 — matches the custom `crc64Keyed` in the
    corpus generator. Pure GF(2)-linear in (seed, data)."""
    crc = seed & MASK64
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc & MASK64


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of `Seed128.ChainHash128(data)` at 1024-bit key under
    the CRC128 primitive. Uses ECMA-side of the 16-uint64 seed for hLo
    (components[0, 2, 4, ..., 14]); ISO-side (components[1, 3, ..., 15])
    feeds hHi which ITB's encoding discards."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"CRC128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo = _crc64_keyed(_TABLE_ECMA, data, seed_components[0] & MASK64)
    h_hi = _crc64_keyed(_TABLE_ISO, data, seed_components[1] & MASK64)
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo = _crc64_keyed(_TABLE_ECMA, data, k_lo)
        h_hi = _crc64_keyed(_TABLE_ISO, data, k_hi)
    return h_lo


def compute_expected_K(meta: dict, nonce: bytes) -> int:
    """Lab-only: return the 64-bit compound key the raw-mode solver
    should recover, computed directly from `meta["data_seed"]` (ground
    truth). Use only for audit / validation — not an attacker capability.

    Because K is pixel-independent and nonce-independent (only the length
    of the chainhash input matters, not its content), ANY pixel index
    produces the same K. We use pixel 0 for simplicity."""
    import struct
    true_ds = list(meta["data_seed"])
    pixel_le = struct.pack("<I", 0)
    data = pixel_le + nonce
    h_true = chainhash_lo(data, true_ds)
    h_zero = chainhash_lo(data, [0] * N_SEED_COMPONENTS)
    return h_true ^ h_zero


def compute_expected_K_noise(meta: dict, nonce: bytes) -> int:
    """Lab-only counterpart of compute_expected_K for the noiseSeed lane.
    Returns the 64-bit compound key K_noise derived from `meta["noise_seed"]`.

    noiseSeed uses the SAME CRC128 primitive and the SAME ChainHash structure
    as dataSeed, just on a separate seed vector. The seed-independent
    `c_public = h_zero` is therefore identical for both lanes; K_noise is
    just `chainhash_lo(..., noise_seed) XOR c_public`. Audit / validation
    only."""
    import struct
    true_ns = list(meta["noise_seed"])
    pixel_le = struct.pack("<I", 0)
    data = pixel_le + nonce
    h_true = chainhash_lo(data, true_ns)
    h_zero = chainhash_lo(data, [0] * N_SEED_COMPONENTS)
    return h_true ^ h_zero
