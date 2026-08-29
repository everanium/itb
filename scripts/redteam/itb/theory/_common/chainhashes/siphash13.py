"""SipHash-1-3 128-bit pluggable ChainHash — reduced-round SipHash variant
(1 message-mixing round + 3 finalization rounds) wrapped into ITB's 128-bit
primitive interface via parallel two-lane construction.

Mirrors `siphash13_64` and `chainHash128Siphash13` in `harness_test.go`
bit-for-bit. Canonical SipHash reference: Aumasson & Bernstein, "SipHash:
a fast short-input PRF" (CHES 2012, https://www.aumasson.jp/siphash/).

ITB deployment fixes the high half of SipHash's 128-bit key to zero
(`k1 = 0`), driving the primitive from a single 64-bit seed component
per call. This keeps the 16-component seed budget consistent with the
other shelf primitives (mx3, t1ha1, seahash) and reduces the SAT
recovery target on Axis C to 64 bits per call.

Expected HARNESS.md Axis A signature: SipHash-1-3 is the reduced-round
boundary case in § 4.1 row 7 — formally PRF at full SipHash-2-4 rounds,
measurable ≈0.9% worst-case avalanche bias at reduced 1-3 rounds. The
SipHash-2-1 / SipHash-2-2 published cryptanalysis (He & Yu, ePrint
2019/865) does not directly cover SipHash-1-3, so this row also
serves as an open boundary for the Axis C SAT KPA calibration.
"""

from __future__ import annotations

from typing import Sequence

MASK64 = (1 << 64) - 1

# SipHash IV constants (Aumasson & Bernstein 2012, ASCII tags).
_IV0 = 0x736F6D6570736575  # "somepseu"
_IV1 = 0x646F72616E646F6D  # "dorandom"
_IV2 = 0x6C7967656E657261  # "lygenera"
_IV3 = 0x7465646279746573  # "tedbytes"

# Message-mixing round count and finalization round count for SipHash-1-3.
SIP_C = 1
SIP_D = 3

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit wrap


def _rotl64(x: int, n: int) -> int:
    n &= 63
    if n == 0:
        return x & MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _sip_round(v0: int, v1: int, v2: int, v3: int) -> tuple[int, int, int, int]:
    """One SipRound permutation. Matches the canonical 4-step ARX layout
    from Aumasson & Bernstein 2012 § 2.1."""
    v0 = (v0 + v1) & MASK64
    v1 = _rotl64(v1, 13)
    v1 ^= v0
    v0 = _rotl64(v0, 32)

    v2 = (v2 + v3) & MASK64
    v3 = _rotl64(v3, 16)
    v3 ^= v2

    v0 = (v0 + v3) & MASK64
    v3 = _rotl64(v3, 21)
    v3 ^= v0

    v2 = (v2 + v1) & MASK64
    v1 = _rotl64(v1, 17)
    v1 ^= v2
    v2 = _rotl64(v2, 32)

    return v0, v1, v2, v3


def _read_u64_le(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 8], "little")


def siphash13_hash(data: bytes, seed: int) -> int:
    """Pure-Python port of SipHash-1-3 with the ITB deployment choice
    `k1 = 0`. Bit-for-bit match with the Go reference siphash13_64."""
    k0 = seed & MASK64
    k1 = 0

    v0 = (k0 ^ _IV0) & MASK64
    v1 = (k1 ^ _IV1) & MASK64
    v2 = (k0 ^ _IV2) & MASK64
    v3 = (k1 ^ _IV3) & MASK64

    length = len(data)
    end_8 = length - (length % 8)

    pos = 0
    while pos < end_8:
        m = _read_u64_le(data, pos)
        v3 ^= m
        for _ in range(SIP_C):
            v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0 ^= m
        pos += 8

    # Final partial block: pad with zeros up to 7 bytes, then byte 7 holds
    # `length & 0xff` (canonical SipHash padding rule).
    last = bytearray(8)
    rem = length - end_8
    if rem > 0:
        last[:rem] = data[end_8:]
    last[7] = length & 0xFF
    m = int.from_bytes(bytes(last), "little")
    v3 ^= m
    for _ in range(SIP_C):
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0 ^= m

    # Finalization.
    v2 ^= 0xFF
    for _ in range(SIP_D):
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)

    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


def _siphash13_128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """Parallel two-lane adapter matching siphash13Hash128 in the Go harness."""
    lo = siphash13_hash(data, seed_lo & MASK64)
    hi = siphash13_hash(data, seed_hi & MASK64)
    return lo, hi


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of ChainHash128(data, seed) with SipHash-1-3 as the
    inner primitive at keyBits=1024 (16 seed components)."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"siphash13 128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = _siphash13_128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _siphash13_128(data, k_lo, k_hi)
    return h_lo
