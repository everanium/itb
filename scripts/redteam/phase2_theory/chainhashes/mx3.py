"""mx3 128-bit pluggable ChainHash — Jon Maiga's quality-focused 64-bit
hash (CC0 license; v3.0.0 2022-04-19) adapted to ITB's 128-bit primitive
interface via parallel two-lane construction.

Mirrors `mx3Hash` in `harness_test.go` bit-for-bit. Canonical reference:
https://github.com/jonmaiga/mx3/blob/master/mx3.h. No published test
vectors — parity with the Go reference is established via 13 randomly-
drawn vectors covering every tail-handling branch (0 / 1 / 2 / 3 / 4 /
5 / 6 / 7 byte tails + 64-byte-aligned + large lengths).

Expected HARNESS.md Axis A signature: mx3 is the 'paradox' row in
§ 4.1 — a primitive engineered for SMHasher quality yet catastrophically
failing the PerlinNoise AV subtest (1.48 × 10¹² × over-expected
collisions per rurban). This Axis A' structural-input harness does not
directly exercise PerlinNoise (which requires coordinate-structured
corpora); the avalanche Axis A harness is expected to pass because
avalanche is not mx3's weakness.
"""

from __future__ import annotations

from typing import Sequence

MASK64 = (1 << 64) - 1

MX3_C = 0xBEA225F9EB34556D

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit wrap


def _mix(x: int) -> int:
    """4-multiply XOR-shift mixer. Matches jonmaiga/mx3 mix()."""
    x = (x ^ (x >> 32)) & MASK64
    x = (x * MX3_C) & MASK64
    x = (x ^ (x >> 29)) & MASK64
    x = (x * MX3_C) & MASK64
    x = (x ^ (x >> 32)) & MASK64
    x = (x * MX3_C) & MASK64
    x = (x ^ (x >> 29)) & MASK64
    return x


def _mix_stream(h: int, x: int) -> int:
    """Single-input stream absorber. Matches jonmaiga/mx3
    mix_stream(h, x)."""
    x = (x * MX3_C) & MASK64
    x = (x ^ (x >> 39)) & MASK64
    h = (h + (x * MX3_C)) & MASK64
    h = (h * MX3_C) & MASK64
    return h


def _mix_stream4(h: int, a: int, b: int, c: int, d: int) -> int:
    """4-lane parallel stream absorber. Matches jonmaiga/mx3
    mix_stream(h, a, b, c, d)."""
    a = (a * MX3_C) & MASK64
    b = (b * MX3_C) & MASK64
    c = (c * MX3_C) & MASK64
    d = (d * MX3_C) & MASK64
    a = (a ^ (a >> 39)) & MASK64
    b = (b ^ (b >> 39)) & MASK64
    c = (c ^ (c >> 39)) & MASK64
    d = (d ^ (d >> 39)) & MASK64
    h = (h + (a * MX3_C)) & MASK64
    h = (h * MX3_C) & MASK64
    h = (h + (b * MX3_C)) & MASK64
    h = (h * MX3_C) & MASK64
    h = (h + (c * MX3_C)) & MASK64
    h = (h * MX3_C) & MASK64
    h = (h + (d * MX3_C)) & MASK64
    h = (h * MX3_C) & MASK64
    return h


def _read_le(data: bytes, start: int, width: int) -> int:
    return int.from_bytes(data[start:start + width], "little")


def mx3_hash(data: bytes, seed: int) -> int:
    """Pure-Python port of jonmaiga/mx3 hash(buf, len, seed). Bit-for-bit
    match with the Go reference mx3Hash."""
    length = len(data)
    h = _mix_stream(seed & MASK64, (length + 1) & MASK64)

    pos = 0
    while length - pos >= 64:
        w0 = _read_le(data, pos, 8)
        w1 = _read_le(data, pos + 8, 8)
        w2 = _read_le(data, pos + 16, 8)
        w3 = _read_le(data, pos + 24, 8)
        w4 = _read_le(data, pos + 32, 8)
        w5 = _read_le(data, pos + 40, 8)
        w6 = _read_le(data, pos + 48, 8)
        w7 = _read_le(data, pos + 56, 8)
        h = _mix_stream4(h, w0, w1, w2, w3)
        h = _mix_stream4(h, w4, w5, w6, w7)
        pos += 64
    while length - pos >= 8:
        h = _mix_stream(h, _read_le(data, pos, 8))
        pos += 8

    # Tail 0..7 bytes — mirror canonical switch layout bit-exactly.
    tail = data[pos:]
    tlen = len(tail)
    if tlen == 0:
        return _mix(h)
    elif tlen == 1:
        return _mix(_mix_stream(h, tail[0]))
    elif tlen == 2:
        return _mix(_mix_stream(h, _read_le(tail, 0, 2)))
    elif tlen == 3:
        x = _read_le(tail, 0, 2) | (tail[2] << 16)
        return _mix(_mix_stream(h, x & MASK64))
    elif tlen == 4:
        return _mix(_mix_stream(h, _read_le(tail, 0, 4)))
    elif tlen == 5:
        x = _read_le(tail, 0, 4) | (tail[4] << 32)
        return _mix(_mix_stream(h, x & MASK64))
    elif tlen == 6:
        x = _read_le(tail, 0, 4) | (_read_le(tail, 4, 2) << 32)
        return _mix(_mix_stream(h, x & MASK64))
    elif tlen == 7:
        x = (_read_le(tail, 0, 4)
             | (_read_le(tail, 4, 2) << 32)
             | (tail[6] << 48))
        return _mix(_mix_stream(h, x & MASK64))
    return _mix(h)  # unreachable


def _mx3_128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """Parallel two-lane adapter matching mx3Hash128 in the Go harness."""
    lo = mx3_hash(data, seed_lo & MASK64)
    hi = mx3_hash(data, seed_hi & MASK64)
    return lo, hi


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of ChainHash128(data, seed) with mx3 as the inner
    primitive at keyBits=1024 (16 seed components)."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"mx3 128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = _mx3_128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _mx3_128(data, k_lo, k_hi)
    return h_lo
