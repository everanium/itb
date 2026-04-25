"""t1ha1_64le 128-bit pluggable ChainHash — Leonid Yuriev's Fast Positive
Hash v1 (LE variant) adapted to ITB's 128-bit primitive interface via
parallel two-lane construction.

Mirrors `t1ha1_64le` in `harness_test.go` bit-for-bit. Canonical
reference: https://github.com/erthink/t1ha/blob/master/src/t1ha1.c + helpers
at .../t1ha_bits.h. Cross-language parity verified via `_parity_test.py`
against the Go-generated vector dump.

Native primitive produces a 64-bit output. For ITB's ChainHash128 wrapping
we use a parallel two-lane construction:

    t1ha1Hash128(data, seed0, seed1) = (t1ha1_64le(data, seed0),
                                        t1ha1_64le(data, seed1))

where lo = hash under seed0 and hi = hash under seed1. Both lanes feed
back into ChainHash XOR-keying identically to the 128-bit-native primitives
(fnv1a128, md5Hash128).

Expected HARNESS.md Axis A signature: avalanche FAIL at 512 / 1024-bit
keys (3.77–3.95 % bias per rurban/smhasher t1ha1_64le.txt). Whether the
hHi discard and the subsequent rotation + noise barrier absorb that bias
on the hLo projection used by ITB encoding is what Axis B measures.
Axis C measures SAT KPA resistance orthogonally — multi-round ARX with
64×64-to-128 multiplications is the structure empirical SAT must defeat.
"""

from __future__ import annotations

from typing import Sequence

MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1

# t1ha1 "magic" primes (erthink/t1ha src/t1ha_bits.h lines 1081-1087).
T1HA_PRIME_0 = 0xEC99BF0D8372CAAB
T1HA_PRIME_1 = 0x82434FE90EDCEF39
T1HA_PRIME_2 = 0xD4F06DB99D67BE4B
T1HA_PRIME_3 = 0xBD9CACC22C6E9571
T1HA_PRIME_4 = 0x9C06FAF4D023E3AB
T1HA_PRIME_5 = 0xC060724A8424F345
T1HA_PRIME_6 = 0xCB5AF53AE3AAAC31

N_SEED_COMPONENTS = 16  # 8 rounds × 2 components per round at 128-bit wrap


def _rot64(v: int, s: int) -> int:
    """Right rotation (rotr64) — matches erthink/t1ha rot64 macro."""
    return ((v >> s) | (v << (64 - s))) & MASK64


def _mux64(v: int, prime: int) -> int:
    """XOR of low and high 64-bit halves of the full 128-bit product
    v * prime. Matches erthink/t1ha mux64()."""
    prod = (v * prime) & MASK128
    lo = prod & MASK64
    hi = (prod >> 64) & MASK64
    return lo ^ hi


def _mix64(v: int, prime: int) -> int:
    """Canonical xor-mul-xor mixer used inside final_weak_avalanche.
    Equivalent to `v *= prime; return v ^ rot64(v, 41)` in C."""
    v = (v * prime) & MASK64
    return v ^ _rot64(v, 41)


def _final_weak_avalanche(a: int, b: int) -> int:
    """The 2-operand final mixer of t1ha1. Uses mix64 (not mux64) in its
    second addend — an intentional performance compromise that fails
    SMHasher's strict avalanche criterion, distinguishing t1ha1 from
    stronger variants (t1ha2)."""
    return (_mux64(_rot64((a + b) & MASK64, 17), T1HA_PRIME_4) +
            _mix64((a ^ b) & MASK64, T1HA_PRIME_0)) & MASK64


def _read64_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little")


def _tail64_le(data: bytes, tail: int) -> int:
    """Read up to 8 bytes of tail as little-endian uint64. Matches the
    canonical tail64_le_aligned behaviour: (tail & 7) == 0 when tail > 0
    means read 8 bytes without masking."""
    n = tail & 7
    if n == 0:
        return int.from_bytes(data[:8], "little")
    r = 0
    for i in range(n):
        r |= data[i] << (8 * i)
    return r


def t1ha1_64le(data: bytes, seed: int) -> int:
    """Pure-Python port of erthink/t1ha t1ha1_le. Bit-for-bit match with
    the Go reference in harness_test.go."""
    length = len(data)
    a = seed & MASK64
    b = length & MASK64

    pos = 0
    if length > 32:
        c = (_rot64(length, 17) + seed) & MASK64
        d = (length ^ _rot64(seed, 17)) & MASK64
        # do-while equivalent: process 32-byte blocks, exit when next block
        # would exceed the input.
        while True:
            w0 = _read64_le(data, pos)
            w1 = _read64_le(data, pos + 8)
            w2 = _read64_le(data, pos + 16)
            w3 = _read64_le(data, pos + 24)
            pos += 32

            d02 = (w0 ^ _rot64((w2 + d) & MASK64, 17)) & MASK64
            c13 = (w1 ^ _rot64((w3 + c) & MASK64, 17)) & MASK64
            d = (d - (b ^ _rot64(w1, 31))) & MASK64
            c = (c + (a ^ _rot64(w0, 41))) & MASK64
            b = (b ^ (T1HA_PRIME_0 * ((c13 + w2) & MASK64))) & MASK64
            a = (a ^ (T1HA_PRIME_1 * ((d02 + w3) & MASK64))) & MASK64

            if pos + 32 > length:
                break

        a = (a ^ (T1HA_PRIME_6 * ((_rot64(c, 17) + d) & MASK64))) & MASK64
        b = (b ^ (T1HA_PRIME_5 * ((c + _rot64(d, 17)) & MASK64))) & MASK64
        length &= 31

    # Tail handling — mirror of the fall-through switch in canonical C.
    # Each `if length > N` corresponds to one case-block boundary;
    # independent ifs (not else-if) because fall-through means every lower
    # case also fires.
    tail = data[pos:]
    if length > 24:
        b = (b + _mux64(_read64_le(tail, 0), T1HA_PRIME_4)) & MASK64
        tail = tail[8:]
    if length > 16:
        a = (a + _mux64(_read64_le(tail, 0), T1HA_PRIME_3)) & MASK64
        tail = tail[8:]
    if length > 8:
        b = (b + _mux64(_read64_le(tail, 0), T1HA_PRIME_2)) & MASK64
        tail = tail[8:]
    if length > 0:
        a = (a + _mux64(_tail64_le(tail, length), T1HA_PRIME_1)) & MASK64

    return _final_weak_avalanche(a, b)


def _t1ha1_128(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """Parallel two-lane adapter matching t1ha1Hash128 in the Go harness.
    Two independent t1ha1_64le invocations with seed_lo and seed_hi."""
    lo = t1ha1_64le(data, seed_lo & MASK64)
    hi = t1ha1_64le(data, seed_hi & MASK64)
    return lo, hi


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Low 64 bits of `ChainHash128(data, seed)` with t1ha1 as the inner
    primitive at keyBits=1024 (16 seed components). Standard ChainHash
    XOR-keying between rounds; output is `h[0]` (low uint64) of the
    final round."""
    assert len(seed_components) == N_SEED_COMPONENTS, (
        f"t1ha1 128 ChainHash expects {N_SEED_COMPONENTS} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = _t1ha1_128(data, seed_components[0], seed_components[1])
    for i in range(2, N_SEED_COMPONENTS, 2):
        k_lo = (seed_components[i] ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo, h_hi = _t1ha1_128(data, k_lo, k_hi)
    return h_lo
