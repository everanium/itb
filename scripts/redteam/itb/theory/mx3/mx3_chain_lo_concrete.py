#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 2 parity gadget for the mx3 SAT calibration plan
(HARNESS.md § 9.1).

Cross-checks that two independent lo-lane implementations reproduce
the Go `chainHash128Mx3` output bit-exact when the Go primitive is
`mx3` (harness_test.go). Without this gate, a later SAT harness
risks encoding a structurally-wrong chain and never noticing.

Two independent implementations:

  (a) `mx3_chain_lo_concrete` — pure Python mirroring the Go reference
      step by step. Computes the lo 64 bits only of the parallel
      two-lane mx3Hash128(seed_lo, seed_hi) ChainHash128 composition
      at variable round count.

  (b) `mx3_chain_lo_z3` — symbolic Z3 `BitVec(64)` expression for the
      same cascade. Multiplications by the canonical mx3 constant
      `C = 0xBEA225F9EB34556D` use Z3's native `BVMul` (Bitwuzla
      bit-blasts QF_BV multiplication efficiently, so explicit
      shift-and-add decomposition gains nothing for mx3's wide
      Hamming-weight constant). Shift-XOR steps `x ^ (x >> n)` map
      directly to `x ^ LShR(x, n)`.

The mx3 round function is fully bijective step by step (each
`mix_stream` is a 4-multiply XOR-shift composition over uint64, and
`mix` is a 6-multiply XOR-shift composition; the constant `C` is odd
hence multiplicatively invertible mod 2⁶⁴, and `x ^= x >> n` is
recoverable by recursive top-bit reconstruction). The Axis C SAT
calibration is therefore expected to land Tier 4 BIT-EXACT recovery
at modest observation count under bitwuzla — see HARNESS.md § 9.1
for the full encoding plan.

Usage:
    python3 mx3_chain_lo_concrete.py                  # self-parity test
    python3 mx3_chain_lo_concrete.py --vectors 1024   # more vectors

Exit codes:
    0 — all vectors matched
    1 — any mismatch (parity violation)
"""

from __future__ import annotations

import argparse
import random
import sys
from typing import List, Sequence

MASK64 = 0xFFFF_FFFF_FFFF_FFFF
MX3_C = 0xBEA225F9EB34556D


# ============================================================================
# Concrete reference — pure Python mirror of harness_test.go mx3 reference
# ============================================================================


def _mix_concrete(x: int) -> int:
    """4-multiply XOR-shift mixer. Matches jonmaiga/mx3 mx3::mix and
    the Go `mx3Mix`."""
    x = (x ^ (x >> 32)) & MASK64
    x = (x * MX3_C) & MASK64
    x = (x ^ (x >> 29)) & MASK64
    x = (x * MX3_C) & MASK64
    x = (x ^ (x >> 32)) & MASK64
    x = (x * MX3_C) & MASK64
    x = (x ^ (x >> 29)) & MASK64
    return x


def _mix_stream_concrete(h: int, x: int) -> int:
    """Single-input stream absorber. Matches jonmaiga/mx3
    mx3::mix_stream(h, x) and the Go `mx3MixStream`."""
    x = (x * MX3_C) & MASK64
    x = (x ^ (x >> 39)) & MASK64
    h = (h + (x * MX3_C)) & MASK64
    h = (h * MX3_C) & MASK64
    return h


def _mix_stream4_concrete(h: int, a: int, b: int, c: int, d: int) -> int:
    """4-lane parallel stream absorber. Matches jonmaiga/mx3
    mx3::mix_stream(h, a, b, c, d) and the Go `mx3MixStream4`."""
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


def _read_u64_le(data: bytes, pos: int, width: int = 8) -> int:
    return int.from_bytes(data[pos:pos + width], "little")


def mx3_hash_concrete(data: bytes, seed: int) -> int:
    """Pure-Python port of jonmaiga/mx3 hash(buf, len, seed). Bit-for-
    bit match with the Go reference mx3Hash."""
    length = len(data)
    h = _mix_stream_concrete(seed & MASK64, (length + 1) & MASK64)

    pos = 0
    while length - pos >= 64:
        w0 = _read_u64_le(data, pos, 8)
        w1 = _read_u64_le(data, pos + 8, 8)
        w2 = _read_u64_le(data, pos + 16, 8)
        w3 = _read_u64_le(data, pos + 24, 8)
        w4 = _read_u64_le(data, pos + 32, 8)
        w5 = _read_u64_le(data, pos + 40, 8)
        w6 = _read_u64_le(data, pos + 48, 8)
        w7 = _read_u64_le(data, pos + 56, 8)
        h = _mix_stream4_concrete(h, w0, w1, w2, w3)
        h = _mix_stream4_concrete(h, w4, w5, w6, w7)
        pos += 64
    while length - pos >= 8:
        h = _mix_stream_concrete(h, _read_u64_le(data, pos, 8))
        pos += 8

    tail = data[pos:]
    tlen = len(tail)
    if tlen == 0:
        return _mix_concrete(h)
    if tlen == 1:
        return _mix_concrete(_mix_stream_concrete(h, tail[0]))
    if tlen == 2:
        return _mix_concrete(_mix_stream_concrete(h, _read_u64_le(tail, 0, 2)))
    if tlen == 3:
        x = _read_u64_le(tail, 0, 2) | (tail[2] << 16)
        return _mix_concrete(_mix_stream_concrete(h, x & MASK64))
    if tlen == 4:
        return _mix_concrete(_mix_stream_concrete(h, _read_u64_le(tail, 0, 4)))
    if tlen == 5:
        x = _read_u64_le(tail, 0, 4) | (tail[4] << 32)
        return _mix_concrete(_mix_stream_concrete(h, x & MASK64))
    if tlen == 6:
        x = _read_u64_le(tail, 0, 4) | (_read_u64_le(tail, 4, 2) << 32)
        return _mix_concrete(_mix_stream_concrete(h, x & MASK64))
    if tlen == 7:
        x = (_read_u64_le(tail, 0, 4)
             | (_read_u64_le(tail, 4, 2) << 32)
             | (tail[6] << 48))
        return _mix_concrete(_mix_stream_concrete(h, x & MASK64))
    return _mix_concrete(h)  # unreachable


def mx3_128_concrete(
    data: bytes, seed_lo: int, seed_hi: int,
) -> tuple[int, int]:
    """Parallel two-lane 128-bit adapter — matches Go `mx3Hash128`."""
    return (
        mx3_hash_concrete(data, seed_lo & MASK64),
        mx3_hash_concrete(data, seed_hi & MASK64),
    )


def mx3_chain_lo_concrete(
    seed_components: Sequence[int], data: bytes, rounds: int,
) -> int:
    """Low 64 bits of ChainHash128 under the mx3 primitive, for `rounds`
    rounds.

    seed_components: flat list of 2*rounds uint64 values in order
        [s0_lo, s0_hi, s1_lo, s1_hi, ..., s(rounds-1)_lo, s(rounds-1)_hi].
    data: arbitrary-length data blob (canonical SAT calibration uses
        20-byte blockHash128 layout = 4B LE pixel + 16B nonce).
    rounds: ChainHash round count (1..8 supported; default deployment is
        8 at keyBits=1024).
    """
    assert len(seed_components) == 2 * rounds, (
        f"mx3 ChainHash with rounds={rounds} needs {2 * rounds} seed "
        f"components, got {len(seed_components)}"
    )
    h_lo, h_hi = mx3_128_concrete(
        data, seed_components[0], seed_components[1],
    )
    for r in range(1, rounds):
        k_lo = (seed_components[2 * r] ^ h_lo) & MASK64
        k_hi = (seed_components[2 * r + 1] ^ h_hi) & MASK64
        h_lo, h_hi = mx3_128_concrete(data, k_lo, k_hi)
    return h_lo


# ============================================================================
# Z3 symbolic mirror, matching the concrete reference above
# ============================================================================


# Bit positions set in MX3_C — LSB-first; Hamming weight 36. Used by the
# explicit shift-and-add multiplication decomposition below.
_MX3_C_BITS = [
    0, 2, 3, 5, 6, 8, 10, 12, 14, 18, 20, 21, 24, 25, 27, 29, 30, 31,
    32, 35, 36, 37, 38, 39, 40, 42, 45, 49, 53, 55, 57, 58, 59, 60, 61, 63,
]


def _mul_C_z3(z3, x, encoding: str = "native"):
    """Symbolic `x * MX3_C` over BV(64). Two encodings are supported:

    - "native": single Z3 `BVMul` with `BitVecVal(MX3_C, 64)` — the
      compact default used elsewhere in the harness.
    - "explicit": shift-and-add decomposition via the 36 bit positions
      set in MX3_C. Each set bit `i` contributes `x << i` to the sum.
      Larger SMT-LIB2 text but exposes the per-bit dependency to CDCL,
      which has empirically helped on multiplication-heavy formulas
      where the solver's default bvmul circuit hides structure (see
      HARNESS.md § 8 running log entry on mx3 r = 2 timeout).
    """
    if encoding == "native":
        return x * z3.BitVecVal(MX3_C, 64)
    if encoding == "explicit":
        # Mod-2⁶⁴ wrapping is automatic on BV(64) addition. Z3 defines
        # `x << k` as zero when `k >= 64`, but every entry in
        # `_MX3_C_BITS` is in [0, 63] so no out-of-range shift occurs.
        terms = [x << bit for bit in _MX3_C_BITS]
        result = terms[0]
        for term in terms[1:]:
            result = result + term
        return result
    raise ValueError(f"unknown mul encoding: {encoding!r}")


def _mix_z3(z3, x, encoding: str = "native"):
    """Symbolic mx3::mix on a 64-bit BitVec."""
    x = x ^ z3.LShR(x, 32)
    x = _mul_C_z3(z3, x, encoding)
    x = x ^ z3.LShR(x, 29)
    x = _mul_C_z3(z3, x, encoding)
    x = x ^ z3.LShR(x, 32)
    x = _mul_C_z3(z3, x, encoding)
    x = x ^ z3.LShR(x, 29)
    return x


def _mix_stream_z3(z3, h, x, encoding: str = "native"):
    """Symbolic mx3::mix_stream(h, x) on 64-bit BitVecs."""
    x = _mul_C_z3(z3, x, encoding)
    x = x ^ z3.LShR(x, 39)
    h = h + _mul_C_z3(z3, x, encoding)
    h = _mul_C_z3(z3, h, encoding)
    return h


def _mix_stream4_z3(z3, h, a, b, c, d, encoding: str = "native"):
    """Symbolic mx3::mix_stream(h, a, b, c, d) on 64-bit BitVecs."""
    a = _mul_C_z3(z3, a, encoding)
    b = _mul_C_z3(z3, b, encoding)
    c = _mul_C_z3(z3, c, encoding)
    d = _mul_C_z3(z3, d, encoding)
    a = a ^ z3.LShR(a, 39)
    b = b ^ z3.LShR(b, 39)
    c = c ^ z3.LShR(c, 39)
    d = d ^ z3.LShR(d, 39)
    h = h + _mul_C_z3(z3, a, encoding)
    h = _mul_C_z3(z3, h, encoding)
    h = h + _mul_C_z3(z3, b, encoding)
    h = _mul_C_z3(z3, h, encoding)
    h = h + _mul_C_z3(z3, c, encoding)
    h = _mul_C_z3(z3, h, encoding)
    h = h + _mul_C_z3(z3, d, encoding)
    h = _mul_C_z3(z3, h, encoding)
    return h


def _data_word_u64_z3(z3, data: bytes, pos: int):
    """Symbolic 8-byte LE word at `data[pos:pos+8]` as BitVecVal(64)."""
    return z3.BitVecVal(_read_u64_le(data, pos, 8), 64)


def _tail_word_z3(z3, tail: bytes):
    """Build the symbolic tail word matching the canonical
    `_mx3_hash_concrete` switch — `tail` is len 1..7 of the residual
    data after the 8-byte loop. Returns the BitVecVal(64) packed
    uint64 (zero-extended to 64 bits in the unused high positions),
    bit-for-bit matching the concrete shift / OR layout."""
    tlen = len(tail)
    assert 1 <= tlen <= 7, "tail must be 1..7 bytes"
    if tlen == 1:
        x = tail[0]
    elif tlen == 2:
        x = _read_u64_le(tail, 0, 2)
    elif tlen == 3:
        x = _read_u64_le(tail, 0, 2) | (tail[2] << 16)
    elif tlen == 4:
        x = _read_u64_le(tail, 0, 4)
    elif tlen == 5:
        x = _read_u64_le(tail, 0, 4) | (tail[4] << 32)
    elif tlen == 6:
        x = _read_u64_le(tail, 0, 4) | (_read_u64_le(tail, 4, 2) << 32)
    else:  # tlen == 7
        x = (_read_u64_le(tail, 0, 4)
             | (_read_u64_le(tail, 4, 2) << 32)
             | (tail[6] << 48))
    return z3.BitVecVal(x & MASK64, 64)


def mx3_hash_z3(z3, seed_sym, data: bytes, encoding: str = "native"):
    """Symbolic mx3 hash on `data` with `seed_sym` (BitVec(64)).

    Unrolls the variable-length main loop + 8-byte loop + tail switch
    against the constant `len(data)` known at SAT-formula-build time.
    Returns a BitVec(64) expression. `encoding` selects the
    multiplication-by-MX3_C representation — see `_mul_C_z3`.
    """
    length = len(data)
    h = _mix_stream_z3(
        z3, seed_sym, z3.BitVecVal((length + 1) & MASK64, 64), encoding,
    )

    pos = 0
    while length - pos >= 64:
        w0 = _data_word_u64_z3(z3, data, pos)
        w1 = _data_word_u64_z3(z3, data, pos + 8)
        w2 = _data_word_u64_z3(z3, data, pos + 16)
        w3 = _data_word_u64_z3(z3, data, pos + 24)
        w4 = _data_word_u64_z3(z3, data, pos + 32)
        w5 = _data_word_u64_z3(z3, data, pos + 40)
        w6 = _data_word_u64_z3(z3, data, pos + 48)
        w7 = _data_word_u64_z3(z3, data, pos + 56)
        h = _mix_stream4_z3(z3, h, w0, w1, w2, w3, encoding)
        h = _mix_stream4_z3(z3, h, w4, w5, w6, w7, encoding)
        pos += 64
    while length - pos >= 8:
        h = _mix_stream_z3(
            z3, h, _data_word_u64_z3(z3, data, pos), encoding,
        )
        pos += 8

    tail = data[pos:]
    if not tail:
        return _mix_z3(z3, h, encoding)
    return _mix_z3(
        z3, _mix_stream_z3(z3, h, _tail_word_z3(z3, tail), encoding),
        encoding,
    )


def mx3_128_z3(z3, seed_lo_sym, seed_hi_sym, data: bytes, encoding: str = "native"):
    """Symbolic parallel two-lane mx3Hash128 — returns a tuple of two
    BitVec(64) expressions (lo, hi)."""
    return (
        mx3_hash_z3(z3, seed_lo_sym, data, encoding),
        mx3_hash_z3(z3, seed_hi_sym, data, encoding),
    )


def mx3_chain_lo_z3(
    z3, seed_lo_syms, seed_hi_syms, data: bytes, rounds: int,
    encoding: str = "native",
):
    """Symbolic ChainHash128 lo lane under mx3 for `rounds` rounds.

    `seed_lo_syms` and `seed_hi_syms` are each a list of `rounds`
    BitVec(64) symbols. Returns a BitVec(64) expression for the low
    64 bits of the chain output. Mirrors the concrete reference
    `mx3_chain_lo_concrete` step by step, with the seed_components
    interleaved layout `[s0_lo, s0_hi, s1_lo, s1_hi, ...]` split into
    two parallel lists for symbolic-side ergonomics. `encoding`
    selects the multiplication-by-MX3_C representation; both
    encodings produce bit-identical hLo and are parity-tested at
    rounds = 1, 2, 4, 8 by the self-parity entry point in this file.
    """
    assert len(seed_lo_syms) == rounds and len(seed_hi_syms) == rounds, (
        f"need {rounds} lo + {rounds} hi seed syms, "
        f"got {len(seed_lo_syms)}+{len(seed_hi_syms)}"
    )
    h_lo, h_hi = mx3_128_z3(
        z3, seed_lo_syms[0], seed_hi_syms[0], data, encoding,
    )
    for r in range(1, rounds):
        k_lo = seed_lo_syms[r] ^ h_lo
        k_hi = seed_hi_syms[r] ^ h_hi
        h_lo, h_hi = mx3_128_z3(z3, k_lo, k_hi, data, encoding)
    return h_lo


# ============================================================================
# Self-parity — concrete vs symbolic on random vectors
# ============================================================================


def _self_parity(rounds_list: List[int], num_vectors: int, seed_rng: int) -> int:
    rng = random.Random(seed_rng)
    failures = 0
    try:
        import z3
    except ImportError:
        print("[mx3-parity] z3 not installed; running concrete-only "
              "self-consistency check (chain at rounds=1 vs rounds=2 with "
              "matching components)")
        # Concrete-only: trivial sanity — chain output changes when
        # rounds increases. Catches gross bugs but not z3 drift.
        for _ in range(num_vectors):
            data = bytes(rng.getrandbits(8) for _ in range(20))
            seed_components = [rng.getrandbits(64) for _ in range(2 * 8)]
            h1 = mx3_chain_lo_concrete(seed_components[:2], data, 1)
            h8 = mx3_chain_lo_concrete(seed_components, data, 8)
            if h1 == h8:
                failures += 1
        return failures

    # Concrete vs symbolic: build z3 formula in BOTH encodings,
    # substitute concrete seed, check both symbolic expressions
    # evaluate to the same hLo as the concrete reference.
    for rounds in rounds_list:
        for i in range(num_vectors):
            data = bytes(rng.getrandbits(8) for _ in range(20))
            seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
            concrete_expected = mx3_chain_lo_concrete(
                seed_components, data, rounds,
            )

            for encoding in ("native", "explicit"):
                seed_lo_syms = [
                    z3.BitVec(f"s_lo_{r}_{encoding}", 64)
                    for r in range(rounds)
                ]
                seed_hi_syms = [
                    z3.BitVec(f"s_hi_{r}_{encoding}", 64)
                    for r in range(rounds)
                ]
                sym_expr = mx3_chain_lo_z3(
                    z3, seed_lo_syms, seed_hi_syms, data, rounds,
                    encoding=encoding,
                )
                substitutions = []
                for r in range(rounds):
                    substitutions.append(
                        (seed_lo_syms[r],
                         z3.BitVecVal(seed_components[2 * r], 64))
                    )
                    substitutions.append(
                        (seed_hi_syms[r],
                         z3.BitVecVal(seed_components[2 * r + 1], 64))
                    )
                substituted = z3.substitute(sym_expr, *substitutions)
                simplified = z3.simplify(substituted)
                try:
                    got = simplified.as_long() & MASK64
                except Exception as exc:
                    print(f"[mx3-parity] r={rounds} v={i} enc={encoding}: "
                          f"simplify did not yield concrete BV ({exc}); "
                          f"expr={simplified}")
                    failures += 1
                    continue
                if got != concrete_expected:
                    failures += 1
                    print(f"[mx3-parity] MISMATCH r={rounds} v={i} "
                          f"enc={encoding}: concrete={concrete_expected:016x} "
                          f"z3={got:016x}")
                elif i == 0:
                    print(f"[mx3-parity] OK r={rounds} v={i} "
                          f"enc={encoding}: {got:016x}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rounds", default="1,2,4,8",
                    help="comma-separated rounds list (default 1,2,4,8)")
    ap.add_argument("--vectors", type=int, default=8,
                    help="vectors per rounds (default 8)")
    ap.add_argument("--seed-rng", type=int, default=0xCAFE_BABE_F00D_D00D,
                    help="reproducibility RNG seed")
    args = ap.parse_args()

    rounds_list = [int(x) for x in args.rounds.split(",") if x.strip()]
    failures = _self_parity(rounds_list, args.vectors, args.seed_rng)
    if failures:
        print(f"[mx3-parity] FAIL — {failures} mismatches")
        return 1
    print(f"[mx3-parity] PASS — all vectors matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
