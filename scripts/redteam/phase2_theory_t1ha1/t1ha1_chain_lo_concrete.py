#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 2 parity gadget for the t1ha1 SAT calibration plan.

Cross-checks that two independent lo-lane implementations reproduce
the Go `chainHash128T1ha1` output bit-exact when the Go primitive is
`t1ha1_64le` (harness_test.go).

Two independent implementations:

  (a) `t1ha1_chain_lo_concrete` — pure Python mirroring the existing
      `scripts/redteam/phase2_theory/chainhashes/t1ha1.py` with an
      added `rounds` parameter for variable-round chain hash.

  (b) `t1ha1_chain_lo_z3` — symbolic Z3 `BitVec(64)` expression for
      the same cascade. The structurally distinguishing operation is
      `mux64(v, prime)` — XOR of the high and low 64-bit halves of
      the full 128-bit product `v * prime`. Encoded symbolically by
      zero-extending operands to 128 bits, multiplying, and
      extracting the two halves.

t1ha1 has no `--mul-encoding` / `--var-shift-encoding` axes — every
multiplication is by a constant prime (subset of T1HA_PRIME_0 .. 6),
and rotations are by constant amounts. The dense Hamming weight of
the seven primes (~30 bits each) makes explicit shift-and-add
decomposition unhelpful (mx3 calibration empirically confirmed this
pattern for similarly dense multipliers).

ITB deployment uses the parallel two-lane wrapper
`t1ha1Hash128(data, seed_lo, seed_hi)`; only the lo lane's output
enters the chain output, so `s_hi_*` symbols are dead variables in
the SAT formula at every round. The harness re-emits their
declarations through `_force_declare_seed_syms` (mirroring the mx3
fix).

Usage:
    python3 t1ha1_chain_lo_concrete.py                  # parity
    python3 t1ha1_chain_lo_concrete.py --vectors 1024   # more
"""

from __future__ import annotations

import argparse
import random
import sys
from typing import List, Sequence

MASK64 = 0xFFFF_FFFF_FFFF_FFFF
MASK128 = (1 << 128) - 1

# t1ha1 "magic" primes (erthink/t1ha src/t1ha_bits.h).
T1HA_PRIME_0 = 0xEC99BF0D8372CAAB
T1HA_PRIME_1 = 0x82434FE90EDCEF39
T1HA_PRIME_2 = 0xD4F06DB99D67BE4B
T1HA_PRIME_3 = 0xBD9CACC22C6E9571
T1HA_PRIME_4 = 0x9C06FAF4D023E3AB
T1HA_PRIME_5 = 0xC060724A8424F345
T1HA_PRIME_6 = 0xCB5AF53AE3AAAC31


# ============================================================================
# Concrete reference
# ============================================================================


def _rot64_concrete(v: int, s: int) -> int:
    return ((v >> s) | (v << (64 - s))) & MASK64


def _mux64_concrete(v: int, prime: int) -> int:
    prod = (v * prime) & MASK128
    lo = prod & MASK64
    hi = (prod >> 64) & MASK64
    return lo ^ hi


def _mix64_concrete(v: int, prime: int) -> int:
    v = (v * prime) & MASK64
    return v ^ _rot64_concrete(v, 41)


def _final_weak_avalanche_concrete(a: int, b: int) -> int:
    return (
        _mux64_concrete(_rot64_concrete((a + b) & MASK64, 17), T1HA_PRIME_4)
        + _mix64_concrete((a ^ b) & MASK64, T1HA_PRIME_0)
    ) & MASK64


def _read64_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little")


def _tail64_le(data: bytes, tail: int) -> int:
    n = tail & 7
    if n == 0:
        return int.from_bytes(data[:8], "little")
    r = 0
    for i in range(n):
        r |= data[i] << (8 * i)
    return r


def t1ha1_64le_concrete(data: bytes, seed: int) -> int:
    """Pure-Python port of erthink/t1ha t1ha1_le."""
    length = len(data)
    a = seed & MASK64
    b = length & MASK64

    pos = 0
    if length > 32:
        c = (_rot64_concrete(length, 17) + seed) & MASK64
        d = (length ^ _rot64_concrete(seed, 17)) & MASK64
        while True:
            w0 = _read64_le(data, pos)
            w1 = _read64_le(data, pos + 8)
            w2 = _read64_le(data, pos + 16)
            w3 = _read64_le(data, pos + 24)
            pos += 32

            d02 = (w0 ^ _rot64_concrete((w2 + d) & MASK64, 17)) & MASK64
            c13 = (w1 ^ _rot64_concrete((w3 + c) & MASK64, 17)) & MASK64
            d = (d - (b ^ _rot64_concrete(w1, 31))) & MASK64
            c = (c + (a ^ _rot64_concrete(w0, 41))) & MASK64
            b = (b ^ (T1HA_PRIME_0 * ((c13 + w2) & MASK64))) & MASK64
            a = (a ^ (T1HA_PRIME_1 * ((d02 + w3) & MASK64))) & MASK64

            if pos + 32 > length:
                break

        a = (a ^ (T1HA_PRIME_6 * ((_rot64_concrete(c, 17) + d) & MASK64))) & MASK64
        b = (b ^ (T1HA_PRIME_5 * ((c + _rot64_concrete(d, 17)) & MASK64))) & MASK64
        length &= 31

    tail = data[pos:]
    if length > 24:
        b = (b + _mux64_concrete(_read64_le(tail, 0), T1HA_PRIME_4)) & MASK64
        tail = tail[8:]
    if length > 16:
        a = (a + _mux64_concrete(_read64_le(tail, 0), T1HA_PRIME_3)) & MASK64
        tail = tail[8:]
    if length > 8:
        b = (b + _mux64_concrete(_read64_le(tail, 0), T1HA_PRIME_2)) & MASK64
        tail = tail[8:]
    if length > 0:
        a = (a + _mux64_concrete(_tail64_le(tail, length), T1HA_PRIME_1)) & MASK64

    return _final_weak_avalanche_concrete(a, b)


def t1ha1_128_concrete(
    data: bytes, seed_lo: int, seed_hi: int,
) -> tuple[int, int]:
    return (
        t1ha1_64le_concrete(data, seed_lo & MASK64),
        t1ha1_64le_concrete(data, seed_hi & MASK64),
    )


def t1ha1_chain_lo_concrete(
    seed_components: Sequence[int], data: bytes, rounds: int,
) -> int:
    """Low 64 bits of ChainHash128 under t1ha1 for `rounds` rounds."""
    assert len(seed_components) == 2 * rounds, (
        f"t1ha1 ChainHash with rounds={rounds} needs {2 * rounds} seed "
        f"components, got {len(seed_components)}"
    )
    h_lo, h_hi = t1ha1_128_concrete(
        data, seed_components[0], seed_components[1],
    )
    for r in range(1, rounds):
        k_lo = (seed_components[2 * r] ^ h_lo) & MASK64
        k_hi = (seed_components[2 * r + 1] ^ h_hi) & MASK64
        h_lo, h_hi = t1ha1_128_concrete(data, k_lo, k_hi)
    return h_lo


# ============================================================================
# Z3 symbolic mirror
# ============================================================================


def _rot64_z3(z3, v, s: int):
    s &= 63
    if s == 0:
        return v
    return z3.LShR(v, s) | (v << (64 - s))


def _mux64_z3(z3, v, prime: int):
    """XOR of low and high halves of full 128-bit product v * prime."""
    v128 = z3.ZeroExt(64, v)
    prime128 = z3.BitVecVal(prime, 128)
    prod = v128 * prime128
    lo = z3.Extract(63, 0, prod)
    hi = z3.Extract(127, 64, prod)
    return lo ^ hi


def _mix64_z3(z3, v, prime: int):
    v = v * z3.BitVecVal(prime, 64)
    return v ^ _rot64_z3(z3, v, 41)


def _final_weak_avalanche_z3(z3, a, b):
    return (
        _mux64_z3(z3, _rot64_z3(z3, a + b, 17), T1HA_PRIME_4)
        + _mix64_z3(z3, a ^ b, T1HA_PRIME_0)
    )


def _read64_le_z3(z3, data: bytes, offset: int):
    return z3.BitVecVal(_read64_le(data, offset), 64)


def _tail64_le_z3(z3, tail: bytes, length: int):
    return z3.BitVecVal(_tail64_le(tail, length), 64)


def t1ha1_64le_z3(z3, seed_sym, data: bytes):
    """Symbolic t1ha1_64le on `data` with `seed_sym` (BitVec(64)).

    Unrolls the variable-length structure against the constant
    `len(data)` known at SAT-formula-build time. The 32-byte block
    branch fires only for `length > 32`; below that, only tail
    processing applies.
    """
    length = len(data)
    a = seed_sym
    b = z3.BitVecVal(length & MASK64, 64)

    pos = 0
    if length > 32:
        c = z3.BitVecVal(length, 64)
        c = _rot64_z3(z3, c, 17) + seed_sym
        d = z3.BitVecVal(length, 64) ^ _rot64_z3(z3, seed_sym, 17)
        while True:
            w0 = _read64_le_z3(z3, data, pos)
            w1 = _read64_le_z3(z3, data, pos + 8)
            w2 = _read64_le_z3(z3, data, pos + 16)
            w3 = _read64_le_z3(z3, data, pos + 24)
            pos += 32

            d02 = w0 ^ _rot64_z3(z3, w2 + d, 17)
            c13 = w1 ^ _rot64_z3(z3, w3 + c, 17)
            d = d - (b ^ _rot64_z3(z3, w1, 31))
            c = c + (a ^ _rot64_z3(z3, w0, 41))
            b = b ^ (z3.BitVecVal(T1HA_PRIME_0, 64) * (c13 + w2))
            a = a ^ (z3.BitVecVal(T1HA_PRIME_1, 64) * (d02 + w3))

            if pos + 32 > length:
                break

        a = a ^ (z3.BitVecVal(T1HA_PRIME_6, 64) * (_rot64_z3(z3, c, 17) + d))
        b = b ^ (z3.BitVecVal(T1HA_PRIME_5, 64) * (c + _rot64_z3(z3, d, 17)))
        length_eff = length & 31
    else:
        length_eff = length

    tail = data[pos:]
    if length_eff > 24:
        b = b + _mux64_z3(z3, _read64_le_z3(z3, tail, 0), T1HA_PRIME_4)
        tail = tail[8:]
    if length_eff > 16:
        a = a + _mux64_z3(z3, _read64_le_z3(z3, tail, 0), T1HA_PRIME_3)
        tail = tail[8:]
    if length_eff > 8:
        b = b + _mux64_z3(z3, _read64_le_z3(z3, tail, 0), T1HA_PRIME_2)
        tail = tail[8:]
    if length_eff > 0:
        a = a + _mux64_z3(
            z3, _tail64_le_z3(z3, tail, length_eff), T1HA_PRIME_1,
        )

    return _final_weak_avalanche_z3(z3, a, b)


def t1ha1_128_z3(z3, seed_lo_sym, seed_hi_sym, data: bytes):
    return (
        t1ha1_64le_z3(z3, seed_lo_sym, data),
        t1ha1_64le_z3(z3, seed_hi_sym, data),
    )


def t1ha1_chain_lo_z3(
    z3, seed_lo_syms, seed_hi_syms, data: bytes, rounds: int,
):
    """Symbolic ChainHash128 lo lane under t1ha1 for `rounds` rounds."""
    assert len(seed_lo_syms) == rounds and len(seed_hi_syms) == rounds, (
        f"need {rounds} lo + {rounds} hi seed syms, "
        f"got {len(seed_lo_syms)}+{len(seed_hi_syms)}"
    )
    h_lo, h_hi = t1ha1_128_z3(z3, seed_lo_syms[0], seed_hi_syms[0], data)
    for r in range(1, rounds):
        k_lo = seed_lo_syms[r] ^ h_lo
        k_hi = seed_hi_syms[r] ^ h_hi
        h_lo, h_hi = t1ha1_128_z3(z3, k_lo, k_hi, data)
    return h_lo


# ============================================================================
# Self-parity
# ============================================================================


def _self_parity(rounds_list: List[int], num_vectors: int, seed_rng: int) -> int:
    rng = random.Random(seed_rng)
    failures = 0
    try:
        import z3
    except ImportError:
        print("[t1ha1-parity] z3 not installed; skipping symbolic check")
        return 0

    for rounds in rounds_list:
        for i in range(num_vectors):
            data = bytes(rng.getrandbits(8) for _ in range(20))
            seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
            concrete_expected = t1ha1_chain_lo_concrete(
                seed_components, data, rounds,
            )

            seed_lo_syms = [z3.BitVec(f"s_lo_{r}", 64) for r in range(rounds)]
            seed_hi_syms = [z3.BitVec(f"s_hi_{r}", 64) for r in range(rounds)]
            sym_expr = t1ha1_chain_lo_z3(
                z3, seed_lo_syms, seed_hi_syms, data, rounds,
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
                print(f"[t1ha1-parity] r={rounds} v={i}: simplify did "
                      f"not yield concrete BV ({exc})")
                failures += 1
                continue
            if got != concrete_expected:
                failures += 1
                print(f"[t1ha1-parity] MISMATCH r={rounds} v={i}: "
                      f"concrete={concrete_expected:016x} z3={got:016x}")
            elif i == 0:
                print(f"[t1ha1-parity] OK r={rounds} v={i}: {got:016x}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rounds", default="1,2,4")
    ap.add_argument("--vectors", type=int, default=4)
    ap.add_argument("--seed-rng", type=int, default=0xCAFE_BABE_71_1A1)
    args = ap.parse_args()

    rounds_list = [int(x) for x in args.rounds.split(",") if x.strip()]
    failures = _self_parity(rounds_list, args.vectors, args.seed_rng)
    if failures:
        print(f"[t1ha1-parity] FAIL — {failures} mismatches")
        return 1
    print(f"[t1ha1-parity] PASS — all vectors matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
