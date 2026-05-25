#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parity gadget for the MurmurHash3 SAT calibration (HARNESS.md pre-screen).

MurmurHash3 is the pre-screen's `inv = ?` contrast to the invertible control
splitmix64: it reads clean on every avalanche / differential / degree column
AND the screen declares no cheap structural inverse, so the pre-screen
verdict is "defer to the SAT calibration" rather than a prediction either
way. This module supplies the two implementations Axis C needs to settle it
empirically:

  (a) murmur3_chain_lo_concrete — pure-Python forward, the lo lane built on
      the screen primitive chainhashes/murmur3.py.murmur3_x64_128 (single
      source of truth; parity-asserted in the self-test).
  (b) murmur3_chain_lo_z3 — symbolic Z3 BitVec(64) expression for the lo
      lane. As with the other two-lane primitives, the chain lo output is a
      function of the lo seeds only; within one MurmurHash3_x64_128 both
      internal accumulators h1 / h2 contribute to the low half (h1), so the
      symbolic build carries both internal lanes of a single hash but only
      the lo SEED recursion across rounds.

Unlike splitmix64 (a designed bijection) MurmurHash3 carries no documented
solver-exploitable shortcut; whether the lo seed is SAT-recoverable at
modest observation count is the open question this calibration answers.

Usage:
    python3 murmur3_chain_lo_concrete.py            # self-parity test
    python3 murmur3_chain_lo_concrete.py --vectors 256
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import List, Sequence

_CHAINHASHES_PARENT = Path(__file__).resolve().parent.parent / "phase2_theory"
if str(_CHAINHASHES_PARENT) not in sys.path:
    sys.path.insert(0, str(_CHAINHASHES_PARENT))
from chainhashes.murmur3 import (  # type: ignore
    C1,
    C2,
    MASK64,
    murmur3_x64_128,
)


# ============================================================================
# Concrete reference — variable-round lo-lane chain over murmur3_x64_128 (h1)
# ============================================================================


def murmur3_chain_lo_concrete(
    seed_components: Sequence[int], data: bytes, rounds: int,
) -> int:
    """Low 64 bits of the two-lane ChainHash under MurmurHash3 for `rounds`
    rounds. The lo output is the h1 (low) half of MurmurHash3_x64_128 on each
    lo-seed; only the lo components affect it."""
    assert len(seed_components) == 2 * rounds, (
        f"murmur3 ChainHash rounds={rounds} needs {2 * rounds} seed "
        f"components, got {len(seed_components)}")
    h_lo, _ = murmur3_x64_128(data, seed_components[0] & MASK64)
    for r in range(1, rounds):
        k_lo = (seed_components[2 * r] ^ h_lo) & MASK64
        h_lo, _ = murmur3_x64_128(data, k_lo)
    return h_lo & MASK64


# ============================================================================
# Z3 symbolic mirror
# ============================================================================


def _rotl64_z3(z3, x, r: int):
    return (x << r) | z3.LShR(x, 64 - r)


def _fmix64_z3(z3, k):
    k = k ^ z3.LShR(k, 33)
    k = k * z3.BitVecVal(0xFF51AFD7ED558CCD, 64)
    k = k ^ z3.LShR(k, 33)
    k = k * z3.BitVecVal(0xC4CEB9FE1A85EC53, 64)
    k = k ^ z3.LShR(k, 33)
    return k


def _murmur3_x64_128_h1_z3(z3, seed_sym, data: bytes):
    """Symbolic MurmurHash3_x64_128 low half (h1) on `data` with `seed_sym`
    (BitVec(64)). Mirrors chainhashes/murmur3.py.murmur3_x64_128. Data is
    fixed at formula-build time, so every k1 / k2 / tail term is a constant."""
    length = len(data)
    nblocks = length // 16
    C1v = z3.BitVecVal(C1, 64)
    C2v = z3.BitVecVal(C2, 64)
    h1 = seed_sym
    h2 = seed_sym

    for i in range(nblocks):
        base = i * 16
        k1 = z3.BitVecVal(int.from_bytes(data[base:base + 8], "little"), 64)
        k2 = z3.BitVecVal(int.from_bytes(data[base + 8:base + 16], "little"), 64)
        k1 = k1 * C1v
        k1 = _rotl64_z3(z3, k1, 31)
        k1 = k1 * C2v
        h1 = h1 ^ k1
        h1 = _rotl64_z3(z3, h1, 27)
        h1 = h1 + h2
        h1 = h1 * z3.BitVecVal(5, 64) + z3.BitVecVal(0x52DCE729, 64)
        k2 = k2 * C2v
        k2 = _rotl64_z3(z3, k2, 33)
        k2 = k2 * C1v
        h2 = h2 ^ k2
        h2 = _rotl64_z3(z3, h2, 31)
        h2 = h2 + h1
        h2 = h2 * z3.BitVecVal(5, 64) + z3.BitVecVal(0x38495AB5, 64)

    tail = data[nblocks * 16:]
    tl = len(tail)
    k1c = 0
    k2c = 0
    if tl >= 15:
        k2c ^= tail[14] << 48
    if tl >= 14:
        k2c ^= tail[13] << 40
    if tl >= 13:
        k2c ^= tail[12] << 32
    if tl >= 12:
        k2c ^= tail[11] << 24
    if tl >= 11:
        k2c ^= tail[10] << 16
    if tl >= 10:
        k2c ^= tail[9] << 8
    if tl >= 9:
        k2c ^= tail[8]
        k2e = z3.BitVecVal(k2c & MASK64, 64) * C2v
        k2e = _rotl64_z3(z3, k2e, 33)
        k2e = k2e * C1v
        h2 = h2 ^ k2e
    if tl >= 8:
        k1c ^= tail[7] << 56
    if tl >= 7:
        k1c ^= tail[6] << 48
    if tl >= 6:
        k1c ^= tail[5] << 40
    if tl >= 5:
        k1c ^= tail[4] << 32
    if tl >= 4:
        k1c ^= tail[3] << 24
    if tl >= 3:
        k1c ^= tail[2] << 16
    if tl >= 2:
        k1c ^= tail[1] << 8
    if tl >= 1:
        k1c ^= tail[0]
        k1e = z3.BitVecVal(k1c & MASK64, 64) * C1v
        k1e = _rotl64_z3(z3, k1e, 31)
        k1e = k1e * C2v
        h1 = h1 ^ k1e

    lenv = z3.BitVecVal(length & MASK64, 64)
    h1 = h1 ^ lenv
    h2 = h2 ^ lenv
    h1 = h1 + h2
    h2 = h2 + h1
    h1 = _fmix64_z3(z3, h1)
    h2 = _fmix64_z3(z3, h2)
    h1 = h1 + h2
    # h2 = h2 + h1  — not needed; we return only h1 (the low half).
    return h1


def murmur3_chain_lo_z3(
    z3, seed_lo_syms, seed_hi_syms, data: bytes, rounds: int,
    encoding: str = "native",
):
    """Symbolic ChainHash lo lane under MurmurHash3 for `rounds` rounds.
    Only the lo recursion is built — the lo output is independent of every hi
    seed. `encoding` is accepted for harness-call compatibility and ignored
    (the only multiplications are by the fixed Murmur constants; Z3's native
    BVMul bit-blasts them directly)."""
    assert len(seed_lo_syms) == rounds, (
        f"need {rounds} lo seed syms, got {len(seed_lo_syms)}")
    h_lo = _murmur3_x64_128_h1_z3(z3, seed_lo_syms[0], data)
    for r in range(1, rounds):
        k_lo = seed_lo_syms[r] ^ h_lo
        h_lo = _murmur3_x64_128_h1_z3(z3, k_lo, data)
    return h_lo


# ============================================================================
# Self-parity — concrete vs the screen primitive, and concrete vs symbolic
# ============================================================================


def _self_parity(rounds_list: List[int], num_vectors: int, seed_rng: int) -> int:
    rng = random.Random(seed_rng)
    failures = 0
    for _ in range(64):
        data = bytes(rng.getrandbits(8) for _ in range(20))
        s = rng.getrandbits(64)
        lo, _ = murmur3_x64_128(data, s)
        if murmur3_chain_lo_concrete([s, 0], data, 1) != lo:
            print("[murmur3-parity] concrete rounds=1 != murmur3_x64_128 h1")
            failures += 1

    try:
        import z3
    except ImportError:
        print("[murmur3-parity] z3 not installed; concrete-only checks done")
        return failures

    for rounds in rounds_list:
        for i in range(num_vectors):
            data = bytes(rng.getrandbits(8) for _ in range(20))
            seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
            expected = murmur3_chain_lo_concrete(seed_components, data, rounds)
            lo_syms = [z3.BitVec(f"s_lo_{r}", 64) for r in range(rounds)]
            hi_syms = [z3.BitVec(f"s_hi_{r}", 64) for r in range(rounds)]
            expr = murmur3_chain_lo_z3(z3, lo_syms, hi_syms, data, rounds)
            subs = [(lo_syms[r], z3.BitVecVal(seed_components[2 * r], 64))
                    for r in range(rounds)]
            got = z3.simplify(z3.substitute(expr, *subs)).as_long() & MASK64
            if got != expected:
                failures += 1
                print(f"[murmur3-parity] MISMATCH r={rounds} v={i}: "
                      f"concrete={expected:016x} z3={got:016x}")
            elif i == 0:
                print(f"[murmur3-parity] OK r={rounds}: {got:016x}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rounds", default="1,2,4")
    ap.add_argument("--vectors", type=int, default=8)
    ap.add_argument("--seed-rng", type=int, default=0x4D55524D55523358)  # "MURMUR3X"
    args = ap.parse_args()
    rounds_list = [int(x) for x in args.rounds.split(",") if x.strip()]
    failures = _self_parity(rounds_list, args.vectors, args.seed_rng)
    if failures:
        print(f"[murmur3-parity] FAIL — {failures} mismatches")
        return 1
    print("[murmur3-parity] PASS — all vectors matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
