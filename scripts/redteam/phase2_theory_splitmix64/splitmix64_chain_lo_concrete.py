#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parity gadget for the SplitMix64 SAT calibration (HARNESS.md pre-screen).

SplitMix64 is the avalanche/differential pre-screen's INVERTIBLE control
(chainhashes/splitmix64.py, `INVERTIBLE = True`): its mix64 is a composition
of word-level bijections, so the pre-screen predicts the ChainHash lo-lane is
solver-tractable at the primitive layer despite ideal avalanche / differential
/ degree columns. This module supplies the two implementations the Axis C SAT
harness needs to test that prediction empirically:

  (a) splitmix64_chain_lo_concrete — pure-Python forward, mirroring
      chainhashes/splitmix64.py byte-for-byte (parity-asserted in the
      self-test against that module's splitmix64_hash) at a variable round
      count.
  (b) splitmix64_chain_lo_z3 — symbolic Z3 BitVec(64) expression for the same
      lo-lane cascade. The lo output depends ONLY on the lo-lane seed
      components (the two lanes are independent and only lo feeds forward into
      lo), so the hi seeds never enter the lo expression — the symbolic build
      computes the lo recursion alone, leaving the hi symbols free (the
      harness force-declares them for the model query).

mix64 is invertible step by step: each `z ^= z >> k` is recoverable by
top-down bit reconstruction and each `z *= M` (M odd) by the modular inverse.
Tier 3/4 SAT recovery at modest observation count is therefore the
structurally expected outcome — the empirical analogue of the FNV-1a Phase 2g
break, in xorshift-multiply algebra rather than a carry chain.

Usage:
    python3 splitmix64_chain_lo_concrete.py            # self-parity test
    python3 splitmix64_chain_lo_concrete.py --vectors 256
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from typing import List, Sequence

# Reuse the exact primitive the pre-screen measures (single source of truth).
_CHAINHASHES_PARENT = Path(__file__).resolve().parent.parent / "phase2_theory"
if str(_CHAINHASHES_PARENT) not in sys.path:
    sys.path.insert(0, str(_CHAINHASHES_PARENT))
from chainhashes.splitmix64 import (  # type: ignore
    M1,
    M2,
    MASK64,
    mix64,
    splitmix64_hash,
)


# ============================================================================
# Concrete reference — variable-round lo-lane chain over splitmix64_hash
# ============================================================================


def splitmix64_chain_lo_concrete(
    seed_components: Sequence[int], data: bytes, rounds: int,
) -> int:
    """Low 64 bits of the two-lane ChainHash under splitmix64 for `rounds`
    rounds.

    seed_components: flat [s0_lo, s0_hi, s1_lo, s1_hi, ...] of 2*rounds u64.
    Only the lo components affect the returned lo output; the hi components
    are carried for layout parity with the other primitives' harnesses.
    """
    assert len(seed_components) == 2 * rounds, (
        f"splitmix64 ChainHash rounds={rounds} needs {2 * rounds} seed "
        f"components, got {len(seed_components)}"
    )
    h_lo = splitmix64_hash(data, seed_components[0] & MASK64)
    for r in range(1, rounds):
        k_lo = (seed_components[2 * r] ^ h_lo) & MASK64
        h_lo = splitmix64_hash(data, k_lo)
    return h_lo & MASK64


# ============================================================================
# Z3 symbolic mirror
# ============================================================================


def _mix64_z3(z3, z):
    """Symbolic SplitMix64 mix64 on a 64-bit BitVec."""
    z = (z ^ z3.LShR(z, 30)) * z3.BitVecVal(M1, 64)
    z = (z ^ z3.LShR(z, 27)) * z3.BitVecVal(M2, 64)
    z = z ^ z3.LShR(z, 31)
    return z


def _splitmix64_hash_z3(z3, seed_sym, data: bytes):
    """Symbolic splitmix64_hash: fold each data byte through mix64, then the
    length. Mirrors chainhashes/splitmix64.py.splitmix64_hash."""
    h = seed_sym
    for b in data:
        h = _mix64_z3(z3, h ^ z3.BitVecVal(b, 64))
    h = _mix64_z3(z3, h ^ z3.BitVecVal(len(data) & MASK64, 64))
    return h


def splitmix64_chain_lo_z3(
    z3, seed_lo_syms, seed_hi_syms, data: bytes, rounds: int,
    encoding: str = "native",
):
    """Symbolic ChainHash lo lane under splitmix64 for `rounds` rounds.

    Only the lo recursion is built — the lo output is independent of every hi
    seed (the lanes are independent, lo feeds forward only into lo). `encoding`
    is accepted for harness-call compatibility and ignored (splitmix64's only
    multiplications are by the odd constants M1 / M2, which Z3's native BVMul
    bit-blasts directly; there is no wide-constant case to decompose)."""
    assert len(seed_lo_syms) == rounds, (
        f"need {rounds} lo seed syms, got {len(seed_lo_syms)}")
    h_lo = _splitmix64_hash_z3(z3, seed_lo_syms[0], data)
    for r in range(1, rounds):
        k_lo = seed_lo_syms[r] ^ h_lo
        h_lo = _splitmix64_hash_z3(z3, k_lo, data)
    return h_lo


# ============================================================================
# Self-parity — concrete vs the screen primitive, and concrete vs symbolic
# ============================================================================


def _self_parity(rounds_list: List[int], num_vectors: int, seed_rng: int) -> int:
    rng = random.Random(seed_rng)
    failures = 0

    # (1) concrete chain at rounds=1 must equal the screen primitive directly.
    for _ in range(64):
        data = bytes(rng.getrandbits(8) for _ in range(20))
        s = rng.getrandbits(64)
        if splitmix64_chain_lo_concrete([s, 0], data, 1) != splitmix64_hash(data, s):
            print("[splitmix64-parity] concrete rounds=1 != splitmix64_hash")
            failures += 1

    try:
        import z3
    except ImportError:
        print("[splitmix64-parity] z3 not installed; concrete-only checks done")
        return failures

    # (2) concrete vs symbolic across rounds.
    for rounds in rounds_list:
        for i in range(num_vectors):
            data = bytes(rng.getrandbits(8) for _ in range(20))
            seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
            expected = splitmix64_chain_lo_concrete(seed_components, data, rounds)
            lo_syms = [z3.BitVec(f"s_lo_{r}", 64) for r in range(rounds)]
            hi_syms = [z3.BitVec(f"s_hi_{r}", 64) for r in range(rounds)]
            expr = splitmix64_chain_lo_z3(z3, lo_syms, hi_syms, data, rounds)
            subs = [(lo_syms[r], z3.BitVecVal(seed_components[2 * r], 64))
                    for r in range(rounds)]
            got = z3.simplify(z3.substitute(expr, *subs)).as_long() & MASK64
            if got != expected:
                failures += 1
                print(f"[splitmix64-parity] MISMATCH r={rounds} v={i}: "
                      f"concrete={expected:016x} z3={got:016x}")
            elif i == 0:
                print(f"[splitmix64-parity] OK r={rounds}: {got:016x}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rounds", default="1,2,4")
    ap.add_argument("--vectors", type=int, default=8)
    ap.add_argument("--seed-rng", type=int, default=0x5350_4C49_544D_5836)  # "SPLITMX6"
    args = ap.parse_args()
    rounds_list = [int(x) for x in args.rounds.split(",") if x.strip()]
    failures = _self_parity(rounds_list, args.vectors, args.seed_rng)
    if failures:
        print(f"[splitmix64-parity] FAIL — {failures} mismatches")
        return 1
    print("[splitmix64-parity] PASS — all vectors matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
