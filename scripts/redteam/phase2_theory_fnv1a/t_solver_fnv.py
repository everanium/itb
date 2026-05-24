#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Structure-aware solver for the FNV-1a lo-lane ChainHash seed-recovery — a
hand-written alternative to the generic z3 / bitwuzla backends in
sat_calibration_raw_fnv.py.

STRUCTURE
---------
The FNV-1a lo-lane chain (fnv_chain_lo_concrete) is a T-function in the seed
bits: every operation is XOR (with a data byte, or with the previous round's
output) or multiply by the constant 0x13B mod 2^64, and multiply-by-constant
propagates carries UPWARD only. So output bit t depends only on input bits
0..t, and the whole seed -> hLo map is triangular. That invites an LSB -> MSB
plane-by-plane recovery.

THE FEEDFORWARD WRINKLE (why it is not a one-pass linear solve)
--------------------------------------------------------------
For a single round the per-plane system is full rank and the seed falls out
directly. For two or more rounds the round-to-round feedforward
(state_r = seed[r] XOR h_{r-1}) makes the LINEAR part of plane t collapse to
rank 1: output bit t = (XOR over all r of seed[r][t]) XOR c, where c is a
constant fixed by the already-known lower bits. One plane therefore pins only
the XOR of that plane's seed bits, leaving R-1 bits free. The individual bits
are disambiguated NOT within the plane but ACROSS planes: the multiply's carry
out of bit t into bit t+1 depends on how many of the bit-t's are set (the
integer sum), not merely on their parity, so a wrong choice of individual bits
at plane t perturbs the carry and shows up as an inconsistency a plane or two
higher. (Empirically confirmed: a naive free-bits-zero plane solve cascades to
contradiction; z3 reports a non-ground-truth but observation-consistent seed;
the ground-truth seed is recoverable but the class is small, not a singleton.)

ALGORITHM — DFS over planes with carry pruning
----------------------------------------------
Depth-first over t = 0..63. At each plane, with bits 0..t-1 committed:

  1. Read each observation's affine constant c_i (the forward output bit t with
     the plane's seed bits zeroed). All observations must agree on the required
     XOR value V = target_i[t] XOR c_i; a disagreement means the committed
     lower bits are wrong, so the branch is dead — backtrack.
  2. Enumerate the 2^(R-1) bit-t assignments whose XOR equals V and recurse.
     The recursion's own step-1 check at plane t+1 (whose constants depend on
     this plane's carries) prunes the wrong assignments, so the effective
     branch factor stays small when the carries are bit-sensitive.

At t = 64 the candidate seed is verified against every observation. The
solver returns the first observation-consistent seed it finds; whether that
equals the literal ground truth is solver order dependent (the recovered seed
reproduces the full keystream either way, which is what an attacker needs).

A node budget bounds the search so a pathological branch factor returns
"unknown" instead of hanging — the honest outcome to report rather than a
fabricated timeout.

SCOPE: FNV-1a only. The technique rests on the carry-up-only T-function
structure that mx3 / BLAKE / real mixers break with right-shifts; it does not
generalise, and is not a generic ChainHash attack.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from fnv_chain_lo_concrete import fnv_chain_lo_concrete  # type: ignore

MASK64 = (1 << 64) - 1

# Default ceiling on DFS nodes visited before giving up. Generous enough for a
# small branch factor across 64 planes; trips only if the carries fail to prune.
DEFAULT_NODE_BUDGET = 20_000_000


def solve_via_tsolver(
    rounds: int, observations: Sequence, node_budget: int = DEFAULT_NODE_BUDGET
) -> Tuple[str, List[int]]:
    """Recover a `rounds`-word lo-lane seed reproducing every observation.

    observations: a sequence of objects with `.data_bytes` (bytes) and
    `.target_hlo` (int), matching sat_calibration_raw_fnv.Observation.

    Returns ("sat", seed) on success, or ("unknown", []) if the node budget is
    exhausted (no observation-consistent seed found within budget).
    """
    obs: List[Tuple[bytes, int]] = [
        (o.data_bytes, o.target_hlo) for o in observations
    ]
    seed = [0] * rounds
    nodes = [0]

    def rec(t: int) -> bool:
        if t == 64:
            return all(
                fnv_chain_lo_concrete(seed, d, rounds) == tg for d, tg in obs
            )
        nodes[0] += 1
        if nodes[0] > node_budget:
            return False

        # Step 1: agreement check. With this plane's seed bits zeroed, read each
        # observation's affine constant and require a single XOR value V.
        V = -1
        for d, tg in obs:
            c = (fnv_chain_lo_concrete(seed, d, rounds) >> t) & 1
            v = ((tg >> t) & 1) ^ c
            if V == -1:
                V = v
            elif V != v:
                return False  # dead branch — committed lower bits are wrong

        # Step 2: try each XOR==V assignment of this plane's R seed bits.
        for bits in range(1 << rounds):
            if (bin(bits).count("1") & 1) != V:
                continue
            for j in range(rounds):
                if (bits >> j) & 1:
                    seed[j] |= (1 << t)
            if rec(t + 1):
                return True
            for j in range(rounds):
                seed[j] &= ~(1 << t)
        return False

    if rec(0):
        return "sat", [s & MASK64 for s in seed]
    return "unknown", []
