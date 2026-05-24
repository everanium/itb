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

MASK64 = (1 << 64) - 1
P_LO = 0x13B  # low 64 bits of FNV_PRIME_128 (the only part reaching hLo)


def _chain_fast(seed, data: bytes, rounds: int) -> int:
    """Bit-exact, fast forward of the FNV-1a lo-lane ChainHash.

    Mirrors fnv_chain_lo_concrete but uses the native modular multiply
    `s * 0x13B mod 2^64` instead of the shift-and-add decomposition that
    module carries for the z3 symbolic encoding, and inlines the byte loop
    with no per-call assert. The shift-add and native forms are equal mod
    2^64 (verified by fnv_chain_lo_concrete._check_mul_equivalence), so the
    solver output is identical; the calibration's match / holdout checks are
    the parity gate.
    """
    h = 0
    for r in range(rounds):
        s = seed[r] & MASK64 if r == 0 else (seed[r] ^ h) & MASK64
        for b in data:
            s = ((s ^ b) * P_LO) & MASK64
        h = s
    return h

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
                _chain_fast(seed, d, rounds) == tg for d, tg in obs
            )
        nodes[0] += 1
        if nodes[0] > node_budget:
            return False

        # Step 1: agreement check. With this plane's seed bits zeroed, read each
        # observation's affine constant and require a single XOR value V.
        V = -1
        for d, tg in obs:
            c = (_chain_fast(seed, d, rounds) >> t) & 1
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


def solve_via_tsolver_masked(
    rounds: int, observations: Sequence, node_budget: int = DEFAULT_NODE_BUDGET,
    leaf_check=None, max_plane: int = 64,
) -> Tuple[str, List[int]]:
    """Masked variant for the ITB barrier hybrid (Level 2).

    Each observation carries only PART of its hLo: the ITB channel projection
    `hLo >> 3 & 0x7F` per channel reveals dataHash bits 3..58 (for the known
    channels of a crib pixel) but not bits 0..2 (used by rotation = dataHash %
    7, not the xorMask) nor, cleanly, the kernel bit 63. So an observation is
    `(data_bytes, target_hlo, known_mask)`: `known_mask` has a 1 in every hLo
    bit position the barrier layer recovered.

    The plane solve is the same LSB -> MSB DFS, with two changes:
      - At plane t, only observations with bit t known (`known_mask >> t & 1`)
        contribute to the agreement check.
      - A plane where NO observation knows bit t is vacuous: the XOR value V is
        unconstrained, so both V = 0 and V = 1 are tried (the low bits 0..2 are
        such planes; higher planes are richly covered and prune the fan-out).

    At the leaf the candidate seed is verified on the KNOWN bits of every
    observation. Functional equivalence (reproducing future ciphertext) is the
    caller's concern; bit 63 of a lane may differ — it is architecturally
    unobservable through the channel projection.
    """
    obs = [
        (o.data_bytes, o.target_hlo, o.known_mask) for o in observations
    ]
    seed = [0] * rounds
    nodes = [0]

    def rec(t: int) -> bool:
        if t == max_plane:
            # Stopping before plane 64 is a sound consistency check: if a seed
            # prefix reaches max_plane satisfying every known bit below it, the
            # unset higher bits are free, so a full seed exists. The propagator
            # uses max_plane = 59 (just past the observed channel range 3..58)
            # to test feasibility without enumerating the unobserved high bits.
            for d, tg, km in obs:
                if (_chain_fast(seed, d, rounds) ^ tg) & km & ((1 << max_plane) - 1):
                    return False
            # leaf_check (optional) pins the bits the channel projection leaves
            # unobserved — e.g. the rotation = dataHash % 7 constraint, which
            # constrains the low bits 0..2. Without it the seed reproduces the
            # channel projection but not the rotation, so a full decrypt would
            # rotate wrong; with it the recovered lo-lane matches bitwuzla's
            # bits 0..62.
            if leaf_check is not None:
                return leaf_check(seed)
            return True
        nodes[0] += 1
        if nodes[0] > node_budget:
            return False

        # Agreement over observations that know bit t. Vacuous if none do.
        bit = 1 << t
        Vs: List[int]
        V = -1
        for d, tg, km in obs:
            if not (km & bit):
                continue
            c = (_chain_fast(seed, d, rounds) >> t) & 1
            v = ((tg >> t) & 1) ^ c
            if V == -1:
                V = v
            elif V != v:
                return False  # dead branch
        Vs = [0, 1] if V == -1 else [V]

        for Vval in Vs:
            for bits in range(1 << rounds):
                if (bin(bits).count("1") & 1) != Vval:
                    continue
                for j in range(rounds):
                    if (bits >> j) & 1:
                        seed[j] |= bit
                if rec(t + 1):
                    return True
                for j in range(rounds):
                    seed[j] &= ~bit
        return False

    if rec(0):
        return "sat", [s & MASK64 for s in seed]
    return "unknown", []
