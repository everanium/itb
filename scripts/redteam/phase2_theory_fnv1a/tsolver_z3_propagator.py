#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prototype — Z3 user-propagator that injects the T-function solver as a
theory oracle into Z3's CDCL search for the ITB FNV-1a Level-2 break.

This is the attacker-realistic route the analysis pointed to: the full break
is the joint search over the barrier unknowns (per crib pixel: noise_pos and
rotation, 6 bits each pixel), and the structure-aware tsolver alone cannot
collapse it (naive enumeration is ~56^5, no better than Bitwuzla). Instead Z3
searches the barrier bits with CDCL clause learning, and a user-propagator
calls solve_via_tsolver_masked to supply FAST conflicts: as soon as enough
pixels have a fully-assigned (noise_pos, rotation), the propagator decodes the
implied dataHash bits and asks the tsolver whether ANY lo-lane seed fits them;
if not, it raises a conflict over exactly those fixed bits, so Z3 learns a
clause and prunes every assignment sharing that dead combination.

Attacker-realistic: the search uses only the public-schema cribs + the
ciphertext (via sat_harness_4round._build_cell_context) and the tsolver. The
lab seeds are read for the terminal audit line only, never in the search.

STATUS: research prototype — the mechanism works, but it does NOT beat
Bitwuzla. The propagator wiring is demonstrated (Z3 fires the fixed callback,
the tsolver returns conflicts, Z3's CDCL learns clauses). MEASURED: on a
6-pixel instance it does not converge within 300 s; ~1100 tsolver conflict
checks at ~0.26 s each. The bottleneck is the per-conflict UNSAT proof: the
masked tsolver is fast on SAT (first leaf) but slow on UNSAT (it must exhaust
the branching), and the carries are non-linear, so there is no GF(2) linear
shortcut for the consistency test (stopping at plane 59 to skip the
unobserved high bits did not help — the cost is the observed-range branching).
SOUNDNESS CAVEAT: conflicting on a node-budget-exhausted check is a heuristic,
not a verified UNSAT, so a budget-limited run can prune a real solution; it is
sound only when the check truly exhausts. Bitwuzla exposes no equivalent
user-propagator hook, which is why Z3 is the host here.

CONCLUSION (re-confirmed by analysis, naive search, and this propagator): the
barrier joint-search over the per-pixel noise_pos / rotation bits — the 90
ambiguity bits Bitwuzla solves inside its ~8 h run with a DISCLOSED startPixel
(Concession 1) — is the genuine cost of the ITB break. The structure-aware
tsolver collapses the ChainHash inversion (channel-decode given the barrier,
~0.16 s vs ~7.5 h) but does NOT collapse the barrier search, which is
primitive-independent defence. tsolver wins the sub-problem, not the war.

Usage:
    python3 tsolver_z3_propagator.py [--cell 0] [--max-cribs 4]
                                     [--pixels N] [--threshold K] [--timeout S]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

import z3

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from fnv_chain_lo_concrete import fnv_chain_lo_concrete  # type: ignore
import sat_harness_4round as bw  # _build_cell_context / ChannelObservation
import tsolver_harness_4round as th  # MaskedObs / _decode_pixel
from t_solver_fnv import solve_via_tsolver_masked  # type: ignore

MASK64 = (1 << 64) - 1


class TSolverPropagator(z3.UserPropagateBase):
    """Watches the per-pixel noise_pos / rotation bit-vectors; when at least
    `threshold` pixels are fully fixed, runs the masked tsolver over them and
    raises a conflict if no lo-lane seed is consistent."""

    def __init__(self, s, rounds, pixel_data, pixel_chans, np_terms, rot_terms,
                 threshold, ctx=None):
        super().__init__(s, ctx)
        self.rounds = rounds
        self.pixel_data = pixel_data      # pixel -> data_bytes
        self.pixel_chans = pixel_chans    # pixel -> [ChannelObservation]
        self.np_terms = np_terms          # pixel -> z3 term
        self.rot_terms = rot_terms        # pixel -> z3 term
        self.threshold = threshold
        self.n_pixels = len(pixel_data)

        # term-id -> (pixel, kind)
        self.lookup: Dict[int, Tuple[int, str]] = {}
        for p in range(self.n_pixels):
            self.lookup[np_terms[p].get_id()] = (p, "np")
            self.lookup[rot_terms[p].get_id()] = (p, "rot")

        self.fixed_np: Dict[int, int] = {}
        self.fixed_rot: Dict[int, int] = {}
        self.trail: List[Tuple[str, int]] = []
        self.lim: List[int] = []
        self.calls = 0
        self.conflicts = 0
        self.solution = None

        self.add_fixed(self._on_fixed)
        self.add_final(self._on_final)
        for p in range(self.n_pixels):
            self.add(np_terms[p])
            self.add(rot_terms[p])

    # --- backtracking bookkeeping (required by the API) ---
    def push(self):
        self.lim.append(len(self.trail))

    def pop(self, n):
        for _ in range(n):
            target = self.lim.pop()
            while len(self.trail) > target:
                kind, p = self.trail.pop()
                (self.fixed_np if kind == "np" else self.fixed_rot).pop(p, None)

    def fresh(self, new_ctx):
        # No sub-solver cloning needed for a single solve; return a stub that
        # shares the configuration. Z3 calls this for nested contexts.
        return TSolverPropagator(
            None, self.rounds, self.pixel_data, self.pixel_chans,
            self.np_terms, self.rot_terms, self.threshold, ctx=new_ctx,
        )

    # --- the theory hook ---
    def _fully_fixed_pixels(self) -> List[int]:
        return [p for p in range(self.n_pixels)
                if p in self.fixed_np and p in self.fixed_rot]

    def _on_fixed(self, term, value):
        info = self.lookup.get(term.get_id())
        if info is None:
            return
        p, kind = info
        v = value.as_long() if z3.is_bv_value(value) else int(str(value))
        if kind == "np":
            self.fixed_np[p] = v
        else:
            self.fixed_rot[p] = v
        self.trail.append((kind, p))

        ready = self._fully_fixed_pixels()
        if len(ready) < self.threshold:
            return

        # Decode the ready pixels and ask the tsolver for a consistent seed.
        masked = []
        for p in ready:
            hbits, mask = th._decode_pixel(
                self.pixel_chans[p], self.fixed_np[p], self.fixed_rot[p])
            masked.append(th.MaskedObs(self.pixel_data[p], hbits, mask))
        self.calls += 1
        # Fast feasibility: stop at plane 59 (just past the observed channel
        # range 3..58); the unobserved high bits are free, so reaching plane 59
        # proves a seed exists. Avoids enumerating bits 59..63.
        status, _ = solve_via_tsolver_masked(self.rounds, masked,
                                             node_budget=200_000, max_plane=59)
        if status != "sat":
            # No seed fits this (noise_pos, rotation) combination — conflict
            # over exactly the fixed barrier bits of the ready pixels.
            self.conflicts += 1
            deps = []
            for p in ready:
                deps.append(self.np_terms[p])
                deps.append(self.rot_terms[p])
            self.conflict(deps=deps)

    def _on_final(self):
        ready = self._fully_fixed_pixels()
        if len(ready) < self.n_pixels:
            return
        masked = []
        for p in range(self.n_pixels):
            hbits, mask = th._decode_pixel(
                self.pixel_chans[p], self.fixed_np[p], self.fixed_rot[p])
            masked.append(th.MaskedObs(self.pixel_data[p], hbits, mask))
        status, rec = solve_via_tsolver_masked(self.rounds, masked)
        if status == "sat":
            self.solution = rec
        else:
            deps = []
            for p in range(self.n_pixels):
                deps.append(self.np_terms[p])
                deps.append(self.rot_terms[p])
            self.conflict(deps=deps)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fnvstress-dir", default="tmp/attack/fnvstress")
    ap.add_argument("--cell", type=int, default=0)
    ap.add_argument("--max-cribs", type=int, default=4)
    ap.add_argument("--pixels", type=int, default=6,
                    help="limit to the first N full pixels (small-instance demo)")
    ap.add_argument("--threshold", type=int, default=5,
                    help="full pixels before the tsolver conflict check fires")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    fdir = Path(args.fnvstress_dir)
    summary = json.loads((fdir / "summary.json").read_text())
    rounds = int(summary["rounds"])
    cell_info = summary["cells"][args.cell]
    ctx = bw._build_cell_context(fdir, cell_info, args.cell, args.max_cribs,
                                 start_pixel_override=None)

    by_pixel: Dict[int, List] = defaultdict(list)
    for o in ctx.observations:
        by_pixel[o.p].append(o)
    full = sorted(p for p, c in by_pixel.items() if len(c) == 8)
    use = full[:args.pixels]

    pixel_data = {i: bw._pixel_data_bytes(p, ctx.nonce) for i, p in enumerate(use)}
    pixel_chans = {i: by_pixel[p] for i, p in enumerate(use)}

    s = z3.Solver()
    np_terms = {i: z3.BitVec(f"np_{i}", 3) for i in range(len(use))}
    rot_terms = {i: z3.BitVec(f"rot_{i}", 3) for i in range(len(use))}
    for i in range(len(use)):
        s.add(z3.ULT(rot_terms[i], 7))  # rotation in 0..6

    prop = TSolverPropagator(s, rounds, pixel_data, pixel_chans,
                             np_terms, rot_terms, args.threshold)
    s.set("timeout", args.timeout * 1000)

    print(f"cell={ctx.cell_name} start_pixel={ctx.start_pixel} "
          f"full_pixels_used={len(use)} threshold={args.threshold}")
    t0 = time.perf_counter()
    res = s.check()
    dt = time.perf_counter() - t0
    print(f"z3+propagator: {res} in {dt:.2f}s "
          f"(tsolver calls={prop.calls}, conflicts={prop.conflicts})")

    if prop.solution is not None:
        rec = prop.solution
        data_lo = [int(h, 16) for h in summary["data_lo_lane_hex"]]  # audit only
        mism = [bin((rec[j] ^ data_lo[j]) & ((1 << 63) - 1)).count("1")
                for j in range(rounds)]
        print(f"recovered lo-lane: {[f'{v:016x}' for v in rec]}")
        print(f"GT audit (bits 0..62 mismatch/lane): {mism}")
        return 0
    print("no solution recorded")
    return 1


if __name__ == "__main__":
    sys.exit(main())
