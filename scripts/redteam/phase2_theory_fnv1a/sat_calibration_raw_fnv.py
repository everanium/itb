#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 2 calibration: raw FNV-1a ChainHash lo-lane SAT inversion cost.

Pure-Python, no ITB involvement. The script synthesises its own
(seed_lo_vec, data_i, target_i) tuples, hands them to Z3 as constraints
on a symbolic seed, and measures wall-clock. Answers the question:

    "Can Z3 recover an N-round FNV-1a lo-lane seed from K synthetic
     hLo observations, and if so how fast?"

This isolates hash-chain inversion cost from every ITB encoding layer
(noise_pos ambiguity, rotation, byte->channel packing, startPixel
brute force, COBS anchor). If this bare harness fails to terminate on
4 rounds x 8 observations within reasonable wall-clock, the full ITB
harness (which adds all those layers on top) is a waste of compute.

Attacker-realism note: at this phase the script is its own universe -
it invents the seed, computes the observations, then asks Z3 to invert.
"Lab peek" does not apply: there is no defender, only the SAT solver
facing a problem with a known-to-exist solution.

Usage:
    python3 sat_calibration_raw_fnv.py [--rounds 1,2,3,4]
                                        [--obs 1,2,4,8,16]
                                        [--timeout-sec 300]
                                        [--seed-rng 42]
                                        [--json-report PATH]
                                        [--solver z3|bitwuzla]

The (rounds, obs) grid is the Cartesian product of the two lists.
"""

from __future__ import annotations

import argparse
import json
import random
import resource
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Sequence

# Reuse the Phase 0 parity gadget's concrete lo-lane implementation so
# this calibration cannot drift from the verified Go reference. The
# import path is relative to this file - both live in the same folder.
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from fnv_chain_lo_concrete import (  # type: ignore
    MASK64,
    fnv_chain_lo_concrete,
    fnv_chain_lo_z3,
)


@dataclass
class Observation:
    data_bytes: bytes
    target_hlo: int


@dataclass
class CellResult:
    rounds: int
    num_obs: int
    wall_clock_sec: float
    status: str  # "sat", "unsat", "unknown", "timeout", "error"
    recovered_seed_hex: List[str]
    matches_ground_truth: bool  # recovered seed == ground-truth seed bit-exact
    recovered_seed_is_valid: bool  # recovered seed reproduces every TRAINING hLo
    holdout_pass_count: int  # # of NEW unseen inputs where recovered seed agreed with ground truth
    holdout_total: int
    holdout_functionally_equivalent: bool  # holdout_pass_count == holdout_total AND > 0
    solver_stats: dict
    memory_rss_kb: int
    note: str = ""


def _generate_synthetic_instance(
    rounds: int,
    num_obs: int,
    rng: random.Random,
) -> tuple[List[int], List[Observation]]:
    """Pick a random seed, compute hLo for `num_obs` random inputs.

    Each input is 20 bytes matching ITB's `blockHash128` layout
    (4-byte LE pixel index + 16-byte nonce). Content itself is random
    here because Phase 2 is about raw SAT scaling, not ITB.
    """
    seed_lo_vec = [rng.getrandbits(64) for _ in range(rounds)]
    observations: List[Observation] = []
    for _ in range(num_obs):
        data = bytes(rng.getrandbits(8) for _ in range(20))
        target = fnv_chain_lo_concrete(seed_lo_vec, data, rounds)
        observations.append(Observation(data_bytes=data, target_hlo=target))
    return seed_lo_vec, observations


def _run_z3_cell(
    rounds: int,
    observations: Sequence[Observation],
    ground_truth: Sequence[int],
    timeout_sec: int,
    holdout_rng: Optional[random.Random] = None,
    holdout_count: int = 32,
) -> CellResult:
    """Build one SAT instance, solve, report."""
    import z3

    BitVec = z3.BitVec
    BitVecVal = z3.BitVecVal

    # Fresh solver context.
    solver = z3.Solver()
    solver.set("timeout", int(timeout_sec * 1000))  # ms

    seed_syms = [BitVec(f"s_lo_{i}", 64) for i in range(rounds)]

    # One constraint per observation: chain_lo(syms, data_i) == target_i.
    for obs in observations:
        expr = fnv_chain_lo_z3(z3, seed_syms, obs.data_bytes, rounds)
        solver.add(expr == BitVecVal(obs.target_hlo, 64))

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    t0 = time.perf_counter()
    result = solver.check()
    wall_clock = time.perf_counter() - t0
    rusage_after = resource.getrusage(resource.RUSAGE_SELF)

    # Statistics bag -> plain dict (Z3 returns a Statistics object).
    stats_raw = solver.statistics()
    stats_dict = {}
    try:
        for key in stats_raw.keys():
            stats_dict[key] = stats_raw.get_key_value(key)
    except Exception:
        pass
    memory_kb = max(rusage_after.ru_maxrss, rusage_before.ru_maxrss)

    recovered_hex: List[str] = []
    matches = False
    recovered_valid = False
    holdout_pass = 0
    holdout_total = 0
    status = str(result)

    if result == z3.sat:
        model = solver.model()
        recovered = []
        for sym in seed_syms:
            val = model.eval(sym, model_completion=True)
            if val is None:
                recovered.append(None)
            else:
                recovered.append(int(val.as_long()) & MASK64)
        recovered_hex = [f"{v:016x}" if v is not None else "??" for v in recovered]
        matches = all(
            (recovered[i] is not None) and (recovered[i] == ground_truth[i])
            for i in range(rounds)
        )
        # Forward-check: does the recovered seed actually reproduce every
        # observed hLo target under the concrete reference implementation?
        # If yes and matches=False, the FNV-chain lo-lane has a structural
        # multi-seed collision on this observation set (a real finding).
        # If no, the Z3 encoding drifted from the concrete reference and
        # the whole harness is broken.
        if all(v is not None for v in recovered):
            recovered_valid = all(
                fnv_chain_lo_concrete(recovered, obs.data_bytes, rounds)
                == obs.target_hlo
                for obs in observations
            )
            # Holdout test: does the recovered seed reproduce hLo for
            # fresh unseen inputs under the ground-truth seed? This is
            # the ONLY metric that separates "functional equivalence"
            # (recovered seed behaves identically to ground truth on
            # every possible input — attack would decrypt any new
            # message) from "training-set-only fit" (recovered seed
            # happened to match on the N training observations but
            # diverges elsewhere — attack is useless beyond the training
            # set). The ChainHash lo-lane function is NOT pixel-
            # independent, so "matches on training" is not enough.
            if holdout_rng is not None and holdout_count > 0:
                holdout_total = holdout_count
                for _ in range(holdout_count):
                    data = bytes(holdout_rng.getrandbits(8) for _ in range(20))
                    truth_target = fnv_chain_lo_concrete(
                        list(ground_truth), data, rounds
                    )
                    recovered_target = fnv_chain_lo_concrete(
                        recovered, data, rounds
                    )
                    if truth_target == recovered_target:
                        holdout_pass += 1
    elif result == z3.unknown:
        # unknown usually means timeout - distinguish if reason is timeout.
        reason = solver.reason_unknown()
        if "timeout" in reason.lower() or "canceled" in reason.lower():
            status = "timeout"
        else:
            status = f"unknown ({reason})"

    return CellResult(
        rounds=rounds,
        num_obs=len(observations),
        wall_clock_sec=wall_clock,
        status=status,
        recovered_seed_hex=recovered_hex,
        matches_ground_truth=matches,
        recovered_seed_is_valid=recovered_valid,
        holdout_pass_count=holdout_pass,
        holdout_total=holdout_total,
        holdout_functionally_equivalent=(
            holdout_total > 0 and holdout_pass == holdout_total
        ),
        solver_stats=stats_dict,
        memory_rss_kb=memory_kb,
    )


def _parse_int_list(s: str) -> List[int]:
    return [int(x) for x in s.split(",") if x.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--rounds", default="1,2,3,4", help="comma-separated round counts"
    )
    ap.add_argument(
        "--obs",
        default="1,2,4,8,16",
        help="comma-separated observation counts per cell",
    )
    ap.add_argument(
        "--timeout-sec",
        type=int,
        default=300,
        help="per-cell Z3 timeout in seconds (default 300 = 5 min)",
    )
    ap.add_argument(
        "--seed-rng",
        type=int,
        default=0x42_4E_56_31_61_43_41_4C,  # "BNV1aCAL"
        help="Python-level random seed for reproducibility",
    )
    ap.add_argument(
        "--json-report",
        default="tmp/attack/fnvstress/phase2_raw_sat_calibration.json",
        help="path to write the full cell-by-cell report",
    )
    ap.add_argument(
        "--solver",
        choices=["z3"],
        default="z3",
        help="Bitwuzla support not wired yet; use z3 for Phase 2 calibration",
    )
    args = ap.parse_args()

    rounds_list = _parse_int_list(args.rounds)
    obs_list = _parse_int_list(args.obs)
    if not rounds_list or not obs_list:
        print("empty rounds/obs list", file=sys.stderr)
        return 2

    rng = random.Random(args.seed_rng)
    # Separate RNG for holdout so training-data RNG stream is unaffected.
    holdout_rng = random.Random(args.seed_rng ^ 0xA5A5A5A5A5A5A5A5)
    results: List[CellResult] = []

    print(
        f"Phase 2 raw FNV-1a SAT calibration: "
        f"rounds={rounds_list} obs={obs_list} timeout={args.timeout_sec}s"
    )
    print(
        f"{'rounds':>6} {'obs':>4} {'status':>10} {'wall_sec':>10} "
        f"{'match':>5} {'valid':>5} {'hold':>7} {'mem_MB':>7}"
    )

    for rounds in rounds_list:
        for num_obs in obs_list:
            seed_lo, obs = _generate_synthetic_instance(rounds, num_obs, rng)
            try:
                result = _run_z3_cell(
                    rounds=rounds,
                    observations=obs,
                    ground_truth=seed_lo,
                    timeout_sec=args.timeout_sec,
                    holdout_rng=holdout_rng,
                    holdout_count=32,
                )
            except Exception as e:
                result = CellResult(
                    rounds=rounds,
                    num_obs=num_obs,
                    wall_clock_sec=0.0,
                    status="error",
                    recovered_seed_hex=[],
                    matches_ground_truth=False,
                    recovered_seed_is_valid=False,
                    holdout_pass_count=0,
                    holdout_total=0,
                    holdout_functionally_equivalent=False,
                    solver_stats={},
                    memory_rss_kb=0,
                    note=repr(e),
                )
            results.append(result)
            holdout_str = f"{result.holdout_pass_count}/{result.holdout_total}"
            print(
                f"{result.rounds:>6d} {result.num_obs:>4d} "
                f"{result.status:>10s} {result.wall_clock_sec:>10.3f} "
                f"{str(result.matches_ground_truth):>5s} "
                f"{str(result.recovered_seed_is_valid):>5s} "
                f"{holdout_str:>7s} "
                f"{result.memory_rss_kb/1024:>7.1f}"
            )

    # Write report.
    report_path = Path(args.json_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "rounds_list": rounds_list,
                "obs_list": obs_list,
                "timeout_sec": args.timeout_sec,
                "solver": args.solver,
                "cells": [asdict(r) for r in results],
            },
            indent=2,
        )
    )
    print(f"\nreport: {report_path}")

    # Exit code: 0 if at least the 4-round x 8-obs cell matched GT,
    # else 1 (scaling suggests full 4-round harness is risky) or 2 (setup
    # error / z3 missing).
    critical = next(
        (r for r in results if r.rounds == max(rounds_list) and r.num_obs == max(obs_list)),
        None,
    )
    if critical is None:
        return 0
    if critical.status == "error":
        return 2
    return 0 if critical.matches_ground_truth else 1


if __name__ == "__main__":
    sys.exit(main())
