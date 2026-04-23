#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 0 calibration: raw MD5 ChainHash lo-lane SAT inversion cost.

Pure-Python, no ITB envelope. The script synthesises its own
(seed_lo_vec, seed_hi_vec, data_i, target_i) tuples, hands them to Z3 as
constraints on symbolic seed components, and measures wall-clock. Answers:

    "Can Z3 recover an N-round MD5 ChainHash seed (lo+hi lanes) from K
     synthetic hLo observations, and how fast?"

Structural differences vs the FNV-1a calibration:

- MD5 mixes lo + hi lanes inside its compression function (ADD with carry +
  F/G/H/I boolean mixers). There is no hLo-only collapse like FNV-1a's
  carry-up-only multiply. Effective SAT unknowns per round = 128 bits
  (full lo+hi), twice the FNV-1a 64 bits/round.
- One full MD5 compression per ChainHash round (64 internal ops each) is
  ~20× larger bit-blast than FNV-1a's 20-byte carry-multiply cascade.
- At keyBits=512 / 4 rounds: 512 SAT unknowns vs FNV-1a's 256.

If this bare harness fails on 1 round × small obs count within a day of
single-core wall-clock, the full ITB-wrapped MD5 harness is out of reach
on commodity hardware — which is itself a publishable negative empirical
bound.

Attacker-realism note: same as FNV-1a calibration — the script is its own
universe. It picks the seed, computes targets, asks Z3 to invert. No
defender, no lab peek; the SAT solver faces a problem with a known-to-
exist solution.

Usage:
    python3 sat_calibration_raw_md5.py [--rounds 1]
                                       [--obs 16]
                                       [--timeout-sec 86400]
                                       [--seed-rng 42]
                                       [--json-report PATH]

Supports up to 4 rounds (keyBits=512 minimum: 4 ChainHash rounds for the
128-bit primitive family). Higher rounds pass through unchanged, but
commodity-budget viability at 4+ rounds is the whole empirical question
this script exists to answer.

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

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from md5_chain_lo_concrete import (  # type: ignore
    MASK64,
    md5_chain_lo_concrete,
    md5_chain_lo_z3,
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
    recovered_seed_lo_hex: List[str]
    recovered_seed_hi_hex: List[str]
    matches_ground_truth: bool
    recovered_seed_is_valid: bool  # reproduces every TRAINING hLo
    holdout_pass_count: int
    holdout_total: int
    holdout_functionally_equivalent: bool
    solver_stats: dict
    memory_rss_kb: int
    note: str = ""


def _generate_synthetic_instance(
    rounds: int,
    num_obs: int,
    rng: random.Random,
) -> tuple[List[int], List[Observation]]:
    """Pick random seed (lo+hi per round), compute hLo for `num_obs` inputs."""
    # Flat list [s0_lo, s0_hi, s1_lo, s1_hi, ...] — matches md5_chain_lo_concrete API.
    seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
    observations: List[Observation] = []
    for _ in range(num_obs):
        data = bytes(rng.getrandbits(8) for _ in range(20))
        target = md5_chain_lo_concrete(seed_components, data, rounds)
        observations.append(Observation(data_bytes=data, target_hlo=target))
    return seed_components, observations


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

    solver = z3.Solver()
    solver.set("timeout", int(timeout_sec * 1000))  # ms

    seed_lo_syms = [BitVec(f"s_lo_{i}", 64) for i in range(rounds)]
    seed_hi_syms = [BitVec(f"s_hi_{i}", 64) for i in range(rounds)]

    for obs in observations:
        expr = md5_chain_lo_z3(
            z3, seed_lo_syms, seed_hi_syms, obs.data_bytes, rounds,
        )
        solver.add(expr == BitVecVal(obs.target_hlo, 64))

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    t0 = time.perf_counter()
    result = solver.check()
    wall_clock = time.perf_counter() - t0
    rusage_after = resource.getrusage(resource.RUSAGE_SELF)

    stats_raw = solver.statistics()
    stats_dict = {}
    try:
        for key in stats_raw.keys():
            stats_dict[key] = stats_raw.get_key_value(key)
    except Exception:
        pass
    memory_kb = max(rusage_after.ru_maxrss, rusage_before.ru_maxrss)

    recovered_lo_hex: List[str] = []
    recovered_hi_hex: List[str] = []
    matches = False
    recovered_valid = False
    holdout_pass = 0
    holdout_total = 0
    status = str(result)

    if result == z3.sat:
        model = solver.model()
        recovered_lo = [
            int(model.eval(s, model_completion=True).as_long()) & MASK64
            for s in seed_lo_syms
        ]
        recovered_hi = [
            int(model.eval(s, model_completion=True).as_long()) & MASK64
            for s in seed_hi_syms
        ]
        recovered_lo_hex = [f"{v:016x}" for v in recovered_lo]
        recovered_hi_hex = [f"{v:016x}" for v in recovered_hi]

        # Ground-truth compare: seed_components flat layout
        # [s0_lo, s0_hi, s1_lo, s1_hi, ...] → split into lo / hi vectors.
        truth_lo = [ground_truth[2 * i] for i in range(rounds)]
        truth_hi = [ground_truth[2 * i + 1] for i in range(rounds)]
        matches = (recovered_lo == truth_lo) and (recovered_hi == truth_hi)

        # Forward-check: does the recovered seed reproduce every observed
        # hLo under the concrete reference? If yes and matches=False, MD5
        # has a structural multi-seed collision on this observation set
        # (a real empirical finding, unlikely but worth flagging). If no,
        # the Z3 encoding drifted — harness broken.
        recovered_components = []
        for i in range(rounds):
            recovered_components.append(recovered_lo[i])
            recovered_components.append(recovered_hi[i])
        recovered_valid = all(
            md5_chain_lo_concrete(
                recovered_components, obs.data_bytes, rounds,
            ) == obs.target_hlo
            for obs in observations
        )

        # Holdout: fresh unseen inputs reproduced under recovered seed?
        if holdout_rng is not None and holdout_count > 0:
            holdout_total = holdout_count
            for _ in range(holdout_count):
                data = bytes(holdout_rng.getrandbits(8) for _ in range(20))
                truth_target = md5_chain_lo_concrete(
                    list(ground_truth), data, rounds,
                )
                recovered_target = md5_chain_lo_concrete(
                    recovered_components, data, rounds,
                )
                if truth_target == recovered_target:
                    holdout_pass += 1

    elif result == z3.unknown:
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
        recovered_seed_lo_hex=recovered_lo_hex,
        recovered_seed_hi_hex=recovered_hi_hex,
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
        "--rounds", default="1",
        help="comma-separated round counts (default 1; supports up to 4)",
    )
    ap.add_argument(
        "--obs", default="16",
        help="comma-separated observation counts per cell (default 16)",
    )
    ap.add_argument(
        "--timeout-sec", type=int, default=86400,
        help="per-cell Z3 timeout in seconds (default 86400 = 24 h; "
             "MD5's larger bit-blast relative to FNV-1a warrants longer "
             "per-cell budgets than the FNV calibration's 300 s default)",
    )
    ap.add_argument(
        "--seed-rng", type=int, default=0x4D_44_35_43_41_4C_49_42,  # "MD5CALIB"
        help="Python-level random seed for reproducibility",
    )
    ap.add_argument(
        "--json-report",
        default="tmp/attack/md5stress/phase0_raw_sat_calibration.json",
        help="path to write the full cell-by-cell report",
    )
    args = ap.parse_args()

    rounds_list = _parse_int_list(args.rounds)
    obs_list = _parse_int_list(args.obs)
    if not rounds_list or not obs_list:
        print("empty rounds/obs list", file=sys.stderr)
        return 2

    rng = random.Random(args.seed_rng)
    holdout_rng = random.Random(args.seed_rng ^ 0xA5A5A5A5A5A5A5A5)
    results: List[CellResult] = []

    print(
        f"Phase 0 raw MD5 SAT calibration: "
        f"rounds={rounds_list} obs={obs_list} timeout={args.timeout_sec}s"
    )
    print(
        f"{'rounds':>6} {'obs':>4} {'status':>10} {'wall_sec':>12} "
        f"{'match':>5} {'valid':>5} {'hold':>7} {'mem_MB':>8}"
    )

    for rounds in rounds_list:
        for num_obs in obs_list:
            seed_components, obs = _generate_synthetic_instance(
                rounds, num_obs, rng,
            )
            try:
                result = _run_z3_cell(
                    rounds=rounds,
                    observations=obs,
                    ground_truth=seed_components,
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
                    recovered_seed_lo_hex=[],
                    recovered_seed_hi_hex=[],
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
                f"{result.status:>10s} {result.wall_clock_sec:>12.3f} "
                f"{str(result.matches_ground_truth):>5s} "
                f"{str(result.recovered_seed_is_valid):>5s} "
                f"{holdout_str:>7s} "
                f"{result.memory_rss_kb/1024:>8.1f}",
                flush=True,
            )

            # Persist partial report after every cell so long-running
            # calibration can be inspected mid-flight.
            report_path = Path(args.json_report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                json.dumps(
                    {
                        "rounds_list": rounds_list,
                        "obs_list": obs_list,
                        "timeout_sec": args.timeout_sec,
                        "solver": "z3",
                        "cells": [asdict(r) for r in results],
                    },
                    indent=2,
                )
            )

    print(f"\nreport: {args.json_report}")

    # Exit code: 0 if at least the final cell matched GT, else 1.
    critical = results[-1] if results else None
    if critical is None:
        return 0
    if critical.status == "error":
        return 2
    return 0 if critical.matches_ground_truth else 1


if __name__ == "__main__":
    sys.exit(main())
