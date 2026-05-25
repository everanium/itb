#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Axis C SAT calibration: raw SplitMix64 ChainHash lo-lane seed recovery.

Pure-Python, no ITB envelope — the script synthesises its own
(seed, data_i, hLo_i) tuples, hands them to a SAT backend as constraints on
the symbolic lo-lane seed components, and measures wall-clock. It answers, for
the avalanche/differential pre-screen's INVERTIBLE control:

    "Does the pre-screen's `inv = Y` flag for SplitMix64 cash out as an actual
     SAT seed recovery, the way it does for FNV-1a (Phase 2g), even though
     SplitMix64 reads ideal on every avalanche / differential / degree column?"

Structure mirrors sat_calibration_raw_mx3.py: independent lo / hi lanes, the
lo output a function of the lo seeds only (so the hi symbols are dead and are
re-declared before the bitwuzla model query via `_force_declare_seed_syms`).
SplitMix64's mix64 is a composition of word-level bijections, so a Tier 3/4
recovery at modest observation count is the structurally expected outcome — a
positive result here is the empirical counterpart of the pre-screen's
prediction, not a new attack on a deployed primitive (SplitMix64 is a
research pre-screen primitive, not wired into ITB).

Usage:
    python3 sat_calibration_raw_splitmix64.py [--rounds 2] [--obs 16]
        [--timeout-sec 3600] [--solver bitwuzla|z3] [--json-report PATH]
"""

from __future__ import annotations

import argparse
import json
import random
import re
import resource
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Sequence

_THIS_DIR = Path(__file__).resolve().parent
_PHASE2_THEORY_DIR = _THIS_DIR.parent / "phase2_theory"
for _p in (_THIS_DIR, _PHASE2_THEORY_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from splitmix64_chain_lo_concrete import (  # type: ignore
    MASK64,
    splitmix64_chain_lo_concrete,
    splitmix64_chain_lo_z3,
)
from sat_solver_bitwuzla import solve_via_bitwuzla  # type: ignore


@dataclass
class Observation:
    data_bytes: bytes
    target_hlo: int


@dataclass
class CellResult:
    rounds: int
    num_obs: int
    wall_clock_sec: float
    status: str
    recovered_seed_lo_hex: List[str]
    matches_ground_truth_lo: bool
    recovered_seed_is_valid: bool
    holdout_pass_count: int
    holdout_total: int
    holdout_functionally_equivalent: bool
    memory_rss_kb: int
    note: str = ""


def _generate_synthetic_instance(rounds: int, num_obs: int, rng: random.Random):
    seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
    observations: List[Observation] = []
    for _ in range(num_obs):
        data = bytes(rng.getrandbits(8) for _ in range(20))
        target = splitmix64_chain_lo_concrete(seed_components, data, rounds)
        observations.append(Observation(data_bytes=data, target_hlo=target))
    return seed_components, observations


def _force_declare_seed_syms(smt2_text: str, seed_var_names: Sequence[str]) -> str:
    """Re-emit declarations for seed symbols Z3's to_smt2 dropped as dead
    (every hi symbol here — the lo output never references the hi lane), so
    bitwuzla's (get-value ...) query stays well-defined. Same trick as the
    mx3 / FNV-1a harnesses."""
    declared = set(re.findall(r"\(declare-(?:const|fun)\s+(\S+)", smt2_text))
    missing = [n for n in seed_var_names if n not in declared]
    if not missing:
        return smt2_text
    extra = "\n".join(f"(declare-fun {n} () (_ BitVec 64))" for n in missing)
    return smt2_text.replace("(check-sat)", extra + "\n(check-sat)", 1)


def _run_cell(rounds: int, observations: Sequence[Observation],
              ground_truth: Sequence[int], timeout_sec: int,
              solver_backend: str, holdout_rng: random.Random,
              holdout_count: int = 32) -> CellResult:
    import z3

    solver = z3.Solver()
    if solver_backend == "z3":
        solver.set("timeout", int(timeout_sec * 1000))

    lo_syms = [z3.BitVec(f"s_lo_{i}", 64) for i in range(rounds)]
    hi_syms = [z3.BitVec(f"s_hi_{i}", 64) for i in range(rounds)]
    for obs in observations:
        expr = splitmix64_chain_lo_z3(z3, lo_syms, hi_syms, obs.data_bytes, rounds)
        solver.add(expr == z3.BitVecVal(obs.target_hlo, 64))

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    t0 = time.perf_counter()
    recovered_lo: List[int] = []
    status: str

    if solver_backend == "bitwuzla":
        smt2 = solver.to_smt2()
        names: List[str] = []
        for i in range(rounds):
            names.append(f"s_lo_{i}")
            names.append(f"s_hi_{i}")
        smt2 = _force_declare_seed_syms(smt2, names)
        bw_status, bw_values = solve_via_bitwuzla(smt2, names, timeout_sec, var_bit_width=64)
        wall = time.perf_counter() - t0
        status = bw_status
        if bw_status == "sat":
            recovered_lo = [int(bw_values[2 * i]) & MASK64 for i in range(rounds)]
    else:
        result = solver.check()
        wall = time.perf_counter() - t0
        status = str(result)
        if result == z3.sat:
            model = solver.model()
            recovered_lo = [int(model.eval(s, model_completion=True).as_long()) & MASK64
                            for s in lo_syms]
        elif result == z3.unknown:
            reason = solver.reason_unknown().lower()
            status = "timeout" if ("timeout" in reason or "canceled" in reason) else f"unknown ({reason})"

    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    memory_kb = max(rusage_after.ru_maxrss, rusage_before.ru_maxrss)

    recovered_lo_hex: List[str] = []
    matches_lo = False
    recovered_valid = False
    holdout_pass = 0
    holdout_total = 0

    if status == "sat" and recovered_lo:
        recovered_lo_hex = [f"{v:016x}" for v in recovered_lo]
        truth_lo = [ground_truth[2 * i] for i in range(rounds)]
        matches_lo = recovered_lo == truth_lo
        # Rebuild a full seed_components vector (hi arbitrary — lo output is
        # hi-independent; use 0 for the unconstrained hi slots).
        rec_components: List[int] = []
        for i in range(rounds):
            rec_components.append(recovered_lo[i])
            rec_components.append(0)
        recovered_valid = all(
            splitmix64_chain_lo_concrete(rec_components, obs.data_bytes, rounds) == obs.target_hlo
            for obs in observations)
        holdout_total = holdout_count
        for _ in range(holdout_count):
            data = bytes(holdout_rng.getrandbits(8) for _ in range(20))
            truth_t = splitmix64_chain_lo_concrete(list(ground_truth), data, rounds)
            rec_t = splitmix64_chain_lo_concrete(rec_components, data, rounds)
            if truth_t == rec_t:
                holdout_pass += 1

    return CellResult(
        rounds=rounds, num_obs=len(observations), wall_clock_sec=wall,
        status=status, recovered_seed_lo_hex=recovered_lo_hex,
        matches_ground_truth_lo=matches_lo, recovered_seed_is_valid=recovered_valid,
        holdout_pass_count=holdout_pass, holdout_total=holdout_total,
        holdout_functionally_equivalent=(holdout_total > 0 and holdout_pass == holdout_total),
        memory_rss_kb=memory_kb)


def _parse_int_list(s: str) -> List[int]:
    return [int(x) for x in s.split(",") if x.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rounds", default="2")
    ap.add_argument("--obs", default="16")
    ap.add_argument("--timeout-sec", type=int, default=3600)
    ap.add_argument("--seed-rng", type=int, default=0x5350_4C49_544D_5836)
    ap.add_argument("--solver", choices=["z3", "bitwuzla"], default="bitwuzla")
    ap.add_argument("--json-report",
                    default="tmp/attack/splitmix64stress/axis_c_raw_sat.json")
    args = ap.parse_args()

    rounds_list = _parse_int_list(args.rounds)
    obs_list = _parse_int_list(args.obs)
    rng = random.Random(args.seed_rng)
    holdout_rng = random.Random(args.seed_rng ^ 0xA5A5A5A5A5A5A5A5)
    results: List[CellResult] = []

    print(f"Axis C raw splitmix64 SAT calibration: rounds={rounds_list} "
          f"obs={obs_list} timeout={args.timeout_sec}s solver={args.solver}")
    print(f"{'rounds':>6} {'obs':>4} {'status':>10} {'wall_sec':>12} "
          f"{'match_lo':>9} {'valid':>5} {'hold':>7} {'mem_MB':>8}")

    for rounds in rounds_list:
        for num_obs in obs_list:
            seed_components, obs = _generate_synthetic_instance(rounds, num_obs, rng)
            try:
                result = _run_cell(rounds, obs, seed_components, args.timeout_sec,
                                   args.solver, holdout_rng, holdout_count=32)
            except Exception as e:  # noqa: BLE001
                result = CellResult(rounds, num_obs, 0.0, "error", [], False,
                                    False, 0, 0, False, 0, note=repr(e))
            results.append(result)
            print(f"{result.rounds:>6d} {result.num_obs:>4d} {result.status:>10s} "
                  f"{result.wall_clock_sec:>12.3f} {str(result.matches_ground_truth_lo):>9s} "
                  f"{str(result.recovered_seed_is_valid):>5s} "
                  f"{result.holdout_pass_count}/{result.holdout_total:<5d} "
                  f"{result.memory_rss_kb/1024:>8.1f}", flush=True)
            report_path = Path(args.json_report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(
                {"rounds_list": rounds_list, "obs_list": obs_list,
                 "timeout_sec": args.timeout_sec, "solver": args.solver,
                 "cells": [asdict(r) for r in results]}, indent=2))

    print(f"\nreport: {args.json_report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
