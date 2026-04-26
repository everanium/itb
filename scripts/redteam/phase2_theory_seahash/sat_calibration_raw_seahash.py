#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 0 calibration: raw SeaHash ChainHash lo-lane SAT inversion cost.

Pure-Python, no ITB envelope. The script synthesises its own
(seed_lo_vec, seed_hi_vec, data_i, target_i) tuples, hands them to Z3 as
constraints on symbolic seed components, and measures wall-clock. Answers:

    "Can Z3 recover an N-round SeaHash ChainHash seed (lo+hi lanes) from K
     synthetic hLo observations, and how fast?"

Structural differences vs the FNV-1a and MD5 calibrations:

- SeaHash has independent lo + hi lanes (parallel two-lane adapter
  `seahashHash128`) — each lane runs a separate `seahash64` call. Unlike
  MD5's single-block compression that mixes lo + hi inside one
  primitive call, SeaHash does lo and hi mixing only via the chain
  composition `(seed[2r] ^ prev_lo, seed[2r+1] ^ prev_hi)`.
- SeaHash's per-call internal structure is a 4-multiply XOR-shift mixer
  on a single 64-bit accumulator — far smaller than MD5's 64-op
  compression and comparable to FNV-1a's 20-byte carry-multiply
  cascade. Effective SAT unknowns per chain round = 128 bits
  (lo + hi seeds combined), same as MD5; bit-blast is
  intermediate between FNV-1a (~10⁵ clauses) and MD5 (~10⁷).
- Every internal step is a closed-form bijection (multiplication by
  the odd constant `SEAHASH_PRIME = 0x6EED0E9DA4D94A4F` is invertible by
  modular inverse; `x ^= x >> n` is invertible by recursive top-bit
  reconstruction). Tier 4 BIT-EXACT recovery is the structurally
  expected outcome — see HARNESS.md § 9.1.

Attacker-realism note: same as FNV-1a calibration — the script is its own
universe. It picks the seed, computes targets, asks Z3 to invert. No
defender, no lab peek; the SAT solver faces a problem with a known-to-
exist solution.

Usage:
    python3 sat_calibration_raw_seahash.py [--rounds 1]
                                       [--obs 16]
                                       [--timeout-sec 86400]
                                       [--seed-rng 42]
                                       [--json-report PATH]
                                       [--solver z3|bitwuzla]
                                       [--cube-and-conquer]
                                       [--workers 8]

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
_PHASE2_THEORY_DIR = _THIS_DIR.parent / "phase2_theory"
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))
if str(_PHASE2_THEORY_DIR) not in sys.path:
    sys.path.insert(0, str(_PHASE2_THEORY_DIR))

from seahash_chain_lo_concrete import (  # type: ignore
    MASK64,
    seahash_chain_lo_concrete,
    seahash_chain_lo_z3,
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
    # Flat list [s0_lo, s0_hi, s1_lo, s1_hi, ...] — matches seahash_chain_lo_concrete API.
    seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
    observations: List[Observation] = []
    for _ in range(num_obs):
        data = bytes(rng.getrandbits(8) for _ in range(20))
        target = seahash_chain_lo_concrete(seed_components, data, rounds)
        observations.append(Observation(data_bytes=data, target_hlo=target))
    return seed_components, observations


def _force_declare_seed_syms(smt2_text: str, seed_var_names: Sequence[str]) -> str:
    """Inject `(declare-fun ... (_ BitVec 64))` lines for any seed
    symbol that Z3's `solver.to_smt2()` simplifier dropped from the
    output (e.g. `s_hi_0` at r = 1, where the hi-lane seahash64 is
    computed but its output is not part of any constraint, so Z3
    treats `s_hi_0` as dead and elides its declaration).

    Bitwuzla raises an "undefined symbol" error on the subsequent
    `(get-value ...)` query for the missing symbol and — only when
    `--time-limit` is also set — appears to idle until the time limit
    expires, inflating wall-clock by 30–60× over the genuine sat-find
    time. Re-emitting the missing declarations in front of the
    `(check-sat)` line keeps `(get-value ...)` well-defined and
    restores the true bitwuzla wall-clock.
    """
    import re
    declared = set(re.findall(r"\(declare-(?:const|fun)\s+(\S+)", smt2_text))
    missing = [n for n in seed_var_names if n not in declared]
    if not missing:
        return smt2_text
    extra = "\n".join(f"(declare-fun {n} () (_ BitVec 64))" for n in missing)
    # Insert before the FIRST `(check-sat)` (Z3's to_smt2 emits exactly
    # one). `replace(..., count=1)` guards against any edge case where
    # the literal string appears later in the dump.
    return smt2_text.replace("(check-sat)", extra + "\n(check-sat)", 1)


def _run_cell(
    rounds: int,
    observations: Sequence[Observation],
    ground_truth: Sequence[int],
    timeout_sec: int,
    solver_backend: str = "z3",
    mul_encoding: str = "native",
    var_shift_encoding: str = "native",
    holdout_rng: Optional[random.Random] = None,
    holdout_count: int = 32,
) -> CellResult:
    """Build one SAT instance, solve via the chosen backend, report.

    The Z3 path uses an in-process `solver.check()` with
    `set('timeout', ...)` — fast for small instances but the timer
    only halts CDCL, not bit-blasting.

    The Bitwuzla path dumps the same Z3-built formula via
    `solver.to_smt2()` and ships it to the `bitwuzla` CLI through a
    `subprocess.run(timeout=...)` boundary, giving a HARD wall-clock
    cap honoured across every solver phase. See
    `sat_solver_bitwuzla.solve_via_bitwuzla` for the export details.
    """
    import z3

    BitVec = z3.BitVec
    BitVecVal = z3.BitVecVal

    solver = z3.Solver()
    if solver_backend == "z3":
        solver.set("timeout", int(timeout_sec * 1000))  # ms

    seed_lo_syms = [BitVec(f"s_lo_{i}", 64) for i in range(rounds)]
    seed_hi_syms = [BitVec(f"s_hi_{i}", 64) for i in range(rounds)]

    for obs in observations:
        expr = seahash_chain_lo_z3(
            z3, seed_lo_syms, seed_hi_syms, obs.data_bytes, rounds,
            mul_encoding=mul_encoding,
            var_shift_encoding=var_shift_encoding,
        )
        solver.add(expr == BitVecVal(obs.target_hlo, 64))

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    t0 = time.perf_counter()

    recovered_lo: List[int] = []
    recovered_hi: List[int] = []
    stats_dict: dict = {}
    status: str

    if solver_backend == "bitwuzla":
        smt2_text = solver.to_smt2()
        # Interleave lo/hi names so the model parser returns them in
        # round order; then split back into lo / hi vectors below.
        seed_names: List[str] = []
        for i in range(rounds):
            seed_names.append(f"s_lo_{i}")
            seed_names.append(f"s_hi_{i}")
        smt2_text = _force_declare_seed_syms(smt2_text, seed_names)
        bw_status, bw_values = solve_via_bitwuzla(
            smt2_text, seed_names, timeout_sec, var_bit_width=64,
        )
        wall_clock = time.perf_counter() - t0
        rusage_after = resource.getrusage(resource.RUSAGE_SELF)
        status = bw_status
        if bw_status == "sat":
            for i in range(rounds):
                recovered_lo.append(int(bw_values[2 * i]) & MASK64)
                recovered_hi.append(int(bw_values[2 * i + 1]) & MASK64)
    else:
        result = solver.check()
        wall_clock = time.perf_counter() - t0
        rusage_after = resource.getrusage(resource.RUSAGE_SELF)
        stats_raw = solver.statistics()
        try:
            for key in stats_raw.keys():
                stats_dict[key] = stats_raw.get_key_value(key)
        except Exception:
            pass
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
        elif result == z3.unknown:
            reason = solver.reason_unknown()
            if "timeout" in reason.lower() or "canceled" in reason.lower():
                status = "timeout"
            else:
                status = f"unknown ({reason})"

    memory_kb = max(rusage_after.ru_maxrss, rusage_before.ru_maxrss)

    recovered_lo_hex: List[str] = []
    recovered_hi_hex: List[str] = []
    matches = False
    recovered_valid = False
    holdout_pass = 0
    holdout_total = 0

    if status == "sat" and recovered_lo and recovered_hi:
        recovered_lo_hex = [f"{v:016x}" for v in recovered_lo]
        recovered_hi_hex = [f"{v:016x}" for v in recovered_hi]

        # Ground-truth compare: seed_components flat layout
        # [s0_lo, s0_hi, s1_lo, s1_hi, ...] → split into lo / hi vectors.
        truth_lo = [ground_truth[2 * i] for i in range(rounds)]
        truth_hi = [ground_truth[2 * i + 1] for i in range(rounds)]
        matches = (recovered_lo == truth_lo) and (recovered_hi == truth_hi)

        # Forward-check: does the recovered seed reproduce every observed
        # hLo under the concrete reference? If yes and matches=False, SeaHash
        # has a structural multi-seed collision on this observation set
        # (a real empirical finding, unlikely but worth flagging). If no,
        # the SAT encoding drifted — harness broken.
        recovered_components: List[int] = []
        for i in range(rounds):
            recovered_components.append(recovered_lo[i])
            recovered_components.append(recovered_hi[i])
        recovered_valid = all(
            seahash_chain_lo_concrete(
                recovered_components, obs.data_bytes, rounds,
            ) == obs.target_hlo
            for obs in observations
        )

        # Holdout: fresh unseen inputs reproduced under recovered seed?
        if holdout_rng is not None and holdout_count > 0:
            holdout_total = holdout_count
            for _ in range(holdout_count):
                data = bytes(holdout_rng.getrandbits(8) for _ in range(20))
                truth_target = seahash_chain_lo_concrete(
                    list(ground_truth), data, rounds,
                )
                recovered_target = seahash_chain_lo_concrete(
                    recovered_components, data, rounds,
                )
                if truth_target == recovered_target:
                    holdout_pass += 1

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


# ============================================================================
# Cube-and-conquer (CnC) — split a single SeaHash calibration cell's SAT
# instance into 8 cubes by enumerating the top 3 bits of `s_lo_0` ∈
# [0..7]. Each cube is solved independently via a Bitwuzla subprocess
# in a ProcessPoolExecutor worker. The first cube returning `sat` whose
# recovered seed is holdout-functionally-equivalent to the ground truth
# wins; remaining cubes are cancelled best-effort.
#
# The cube constraint is a single `Extract(63, 61, s_lo_0) == k` assert
# added AFTER all chain-hash constraints — it pins seed-input domain
# only and never enters the SeaHash diffuse encoding (`seahash_chain_lo_z3`
# in `seahash_chain_lo_concrete.py`). The F/G/H/I boolean lattice and round
# function constants are untouched.
# ============================================================================


def _solve_seahash_cube_worker(worker_args: dict) -> dict:
    """Top-level (picklable) worker for cube-and-conquer dispatch.

    Builds the SeaHash ChainHash z3 formula identically to `_run_cell`,
    appends a single cube assertion pinning the top 3 bits of
    `s_lo_0` to `cube_id`, exports SMT-LIB2 via `solver.to_smt2()`,
    and ships the dump through `solve_via_bitwuzla`. Holdout / forward
    verification deliberately stays in the parent process so ground
    truth is never serialised across the pickle boundary.
    """
    import sys as _sys
    import time as _time
    from pathlib import Path as _Path

    _this_dir = _Path(worker_args["this_dir_str"])
    _phase2_theory_dir = _Path(worker_args["phase2_theory_dir_str"])
    if str(_this_dir) not in _sys.path:
        _sys.path.insert(0, str(_this_dir))
    if str(_phase2_theory_dir) not in _sys.path:
        _sys.path.insert(0, str(_phase2_theory_dir))

    import z3 as _z3
    from seahash_chain_lo_concrete import (  # type: ignore
        MASK64 as _MASK64,
        seahash_chain_lo_z3 as _seahash_chain_lo_z3,
    )
    from sat_solver_bitwuzla import (  # type: ignore
        solve_via_bitwuzla as _solve_via_bitwuzla,
    )

    cube_id = worker_args["cube_id"]
    rounds = worker_args["rounds"]
    timeout_sec = worker_args["timeout_sec"]
    data_bytes_list = worker_args["data_bytes_list"]
    targets = worker_args["targets"]

    BitVec = _z3.BitVec
    BitVecVal = _z3.BitVecVal

    mul_encoding = worker_args.get("mul_encoding", "native")
    var_shift_encoding = worker_args.get("var_shift_encoding", "native")

    solver = _z3.Solver()
    seed_lo_syms = [BitVec(f"s_lo_{i}", 64) for i in range(rounds)]
    seed_hi_syms = [BitVec(f"s_hi_{i}", 64) for i in range(rounds)]
    for data_bytes, target_hlo in zip(data_bytes_list, targets):
        expr = _seahash_chain_lo_z3(
            _z3, seed_lo_syms, seed_hi_syms, data_bytes, rounds,
            mul_encoding=mul_encoding,
            var_shift_encoding=var_shift_encoding,
        )
        solver.add(expr == BitVecVal(target_hlo, 64))
    # Cube pin: Extract(63, 61, s_lo_0) == cube_id ∈ [0..7].
    # Added after all chain-hash constraints; touches only the
    # input seed-domain, never the SeaHash diffuse function.
    solver.add(
        _z3.Extract(63, 61, seed_lo_syms[0]) == BitVecVal(cube_id, 3)
    )

    smt2 = solver.to_smt2()
    seed_names: List[str] = []
    for i in range(rounds):
        seed_names.append(f"s_lo_{i}")
        seed_names.append(f"s_hi_{i}")
    smt2 = _force_declare_seed_syms(smt2, seed_names)

    t0 = _time.perf_counter()
    status, values = _solve_via_bitwuzla(
        smt2, seed_names, timeout_sec, var_bit_width=64,
    )
    wall_sec = _time.perf_counter() - t0

    recovered_lo: List[int] = []
    recovered_hi: List[int] = []
    if status == "sat" and len(values) >= 2 * rounds:
        for i in range(rounds):
            recovered_lo.append(int(values[2 * i]) & _MASK64)
            recovered_hi.append(int(values[2 * i + 1]) & _MASK64)

    return {
        "cube_id": cube_id,
        "status": status,
        "recovered_lo": recovered_lo,
        "recovered_hi": recovered_hi,
        "wall_sec": wall_sec,
    }


def _holdout_check(
    rounds: int,
    ground_truth: Sequence[int],
    recovered_components: Sequence[int],
    holdout_rng: Optional[random.Random],
    holdout_count: int,
) -> tuple[int, int]:
    """Replay `holdout_count` fresh inputs under both ground truth
    and recovered seed, count matches. Pure concrete impl — fast.
    Uses a clone of `holdout_rng` so the caller's RNG stream is
    not advanced (multi-cube comparisons see identical inputs)."""
    if holdout_rng is None or holdout_count <= 0:
        return (0, 0)
    rng_clone = random.Random()
    rng_clone.setstate(holdout_rng.getstate())
    pass_count = 0
    for _ in range(holdout_count):
        data = bytes(rng_clone.getrandbits(8) for _ in range(20))
        truth_target = seahash_chain_lo_concrete(
            list(ground_truth), data, rounds,
        )
        recovered_target = seahash_chain_lo_concrete(
            list(recovered_components), data, rounds,
        )
        if truth_target == recovered_target:
            pass_count += 1
    return (pass_count, holdout_count)


def _run_cell_cnc(
    rounds: int,
    observations: Sequence[Observation],
    ground_truth: Sequence[int],
    timeout_sec: int,
    mul_encoding: str = "native",
    var_shift_encoding: str = "native",
    holdout_rng: Optional[random.Random] = None,
    holdout_count: int = 32,
    num_cubes: int = 8,
    workers: int = 8,
) -> CellResult:
    """Cube-and-conquer driver for one calibration cell.

    Spawns `num_cubes` worker processes (capped by `workers`), each
    pinning a distinct top-3-bit value of `s_lo_0`. First cube whose
    recovered seed is holdout-functionally-equivalent wins; if none
    achieves full holdout, falls back to the cube with the highest
    holdout pass count (still SAT-valid against training).
    """
    from concurrent.futures import ProcessPoolExecutor, as_completed
    import multiprocessing as _mp

    _this_dir = Path(__file__).resolve().parent
    _phase2_theory_dir = _this_dir.parent / "phase2_theory"

    data_bytes_list = [obs.data_bytes for obs in observations]
    targets = [obs.target_hlo for obs in observations]
    jobs = [
        {
            "cube_id": cid,
            "rounds": rounds,
            "data_bytes_list": data_bytes_list,
            "targets": targets,
            "timeout_sec": timeout_sec,
            "this_dir_str": str(_this_dir),
            "phase2_theory_dir_str": str(_phase2_theory_dir),
            "mul_encoding": mul_encoding,
            "var_shift_encoding": var_shift_encoding,
        }
        for cid in range(num_cubes)
    ]

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    t0 = time.perf_counter()

    cube_results: List[dict] = []
    sat_valid_cubes: List[dict] = []
    winner: Optional[dict] = None

    print(
        f"  [C&C] {num_cubes} cubes (top-3-bits of s_lo_0), "
        f"{workers} workers, {timeout_sec}s/cube subprocess timeout",
        flush=True,
    )

    ctx = _mp.get_context("fork")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
        futures = {
            pool.submit(_solve_seahash_cube_worker, job): job["cube_id"]
            for job in jobs
        }
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as exc:
                cid = futures[fut]
                r = {
                    "cube_id": cid,
                    "status": "error",
                    "recovered_lo": [],
                    "recovered_hi": [],
                    "wall_sec": 0.0,
                    "error": repr(exc),
                }
            cube_results.append(r)
            cid = r["cube_id"]
            print(
                f"    [cube {cid}] status={r['status']:<8s} "
                f"wall={r.get('wall_sec', 0):.1f}s",
                flush=True,
            )

            if r["status"] != "sat":
                continue
            if not r["recovered_lo"] or not r["recovered_hi"]:
                continue

            recovered_components: List[int] = []
            for i in range(rounds):
                recovered_components.append(r["recovered_lo"][i])
                recovered_components.append(r["recovered_hi"][i])

            valid = all(
                seahash_chain_lo_concrete(
                    list(recovered_components), obs.data_bytes, rounds,
                ) == obs.target_hlo
                for obs in observations
            )
            if not valid:
                # Sat but recovered seed does not reproduce training —
                # SAT encoding drift; loud warning, do not let this
                # cube influence aggregation.
                print(
                    f"    [cube {cid}] WARNING: sat but recovered seed "
                    f"does NOT reproduce training observations — SAT "
                    f"encoding drift suspected",
                    flush=True,
                )
                continue

            holdout_pass, holdout_total_local = _holdout_check(
                rounds=rounds,
                ground_truth=ground_truth,
                recovered_components=recovered_components,
                holdout_rng=holdout_rng,
                holdout_count=holdout_count,
            )
            # Tier classification — independent of GT bit-exact match.
            # Tier 4 (BIT-EXACT): recovered seed == ground truth bit-exact.
            # Tier 3 (FUNCTIONAL-EQ): valid + holdout=N/N (usable K).
            # Tier 2 (PARTIAL): valid + 0 < holdout < N (structural signal).
            # Tier 1 (TRAINING-ONLY): valid + holdout=0/N (local fit).
            # Tier 0 (TRASH): not valid (handled in `if not valid` branch).
            truth_lo_check = [ground_truth[2 * i] for i in range(rounds)]
            truth_hi_check = [ground_truth[2 * i + 1] for i in range(rounds)]
            bit_exact = (
                r["recovered_lo"] == truth_lo_check
                and r["recovered_hi"] == truth_hi_check
            )
            if bit_exact:
                tier = "BIT-EXACT"
            elif holdout_total_local > 0 and holdout_pass == holdout_total_local:
                tier = "FUNCTIONAL-EQ"
            elif holdout_pass > 0:
                tier = "PARTIAL"
            else:
                tier = "TRAINING-ONLY"
            r["valid"] = True
            r["holdout_pass"] = holdout_pass
            r["holdout_total"] = holdout_total_local
            r["recovered_components"] = recovered_components
            r["tier"] = tier
            sat_valid_cubes.append(r)
            print(
                f"    [cube {cid}] tier={tier:<13s} "
                f"holdout {holdout_pass}/{holdout_total_local}"
                + (
                    "  *** canonical winner ***"
                    if winner is None and tier in ("BIT-EXACT", "FUNCTIONAL-EQ")
                    else ""
                ),
                flush=True,
            )

            # Track the first Tier 3+ cube as canonical winner, but do
            # NOT short-circuit — every sat-valid cube is itself a
            # K-candidate (compound seed satisfying training under its
            # 3-bit cube pin); SeaHash's parallel two-lane composition with cross-coupled chain feedback makes
            # per-cube candidates the realistic empirical outcome
            # rather than a single bit-exact recovery. Letting all 8
            # cubes finish maximises candidate yield.
            if winner is None and tier in ("BIT-EXACT", "FUNCTIONAL-EQ"):
                winner = r

    wall_clock = time.perf_counter() - t0
    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    memory_kb = max(rusage_after.ru_maxrss, rusage_before.ru_maxrss)

    if winner is None and sat_valid_cubes:
        # No holdout-equivalent winner — fall back to highest-holdout
        # SAT-valid cube. Reports as `sat` with partial functional
        # equivalence (multi-seed collision that fits training but
        # diverges on a fraction of holdout inputs).
        winner = max(sat_valid_cubes, key=lambda x: x["holdout_pass"])

    matches = False
    recovered_lo_hex: List[str] = []
    recovered_hi_hex: List[str] = []
    recovered_valid = False
    holdout_pass_total = 0
    holdout_total_total = 0

    if winner is not None:
        recovered_lo_hex = [f"{v:016x}" for v in winner["recovered_lo"]]
        recovered_hi_hex = [f"{v:016x}" for v in winner["recovered_hi"]]
        truth_lo = [ground_truth[2 * i] for i in range(rounds)]
        truth_hi = [ground_truth[2 * i + 1] for i in range(rounds)]
        matches = (
            winner["recovered_lo"] == truth_lo
            and winner["recovered_hi"] == truth_hi
        )
        recovered_valid = winner["valid"]
        holdout_pass_total = winner["holdout_pass"]
        holdout_total_total = winner["holdout_total"]
        status = "sat"
    else:
        statuses = {r["status"] for r in cube_results}
        if statuses == {"unsat"}:
            # Mathematically impossible — at least one cube must
            # contain the GT top-3-bits. If we get here, the SAT
            # encoding is broken.
            print(
                "  [C&C] WARNING: ALL cubes UNSAT — SAT encoding drift "
                "suspected (≥1 cube must contain ground truth)",
                flush=True,
            )
            status = "unsat"
        elif "timeout" in statuses:
            status = "timeout"
        elif "error" in statuses:
            status = "error"
        else:
            status = "unknown"

    return CellResult(
        rounds=rounds,
        num_obs=len(observations),
        wall_clock_sec=wall_clock,
        status=status,
        recovered_seed_lo_hex=recovered_lo_hex,
        recovered_seed_hi_hex=recovered_hi_hex,
        matches_ground_truth=matches,
        recovered_seed_is_valid=recovered_valid,
        holdout_pass_count=holdout_pass_total,
        holdout_total=holdout_total_total,
        holdout_functionally_equivalent=(
            holdout_total_total > 0
            and holdout_pass_total == holdout_total_total
        ),
        solver_stats={"cnc_cube_results": cube_results},
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
             "SeaHash's bit-blast is intermediate between FNV-1a and MD5, "
             "but every step is closed-form bijective so commodity "
             "wall-clock is expected to be modest at low round counts)",
    )
    ap.add_argument(
        "--seed-rng", type=int, default=0x53_45_41_43_41_4C_49_42,  # "SEACALIB"
        help="Python-level random seed for reproducibility",
    )
    ap.add_argument(
        "--json-report",
        default="tmp/attack/seahashstress/phase0_raw_sat_calibration.json",
        help="path to write the full cell-by-cell report",
    )
    ap.add_argument(
        "--solver",
        choices=["z3", "bitwuzla"],
        default="z3",
        help="SAT backend. 'bitwuzla' exports the Z3-built formula as "
             "SMT-LIB2 and ships it to the `bitwuzla` CLI via subprocess "
             "(`yay -S bitwuzla` on Arch). The subprocess boundary is "
             "the only mechanism that gives a HARD wall-clock cap "
             "across every solver phase (Z3's in-process `timeout` "
             "halts only CDCL, not bit-blasting — same reasoning as "
             "the FNV-1a and MD5 calibrations).",
    )
    ap.add_argument(
        "--cube-and-conquer", action="store_true",
        help="Split each cell's SAT instance into 8 cubes by enumerating "
             "the top 3 bits of `s_lo_0` ∈ [0..7] and dispatch them to "
             "parallel Bitwuzla subprocesses via ProcessPoolExecutor. "
             "All 8 cubes are run to completion; every sat-valid cube "
             "becomes a recorded K-candidate (compound seed satisfying "
             "training under its 3-bit pin). Cell wall_clock = "
             "max(cube_times); the canonical winner reported in "
             "CellResult is the first holdout-equivalent cube, falling "
             "back to the highest-holdout sat-valid cube otherwise. "
             "Forces --solver=bitwuzla. Use when the monolithic solve "
             "does not converge in wall-clock at higher rounds; the "
             "cube assert pins seed-input bits only and never touches "
             "the SeaHash diffuse encoding.",
    )
    ap.add_argument(
        "--mul-encoding",
        choices=["native", "explicit"],
        default="native",
        help="Symbolic encoding for `x * SEAHASH_PRIME` multiplications. "
             "'native' uses Z3's BVMul with a constant operand "
             "(compact SMT-LIB2; default). 'explicit' decomposes the "
             "multiplication into 35 shift-and-add terms (one per bit "
             "set in SEAHASH_PRIME = 0x6EED0E9DA4D94A4F, Hamming "
             "weight 35). Both encodings produce bit-identical hLo.",
    )
    ap.add_argument(
        "--var-shift-encoding",
        choices=["native", "case-split"],
        default="native",
        help="Symbolic encoding for the variable shift "
             "`(x >> 32) >> (x >> 60)` inside SeaHash's `_diffuse`. "
             "'native' uses a single Z3 LShR with both operands as "
             "BV(64) (bit-blasts to a 6-stage barrel shifter). "
             "'case-split' enumerates the 16 possible shift amounts "
             "(b ∈ [0..15]) via nested `If` — more verbose but "
             "exposes per-case shift constants directly to CDCL. "
             "Both encodings produce bit-identical hLo. The (mul × "
             "var-shift) cross-product gives 4 encoding combinations; "
             "their SAT performance is open-empirical and the harness "
             "is intended to compare them on the same calibration cell.",
    )
    ap.add_argument(
        "--workers", type=int, default=8,
        help="Number of parallel cube workers when --cube-and-conquer "
             "is set (default 8 — matches the 3-bit cube split). "
             "Should not exceed physical cores.",
    )
    args = ap.parse_args()

    if args.cube_and_conquer and args.solver != "bitwuzla":
        print(
            "--cube-and-conquer requires --solver bitwuzla "
            "(per-cube subprocess timeout is the only hard wall-clock "
            "cap; Z3 in-process timer is unreliable on the bit-blast "
            "path).",
            file=sys.stderr,
        )
        return 2

    rounds_list = _parse_int_list(args.rounds)
    obs_list = _parse_int_list(args.obs)
    if not rounds_list or not obs_list:
        print("empty rounds/obs list", file=sys.stderr)
        return 2

    rng = random.Random(args.seed_rng)
    holdout_rng = random.Random(args.seed_rng ^ 0xA5A5A5A5A5A5A5A5)
    results: List[CellResult] = []

    print(
        f"Phase 0 raw SeaHash SAT calibration: "
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
                if args.cube_and_conquer:
                    result = _run_cell_cnc(
                        rounds=rounds,
                        observations=obs,
                        ground_truth=seed_components,
                        timeout_sec=args.timeout_sec,
                        holdout_rng=holdout_rng,
                        holdout_count=32,
                        num_cubes=8,
                        workers=args.workers,
                        mul_encoding=args.mul_encoding,
                        var_shift_encoding=args.var_shift_encoding,
                    )
                else:
                    result = _run_cell(
                        rounds=rounds,
                        observations=obs,
                        ground_truth=seed_components,
                        timeout_sec=args.timeout_sec,
                        solver_backend=args.solver,
                        mul_encoding=args.mul_encoding,
                        var_shift_encoding=args.var_shift_encoding,
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
                        "solver": args.solver,
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
