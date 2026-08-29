#!/usr/bin/env python3
"""Aggregate the related-seed probe JSON records into a structural table.

Reads the three record files under ~/scratch/redteam/related_seed/
(override via REDTEAM_RELATED_SEED_OUTPUT_DIR) and prints a compact
4-dimensional structural analysis: axis dominance ranking, primitive
contrast, delta-pattern sensitivity, plaintext-kind effect, and
excess-over-no-delta-floor per (primitive, axis).

Consumes only the emitted JSON records — no Go test state.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path


DEFAULT_ROOT = Path(os.environ.get(
    "REDTEAM_RELATED_SEED_OUTPUT_DIR",
    str(Path.home() / "scratch" / "redteam" / "related_seed"),
))

AXES = [
    "noiseSeed", "lockSeed",
    "dataSeed1", "dataSeed2", "dataSeed3",
    "startSeed1", "startSeed2", "startSeed3",
]
DELTA_KINDS = ["bit0", "bit_mid", "bit_high"]
PT_KINDS = ["random", "ascii"]


def load(root: Path) -> tuple[dict, dict, dict]:
    ctrl = json.loads((root / "related_seed_control.json").read_text())
    floor = json.loads((root / "related_seed_floor.json").read_text())
    matrix = json.loads((root / "related_seed_matrix.json").read_text())
    return ctrl, floor, matrix


def per_primitive_axis_stats(cells: list[dict]) -> dict[str, dict[str, dict]]:
    """Return {primitive: {axis: {min, mean, max, argmax_dk, argmax_pt}}}."""
    per: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(dict))
    grouped = defaultdict(list)
    for c in cells:
        grouped[(c["primitive"], c["axis"])].append(c)
    for (prim, axis), rows in grouped.items():
        chis = [(r["chi2"], r["delta_kind"], r["plaintext_kind"]) for r in rows]
        chis.sort(key=lambda t: t[0])
        cmin, dmin, pmin = chis[0]
        cmax, dmax, pmax = chis[-1]
        mean = sum(c for c, _, _ in chis) / len(chis)
        per[prim][axis] = {
            "min": cmin, "argmin_dk": dmin, "argmin_pt": pmin,
            "mean": mean,
            "max": cmax, "argmax_dk": dmax, "argmax_pt": pmax,
            "n_cells": len(rows),
        }
    return per


def per_delta_stats(cells: list[dict]) -> dict[str, dict[str, dict]]:
    """Return {primitive: {delta_kind: {min, mean, max}}}."""
    per: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(dict))
    grouped = defaultdict(list)
    for c in cells:
        grouped[(c["primitive"], c["delta_kind"])].append(c["chi2"])
    for (prim, dk), chis in grouped.items():
        per[prim][dk] = {
            "min": min(chis),
            "mean": sum(chis) / len(chis),
            "max": max(chis),
            "n_cells": len(chis),
        }
    return per


def per_pt_stats(cells: list[dict]) -> dict[str, dict[str, dict]]:
    per: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(dict))
    grouped = defaultdict(list)
    for c in cells:
        grouped[(c["primitive"], c["plaintext_kind"])].append(c["chi2"])
    for (prim, ptk), chis in grouped.items():
        per[prim][ptk] = {
            "min": min(chis),
            "mean": sum(chis) / len(chis),
            "max": max(chis),
            "n_cells": len(chis),
        }
    return per


def fmt_chi2(v: float) -> str:
    if v >= 1e6:
        return f"{v/1e6:>7.2f} M"
    if v >= 1e3:
        return f"{v/1e3:>7.2f} k"
    return f"{v:>7.1f}  "


def print_axis_dominance(per_axis: dict, floors: dict[str, float]) -> None:
    print("\n==== Axis dominance ranking (per primitive) ====")
    print("Rank order: axis by max χ² across (Δ pattern × plaintext kind)")
    print("Δ_over_floor: max χ² - no-Δ CSPRNG artefact floor (negative = Δ DIFFUSES the floor)")
    print()
    for prim in per_axis:
        floor = floors.get(prim, 0.0)
        rows = []
        for axis, stats in per_axis[prim].items():
            excess = stats["max"] - floor
            rows.append((axis, stats["min"], stats["mean"], stats["max"], excess,
                         stats["argmax_dk"], stats["argmax_pt"]))
        rows.sort(key=lambda r: r[3], reverse=True)
        print(f"---- {prim} (floor χ² = {fmt_chi2(floor)}) ----")
        print(f"  {'axis':<11} {'min':>10} {'mean':>10} {'max':>10} {'Δ_over_floor':>14} {'argmax_Δ':>10} {'argmax_pt':>8}")
        for axis, cmin, mean, cmax, excess, dk, pt in rows:
            excess_str = ("+" if excess > 0 else "") + fmt_chi2(abs(excess)).strip() + ("" if excess >= 0 else " neg")
            excess_str = f"{'+' if excess>=0 else '-'}{fmt_chi2(abs(excess)).strip():>10}"
            print(f"  {axis:<11} {fmt_chi2(cmin)} {fmt_chi2(mean)} {fmt_chi2(cmax)} {excess_str:>14} {dk:>10} {pt:>8}")
        print()


def print_delta_pattern(per_dk: dict) -> None:
    print("==== Δ pattern sensitivity ====")
    print("Question: is one of {bit0, bit_mid, bit_high} systematically stronger than the others?")
    print()
    for prim in per_dk:
        rows = [(dk, stats["min"], stats["mean"], stats["max"]) for dk, stats in per_dk[prim].items()]
        rows.sort(key=lambda r: r[2], reverse=True)
        print(f"---- {prim} ----")
        print(f"  {'Δ pattern':<10} {'min':>10} {'mean':>10} {'max':>10}")
        for dk, cmin, mean, cmax in rows:
            print(f"  {dk:<10} {fmt_chi2(cmin)} {fmt_chi2(mean)} {fmt_chi2(cmax)}")
        print()


def print_pt_kind(per_pt: dict) -> None:
    print("==== Plaintext kind sensitivity ====")
    print("Question: does random vs ASCII plaintext produce different χ² profiles?")
    print()
    for prim in per_pt:
        print(f"---- {prim} ----")
        print(f"  {'pt kind':<8} {'min':>10} {'mean':>10} {'max':>10}")
        for ptk, stats in per_pt[prim].items():
            print(f"  {ptk:<8} {fmt_chi2(stats['min'])} {fmt_chi2(stats['mean'])} {fmt_chi2(stats['max'])}")
        print()


def print_control_comparison(ctrl: dict, floors: dict[str, float]) -> None:
    print("==== Positive control — archived reproduction via process128Cfg ====")
    print("Confirms the probe methodology matches the archived related-seed archive numbers")
    print("(archive/archive/REDTEAM.md § related-seed row: CRC128 42.5M, FNV-1a 56.7M axis-hit on data-axis bit_high).")
    print()
    for cell in ctrl.get("cells", []):
        prim = cell["primitive"]
        pre = cell.get("pre_v030_baseline", 0.0)
        obs = cell["chi2"]
        drift = (obs - pre) / pre if pre else 0.0
        print(f"  {prim:<6} axis=data Δ=bit_high  chi2_obs={fmt_chi2(obs)}  chi2_pre_v030={fmt_chi2(pre)}  drift={drift*+100:+.2f} %")
    print()


def summary_verdict(per_axis: dict, floors: dict[str, float]) -> None:
    print("==== Structural verdict ====")
    print()
    for prim in per_axis:
        floor = floors.get(prim, 0.0)
        axis_max = {axis: stats["max"] for axis, stats in per_axis[prim].items()}
        ranked = sorted(axis_max.items(), key=lambda kv: kv[1], reverse=True)
        top = ranked[0]
        bot = ranked[-1]
        gap = top[1] / max(bot[1], 1.0)
        excess_top = top[1] - floor
        excess_bot = bot[1] - floor
        print(f"---- {prim} ----")
        print(f"  floor χ² (no-Δ, CSPRNG artefact): {fmt_chi2(floor).strip()}")
        print(f"  top axis: {top[0]:<11} max χ² = {fmt_chi2(top[1]).strip():>10} (Δ_over_floor = {excess_top:+.1e})")
        print(f"  bot axis: {bot[0]:<11} max χ² = {fmt_chi2(bot[1]).strip():>10} (Δ_over_floor = {excess_bot:+.1e})")
        print(f"  gap (top/bot) = {gap:>8.0f}x")
        # Structural interpretation
        if bot[0] == "lockSeed" and excess_bot < -1e6:
            print(f"  interpretation: lockSeed Δ collapses χ² to the df=255 uniform band")
            print(f"                  (barrier's per-chunk permutation avalanches, randomising every touched pixel byte).")
        if excess_top < 1e6 and top[0] != "lockSeed":
            print(f"  interpretation: non-lockSeed Δ signals do NOT exceed the no-Δ floor")
            print(f"                  (the ≈{fmt_chi2(floor).strip()} floor is a CSPRNG + noise-bit artefact, not primitive leak).")
        print()


def main() -> None:
    root = DEFAULT_ROOT
    if len(sys.argv) > 1:
        root = Path(sys.argv[1])
    if not root.exists():
        print(f"[aggregate] no records at {root}", file=sys.stderr)
        sys.exit(1)

    ctrl, floor, matrix = load(root)
    cells = matrix["run"]["cells"]

    # Floors keyed by primitive.
    floors: dict[str, float] = {}
    for row in floor.get("floors", []):
        floors[row["primitive"]] = row["chi2"]

    print("=" * 78)
    print("Related-seed differential — structural analysis")
    print("=" * 78)
    print(f"total cells: {len(cells)}")
    print(f"config: key_bits={matrix['run']['config']['key_bits']}, "
          f"plaintext_bytes={matrix['run']['config']['plaintext_bytes']}, "
          f"primitives={matrix['run']['config']['primitives']}")
    print()
    print_control_comparison(ctrl, floors)
    per_axis = per_primitive_axis_stats(cells)
    per_dk = per_delta_stats(cells)
    per_pt = per_pt_stats(cells)
    print_axis_dominance(per_axis, floors)
    print_delta_pattern(per_dk)
    print_pt_kind(per_pt)
    summary_verdict(per_axis, floors)


if __name__ == "__main__":
    main()
