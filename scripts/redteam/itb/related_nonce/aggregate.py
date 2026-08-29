#!/usr/bin/env python3
"""Aggregate the related-nonce probe JSON records into a structural table.

Reads the two record files under ~/scratch/redteam/related_nonce/
(override via REDTEAM_RELATED_NONCE_OUTPUT_DIR) and prints a compact
structural analysis: Δ pattern ranking, plaintext-kind sensitivity,
primitive contrast, and the excess-over-no-Δ-floor for every cell.

Consumes only the emitted JSON records — no Go test state.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path


DEFAULT_ROOT = Path(os.environ.get(
    "REDTEAM_RELATED_NONCE_OUTPUT_DIR",
    str(Path.home() / "scratch" / "redteam" / "related_nonce"),
))


def load(root: Path) -> tuple[dict, dict]:
    floor = json.loads((root / "related_nonce_floor.json").read_text())
    matrix = json.loads((root / "related_nonce_matrix.json").read_text())
    return floor, matrix


def per_delta_stats(cells: list[dict]) -> dict[str, dict[str, dict]]:
    per: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(dict))
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for c in cells:
        grouped[(c["primitive"], c["delta_kind"])].append(c)
    for (prim, dk), rows in grouped.items():
        chis = [(r["chi2"], r["plaintext_kind"]) for r in rows]
        chis.sort(key=lambda t: t[0])
        per[prim][dk] = {
            "min": chis[0][0], "argmin_pt": chis[0][1],
            "mean": sum(c for c, _ in chis) / len(chis),
            "max": chis[-1][0], "argmax_pt": chis[-1][1],
            "n_cells": len(rows),
        }
    return per


def per_pt_stats(cells: list[dict]) -> dict[str, dict[str, dict]]:
    per: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(dict))
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
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


def print_delta_pattern(per_dk: dict, floors: dict[str, float]) -> None:
    print("\n==== Δ pattern sensitivity (per primitive) ====")
    print("Δ pattern | min_χ² | mean_χ² | max_χ² | Δ_over_floor")
    print("no-Δ CSPRNG artefact floor is the reference each cell is measured against.")
    print()
    for prim in per_dk:
        floor = floors.get(prim, 0.0)
        rows = []
        for dk, stats in per_dk[prim].items():
            excess = stats["max"] - floor
            rows.append((dk, stats["min"], stats["mean"], stats["max"], excess,
                         stats["argmin_pt"], stats["argmax_pt"]))
        rows.sort(key=lambda r: r[3], reverse=True)
        print(f"---- {prim} (floor χ² = {fmt_chi2(floor).strip()}) ----")
        print(f"  {'Δ pattern':<14} {'min':>10} {'mean':>10} {'max':>10} {'Δ_over_floor':>14}")
        for dk, cmin, mean, cmax, excess, ptmin, ptmax in rows:
            sign = "+" if excess >= 0 else "-"
            excess_str = f"{sign}{fmt_chi2(abs(excess)).strip():>10}"
            print(f"  {dk:<14} {fmt_chi2(cmin)} {fmt_chi2(mean)} {fmt_chi2(cmax)} {excess_str:>14}")
        print()


def print_pt_kind(per_pt: dict) -> None:
    print("==== Plaintext kind sensitivity ====")
    print()
    for prim in per_pt:
        print(f"---- {prim} ----")
        print(f"  {'pt kind':<8} {'min':>10} {'mean':>10} {'max':>10}")
        for ptk, stats in per_pt[prim].items():
            print(f"  {ptk:<8} {fmt_chi2(stats['min'])} {fmt_chi2(stats['mean'])} {fmt_chi2(stats['max'])}")
        print()


def summary_verdict(cells: list[dict], floors: dict[str, float]) -> None:
    print("==== Structural verdict ====")
    print()
    df255_top = 323.0  # df=255 one-sided 3σ upper band top
    rank2_lockseed = {"CRC128": 635.0, "FNV-1a": 550.0}
    by_prim: dict[str, list[dict]] = defaultdict(list)
    for c in cells:
        by_prim[c["primitive"]].append(c)
    for prim, rows in by_prim.items():
        floor = floors.get(prim, 0.0)
        rank2 = rank2_lockseed.get(prim, 0.0)
        chis = [r["chi2"] for r in rows]
        max_chi = max(chis)
        mean_chi = sum(chis) / len(chis)
        min_chi = min(chis)
        excess_max = max_chi - floor
        print(f"---- {prim} ----")
        print(f"  floor χ² (no-Δ, CSPRNG artefact):        {fmt_chi2(floor).strip()}")
        print(f"  Rank 2 lockSeed-axis max χ² (v0.3.0):    {fmt_chi2(rank2).strip()}")
        print(f"  df=255 one-sided 3σ uniform band top:    ~{df255_top:.0f}")
        print(f"  Rank 3 nonce-Δ min χ²: {fmt_chi2(min_chi).strip()}")
        print(f"  Rank 3 nonce-Δ mean χ²: {fmt_chi2(mean_chi).strip()}")
        print(f"  Rank 3 nonce-Δ max χ²: {fmt_chi2(max_chi).strip()}")
        print(f"  Δ_over_floor at max:   {excess_max:+.3e}")
        if max_chi < 2 * rank2:
            print(f"  interpretation: nonce Δ SUPERSETS lockSeed Δ — every cell inside")
            print(f"                  a small multiple of Rank 2's lockSeed-axis band")
            print(f"                  ({rank2:.0f}); nonce Δ propagates through the")
            print(f"                  lockSeed slot + noise/data/start slots simultaneously.")
        elif max_chi < 0.01 * floor:
            print(f"  interpretation: nonce Δ collapses χ² far below no-Δ floor.")
            print(f"                  Full diffusion: the barrier absorbs nonce Δ across all")
            print(f"                  8 seed-derivation channels.")
        else:
            print(f"  interpretation: nonce Δ does NOT collapse to the uniform band —")
            print(f"                  investigate structural discrepancy vs Rank 2 lockSeed axis.")
        print()


def main() -> None:
    root = DEFAULT_ROOT
    if len(sys.argv) > 1:
        root = Path(sys.argv[1])
    if not root.exists():
        print(f"[aggregate] no records at {root}", file=sys.stderr)
        sys.exit(1)

    floor, matrix = load(root)
    cells = matrix["run"]["cells"]

    floors: dict[str, float] = {}
    for row in floor.get("floors", []):
        floors[row["primitive"]] = row["chi2"]

    print("=" * 78)
    print("Related-nonce differential — v0.3.0 structural analysis")
    print("=" * 78)
    cfg = matrix["run"]["config"]
    print(f"total cells: {len(cells)}")
    print(f"config: key_bits={cfg['key_bits']}, nonce_bits={cfg['nonce_bits']}, "
          f"plaintext_bytes={cfg['plaintext_bytes']}, "
          f"primitives={cfg['primitives']}")
    print(f"delta_kinds: {cfg['delta_kinds']}")
    print()
    per_dk = per_delta_stats(cells)
    per_pt = per_pt_stats(cells)
    print_delta_pattern(per_dk, floors)
    print_pt_kind(per_pt)
    summary_verdict(cells, floors)


if __name__ == "__main__":
    main()
