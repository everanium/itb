#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aggregate FNV-1a lo-lane SAT probe outputs into a compact summary.

Consumes JSON records under `tmp/redteam/fnv1a_sat/` (emitted by the Go
tests in `redteam_broken_fnv1a_sat_test.go` and by `sat_probe.py`) and
prints a per-layer summary table.

Independent of the Go test / SAT probe — no runtime dependency on
either. Reports:

  - F1 pre-anchor intersection per snake.
  - F2 true-anchor upper bound (channel matches under lab-peek seeds).
  - F3 positive control (Single/barrier-off) anchor recovery.
  - F4 startPixel-peek Layer 3 (channel matches at true sp vs floor).
  - F5 displacement fraction on the JSON crib.
  - Bitwuzla SAT run outcomes per snake per startPixel.

Usage:
    python3 aggregate.py [--dir tmp/redteam/fnv1a_sat]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load(path: Path):
    if not path.is_file():
        return None
    with path.open() as f:
        return json.load(f)


def fmt_table(header, rows):
    widths = [len(str(h)) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    out = []
    out.append("  ".join(str(h).ljust(widths[i]) for i, h in enumerate(header)))
    out.append("  ".join("-" * w for w in widths))
    for row in rows:
        out.append("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path,
                    default=Path("tmp/redteam/fnv1a_sat"))
    args = ap.parse_args(argv)

    if not args.dir.is_dir():
        print(f"[FATAL] directory not found: {args.dir}", file=sys.stderr)
        return 1

    print("\n=== F1 pre-anchor structure (attacker-realistic) ===")
    f1 = load(args.dir / "f1_pre_anchor_structure.json")
    if f1:
        rows = []
        for s in f1["per_snake"]:
            rows.append([s["snake"], s["snake_pixels"],
                         f"{s['per_pixel_set_size_mean']:.2f}",
                         s["per_pixel_set_size_min"],
                         s["per_pixel_set_size_max"],
                         s["max_intersection_over_startpixel"]])
        print(fmt_table(
            ["snake", "snake_pixels", "pp_mean", "pp_min", "pp_max", "max_intersection"],
            rows))
        print("Note:", f1.get("note", ""))
    else:
        print("(missing)")

    print("\n=== F2 true-anchor upper bound (lab-peek seeds) ===")
    f2 = load(args.dir / "f2_true_anchor.json")
    if f2:
        rows = []
        for s in f2["per_snake"]:
            rows.append([s["snake"], s["snake_pixels"],
                         s["full_true_anchor_shifts"],
                         f"{s['max_channel_matches']}/{s['crib_channels_budget']}",
                         f"{s['avg_channel_matches']:.3f}",
                         f"{s['chance_floor_per_channel']:.4f}"])
        print(fmt_table(
            ["snake", "snake_pixels", "full_anchor_shifts", "max_matches",
             "avg_matches", "chance_floor"],
            rows))
        print("Note:", f2.get("note", ""))

    print("\n=== F3 positive control (pre-v0.3.0, barrier off) ===")
    f3 = load(args.dir / "f3_control_positive.json")
    if f3:
        print(f"crib_pixels: {f3['crib_pixels']}")
        print(f"full_anchor_pixels: {f3['full_anchor_pixels']}")
        print(f"true_startpixel_disclosed: {f3['true_startpixel_disclosed']}")
        print("Note:", f3.get("note", ""))

    print("\n=== F4 startPixel-peek (Layer 3) ===")
    f4 = load(args.dir / "f4_startpixel_peek.json")
    if f4:
        rows = []
        for s in f4["per_snake"]:
            rows.append([s["snake"], s["startpixel_disclosed"],
                         f"{s['channel_matches_at_sp']}/{s['crib_channels_budget']}",
                         f"{s['avg_channel_matches_all_shifts']:.3f}"])
        print(fmt_table(
            ["snake", "sp_disclosed", "matches_at_sp", "avg_matches_all"],
            rows))
        print("Note:", f4.get("note", ""))

    print("\n=== F5 displacement fraction on JSON crib ===")
    f5 = load(args.dir / "f5_displacement.json")
    if f5:
        rows = []
        for s in f5["per_snake"]:
            rows.append([s["snake"],
                         f"{s['matched']}/{s['compared']}",
                         f"{s['fraction']:.4f}",
                         f"{s['chance_at_alphabet']:.4f}"])
        print(fmt_table(["snake", "matched/compared", "fraction", "chance"], rows))

    print("\n=== SAT probe (Bitwuzla, N-pixel joint) ===")
    sat = load(args.dir / "sat_probe.json")
    if sat:
        print(f"n_crib_pixels: {sat['n_crib_pixels']}  rounds: {sat['rounds']}  "
              f"regime: {sat['regime']}  timeout: {sat['timeout_sec']}s")
        if "control" in sat:
            c = sat["control"]
            print(f"\nControl (pre-v0.3.0, barrier off, sp disclosed):")
            print(f"  result: {c['result']}  wall: {c['wall_sec']:.2f}s")
            if c.get("audit"):
                a = c["audit"]
                if "bit0_62_matches" in a:
                    print(f"  audit: bits 0..62 lane matches "
                          f"{a['bit0_62_matches']}/{a['lanes_total']}")
        if "barrier" in sat:
            print("\nBarrier (v0.3.0 Triple + always-on 48-bit interlock):")
            for snake_report in sat["barrier"]:
                print(f"  snake {snake_report['snake']}: sp_scan={snake_report['sp_scan_count']} "
                      f"sat={snake_report['sat']} unsat={snake_report['unsat']} "
                      f"unknown={snake_report['unknown']}  true_sp={snake_report['true_sp']}")
                for sp_res in snake_report["per_sp"]:
                    xv = sp_res.get("cross_validation", {})
                    xv_note = ""
                    if xv:
                        xv_note = f"  xval: cross_matches={xv.get('cross_matches')}"
                    print(f"    sp={sp_res['sp']}  result={sp_res['result']}  "
                          f"wall={sp_res['wall_sec']:.2f}s{xv_note}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
