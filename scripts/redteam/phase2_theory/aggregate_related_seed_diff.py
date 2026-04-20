#!/usr/bin/env python3
"""Aggregate Phase 2e related-seed-differential matrix_summary.jsonl into a
markdown roll-up + roll-down per primitive.

Roll-up: one row per primitive, averaged over all (axis, delta_kind,
plaintext_kind) cells it appeared in. Columns show max chi2, min p-value,
max KL, max bit-deviation, max delta-correlation. The primitive that
leaks (CRC128) surfaces as an outlier on every column; neutralized
primitives cluster around the finite-sample floor.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--input", type=Path, required=True,
                    help="matrix_summary.jsonl produced by phase2e_related_seed_matrix.sh")
    ap.add_argument("--cells", action="store_true",
                    help="Also emit per-cell full breakdown (large table).")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"ERROR: {args.input} missing", file=sys.stderr)
        return 1

    rows = []
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    if not rows:
        print("(matrix_summary.jsonl empty)")
        return 1

    # Roll-up per primitive
    by_prim: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_prim[r["hash"]].append(r)

    print("# Phase 2e — related-seed differential summary\n")
    print(f"Total cells analysed: **{len(rows)}**\n")
    print("## Per-primitive roll-up\n")
    print("Each row aggregates across all (axis, delta_kind, plaintext_kind) "
          "combinations for that primitive. `max chi2` = biggest byte-χ² "
          "observed; `min p` = smallest associated p-value "
          "(near 0 → highly non-uniform); `max KL` = max KL divergence in "
          "nats against uniform (floor ≈ `255 / (2·N·ln2)` nats); `max bit-"
          "dev` = biggest deviation from 0.5 in per-bit balance of D; "
          "`max Δ-corr` = biggest bit-level correlation of D against tiled Δ.\n")
    print("| primitive | cells | max chi2 | min p        | max KL (nats) | max bit-dev | max Δ-corr |")
    print("|:----------|------:|---------:|-------------:|--------------:|------------:|-----------:|")
    for prim, subset in sorted(by_prim.items()):
        max_chi2 = max(r["byte_chi2"] for r in subset)
        min_p = min(r["byte_chi2_p"] for r in subset)
        max_kl = max(r["kl_vs_uniform_nats"] for r in subset)
        max_bit_dev = max(r["max_abs_bit_deviation"] for r in subset)
        max_delta_corr = max(r["delta_corr_max_abs"] for r in subset)
        print(f"| {prim:<10} | {len(subset):>5} | {max_chi2:>8.1f} | "
              f"{min_p:>12.2e} | {max_kl:>13.2e} | {max_bit_dev:>11.5f} | "
              f"{max_delta_corr:>10.5f} |")

    # Per-axis roll-up
    print("\n## Per-primitive × axis roll-up (max χ² per axis)\n")
    axes = ["noise", "data", "start"]
    header = "| primitive | " + " | ".join(f"max χ² {a}" for a in axes) + " |"
    sep    = "|:----------|" + "|".join(["------:" for _ in axes]) + "|"
    print(header); print(sep)
    for prim, subset in sorted(by_prim.items()):
        vals = []
        for a in axes:
            axis_rows = [r for r in subset if r["axis"] == a]
            vals.append(max((r["byte_chi2"] for r in axis_rows), default=0))
        print(f"| {prim:<10} | " + " | ".join(f"{v:>8.1f}" for v in vals) + " |")

    # Per-primitive × delta-kind roll-up
    print("\n## Per-primitive × delta-kind roll-up (max χ² per Δ pattern)\n")
    deltas_seen = sorted({r["delta_kind"] for r in rows})
    header = "| primitive | " + " | ".join(f"{d}" for d in deltas_seen) + " |"
    sep    = "|:----------|" + "|".join(["------:" for _ in deltas_seen]) + "|"
    print(header); print(sep)
    for prim, subset in sorted(by_prim.items()):
        vals = []
        for d in deltas_seen:
            delta_rows = [r for r in subset if r["delta_kind"] == d]
            vals.append(max((r["byte_chi2"] for r in delta_rows), default=0))
        print(f"| {prim:<10} | " + " | ".join(f"{v:>6.1f}" for v in vals) + " |")

    # Per-primitive × plaintext-kind roll-up
    print("\n## Per-primitive × plaintext-kind roll-up (max χ² per PT)\n")
    pts = sorted({r["plaintext_kind"] for r in rows})
    header = "| primitive | " + " | ".join(f"max χ² {p}" for p in pts) + " |"
    sep    = "|:----------|" + "|".join(["------:" for _ in pts]) + "|"
    print(header); print(sep)
    for prim, subset in sorted(by_prim.items()):
        vals = []
        for pt in pts:
            pt_rows = [r for r in subset if r["plaintext_kind"] == pt]
            vals.append(max((r["byte_chi2"] for r in pt_rows), default=0))
        print(f"| {prim:<10} | " + " | ".join(f"{v:>8.1f}" for v in vals) + " |")

    # Per-primitive × barrier-fill roll-up (only if BF field present)
    bfs_seen = sorted({r.get("barrier_fill") for r in rows
                       if r.get("barrier_fill") is not None})
    if bfs_seen:
        print("\n## Per-primitive × BarrierFill roll-up (max χ² per BF)\n")
        header = "| primitive | " + " | ".join(f"max χ² BF={b}" for b in bfs_seen) + " |"
        sep    = "|:----------|" + "|".join(["------:" for _ in bfs_seen]) + "|"
        print(header); print(sep)
        for prim, subset in sorted(by_prim.items()):
            vals = []
            for b in bfs_seen:
                bf_rows = [r for r in subset if r.get("barrier_fill") == b]
                vals.append(max((r["byte_chi2"] for r in bf_rows), default=0))
            print(f"| {prim:<10} | " + " | ".join(f"{v:>8.1f}" for v in vals) + " |")

    if args.cells:
        print("\n## Per-cell breakdown\n")
        print("| primitive | axis | Δ | pt | chi2 | p | KL | bit-dev | Δ-corr |")
        print("|:----------|:-----|:--|:---|------:|------:|------:|--------:|-------:|")
        for r in sorted(rows, key=lambda x: (x["hash"], x["axis"],
                                             x["delta_kind"],
                                             x["plaintext_kind"])):
            print(f"| {r['hash']} | {r['axis']} | {r['delta_kind']} | "
                  f"{r['plaintext_kind']} | {r['byte_chi2']:.1f} | "
                  f"{r['byte_chi2_p']:.2e} | {r['kl_vs_uniform_nats']:.2e} | "
                  f"{r['max_abs_bit_deviation']:.5f} | "
                  f"{r['delta_corr_max_abs']:.5f} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
