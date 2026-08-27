#!/usr/bin/env python3
"""Aggregate the fresh-nonce near-identical cross-message distinguisher JSON.

Reads the record file emitted by `TestRedTeamNearIdenticalFreshNonce` at
`tmp/redteam/near_identical_fresh/near_identical_fresh_matrix.json` and
prints a compact structural analysis:

  - per-cell byte-XOR chi² vs df=255 uniform (per size, per delta
    position, per category)
  - per-cell byte-equal floor ratio (target 1.0x for independent
    uniform streams)
  - two-sample homogeneity chi² between the near-identical and
    independent-pair categories at every (size, delta) (df=255)
  - dominant delta position per size and dominant size across the
    matrix
  - null / signal verdict against the uniform band and against the
    archival nonce-reuse near-identical baseline (~16.13x floor at
    512 B)

Consumes only the emitted JSON record — no Go test state.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


DEFAULT_ROOT = Path("tmp/redteam/near_identical_fresh")


def load(root: Path) -> dict:
    return json.loads((root / "near_identical_fresh_matrix.json").read_text())


def fmt_chi2(v: float) -> str:
    return f"{v:>8.2f}"


def print_body_chi2(cells: list[dict]) -> None:
    print("\n==== Per-cell byte-XOR chi² vs df=255 uniform ====")
    print("df=255 uniform band: mean 255, one-sided 3σ top ≈ 323")
    print("Wire path: container body only (nonce + W + H header dropped)")
    print()
    sizes = sorted({c["plaintext_size"] for c in cells})
    deltas = list(dict.fromkeys(c["delta_position"] for c in cells))
    cats = list(dict.fromkeys(c["category"] for c in cells))

    for size in sizes:
        print(f"  --- size = {size} bytes ---")
        header = f"    {'delta':<12} " + " ".join(f"{cat:>22}" for cat in cats)
        print(header)
        for delta in deltas:
            row = [f"    {delta:<12}"]
            for cat in cats:
                match = next(
                    (c for c in cells
                     if c["plaintext_size"] == size
                     and c["delta_position"] == delta
                     and c["category"] == cat),
                    None,
                )
                v = match["chi2_uniform_body_xor"] if match else float("nan")
                row.append(fmt_chi2(v).rjust(22))
            print("".join(row))
        print()


def print_byte_equal_floor(cells: list[dict]) -> None:
    print("==== Byte-equal floor ratio (target 1.0x = 1/256 = 0.00391) ====")
    print("Under fresh nonces the pair body XOR is uniform noise on both")
    print("categories; both should land near 1.0x floor.")
    print()
    sizes = sorted({c["plaintext_size"] for c in cells})
    deltas = list(dict.fromkeys(c["delta_position"] for c in cells))
    cats = list(dict.fromkeys(c["category"] for c in cells))

    for size in sizes:
        print(f"  --- size = {size} bytes ---")
        header = f"    {'delta':<12} " + " ".join(f"{cat:>22}" for cat in cats)
        print(header)
        for delta in deltas:
            row = [f"    {delta:<12}"]
            for cat in cats:
                match = next(
                    (c for c in cells
                     if c["plaintext_size"] == size
                     and c["delta_position"] == delta
                     and c["category"] == cat),
                    None,
                )
                v = match["vs_1_over_256_floor"] if match else float("nan")
                row.append(f"{v:>18.3f}x  ")
            print("".join(row))
        print()


def print_homogeneity(rows: list[dict]) -> None:
    print("==== Cross-category homogeneity chi² (near_identical vs indep_control) ====")
    print("Two-sample chi² homogeneity test, df=255")
    print("Null: the near-identical-pair wire byte distribution is indistinguishable")
    print("      from the independent-pair wire byte distribution at N samples.")
    print(f"Uniform band top (3σ, one-sided): {rows[0]['uniform_band_3sigma_top']:.0f}")
    print()
    sizes = sorted({r["plaintext_size"] for r in rows})
    deltas = list(dict.fromkeys(r["delta_position"] for r in rows))

    for size in sizes:
        print(f"  --- size = {size} bytes ---")
        print(f"    {'delta':<12} {'chi²':>10} {'verdict':<50}")
        for delta in deltas:
            match = next(
                (r for r in rows
                 if r["plaintext_size"] == size
                 and r["delta_position"] == delta),
                None,
            )
            if match:
                print(f"    {delta:<12} {match['chi2_homogeneity_near_id_vs_indep']:>10.2f} {match['verdict']:<50}")
        print()


def print_dominant(rows: list[dict], cells: list[dict]) -> None:
    print("==== Dominant vector per statistic ====")
    print()
    hmax = max(rows, key=lambda r: r["chi2_homogeneity_near_id_vs_indep"])
    print(f"  cross-category chi² max: size={hmax['plaintext_size']:<6} delta={hmax['delta_position']:<12} value={hmax['chi2_homogeneity_near_id_vs_indep']:.2f}")
    ni_cells = [c for c in cells if c["category"] == "near_identical"]
    if ni_cells:
        nmax = max(ni_cells, key=lambda c: c["vs_1_over_256_floor"])
        print(f"  near_identical max floor ratio: size={nmax['plaintext_size']:<6} delta={nmax['delta_position']:<12} value={nmax['vs_1_over_256_floor']:.3f}x")
    ic_cells = [c for c in cells if c["category"] == "independent_control"]
    if ic_cells:
        imax = max(ic_cells, key=lambda c: c["vs_1_over_256_floor"])
        print(f"  independent_control max floor ratio: size={imax['plaintext_size']:<6} delta={imax['delta_position']:<12} value={imax['vs_1_over_256_floor']:.3f}x")

    # Size sensitivity: mean cross-category chi² per size.
    per_size = defaultdict(list)
    for r in rows:
        per_size[r["plaintext_size"]].append(r["chi2_homogeneity_near_id_vs_indep"])
    print()
    print("  size sensitivity (mean cross-category chi² per size):")
    for size in sorted(per_size):
        vals = per_size[size]
        print(f"    size {size:<6} mean={sum(vals)/len(vals):.2f}  min={min(vals):.2f}  max={max(vals):.2f}")
    print()


def print_verdict(rows: list[dict], cells: list[dict], baseline: dict) -> None:
    print("==== Structural verdict ====")
    print()
    hmax = max(rows, key=lambda r: r["chi2_homogeneity_near_id_vs_indep"])
    hmax_val = hmax["chi2_homogeneity_near_id_vs_indep"]
    band_top = hmax["uniform_band_3sigma_top"]
    in_band = all(r["chi2_homogeneity_near_id_vs_indep"] <= band_top for r in rows)
    print("  Two-sample homogeneity chi² is the load-bearing between-pair-shape distinguisher.")
    print(f"  Uniform band top (3σ): {band_top:.0f}   Max observed: {hmax_val:.2f}")
    print(f"    (kind: size={hmax['plaintext_size']} delta={hmax['delta_position']})")
    print()

    ni_cells = [c for c in cells if c["category"] == "near_identical"]
    ic_cells = [c for c in cells if c["category"] == "independent_control"]
    ni_max = max(c["vs_1_over_256_floor"] for c in ni_cells) if ni_cells else float("nan")
    ic_max = max(c["vs_1_over_256_floor"] for c in ic_cells) if ic_cells else float("nan")
    baseline_ratio = baseline.get("nonce_reuse_floor_ratio_at_512B", float("nan"))
    print(f"  Near-identical byte-equal floor ratio max: {ni_max:.3f}x")
    print(f"  Independent-control byte-equal floor ratio max: {ic_max:.3f}x")
    print(f"  Archival nonce-reuse near-identical baseline at 512 B: {baseline_ratio:.3f}x")
    print()
    if in_band:
        print("  Verdict: under fresh nonces the near-identical-pair wire is")
        print("           INDISTINGUISHABLE from the independent-pair wire at the")
        print("           tested sample size across every (size, delta) cell. The")
        print("           mandatory internal nonce alone collapses the pre-v0.3.0")
        print("           traffic-analysis residue the nonce-reuse Layer A probe")
        print("           records at ~16x the 1/256 floor on the same pair shape.")
        print("           Closure argument: each Encrypt call redraws every per-")
        print("           chunk mask, noise position, rotation, and startPixel from")
        print("           the fresh nonce, so no per-position correlation between")
        print("           the two pair wires survives the barrier.")
    else:
        outside = [r for r in rows if r["chi2_homogeneity_near_id_vs_indep"] > band_top]
        print("  Verdict: distinguishable at the tested sample size for the")
        print("           following cells:")
        for r in outside:
            print(f"             - size={r['plaintext_size']}, delta={r['delta_position']}: chi²={r['chi2_homogeneity_near_id_vs_indep']:.2f}")
    print()


def main() -> None:
    root = DEFAULT_ROOT
    if len(sys.argv) > 1:
        root = Path(sys.argv[1])
    if not root.exists():
        print(f"[aggregate] no records at {root}", file=sys.stderr)
        sys.exit(1)

    matrix = load(root)
    cells = matrix["run"]["cells"]
    homog = matrix["run"]["homogeneity"]
    baseline = matrix["run"]["baseline"]

    print("=" * 78)
    print("Fresh-nonce near-identical cross-message distinguisher — v0.3.0 structural analysis")
    print("=" * 78)
    cfg = matrix["run"]["config"]
    print(f"cipher entry: {cfg['cipher_entry']}")
    print(f"attacker posture: {cfg['attacker_posture']}")
    print(f"nonce policy: {cfg['nonce_policy']}")
    print(f"key_bits={cfg['key_bits']}  sample_pairs_per_cell={cfg['sample_pairs_per_cell']}")
    print(f"primitive: {cfg['primitive']}")
    print(f"sizes: {cfg['sizes']}")
    print(f"delta positions: {cfg['delta_positions']}")
    print(f"categories: {cfg['categories']}")
    print(f"wire path measured: {cfg['wire_path']}")
    print()
    print_body_chi2(cells)
    print_byte_equal_floor(cells)
    print_homogeneity(homog)
    print_dominant(homog, cells)
    print_verdict(homog, cells, baseline)


if __name__ == "__main__":
    main()
