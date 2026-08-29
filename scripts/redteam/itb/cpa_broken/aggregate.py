#!/usr/bin/env python3
"""Aggregate the fresh-nonce CPA broken-primitive probe JSON records.

Reads the record file emitted by `TestRedTeamCPABroken` at
`~/scratch/redteam/cpa_broken/cpa_broken_matrix.json` (override the
parent dir via REDTEAM_CPA_BROKEN_OUTPUT_DIR) and prints a compact
structural analysis:

  - per-cell body chi² vs df=255 uniform (per primitive, per plaintext
    kind)
  - per-cell mean pairwise byte-equal rate vs the 1/256 independent
    stream floor
  - two-sample homogeneity chi² between the FNV-1a arm and the BLAKE3
    arm at every plaintext kind (df=255) — the load-bearing between-arm
    distinguisher
  - dominant plaintext-kind ranking
  - null / signal verdict against the uniform band

Consumes only the emitted JSON records — no Go test state.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path


DEFAULT_ROOT = Path(os.environ.get(
    "REDTEAM_CPA_BROKEN_OUTPUT_DIR",
    str(Path.home() / "scratch" / "redteam" / "cpa_broken"),
))


def load(root: Path) -> dict:
    return json.loads((root / "cpa_broken_matrix.json").read_text())


def fmt_chi2(v: float) -> str:
    return f"{v:>8.2f}"


def per_kind_body(cells: list[dict]) -> dict[str, dict[str, dict]]:
    per: dict[str, dict[str, dict]] = defaultdict(dict)
    for c in cells:
        per[c["primitive"]][c["kind"]] = {
            "body_chi2": c["body_chi2_uniform"],
            "pair_be_rate": c["mean_pair_byte_equal_rate"],
            "excess": c["excess_over_floor"],
            "pooled_bytes": c["pooled_body_bytes"],
        }
    return per


def print_body_chi2(per_kind: dict) -> None:
    print("\n==== Per-cell body byte-histogram chi² vs df=255 uniform ====")
    print("df=255 uniform band: mean 255, one-sided 3σ top ≈ 323")
    print("Body extraction: container body only (nonce + W + H header dropped)")
    print()
    kinds = sorted({k for prim_kinds in per_kind.values() for k in prim_kinds})
    header = f"  {'kind':<18} " + " ".join(f"{prim:>10}" for prim in sorted(per_kind))
    print(header)
    for kind in kinds:
        row = [f"  {kind:<18}"]
        for prim in sorted(per_kind):
            cell = per_kind[prim].get(kind, {})
            v = cell.get("body_chi2", float("nan"))
            row.append(fmt_chi2(v) + "  ")
        print("".join(row))
    print()


def print_pair_byte_equal(per_kind: dict) -> None:
    print("==== Mean pairwise byte-equal rate (successive ct pairs) ====")
    print("Independent uniform stream floor: 1/256 = 0.00391")
    print()
    kinds = sorted({k for prim_kinds in per_kind.values() for k in prim_kinds})
    header = f"  {'kind':<18} " + " ".join(f"{prim:>10}" for prim in sorted(per_kind))
    print(header)
    for kind in kinds:
        row = [f"  {kind:<18}"]
        for prim in sorted(per_kind):
            cell = per_kind[prim].get(kind, {})
            v = cell.get("pair_be_rate", float("nan"))
            row.append(f"  {v:.5f}  ")
        print("".join(row))
    print()


def print_homogeneity(rows: list[dict]) -> None:
    print("==== Cross-primitive homogeneity chi² (FNV-1a vs BLAKE3) ====")
    print("Two-sample chi² homogeneity test, df=255")
    print("Null: FNV-1a and BLAKE3 wire byte distributions indistinguishable")
    print("Uniform band top (3σ, one-sided): 323")
    print()
    rows_sorted = sorted(rows, key=lambda r: r["chi2_homogeneity_fnv1a_vs_blake3"], reverse=True)
    print(f"  {'kind':<18} {'chi²':>10} {'band top':>10} {'verdict':<40}")
    for r in rows_sorted:
        chi2 = r["chi2_homogeneity_fnv1a_vs_blake3"]
        verdict = r["verdict"]
        print(f"  {r['kind']:<18} {chi2:>10.2f} {r['uniform_band_3sigma_top']:>10.0f} {verdict:<40}")
    print()


def print_dominant(rows: list[dict], per_kind: dict) -> None:
    print("==== Dominant plaintext kind (per statistic) ====")
    print()
    hmax = max(rows, key=lambda r: r["chi2_homogeneity_fnv1a_vs_blake3"])
    print(f"  homogeneity chi² max:   kind={hmax['kind']:<16} value={hmax['chi2_homogeneity_fnv1a_vs_blake3']:.2f}")
    for prim in sorted(per_kind):
        bmax_kind, bmax_val = max(
            per_kind[prim].items(),
            key=lambda kv: kv[1]["body_chi2"],
        )
        pmax_kind, pmax_val = max(
            per_kind[prim].items(),
            key=lambda kv: abs(kv[1]["pair_be_rate"] - 1.0 / 256.0),
        )
        print(f"  {prim} body chi² max:   kind={bmax_kind:<16} value={bmax_val['body_chi2']:.2f}")
        print(f"  {prim} |pair_be - floor| max: kind={pmax_kind:<16} rate={pmax_val['pair_be_rate']:.5f}")
    print()


def print_verdict(rows: list[dict], per_kind: dict) -> None:
    print("==== Structural verdict ====")
    print()
    hmax = max(rows, key=lambda r: r["chi2_homogeneity_fnv1a_vs_blake3"])
    hmax_val = hmax["chi2_homogeneity_fnv1a_vs_blake3"]
    band_top = hmax["uniform_band_3sigma_top"]
    in_band = all(r["chi2_homogeneity_fnv1a_vs_blake3"] <= band_top for r in rows)
    print("  Two-sample chi² homogeneity is the load-bearing between-arm distinguisher.")
    print(f"  Uniform band top (3σ): {band_top:.0f}   Max observed: {hmax_val:.2f}   (kind: {hmax['kind']})")
    print()
    if in_band:
        print("  Verdict: FNV-1a wire under fresh-nonce CPA is INDISTINGUISHABLE from")
        print("           BLAKE3 wire at the tested sample size across every plaintext")
        print("           kind. The barrier absorbs the below-spec primitive's")
        print("           algebraic weakness at the chosen-plaintext attacker posture.")
        print("           Closure argument: chosen-plaintext capability under fresh")
        print("           nonces surfaces no primitive-attributable handle on any of")
        print("           the 8 seed-derivation slots.")
    else:
        outside = [r for r in rows if r["chi2_homogeneity_fnv1a_vs_blake3"] > band_top]
        print("  Verdict: distinguishable at the tested sample size for the")
        print("           following plaintext kinds:")
        for r in outside:
            print(f"             - {r['kind']}: chi²={r['chi2_homogeneity_fnv1a_vs_blake3']:.2f}")
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

    print("=" * 78)
    print("Fresh-nonce CPA broken-primitive — structural analysis")
    print("=" * 78)
    cfg = matrix["run"]["config"]
    print(f"cipher entry: {cfg['cipher_entry']}")
    print(f"attacker posture: {cfg['attacker_posture']}")
    print(f"nonce policy: {cfg['nonce_policy']}")
    print(f"key_bits={cfg['key_bits']}  plaintext_bytes={cfg['plaintext_bytes']}  sample_n={cfg['sample_n']}")
    print(f"primitives: {cfg['primitives']}")
    print(f"plaintext kinds: {cfg['kinds']}")
    print(f"wire path measured: {cfg['wire_path']}")
    print()
    per_kind = per_kind_body(cells)
    print_body_chi2(per_kind)
    print_pair_byte_equal(per_kind)
    print_homogeneity(homog)
    print_dominant(homog, per_kind)
    print_verdict(homog, per_kind)


if __name__ == "__main__":
    main()
