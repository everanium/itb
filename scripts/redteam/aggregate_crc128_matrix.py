#!/usr/bin/env python3
"""Aggregate the CRC128 compound-key recovery matrix_summary.jsonl into a compact
markdown table suitable for inclusion in REDTEAM.md Phase 2a extension.

Reads from `tmp/attack/nonce_reuse/results/<tag>/matrix_summary.jsonl` —
one JSON object per (size, coverage, kind) cell emitted by
`crc128_compound_key_matrix.sh`.

Per-cell columns surfaced:
  - demasker outcome (OK / FAIL / period-shift / exit-2)
  - solver outcome (K recovered / no K / demasker skipped)
  - brute-force candidate count (attacker-visible)
  - correct-K match (lab-only — 0 or 1, from ground-truth filter)
  - shadow-K count (attacker-visible ambiguity)
  - channels matched on held-out pixels (validates K works)
  - wall-clock (seconds)

Each row is one `(size, coverage, kind)` cell. Rows sorted by size asc,
kind, coverage so the progression shows monotonically (where it is
monotonic).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJ = Path(__file__).resolve().parents[2]


def human_size(n_bytes: int) -> str:
    if n_bytes >= 1 << 20:
        return f"{n_bytes >> 20} MB"
    if n_bytes >= 1 << 10:
        return f"{n_bytes >> 10} KB"
    return f"{n_bytes} B"


def fmt(val, default="—"):
    if val is None:
        return default
    return str(val)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Aggregate CRC128 compound-key recovery matrix into markdown."
    )
    ap.add_argument(
        "--input", type=Path,
        default=PROJ / "tmp/attack/nonce_reuse/results/crc128_compound_key_matrix/matrix_summary.jsonl",
        help="matrix_summary.jsonl from crc128_compound_key_matrix.sh",
    )
    args = ap.parse_args()
    if not args.input.exists():
        print(f"ERROR: {args.input} does not exist", file=sys.stderr)
        return 1

    rows = []
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    if not rows:
        print("(matrix_summary.jsonl is empty — did the matrix run produce any cells?)")
        return 1

    # Sort: size asc, coverage asc, kind alpha.
    rows.sort(key=lambda r: (r.get("matrix_size", 0), r.get("matrix_coverage", 0),
                              r.get("matrix_kind", "")))

    # Group by kind for section headers.
    kinds = sorted({r["matrix_kind"] for r in rows})

    print("# CRC128 compound-key recovery — matrix\n")
    print("Columns:\n"
          "- **size**: plaintext bytes (one of the configured SIZES)\n"
          "- **cov**: attacker-known byte-level coverage (%)\n"
          "- **demask**: `OK` if demasker emitted stream; `FAIL` otherwise\n"
          "- **shift**: period-shift the demasker's Layer 2 locked onto "
          "(`shift=0` = clean, non-zero = period-shifted alignment)\n"
          "- **cand**: brute-force candidate shifts below conflict threshold "
          "(attacker-visible)\n"
          "- **correct**: candidates matching ground-truth dataSeed "
          "(lab-only filter — 1 = attacker found it; 0 = missed)\n"
          "- **shadow**: CRC64 linear-alias false positives "
          "(attacker-visible ambiguity — cannot distinguish without "
          "plaintext-consistency check on companion ciphertext)\n"
          "- **pred**: channelXOR prediction accuracy on 64 held-out pixels "
          "(512 channels total) using the lab-selected K\n"
          "- **wall**: solver wall-clock including precompute + brute + filter (s)\n")

    for kind in kinds:
        kind_rows = [r for r in rows if r["matrix_kind"] == kind]
        print(f"## {kind}\n")
        print("| size | cov | demask | shift | cand | correct | shadow | pred | wall |")
        print("|-----:|----:|:-------|:------|-----:|--------:|-------:|:-----|-----:|")
        for r in kind_rows:
            size = human_size(r.get("matrix_size", 0))
            cov = f"{r.get('matrix_coverage', '?')}%"
            demask_ok = r.get("demask_ok")
            demask = "OK" if demask_ok is True else ("FAIL" if demask_ok is False else "—")
            shift = r.get("compound_key_chosen_shift")
            shift_s = "—" if shift is None else (f"{shift}" if shift == 0 or shift else str(shift))
            cand = r.get("compound_key_brute_candidates", "—")
            correct = r.get("compound_key_n_correct", "—")
            shadow = r.get("compound_key_n_shadow", "—")
            chm = r.get("compound_key_channels_matched")
            cht = r.get("compound_key_channels_total")
            pred = f"{chm}/{cht}" if chm is not None else "—"
            wall = r.get("compound_key_elapsed_s", "—")
            print(f"| {size} | {cov} | {demask} | {shift_s} | "
                  f"{fmt(cand)} | {fmt(correct)} | {fmt(shadow)} | {pred} | {wall} |")
        print()

    # Summary roll-up.
    n_total = len(rows)
    n_demask_ok = sum(1 for r in rows if r.get("demask_ok") is True)
    n_solver_ok = sum(1 for r in rows if r.get("compound_key_ok") is True)
    n_fully_recovered = sum(
        1 for r in rows
        if r.get("compound_key_channels_matched") is not None
        and r.get("compound_key_channels_total") is not None
        and r.get("compound_key_channels_matched") == r.get("compound_key_channels_total")
    )
    print("## Roll-up\n")
    print(f"- Cells attempted        : **{n_total}**")
    print(f"- Demasker OK            : **{n_demask_ok}**  "
          f"(FAIL count: {n_total - n_demask_ok})")
    print(f"- Solver OK              : **{n_solver_ok}**")
    print(f"- K fully inverted       : **{n_fully_recovered}** / {n_total}  "
          f"(prediction 512/512 channels on held-out pixels)")
    total_cand = sum(r.get("compound_key_brute_candidates", 0) for r in rows if r.get("compound_key_brute_candidates"))
    total_shadow = sum(r.get("compound_key_n_shadow", 0) for r in rows if r.get("compound_key_n_shadow"))
    shadow_cells = [r for r in rows if r.get("compound_key_n_shadow")]
    max_shadow = max((r["compound_key_n_shadow"] for r in shadow_cells), default=0)
    mean_shadow = total_shadow / n_fully_recovered if n_fully_recovered else 0
    print(f"- Total brute candidates : **{total_cand}** (across all cells)")
    print(f"- **Total shadow-K       : {total_shadow}**  "
          f"(WRONG dataSeed candidates the attacker would still have to filter "
          f"via plaintext-consistency on companion ct — this is the empirical "
          f"per-cell ambiguity left over after all other defenses)")
    print(f"- Shadow-K per cell      : max **{max_shadow}**, mean **{mean_shadow:.1f}** "
          f"across {n_fully_recovered} inverted cells")
    n_period_shift = sum(1 for r in rows if r.get("compound_key_chosen_shift", 0))
    print(f"- Period-shifted cells   : **{n_period_shift}** "
          f"(Layer 2 locked on period-shifted sp; solver brute-forced the "
          f"correct pixel_shift and lab-filtered the shadow-K)")

    # Shadow-K breakdown by size / coverage / kind.
    print("\n### Shadow-K breakdown\n")
    def agg(key):
        agg = {}
        for r in rows:
            v = r.get(key)
            sh = r.get("compound_key_n_shadow")
            if v is None or sh is None:
                continue
            agg.setdefault(v, []).append(sh)
        return agg
    for label, key, fmtfn in [
        ("by size", "matrix_size", lambda v: human_size(v)),
        ("by coverage", "matrix_coverage", lambda v: f"{v}%"),
        ("by kind", "matrix_kind", str),
    ]:
        print(f"**Shadow-K {label}** (sum / max per cell):\n")
        a = agg(key)
        if not a:
            print("_(no data)_\n")
            continue
        items = sorted(a.items())
        header = "| " + label.replace("by ", "").ljust(8) + " | sum | max | cells |"
        sep = "|---|---:|---:|---:|"
        print(header)
        print(sep)
        for k, vals in items:
            print(f"| {fmtfn(k)} | {sum(vals)} | {max(vals)} | {len(vals)} |")
        print()

    if n_fully_recovered < n_total:
        print(f"{n_total - n_fully_recovered} cell(s) did not fully invert — typically "
              f"demasker could not emit enough usable stream (low coverage / "
              f"small plaintexts) or brute-force range missed the true "
              f"period-shift. See matrix_summary.jsonl for per-cell detail.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
