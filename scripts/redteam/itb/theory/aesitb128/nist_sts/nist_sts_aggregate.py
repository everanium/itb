#!/usr/bin/env python3
"""Aggregate NIST STS 2.1.2 `finalAnalysisReport.txt` outputs across cells.

The NIST STS report format (per test row):
    <10 histogram columns>   P-VALUE   PROPORTION   STATISTICAL TEST
where PROPORTION is `k/N` (`k` passing substreams out of `N`).

The 15 canonical tests are:
    Frequency, BlockFrequency, CumulativeSums, Runs, LongestRun, Rank,
    FFT, NonOverlappingTemplate, OverlappingTemplate, Universal,
    ApproximateEntropy, RandomExcursions, RandomExcursionsVariant, Serial,
    LinearComplexity.

Tests with multiple sub-rows (CumulativeSums: 2, NonOverlappingTemplate: 148,
Serial: 2, RandomExcursions: 8, RandomExcursionsVariant: 18) count as
"pass" only if every sub-row's proportion clears the NIST STS pass
threshold for its sample size. The threshold at α = 0.01, N = 10 is 8/10
(NIST STS Section 4.2.1). RandomExcursions* runs on a variable-N subset
of streams (typically N = 7) with a corresponding 6/7 threshold; the report
prints "----" for the P-VALUE column and the actual N per row.

Usage:
    nist_sts_aggregate.py --root <cell-root>
        --out-md <summary.md> --out-json <summary.json>

`<cell-root>` is expected to hold `r{R}_shape{N}_trial{T}/finalAnalysisReport.txt`
sub-directories (matching the sweep-runner layout in `nist_sts_sweep.sh`).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

CANONICAL_TESTS = [
    "Frequency",
    "BlockFrequency",
    "CumulativeSums",
    "Runs",
    "LongestRun",
    "Rank",
    "FFT",
    "NonOverlappingTemplate",
    "OverlappingTemplate",
    "Universal",
    "ApproximateEntropy",
    "RandomExcursions",
    "RandomExcursionsVariant",
    "Serial",
    "LinearComplexity",
]

RE_ROW = re.compile(
    r"^\s*(?:\d+\s+){10}"                 # 10 histogram counts
    r"(?P<pval>[\d.]+|-{4})\s*\*?\s+"      # p-value (or ----)
    r"(?P<num>\d+)\s*/\s*(?P<den>\d+)\s+"  # proportion N/M
    r"(?P<test>[A-Za-z]+)\s*$"
)

# Cell dir name -> (rounds, shape, trial)
RE_CELL = re.compile(r"^r(?P<r>\d+)_shape(?P<shape>\d+)_trial(?P<t>\d+)$")


def parse_report(path: Path) -> dict:
    """Parse one finalAnalysisReport.txt into
    {test_name: {"min_pass": k, "denom": N, "sub_rows": rows}}.

    For a canonical test, `min_pass` is the minimum k across sub-rows;
    `denom` is the row-level N (usually 10, or 7 for RandomExcursions*).
    """
    per_test = defaultdict(lambda: {"min_pass": None, "denom": None, "sub_rows": 0})
    with open(path) as f:
        for line in f:
            m = RE_ROW.match(line)
            if not m:
                continue
            test = m.group("test")
            k = int(m.group("num"))
            N = int(m.group("den"))
            slot = per_test[test]
            slot["sub_rows"] += 1
            if slot["min_pass"] is None or k < slot["min_pass"]:
                slot["min_pass"] = k
            slot["denom"] = N  # last-seen row's N (rows share it per test)
    return dict(per_test)


def threshold(denom: int) -> int:
    """NIST STS Section 4.2.1 minimum passing count at alpha = 0.01.

    The NIST STS proportion test uses the confidence interval
      p_hat in [ (1-alpha) - 3*sqrt(alpha*(1-alpha)/N), 1 ]
    with alpha = 0.01, and rounds the lower endpoint * N inward to yield
    the minimum k. Yields 8/10, 6/7, 7/8, 8/9, 5/6, 4/5 etc. — matching
    the report footer's "approximately 8 for N=10, 6 for N=7"."""
    import math
    if denom <= 0:
        return 0
    alpha = 0.01
    p_lo = (1 - alpha) - 3 * math.sqrt(alpha * (1 - alpha) / denom)
    # NIST STS rounds inward via int(); reproduce that.
    return int(p_lo * denom)


def summarize_report(per_test: dict) -> dict:
    """Return a normalised summary for one cell:
        {"passed": count of 15 tests passing,
         "per_test": {test: {"min_pass": k, "denom": N, "sub_rows": r, "pass": bool}}}."""
    summary = {}
    passed = 0
    for t in CANONICAL_TESTS:
        slot = per_test.get(t)
        if slot is None or slot["min_pass"] is None:
            summary[t] = {"min_pass": None, "denom": None,
                          "sub_rows": 0, "pass": False}
            continue
        thr = threshold(slot["denom"])
        ok = slot["min_pass"] >= thr
        if ok:
            passed += 1
        summary[t] = {"min_pass": slot["min_pass"],
                      "denom": slot["denom"],
                      "sub_rows": slot["sub_rows"],
                      "threshold": thr,
                      "pass": ok}
    return {"passed": passed, "per_test": summary}


def render_markdown(cells: dict, r_set: list, shape_set: list) -> str:
    """cells: {(r, shape, trial): {"passed": int, "per_test": {...}}}."""
    lines = []
    lines.append("# NIST STS 2.1.2 sweep — ChainHash<AES-ITB-128>\n")
    lines.append("Threshold: proportion >= 8/10 (per NIST STS 4.2.1 at alpha = 0.01,")
    lines.append("10 substreams). RandomExcursions* use their own N per row.\n")

    # Worst-of-trials per (r, shape) cell
    lines.append("## Aggregated table (worst-of-3-trials, tests passed / 15)\n")
    header = "| r \\ shape | " + " | ".join(f"{s} B" for s in shape_set) + " |"
    sep = "|---|" + "|".join("---" for _ in shape_set) + "|"
    lines.append(header)
    lines.append(sep)
    for r in r_set:
        row = [f"| r = {r}" + (" (raw primitive)" if r == 1 else "")]
        for s in shape_set:
            trial_scores = [cells.get((r, s, t), {}).get("passed", None)
                            for t in (1, 2, 3)]
            if any(x is None for x in trial_scores):
                row.append("-")
            else:
                worst = min(trial_scores)
                row.append(f"{worst}/15")
        lines.append(" | ".join(row) + " |")
    lines.append("")

    # Per-test min proportion across every cell (find any weak test)
    lines.append("## Per-test worst-of-fleet (min pass count / row denom across all cells)\n")
    lines.append("| Test | worst min_pass / N (row) | worst cell (r, shape, trial) |")
    lines.append("|---|---|---|")
    for t in CANONICAL_TESTS:
        worst_val = None
        worst_cell = None
        for key, info in cells.items():
            slot = info["per_test"].get(t)
            if slot is None or slot["min_pass"] is None:
                continue
            score = slot["min_pass"] / slot["denom"]
            if worst_val is None or score < worst_val:
                worst_val = score
                worst_cell = (key, slot)
        if worst_val is None:
            lines.append(f"| {t} | - | - |")
        else:
            key, slot = worst_cell
            r, s, tr = key
            lines.append(f"| {t} | {slot['min_pass']}/{slot['denom']} "
                         f"(threshold >= {slot['threshold']}) | r={r} shape={s} trial={tr} |")
    lines.append("")

    # 15-test x (r x shape) heatmap of the worst-of-3-trials min-pass count.
    # Each cell shows min_pass/N for that (test, r, shape); bold if under
    # the NIST STS threshold.
    lines.append("## Per-test heatmap (worst-of-3-trials min_pass / N, "
                 "bold = below threshold)\n")
    col_headers = []
    col_keys = []
    for r in r_set:
        for s in shape_set:
            col_headers.append(f"r{r}/{s}B")
            col_keys.append((r, s))
    lines.append("| Test | " + " | ".join(col_headers) + " |")
    lines.append("|---|" + "|".join(["---"] * len(col_headers)) + "|")
    for t in CANONICAL_TESTS:
        row = [t]
        for (r, s) in col_keys:
            worst = None
            for trial in (1, 2, 3):
                info = cells.get((r, s, trial))
                if info is None:
                    continue
                slot = info["per_test"].get(t)
                if slot is None or slot["min_pass"] is None:
                    continue
                if worst is None or slot["min_pass"] / slot["denom"] < \
                        worst["min_pass"] / worst["denom"]:
                    worst = slot
            if worst is None:
                row.append("-")
            else:
                cell_txt = f"{worst['min_pass']}/{worst['denom']}"
                if not worst["pass"]:
                    cell_txt = f"**{cell_txt}**"
                row.append(cell_txt)
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    # List of cells with any test below threshold
    lines.append("## Cells with at least one test below threshold\n")
    weak = [(key, info) for key, info in cells.items() if info["passed"] < 15]
    if not weak:
        lines.append("_None: every cell passes all 15 tests._")
    else:
        lines.append("| r | shape | trial | tests_passed / 15 | failing tests |")
        lines.append("|---|---|---|---|---|")
        for key, info in sorted(weak):
            r, s, tr = key
            failing = [t for t, slot in info["per_test"].items()
                       if slot["pass"] is False]
            lines.append(f"| {r} | {s} | {tr} | {info['passed']}/15 | "
                         f"{', '.join(failing)} |")
    lines.append("")

    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, required=True,
                    help="Directory holding r{R}_shape{N}_trial{T} sub-directories")
    ap.add_argument("--out-md", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    args = ap.parse_args()

    cells = {}
    r_set = set()
    shape_set = set()
    for d in sorted(args.root.iterdir()):
        if not d.is_dir():
            continue
        m = RE_CELL.match(d.name)
        if not m:
            continue
        r = int(m.group("r"))
        s = int(m.group("shape"))
        t = int(m.group("t"))
        report = d / "finalAnalysisReport.txt"
        if not report.is_file():
            print(f"[warn] missing report: {report}", file=sys.stderr)
            continue
        per_test = parse_report(report)
        info = summarize_report(per_test)
        cells[(r, s, t)] = info
        r_set.add(r)
        shape_set.add(s)

    r_set = sorted(r_set)
    shape_set = sorted(shape_set)

    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(render_markdown(cells, r_set, shape_set))

    json_ready = {"|".join(map(str, k)): v for k, v in cells.items()}
    args.out_json.write_text(json.dumps({"cells": json_ready,
                                         "r_set": r_set,
                                         "shape_set": shape_set},
                                        indent=2))

    print(f"[agg] wrote {args.out_md}", file=sys.stderr)
    print(f"[agg] wrote {args.out_json}", file=sys.stderr)

    # Print a compact stdout summary too
    total_cells = len(cells)
    all_pass = sum(1 for info in cells.values() if info["passed"] == 15)
    print(f"[agg] {all_pass}/{total_cells} cells pass all 15 tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
