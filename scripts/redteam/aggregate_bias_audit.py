#!/usr/bin/env python3
"""Aggregate bias_audit_matrix.sh's matrix_summary.jsonl into a markdown
table suitable for REDTEAM.md Phase 2a extension.

One row per (primitive, size, format) cell with the salient statistics:
minimum conflict rate, median, max, TRUE-shift rank (lab-only), plateau
size, and scan wall-clock. A "verdict" column summarises the empirical
outcome per cell: `neutralized ✓` when the distribution is flat around
50 % with TRUE shift randomly ranked, `bias-leak ✗` when the min is
noticeably below 50 % with a small plateau and TRUE shift near top,
`ambiguous` otherwise.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJ = Path(__file__).resolve().parents[2]


def human_size(n: int) -> str:
    if n >= 1 << 20:
        return f"{n >> 20} MB"
    if n >= 1 << 10:
        return f"{n >> 10} KB"
    return f"{n} B"


def verdict(row: dict) -> str:
    """Assign a textual verdict from two independent axes:

    Axis 1 — bias-probe distribution shape. The TRUE (lab-known)
    pixel-shift's rank among the full sorted conflict-rate distribution.
    Primitives that leak bias through ITB's masking push the TRUE shift
    toward rank 1; primitives ITB neutralises scatter the TRUE shift
    uniformly in [1, total].

    Axis 2 — per-bit prediction accuracy of the compound key K recovered
    at the min-conflict shift (attacker's best guess), measured against
    `config.truth.json` lab-ground-truth on held-out pixels. Random
    baseline ≈ 50.0 %. GF(2)-linear primitives give ~55-62 % empirically
    (rotate7 + noise injection dilutes the raw-mode signal but the
    per-bit majority still retains measurable bias); PRF and carry-chain
    primitives hover at 50.0 ± √(1/N).  Channel-level accuracy is ~0 for
    all primitives in raw-mode and not used for classification.

    Verdict rules (require both axes to agree when available):
      * `bias-leak ✗` — TRUE rank in top 1 % OR bit-accuracy ≥ 53 %
        (≥ 3× binomial noise above baseline at typical probe sizes),
        AND the other axis is consistent.
      * `neutralized ✓` — TRUE rank in middle 10–90 % OR plateau > 10 %
        of total, AND bit-accuracy ≤ 51 %.
      * `ambiguous` — axes disagree or both metrics are marginal.
    """
    plateau = row.get("plateau_size")
    rank = row.get("true_shift_rank")
    total = row.get("total_shifts")
    pred_bits = row.get("pred_min_bits_pct")
    if plateau is None or rank is None or total is None or total <= 0:
        return "—"
    rank_ratio = rank / total
    plateau_ratio = plateau / total

    # Two independent axes, combined with logical-OR for bias-leak and
    # logical-AND for neutralized:
    #
    #   * **axis-1 strong leak** — TRUE rank < 1 % AND plateau < 1 %.
    #     GF(2)-linear primitive with sufficient sample size surfaces here
    #     regardless of plaintext bias direction (CRC128 × 1 MB × any
    #     structured format → rank 1/151321). Axis-1 uses only the full
    #     conflict-rate distribution, so a scrambled K prediction at the
    #     min-conflict shift does not mask the TRUE-shift rank.
    #
    #   * **axis-2 strong leak** — |pred_bits_TRUE − 50| ≥ 2 p.p. The
    #     signed direction flips depending on which token-character
    #     bit-frequency dominates rotation-averaged majority-vote (ASCII
    #     uniform → +10.7, JSON tokens → −8.9 or +3.6, HTML tokens →
    #     +1.8), so the discriminator is distance from baseline. PRFs
    #     stay within ±1 p.p. (binomial noise on ~1800 bit-trials).
    #     Note: `pred_true_bits_pct` is lab-only (attacker cannot pick
    #     the true shift without solving the whole recovery), used here
    #     as measurement methodology to attribute algebraic leak to the
    #     primitive+plaintext combination rather than best-of-N scan
    #     variance.
    #
    # If the probe emitted only `pred_min_bits_pct` (older matrix runs),
    # fall back to it with a looser threshold since MIN carries
    # selection-bias artefact (best-of-151k scan picks an extreme random
    # shift even under uniform plaintext).
    pred_true_bits = row.get("pred_true_bits_pct")
    dist_true = abs(pred_true_bits - 50.0) if pred_true_bits is not None else None
    dist_min = abs(pred_bits - 50.0) if pred_bits is not None else None

    strong_a1 = (rank_ratio < 0.01 and plateau_ratio < 0.01)
    strong_a2 = (dist_true is not None and dist_true >= 2.0)
    weak_a2 = (dist_true is not None and dist_true <= 1.0)

    # Strong signal on EITHER axis → bias-leak.
    if strong_a1 or strong_a2:
        return "bias-leak ✗"
    # TRUE axis-2 within ±1 p.p. of baseline → neutralized. Axis-1 rank
    # has high single-corpus variance (PRF rank uniform in [1, total];
    # a single run can land in top 7 % by chance), so neutralized does
    # NOT require axis-1 middle rank — TRUE axis-2 is the robust signal.
    # MIN-only fallback (no lab truth): still requires MIN |Δ50| ≤ 1
    # since MIN generates best-of-N artefact even on random-binary.
    if weak_a2:
        return "neutralized ✓"
    if dist_true is None:
        if dist_min is not None and dist_min <= 1.0:
            return "neutralized ✓"
        return "ambiguous"
    return "ambiguous"

    # Axis-1 only path (pre-axis-2 matrices / no truth available).
    if rank_ratio < 0.01 and plateau_ratio < 0.01:
        return "bias-leak ✗"
    if plateau_ratio > 0.10:
        return "neutralized ✓"
    if 0.15 < rank_ratio < 0.85 and plateau_ratio > 0.05:
        return "neutralized ✓"
    return "ambiguous"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--input", type=Path,
        default=PROJ / "tmp/attack/nonce_reuse/results/bias_audit_matrix/matrix_summary.jsonl",
    )
    args = ap.parse_args()
    if not args.input.exists():
        print(f"ERROR: {args.input} missing; run bias_audit_matrix.sh first.",
              file=sys.stderr)
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

    rows.sort(key=lambda r: (r.get("primitive", ""), r.get("size_bytes", 0),
                             r.get("format", "")))

    print("# Bias neutralization empirical audit — matrix\n")
    print("Columns:\n"
          "- **primitive**: hash plugged into ChainHash (via `chainhashes/*.py`)\n"
          "- **size**: plaintext bytes (uniform ASCII under `mode=known_ascii`)\n"
          "- **format**: plaintext format — always `ascii` in this matrix\n"
          "- **min / median % conflict**: full conflict-rate distribution "
          "across every candidate pixel_shift\n"
          "- **TRUE rank / total**: lab-only — where the ground-truth shift "
          "falls in the sorted distribution. PRF-like behaviour → rank is "
          "random (middle of distribution). GF(2)-linear bias → rank near 1.\n"
          "- **plateau**: shifts whose conflict count ≤ TRUE shift's — "
          "if small relative to total and TRUE rank is near 1, there's a "
          "real bias signal; if huge fraction of total, noise dominates.\n"
          "- **pred-bits**: axis-2 — per-bit prediction accuracy of K "
          "recovered at the min-conflict shift (attacker's best) against "
          "lab-only `config.truth.json` held-out pixels. Random baseline "
          "≈ 50.00 %. Raw-mode dilution via rotate7 + noise injection "
          "caps GF(2)-linear signal at ~55–62 %; PRFs stay at 50 ± 0.5 %.\n"
          "- **verdict**: combined axis-1 + axis-2 — `neutralized ✓`, "
          "`bias-leak ✗`, `ambiguous`.\n"
          "- **wall**: probe scan wall-clock (seconds)\n")

    print("| primitive | size | format | min % | TRUE rank | plateau | TRUE bits % | \\|Δ50 TRUE\\| | MIN bits % | \\|Δ50 MIN\\| | verdict |")
    print("|:----------|-----:|:-------|------:|:----------|--------:|------------:|------------:|-----------:|-----------:|:--------|")
    for r in rows:
        primitive = r.get("primitive", "?")
        size = human_size(r.get("size_bytes", 0))
        fmt = r.get("format", "?")
        minc = r.get("min_conflict_pct")
        rank = r.get("true_shift_rank")
        total = r.get("total_shifts")
        plateau = r.get("plateau_size")
        pred_min = r.get("pred_min_bits_pct")
        pred_true = r.get("pred_true_bits_pct")
        v = verdict(r)
        rank_str = f"{rank}/{total}" if rank is not None and total is not None else "—"
        pt_str = f"{pred_true:.2f}" if pred_true is not None else "—"
        dt_str = f"{abs(pred_true - 50.0):.2f}" if pred_true is not None else "—"
        pm_str = f"{pred_min:.2f}" if pred_min is not None else "—"
        dm_str = f"{abs(pred_min - 50.0):.2f}" if pred_min is not None else "—"
        print(f"| {primitive} | {size} | {fmt} | "
              f"{minc or '—'} | "
              f"{rank_str} | {plateau or '—'} | "
              f"{pt_str} | {dt_str} | {pm_str} | {dm_str} | {v} |")

    # Roll-up
    print("\n## Roll-up\n")
    by_prim = {}
    for r in rows:
        p = r.get("primitive", "?")
        by_prim.setdefault(p, []).append(r)
    for p, subset in sorted(by_prim.items()):
        verdicts = [verdict(r) for r in subset]
        v_count = {v: verdicts.count(v) for v in set(verdicts)}
        min_conflict = min((r.get("min_conflict_pct") or 100) for r in subset)
        max_plateau = max((r.get("plateau_size") or 0) for r in subset)
        print(f"- **{p}**: cells={len(subset)}  min_conflict_across_cells={min_conflict}%  "
              f"max_plateau={max_plateau}  verdicts={v_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
