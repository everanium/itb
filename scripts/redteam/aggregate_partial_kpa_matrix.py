#!/usr/bin/env python3
"""Aggregate Partial-KPA matrix results into structured markdown.

Produces:
  1. Two compact "Clean Signal %" tables (one per format), rows = sizes,
     cols = 3 coverage × 2 hash = 6 columns. Main reader-friendly view.
  2. Detailed per-cell appendix with every metric (L1 unique rate, Layer 2
     sp status, WRONG count, channel coverage) — one row per cell.
  3. Brief observations (averages, trends) at the end.

Metrics:
  - Clean Signal % = emitted_bits / (data_pixels × 56) × 100
    Fraction of the naive upper bound (all pixels × all channels × 7 bits)
    the demasker actually yields as usable hash-output stream.
  - Coverage Efficiency % = emitted_bits / (channel_known × 7) × 100
    Fraction of the attacker-known budget the demasker emits.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJ = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJ / "tmp" / "attack" / "nonce_reuse" / "results"

KIND_LABELS = {
    "json_structured_80": "JSON 80%",
    "json_structured_50": "JSON 50%",
    "json_structured_25": "JSON 25%",
    "html_structured_80": "HTML 80%",
    "html_structured_50": "HTML 50%",
    "html_structured_25": "HTML 25%",
}
SIZE_LABELS = {
    4096: "4 KB",
    16384: "16 KB",
    65536: "64 KB",
    131072: "128 KB",
    524288: "512 KB",
    1048576: "1 MB",
    2097152: "2 MB",
    4194304: "4 MB",
    8388608: "8 MB",
}
SIZES_ORDER = [4096, 16384, 65536, 131072, 524288, 1048576, 2097152, 4194304, 8388608]
COVERAGES = [80, 50, 25]
HASHES = ["blake3", "fnv1a"]


def parse_demask_log(path: Path) -> dict:
    text = path.read_text() if path.exists() else ""
    out = {
        "data_pixels": None,
        "channel_known_total": None,
        "channel_total": None,
        "channel_coverage_pct": None,
        "pixels_min_k": None,
        "min_known_channels": None,
        "layer2_sp_status": "unknown",
        "period_shift": None,
        "layer1_unique": None,
        "layer1_total": None,
        "layer1_wrong": None,
        "emitted_channels": None,
        "stream_bits": None,
    }
    m = re.search(r"dataPixels\s*:\s*(\d+)", text)
    if m:
        out["data_pixels"] = int(m.group(1))
    m = re.search(
        r"channel-known coverage:\s*(\d+)/(\d+)\s*=\s*([\d.]+)%.*min_known_channels per pixel:\s*(\d+)",
        text,
    )
    if m:
        out["channel_known_total"] = int(m.group(1))
        out["channel_total"] = int(m.group(2))
        out["channel_coverage_pct"] = float(m.group(3))
        out["min_known_channels"] = int(m.group(4))
    m = re.search(r"pixels with ≥ \d+ known channels:\s*(\d+)/\d+", text)
    if m:
        out["pixels_min_k"] = int(m.group(1))
    if "Layer 2 RESULT: ✓ recovered startPixel matches ground truth" in text:
        out["layer2_sp_status"] = "true_sp"
    elif "period-shifted alignment" in text:
        out["layer2_sp_status"] = "period_shifted"
        m = re.search(r"differs from ground-truth \d+ by (\d+) pixels", text)
        if m:
            out["period_shift"] = int(m.group(1))
    elif "no valid startPixel found" in text or "BUG" in text:
        out["layer2_sp_status"] = "no_match"
    m = re.search(r"unique\s*:\s*(\d+)/(\d+)", text)
    if m:
        out["layer1_unique"] = int(m.group(1))
        out["layer1_total"] = int(m.group(2))
    m = re.search(r"WRONG match \(BUG if > 0\)\s*:\s*(\d+)", text)
    if m:
        out["layer1_wrong"] = int(m.group(1))
    m = re.search(r"emitted channels\s*:\s*(\d+)", text)
    if m:
        out["emitted_channels"] = int(m.group(1))
    m = re.search(r"stream size\s*:\s*\d+\s*bytes\s*=\s*(\d+)\s*bits", text)
    if m:
        out["stream_bits"] = int(m.group(1))
    return out


def gather_cells() -> dict:
    """Returns nested dict: by_size_kind_hash[(size, kind, hash)] -> metrics."""
    cells: dict = {}
    for run_dir in sorted(RESULTS_DIR.glob("matrix_*")):
        m = re.match(r"matrix_(\d+)_(.+)", run_dir.name)
        if not m:
            continue
        size = int(m.group(1))
        kind = m.group(2)
        summary_path = run_dir / "summary.jsonl"
        if not summary_path.exists():
            continue
        with open(summary_path) as f:
            for line in f:
                entry = json.loads(line.strip())
                hash_name = entry.get("hash")
                if not hash_name:
                    continue
                logs = list(run_dir.glob(f"cell_*_{hash_name}_BF1_N2_partial_{kind}.demask.log"))
                log_path = logs[0] if logs else Path("/nonexistent")
                metrics = parse_demask_log(log_path)
                metrics["demask_ok"] = bool(entry.get("demask_ok"))
                metrics["gen_ok"] = bool(entry.get("gen_ok"))
                metrics["n_probe"] = entry.get("n_probe")
                metrics["min_known_channels_orch"] = entry.get("min_known_channels")
                cells[(size, kind, hash_name)] = metrics
    return cells


def clean_pct(m: dict) -> float | None:
    dp = m.get("data_pixels")
    sb = m.get("stream_bits")
    if dp and sb is not None:
        return sb / (dp * 56) * 100
    return None


def coverage_eff_pct(m: dict) -> float | None:
    cb = (m.get("channel_known_total") or 0) * 7
    sb = m.get("stream_bits")
    if cb and sb is not None:
        return sb / cb * 100
    return None


def fmt_pct(x, decimals=2) -> str:
    if x is None:
        return "—"
    return f"{x:.{decimals}f}%"


def emit_compact_table(cells: dict, format_prefix: str) -> str:
    """Compact table: rows = sizes, cols = (coverage, hash). Value = Clean Signal %.
    format_prefix is 'json_structured' or 'html_structured'.
    """
    out = []
    header_1 = "| Size | " + " | ".join(
        f"{cov}% BLAKE3 | {cov}% FNV-1a" for cov in COVERAGES
    ) + " |"
    header_2 = "|------|" + "|".join([
        "---:" * 2 for _ in COVERAGES
    ]) + "|"
    # Re-emit cleanly:
    cols = []
    for cov in COVERAGES:
        cols.append(f"{cov}% BLAKE3")
        cols.append(f"{cov}% FNV-1a")
    out.append("| Size | " + " | ".join(cols) + " |")
    out.append("|------|" + "|".join("---:" for _ in cols) + "|")

    for size in SIZES_ORDER:
        size_label = SIZE_LABELS.get(size, f"{size}B")
        row_cells = [size_label]
        has_any = False
        for cov in COVERAGES:
            kind = f"{format_prefix}_{cov}"
            for h in HASHES:
                m = cells.get((size, kind, h))
                if m is None or not m.get("demask_ok"):
                    row_cells.append("—")
                    continue
                cp = clean_pct(m)
                cell_str = fmt_pct(cp, 2)
                # Flag period-shifted (reconstruction valid but offset)
                if m.get("layer2_sp_status") == "period_shifted":
                    cell_str += "⚠"
                row_cells.append(cell_str)
                has_any = True
        if has_any:
            out.append("| " + " | ".join(row_cells) + " |")
    return "\n".join(out)


def emit_coverage_efficiency_table(cells: dict, format_prefix: str) -> str:
    """Same layout but shows Coverage Efficiency % (emitted / known budget)."""
    cols = []
    for cov in COVERAGES:
        cols.append(f"{cov}% BLAKE3")
        cols.append(f"{cov}% FNV-1a")
    out = ["| Size | " + " | ".join(cols) + " |"]
    out.append("|------|" + "|".join("---:" for _ in cols) + "|")
    for size in SIZES_ORDER:
        size_label = SIZE_LABELS.get(size, f"{size}B")
        row_cells = [size_label]
        has_any = False
        for cov in COVERAGES:
            kind = f"{format_prefix}_{cov}"
            for h in HASHES:
                m = cells.get((size, kind, h))
                if m is None or not m.get("demask_ok"):
                    row_cells.append("—")
                    continue
                ce = coverage_eff_pct(m)
                row_cells.append(fmt_pct(ce, 1))
                has_any = True
        if has_any:
            out.append("| " + " | ".join(row_cells) + " |")
    return "\n".join(out)


def emit_detailed_table(cells: dict) -> str:
    """One row per cell, all metrics. Sorted by (size, kind, hash)."""
    kind_order = list(KIND_LABELS.keys())
    rows = sorted(cells.items(), key=lambda kv: (
        kv[0][0],
        kind_order.index(kv[0][1]) if kv[0][1] in kind_order else 99,
        HASHES.index(kv[0][2]) if kv[0][2] in HASHES else 99,
    ))

    out = []
    out.append("| Size | Kind | Hash | Chan cov | L2 sp | L1 uniq | WRONG | Emitted ch | Stream bits | Clean % | Cov eff % |")
    out.append("|------|------|------|---------:|:-----:|--------:|------:|-----------:|------------:|--------:|----------:|")
    for (size, kind, h), m in rows:
        size_label = SIZE_LABELS.get(size, f"{size}B")
        kind_label = KIND_LABELS.get(kind, kind)
        if not m.get("demask_ok"):
            out.append(f"| {size_label} | {kind_label} | {h} | — | FAIL | — | — | — | — | — | — |")
            continue
        l2_label = {"true_sp": "✓", "period_shifted": "⚠shift", "no_match": "✗", "unknown": "?"}[m["layer2_sp_status"]]
        l1_uniq_pct = None
        if m.get("layer1_total"):
            l1_uniq_pct = m["layer1_unique"] / m["layer1_total"] * 100
        cp = clean_pct(m)
        ce = coverage_eff_pct(m)
        out.append(
            f"| {size_label} | {kind_label} | {h} | "
            f"{fmt_pct(m.get('channel_coverage_pct'), 1)} | "
            f"{l2_label} | "
            f"{fmt_pct(l1_uniq_pct, 1)} | "
            f"{m.get('layer1_wrong') if m.get('layer1_wrong') is not None else '—'} | "
            f"{(m.get('emitted_channels') or 0):>10,} | "
            f"{(m.get('stream_bits') or 0):>11,} | "
            f"{fmt_pct(cp, 2)} | "
            f"{fmt_pct(ce, 1)} |"
        )
    return "\n".join(out)


def emit_summary(cells: dict) -> str:
    """Short summary: average clean % by coverage level & hash."""
    out = ["### Summary — average Clean Signal % across sizes"]
    out.append("")
    out.append("| Coverage | JSON BLAKE3 | JSON FNV-1a | HTML BLAKE3 | HTML FNV-1a |")
    out.append("|---------:|------------:|------------:|------------:|------------:|")
    for cov in COVERAGES:
        row = [f"{cov}%"]
        for fmt in ("json_structured", "html_structured"):
            for h in HASHES:
                vals = []
                for size in SIZES_ORDER:
                    m = cells.get((size, f"{fmt}_{cov}", h))
                    if m and m.get("demask_ok"):
                        cp = clean_pct(m)
                        if cp is not None:
                            vals.append(cp)
                avg = sum(vals) / len(vals) if vals else None
                row.append(fmt_pct(avg, 2))
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def main() -> int:
    cells = gather_cells()
    if not cells:
        print("No matrix runs found under", RESULTS_DIR, file=sys.stderr)
        return 1

    done = sum(1 for m in cells.values() if m.get("demask_ok"))
    print(f"# Partial KPA matrix — {done}/{len(cells)} cells successful\n")
    print(f"Metric: **Clean Signal %** = `emitted_bits / (data_pixels × 56) × 100` — "
          f"fraction of the naive upper bound (all data_pixels × 8 channels × 7 bits) "
          f"the demasker actually yielded as usable dataHash-output stream. `⚠` next to "
          f"a cell means Layer 2 converged onto a period-shifted startPixel (reconstruction "
          f"is still valid but offset in pixel-index space; value is still the fraction "
          f"of naive upper bound on the emitted stream).\n")

    print("## JSON — Clean Signal %\n")
    print(emit_compact_table(cells, "json_structured"))
    print()
    print("## HTML — Clean Signal %\n")
    print(emit_compact_table(cells, "html_structured"))
    print()
    print("## JSON — Coverage Efficiency %  (emitted / attacker-known-channel budget)\n")
    print(emit_coverage_efficiency_table(cells, "json_structured"))
    print()
    print("## HTML — Coverage Efficiency %\n")
    print(emit_coverage_efficiency_table(cells, "html_structured"))
    print()
    print(emit_summary(cells))
    print()
    print("## Detailed per-cell metrics\n")
    print(emit_detailed_table(cells))
    return 0


if __name__ == "__main__":
    sys.exit(main())
