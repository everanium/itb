#!/usr/bin/env python3
"""kl_matrix.py — Phase 2b Mode B BF auto-selection driver.

Iterates the Cartesian product of plaintext sizes × BarrierFill values,
runs the Mode B distinguisher on both ITB ciphertext and a matched-size
/dev/urandom sample, and accumulates per-cell metrics to a JSONL log +
final Markdown summary.

Used to measure the minimum BF per plaintext size at which ITB becomes
indistinguishable from /dev/urandom, so that SetBarrierFill(0) can map
plaintext length to the smallest defensive BF via a step function.

Primitive is fixed at BLAKE3 (PRF-grade entries produce statistically
identical Mode B outputs at matched N); Single Ouroboros only.

Usage:
    python3 scripts/redteam/phase2_theory/kl_matrix.py \\
        [--sizes 1024,4096,...] [--bfs 1,2,4,8,16,32] [--resume]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

PROJ = Path(__file__).resolve().parents[3]
OUTPUT_DIR = PROJ / "tmp" / "kltest"
WORKERS_DIR = OUTPUT_DIR / "workers"
JSONL_PATH = OUTPUT_DIR / "matrix.jsonl"
MARKDOWN_PATH = OUTPUT_DIR / "matrix.md"


DEFAULT_SIZES = [
    1024,          # 1 KB
    4096,          # 4 KB
    8192,          # 8 KB
    32 * 1024,     # 32 KB
    64 * 1024,     # 64 KB
    128 * 1024,    # 128 KB
    256 * 1024,    # 256 KB
    512 * 1024,    # 512 KB
    1024 * 1024,   # 1 MB
    2 * 1024 * 1024,   # 2 MB
    4 * 1024 * 1024,   # 4 MB
]

DEFAULT_BFS = [1, 2, 4, 8, 16, 32]
DEFAULT_N_SAMPLES = 25
DEFAULT_WORKERS = 8


def size_label(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n // (1024 * 1024)} MB"
    if n >= 1024:
        return f"{n // 1024} KB"
    return f"{n} B"


def run_cmd(cmd: List[str], env: Optional[Dict[str, str]] = None, timeout: int = 14400) -> str:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.run(
        cmd,
        cwd=PROJ,
        env=merged_env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"[!] command failed: {' '.join(cmd)}\n")
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    return proc.stdout


_print_lock = threading.Lock()
_write_lock = threading.Lock()


def tprint(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


_NUM = r"[\d.eE+-]+"

# kl_massive_single_full.py output patterns.
# NOTE: The χ² header line "Per-candidate χ² (df = 127; H0 mean = 127)"
# itself contains "mean = 127", so the chi2_mean pattern must anchor
# after the `min = X` line to grab the real observed mean.
_MF_PATTERNS = {
    "n_obs":             re.compile(r"observations per candidate[:\s]+([\d,]+)"),
    "floor":             re.compile(r"theoretical KL floor[^=:]*[:=]\s*(" + _NUM + r")"),
    "kl_max":            re.compile(r"Pairwise KL.*?max\s*=\s*(" + _NUM + r")", re.DOTALL),
    "ratio":             re.compile(r"max\s*/\s*theoretical floor\s*=\s*(" + _NUM + r")"),
    "max_bit_dev":       re.compile(r"overall max\s*=\s*(" + _NUM + r")"),
    "mean_bit_fraction": re.compile(r"mean bit fraction\s*=\s*(" + _NUM + r")"),
    "chi2_mean":         re.compile(
        r"Per-candidate χ²[^\n]*\n\s*min\s*=\s*" + _NUM + r"\s*\n\s*mean\s*=\s*(" + _NUM + r")"),
}

# kl_urandom.py per-run block patterns (n_runs=1 prints just the per-run block).
_UR_PATTERNS = {
    "n_obs":             re.compile(r"observations per candidate:\s+([\d,]+)"),
    "floor":             re.compile(r"theoretical KL floor \(bins/N\):\s+(" + _NUM + r")"),
    "kl_max":            re.compile(r"observed pairwise KL.*?max\s*=\s*(" + _NUM + r")", re.DOTALL),
    "ratio":             re.compile(r"ratio max / floor:\s+(" + _NUM + r")"),
    "max_bit_dev":       re.compile(r"max bit-fraction deviation:\s+(" + _NUM + r")"),
    "mean_bit_fraction": re.compile(r"mean bit fraction:\s+(" + _NUM + r")"),
    "chi2_mean":         re.compile(r"χ² \(df = 127;[^)]+\):\s*min=" + _NUM + r"\s+mean=(" + _NUM + r")"),
}

# kl_urandom.py aggregate block patterns (n_runs > 1).
_UR_AGG_PATTERNS = {
    "n_obs":                  re.compile(r"observations per candidate:\s+([\d,]+)"),
    "floor":                  re.compile(r"theoretical KL floor:\s+(" + _NUM + r")"),
    "kl_max_mean":            re.compile(r"pairwise KL max:\s+mean=(" + _NUM + r")"),
    "kl_max_std":             re.compile(r"pairwise KL max:\s+mean=" + _NUM + r"\s+std=(" + _NUM + r")"),
    "ratio_mean":             re.compile(r"ratio max/floor:\s+mean=(" + _NUM + r")"),
    "ratio_std":              re.compile(r"ratio max/floor:\s+mean=" + _NUM + r"×\s+std=(" + _NUM + r")"),
    "max_bit_dev_mean":       re.compile(r"max bit dev:\s+mean=(" + _NUM + r")"),
    "max_bit_dev_std":        re.compile(r"max bit dev:\s+mean=" + _NUM + r"\s+std=(" + _NUM + r")"),
    "mean_bit_fraction_mean": re.compile(r"mean bit fraction:\s+mean=(" + _NUM + r")"),
    "mean_bit_fraction_std":  re.compile(r"mean bit fraction:\s+mean=" + _NUM + r"\s+std=(" + _NUM + r")"),
    "chi2_mean_mean":         re.compile(r"χ² mean:\s+mean=(" + _NUM + r")"),
    "chi2_mean_std":          re.compile(r"χ² mean:\s+mean=" + _NUM + r"\s+std=(" + _NUM + r")"),
}


def parse_output(text: str, patterns: Dict[str, re.Pattern]) -> Dict[str, float]:
    out = {}
    for key, rx in patterns.items():
        m = rx.search(text)
        if not m:
            raise ValueError(f"pattern missing: {key}\n--- output follows ---\n{text}")
        raw = m.group(1).replace(",", "")
        out[key] = float(raw)
    return out


def container_bytes_from_ciphertext(bin_path: Path) -> int:
    # 20-byte header then the container bytes; strip header for urandom match.
    return bin_path.stat().st_size - 20


def already_done(size: int, bf: int) -> bool:
    if not JSONL_PATH.exists():
        return False
    with JSONL_PATH.open("r") as f:
        for line in f:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("size") == size and row.get("bf") == bf:
                return True
    return False


def _mean(xs):
    return sum(xs) / len(xs)


def _std(xs):
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return (sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5


METRICS = ["kl_max", "ratio", "max_bit_dev", "mean_bit_fraction", "chi2_mean"]


def run_cell(size: int, bf: int, n_samples: int, worker_id: int) -> Dict[str, float]:
    label = f"size={size_label(size)} BF={bf}"
    worker_dir = WORKERS_DIR / f"w{worker_id}"
    worker_dir.mkdir(parents=True, exist_ok=True)
    tprint(f"[w{worker_id}] >> {label}  (n_samples={n_samples})")
    t0 = time.time()

    # Step 0 — single probe encrypt to discover container_bytes, so we can
    # start /dev/urandom concurrently.
    run_cmd(
        ["go", "test", "-run", "TestRedTeamGenerateSingleMassive", "-timeout", "14400s"],
        env={
            "ITB_REDTEAM_MASSIVE": "blake3",
            "ITB_REDTEAM_MASSIVE_SIZE": str(size),
            "ITB_BARRIER_FILL": str(bf),
            "ITB_REDTEAM_MASSIVE_OUTDIR": str(worker_dir),
        },
    )
    bin_path = worker_dir / "blake3.bin"
    container_bytes = container_bytes_from_ciphertext(bin_path)

    # Step 1 — start /dev/urandom baseline asynchronously; it runs in parallel
    # with the 5 ITB encrypt+probe iterations below.
    ur_env = os.environ.copy()
    ur_proc = subprocess.Popen(
        ["python3", str(PROJ / "scripts/redteam/phase2_theory/kl_urandom.py"),
         str(container_bytes), str(n_samples)],
        cwd=PROJ,
        env=ur_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Step 2 — first ITB sample is already encrypted; probe it.
    itb_samples: List[Dict[str, float]] = []
    mf_out = run_cmd(
        ["python3", str(PROJ / "scripts/redteam/phase2_theory/kl_massive_single_full.py"), "blake3"],
        env={"ITB_MASSIVE_DIR": str(worker_dir)},
    )
    itb_samples.append(parse_output(mf_out, _MF_PATTERNS))

    # Step 3 — the remaining (n_samples - 1) ITB encryptions + probes.
    for i in range(n_samples - 1):
        run_cmd(
            ["go", "test", "-run", "TestRedTeamGenerateSingleMassive", "-timeout", "14400s"],
            env={
                "ITB_REDTEAM_MASSIVE": "blake3",
                "ITB_REDTEAM_MASSIVE_SIZE": str(size),
                "ITB_BARRIER_FILL": str(bf),
                "ITB_REDTEAM_MASSIVE_OUTDIR": str(worker_dir),
            },
        )
        mf_out = run_cmd(
            ["python3", str(PROJ / "scripts/redteam/phase2_theory/kl_massive_single_full.py"), "blake3"],
            env={"ITB_MASSIVE_DIR": str(worker_dir)},
        )
        itb_samples.append(parse_output(mf_out, _MF_PATTERNS))

    # Step 4 — wait for /dev/urandom to finish.
    ur_stdout, ur_stderr = ur_proc.communicate(timeout=14400)
    if ur_proc.returncode != 0:
        sys.stderr.write(f"[!] urandom failed cell size={size} bf={bf}\n")
        sys.stderr.write(ur_stdout)
        sys.stderr.write(ur_stderr)
        raise SystemExit(ur_proc.returncode)
    ur_out = ur_stdout

    # kl_urandom.py emits the aggregate block when n_runs > 1, and only the
    # per-run block when n_runs == 1. Pick parser accordingly.
    if n_samples > 1:
        ur_agg = parse_output(ur_out, _UR_AGG_PATTERNS)
        ur_mean = {k: ur_agg[k + "_mean"] for k in METRICS}
        ur_std = {k: ur_agg[k + "_std"] for k in METRICS}
        ur_mean["n_obs"] = int(ur_agg["n_obs"])
        ur_mean["floor"] = ur_agg["floor"]
    else:
        ur_single = parse_output(ur_out, _UR_PATTERNS)
        ur_mean = {k: ur_single[k] for k in METRICS}
        ur_std = {k: 0.0 for k in METRICS}
        ur_mean["n_obs"] = int(ur_single["n_obs"])
        ur_mean["floor"] = ur_single["floor"]

    # Aggregate ITB over n_samples.
    itb_mean = {k: _mean([s[k] for s in itb_samples]) for k in METRICS}
    itb_std = {k: _std([s[k] for s in itb_samples]) for k in METRICS}

    elapsed = time.time() - t0

    row: Dict[str, float] = {
        "size": size,
        "size_label": size_label(size),
        "bf": bf,
        "container_bytes": container_bytes,
        "n_samples": n_samples,
        "n_obs": int(itb_samples[0]["n_obs"]),
        "floor": itb_samples[0]["floor"],
    }
    for k in METRICS:
        row[f"itb_{k}_mean"] = itb_mean[k]
        row[f"itb_{k}_std"] = itb_std[k]
        row[f"ur_{k}_mean"] = ur_mean[k]
        row[f"ur_{k}_std"] = ur_std[k]
        row[f"d_{k}"] = itb_mean[k] - ur_mean[k]
        # Pooled std: sqrt(var_itb + var_ur) — treats the two distributions
        # as independent samples with separately estimated variances.
        pooled = (itb_std[k] ** 2 + ur_std[k] ** 2) ** 0.5
        row[f"pooled_std_{k}"] = pooled
        row[f"z_{k}"] = (
            abs(itb_mean[k] - ur_mean[k]) / pooled if pooled > 0 else 0.0
        )
    row["elapsed_sec"] = round(elapsed, 2)

    tprint(
        f"[w{worker_id}] << {label}  "
        f"ITB ratio {itb_mean['ratio']:.3f}±{itb_std['ratio']:.3f}  "
        f"UR {ur_mean['ratio']:.3f}±{ur_std['ratio']:.3f}  "
        f"Δ={row['d_ratio']:+.3f}  z={row['z_ratio']:.2f}  "
        f"χ² Δ={row['d_chi2_mean']:+.2f} z={row['z_chi2_mean']:.2f}  "
        f"({elapsed:.1f}s)"
    )
    return row


Z_THRESHOLD = 1.0  # |Δ_mean| ≤ 1 pooled-σ → indistinguishable


def render_markdown(rows: List[Dict[str, float]], sizes: List[int], bfs: List[int]) -> str:
    by_cell = {(r["size"], r["bf"]): r for r in rows}

    lines = []
    lines.append("# kl_matrix.py output — Phase 2b Mode B BF auto-selection")
    lines.append("")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Cells: {len(rows)}")
    n_samples_any = rows[0]["n_samples"] if rows else 1
    lines.append(f"Samples per cell: {n_samples_any} ITB + {n_samples_any} /dev/urandom")
    lines.append("")
    lines.append(
        "## Indistinguishability grid  "
        f"(✓ = |Δ_ratio| / pooled σ ≤ {Z_THRESHOLD}, ✗ = above)"
    )
    lines.append("")
    header = "| Size | " + " | ".join(f"BF={b}" for b in bfs) + " |"
    sep = "|:-----|" + "|".join([":---:"] * len(bfs)) + "|"
    lines.append(header)
    lines.append(sep)
    for s in sizes:
        cells = []
        for b in bfs:
            r = by_cell.get((s, b))
            if r is None:
                cells.append("–")
            else:
                ok = r["z_ratio"] <= Z_THRESHOLD
                cells.append("✓" if ok else "✗")
        lines.append(f"| {size_label(s)} | " + " | ".join(cells) + " |")
    lines.append("")

    lines.append("## Ratio means and z-scores  (5 ITB × 5 urandom per cell)")
    lines.append("")
    lines.append("| Size | BF | N | ITB ratio | UR ratio | Δ | pooled σ | z | χ² Δ | z(χ²) |")
    lines.append("|:---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for s in sizes:
        for b in bfs:
            r = by_cell.get((s, b))
            if r is None:
                continue
            lines.append(
                f"| {size_label(s)} | {b} | {r['n_obs']:,} | "
                f"{r['itb_ratio_mean']:.3f}±{r['itb_ratio_std']:.3f} | "
                f"{r['ur_ratio_mean']:.3f}±{r['ur_ratio_std']:.3f} | "
                f"{r['d_ratio']:+.3f} | {r['pooled_std_ratio']:.3f} | "
                f"{r['z_ratio']:.2f} | "
                f"{r['d_chi2_mean']:+.2f} | {r['z_chi2_mean']:.2f} |"
            )
    lines.append("")

    lines.append(
        "## Minimum BF per size with z_ratio ≤ "
        f"{Z_THRESHOLD} (indistinguishable from /dev/urandom)"
    )
    lines.append("")
    lines.append("| Size | BF_min | z_ratio at BF_min | Δ_ratio |")
    lines.append("|:---|:---:|---:|---:|")
    for s in sizes:
        bf_min = None
        z_at = None
        d_at = None
        for b in bfs:
            r = by_cell.get((s, b))
            if r and r["z_ratio"] <= Z_THRESHOLD:
                bf_min = b
                z_at = r["z_ratio"]
                d_at = r["d_ratio"]
                break
        if bf_min is None:
            lines.append(f"| {size_label(s)} | **none passes** | — | — |")
        else:
            lines.append(f"| {size_label(s)} | {bf_min} | {z_at:.2f} | {d_at:+.3f} |")

    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=str, default=None,
                    help="comma-separated plaintext sizes in bytes")
    ap.add_argument("--bfs", type=str, default=None,
                    help="comma-separated BF values")
    ap.add_argument("--n-samples", type=int, default=DEFAULT_N_SAMPLES,
                    help=f"number of ITB + urandom samples per cell (default {DEFAULT_N_SAMPLES})")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                    help=f"number of parallel cell workers (default {DEFAULT_WORKERS})")
    ap.add_argument("--resume", action="store_true",
                    help="skip cells already present in matrix.jsonl")
    args = ap.parse_args()

    sizes = DEFAULT_SIZES
    if args.sizes:
        sizes = [int(s) for s in args.sizes.split(",")]

    bfs = DEFAULT_BFS
    if args.bfs:
        bfs = [int(s) for s in args.bfs.split(",")]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    WORKERS_DIR.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, float]] = []
    if args.resume and JSONL_PATH.exists():
        with JSONL_PATH.open("r") as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        tprint(f"[=] resume: {len(rows)} existing rows in {JSONL_PATH}")

    all_cells = [(s, b) for s in sizes for b in bfs]
    if args.resume:
        pending = [(s, b) for (s, b) in all_cells if not already_done(s, b)]
    else:
        pending = all_cells
    total = len(pending)
    tprint(f"[.] matrix: {total} pending cells × (n_samples={args.n_samples})  "
           f"workers={args.workers}")
    t_start = time.time()

    completed = [0]

    def _work(idx: int, s: int, b: int) -> Dict[str, float]:
        worker_id = idx % args.workers
        row = run_cell(s, b, args.n_samples, worker_id)
        return row

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(_work, i, s, b): (s, b)
                   for i, (s, b) in enumerate(pending)}
        for fut in as_completed(futures):
            row = fut.result()
            with _write_lock:
                with JSONL_PATH.open("a") as fout:
                    fout.write(json.dumps(row) + "\n")
                    fout.flush()
                rows.append(row)
                completed[0] += 1
                tprint(f"[=] done {completed[0]}/{total}")

    total_elapsed = time.time() - t_start
    tprint(f"\n[✓] matrix done in {total_elapsed / 60:.1f} min")

    md = render_markdown(rows, sizes, bfs)
    MARKDOWN_PATH.write_text(md)
    tprint(f"[✓] summary written to {MARKDOWN_PATH}")


if __name__ == "__main__":
    main()
