#!/usr/bin/env python3
"""Run NIST STS on reconstructed attack-simulation streams (Probe 1+).

Standalone runner for arbitrary .bin files — independent of the validation
suite's nist_sts_runner.py which assumes `tmp/streams/<hash>.bin` layout.
Used to feed Probe 1's `tmp/attack/nonce_reuse/reconstructed/*.datahash.bin`
streams through NIST STS and produce the PRF-separation table.

Each input .bin file is padded / truncated to `N × 1_000_000` bits, where
`N = floor(len(bits) / 1_000_000)`. Minimum N=1 (1 Mbit = 125 KB).

Usage:
    python3 scripts/redteam/phase3_deep/nist_sts_on_attack_streams.py \\
        --stream tmp/attack/nonce_reuse/reconstructed/blake3_BF1_N2_known.datahash.bin \\
        --stream tmp/attack/nonce_reuse/reconstructed/fnv1a_BF1_N2_known.datahash.bin \\
        --run-dir tmp/attack/nonce_reuse/nist_sts
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

PROJ = Path(__file__).resolve().parents[3]

BITSTREAM_LEN = 1_000_000
INPUT_FORMAT = 1  # binary
ALPHA = 0.01

_PROP_RE = re.compile(r"^(\d+)/(\d+)$")


def nist_min_pass(total: int) -> int:
    """NIST SP 800-22 min-pass formula: (1−α) − 3·√(α(1−α)/m)."""
    if total <= 0:
        return 0
    import math
    ratio = (1 - ALPHA) - 3 * math.sqrt(ALPHA * (1 - ALPHA) / total)
    return int(math.floor(ratio * total))


def setup_experiment_dir(run_dir: Path) -> None:
    """Initialise the NIST STS experiments/ scaffolding inside run_dir."""
    run_dir.mkdir(parents=True, exist_ok=True)
    exp_dir = run_dir / "experiments"
    if exp_dir.exists():
        shutil.rmtree(exp_dir)
    subprocess.run(
        ["nist-sts-create-experiment.sh"],
        cwd=run_dir, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def parse_final_report(path: Path) -> dict:
    """Parse nist-sts finalAnalysisReport.txt."""
    total_tests = 0
    total_pass = 0
    failing = []
    with open(path, "r") as f:
        for line in f:
            toks = line.split()
            if len(toks) < 13:
                continue
            prop_idx = None
            for i, t in enumerate(toks):
                if _PROP_RE.match(t):
                    prop_idx = i
                    break
            if prop_idx is None or prop_idx < 11 or prop_idx == len(toks) - 1:
                continue
            try:
                [int(t) for t in toks[:10]]
            except ValueError:
                continue
            m = _PROP_RE.match(toks[prop_idx])
            passed = int(m.group(1))
            total = int(m.group(2))
            name = toks[prop_idx + 1]
            total_tests += 1
            ok = passed >= nist_min_pass(total)
            if ok:
                total_pass += 1
            else:
                failing.append({"name": name, "passed": passed, "total": total})
    return {
        "total_tests": total_tests,
        "total_pass": total_pass,
        "fail_count": total_tests - total_pass,
        "failing": failing,
    }


def run_nist_on_stream(stream_path: Path, run_dir: Path, n_streams: int) -> dict:
    """Run nist-sts on one input file. Writes experiment output under run_dir."""
    if not stream_path.exists():
        return {"stream": str(stream_path), "error": "file not found"}

    size_bytes = stream_path.stat().st_size
    size_bits = size_bytes * 8
    if size_bits < n_streams * BITSTREAM_LEN:
        return {
            "stream": str(stream_path),
            "error": f"stream too short: {size_bits} bits, need ≥ "
                     f"{n_streams * BITSTREAM_LEN} bits for N={n_streams} × 1 Mbit",
        }

    cell_run_dir = run_dir / stream_path.stem
    setup_experiment_dir(cell_run_dir)
    rel_input = os.path.relpath(stream_path, cell_run_dir)
    prompt = f"0\n{rel_input}\n1\n0\n{n_streams}\n{INPUT_FORMAT}\n"

    t0 = time.time()
    proc = subprocess.run(
        ["nist-sts", str(BITSTREAM_LEN)],
        cwd=cell_run_dir,
        input=prompt,
        capture_output=True,
        text=True,
    )
    elapsed = time.time() - t0

    report_path = cell_run_dir / "experiments" / "AlgorithmTesting" / "finalAnalysisReport.txt"
    if not report_path.exists():
        return {
            "stream": str(stream_path),
            "error": f"no report (exit={proc.returncode})",
            "stderr_tail": proc.stderr[-400:],
        }
    summary = parse_final_report(report_path)
    summary["stream"] = str(stream_path)
    summary["elapsed"] = elapsed
    summary["run_dir"] = str(cell_run_dir)
    summary["n_streams"] = n_streams
    summary["size_bits"] = size_bits
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NIST STS runner for attack-simulation reconstructed streams.",
    )
    parser.add_argument(
        "--stream",
        type=Path,
        action="append",
        required=True,
        help="Path to a reconstructed .bin stream (repeatable).",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=PROJ / "tmp" / "attack" / "nonce_reuse" / "nist_sts",
        help="Base directory for nist-sts experiment artefacts (default: "
             "tmp/attack/nonce_reuse/nist_sts/).",
    )
    parser.add_argument(
        "--n-streams",
        type=int,
        default=0,
        help="Number of 1 Mbit bit-streams per input. 0 = auto-fit to file size "
             "(min 1, max 100).",
    )
    args = parser.parse_args()

    results: List[dict] = []
    for stream_path in args.stream:
        stream_path = stream_path.resolve()
        size_bits = stream_path.stat().st_size * 8 if stream_path.exists() else 0
        if args.n_streams == 0:
            n_streams = max(1, min(100, size_bits // BITSTREAM_LEN))
        else:
            n_streams = args.n_streams

        print(f"\n{'=' * 72}")
        print(f"Stream: {stream_path.name}  ({size_bits:,} bits = "
              f"{size_bits / 1_000_000:.1f} Mbit)")
        print(f"NIST STS N × 1 Mbit: N = {n_streams}")
        print(f"{'=' * 72}")
        r = run_nist_on_stream(stream_path, args.run_dir, n_streams)
        results.append(r)
        if "error" in r:
            print(f"  ERROR: {r['error']}")
            continue
        print(f"  pass/total : {r['total_pass']}/{r['total_tests']}   fails: {r['fail_count']}")
        print(f"  elapsed    : {r['elapsed']:.1f}s")
        print(f"  run dir    : {r['run_dir']}")
        if r["failing"]:
            # Print a sample of failures grouped by category
            cat: Dict[str, int] = {}
            for f in r["failing"]:
                cat[f["name"]] = cat.get(f["name"], 0) + 1
            print(f"  failing categories (count):")
            for name, cnt in sorted(cat.items(), key=lambda x: -x[1])[:10]:
                print(f"    {name:<32} {cnt}")

    # Summary table
    print(f"\n{'=' * 72}")
    print(f"NIST STS summary")
    print(f"{'=' * 72}")
    print(f"  {'stream':<60} {'pass/total':>12}   {'fails':>5}")
    for r in results:
        name = Path(r["stream"]).name if "stream" in r else "?"
        if "error" in r:
            print(f"  {name:<60} {'ERROR':>12}   {r['error'][:30]}")
        else:
            print(f"  {name:<60} {r['total_pass']:>4}/{r['total_tests']:<7d} "
                  f"{r['fail_count']:>5}")

    # Exit 0 regardless — the NIST output IS the result; "failure" on FNV-1a is
    # the expected PRF-separation signal, not an error.
    return 0


if __name__ == "__main__":
    sys.exit(main())
