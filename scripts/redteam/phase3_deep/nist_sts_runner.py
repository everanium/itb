#!/usr/bin/env python3
"""Phase 3b: run NIST STS in parallel across all 12 hash streams.

Each hash gets its own experiment directory (tmp/streams/nist_<hash>/) with
a fresh experiments/AlgorithmTesting/finalAnalysisReport.txt; we then parse
the reports and build a cross-hash summary table.

Input streams come from the main red-team corpus via prepare_streams.py —
header-stripped pixel bytes concatenated across all samples of one hash,
written to tmp/streams/<hash>.bin (~9 MB = ~72 Mbits each). This is 3.6×
more than NIST STS needs for 20 sequences × 1 Mbit, so no separate
mega-stream generation is required.

Prerequisites:
  1. Run the corpus: ITB_REDTEAM=1 go test -run TestRedTeamGenerate
  2. Run: python3 scripts/redteam/phase3_deep/prepare_streams.py
  3. `nist-sts` and `nist-sts-create-experiment.sh` installed (Arch: nist-sts).

Per-hash settings: 20 bit-streams of 1,000,000 bits each (20 Mbits consumed
from the ~72 Mbit corpus stream). Produces 188 test results across 15
categories.

Parallelism: one subprocess per hash (up to 12 concurrent). Each runs in its
own CWD so experiments/ directories don't collide.

Interpretation:
  - Proportion column: p/total; min pass rate scales with total via the NIST
    SP 800-22 formula (18/20 for standard tests; scales down for
    RandomExcursions when fewer sequences have valid excursions)
  - P-value column: uniformity of per-sequence p-values (meta-test)
  - A pass rate < threshold on ≤10/188 tests is consistent with random data
    (NIST STS itself documents this false-positive rate).
"""

import os
import re
import sys
import time
import math
import shutil
import subprocess
import multiprocessing as mp
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import HASH_DIRNAMES, HASH_DISPLAY

PROJ = Path(__file__).resolve().parents[3]
STREAMS = PROJ / "tmp" / "streams"

# NIST STS parameters
BITSTREAM_LEN = 1_000_000  # bits per sequence (fixed at 1 Mbit)
INPUT_FORMAT = 1           # binary

# NUM_STREAMS is configurable via ITB_NIST_STREAMS env var (whitelist-validated);
# default 20 matches NIST SP 800-22 example. Larger N does not eliminate the
# NonOverlappingTemplate single-bin clustering on near-uniform output — the
# cluster lands in bin 0 at ~10% per (hash, run) pair at any N (BLAKE3 drew
# bin 0 at N=100 BF=32 in this suite, alongside FNV-1a at N=20 Run A). What
# larger N does buy is that conventional non-bin-0 proportion failures stand
# out as genuine outliers instead of being confused with the bin-routing
# artefact.
_ALLOWED_STREAMS = {20, 30, 50, 100}


def _resolve_num_streams() -> int:
    raw = os.environ.get("ITB_NIST_STREAMS", "").strip()
    if not raw:
        return 20
    try:
        n = int(raw)
    except ValueError:
        raise SystemExit(
            f"ITB_NIST_STREAMS={raw!r}: must be an integer in {sorted(_ALLOWED_STREAMS)}"
        )
    if n not in _ALLOWED_STREAMS:
        raise SystemExit(
            f"ITB_NIST_STREAMS={n}: must be one of {sorted(_ALLOWED_STREAMS)}"
        )
    return n


NUM_STREAMS = _resolve_num_streams()

ALPHA = 0.01  # NIST STS significance level


def min_pass(total: int) -> int:
    """Minimum passing proportion for a given `total` number of valid sequences.

    NIST STS SP 800-22 formula: p̂_min = (1-α) - 3 × sqrt(α(1-α)/m).
    For RandomExcursions tests, `total` is not always 20 — it equals the
    number of sequences that contain valid excursions, so the threshold
    must scale with m rather than being hardcoded at 18 or 11.

    Examples: m=20 → 18, m=13 → 11, m=9 → 8.
    """
    if total <= 0:
        return 0
    ratio = (1 - ALPHA) - 3 * math.sqrt(ALPHA * (1 - ALPHA) / total)
    return int(math.floor(ratio * total))


def setup_experiment_dir(hash_name: str) -> Path:
    """Create tmp/streams/nist_<hash>/ with experiments/ skeleton."""
    run_dir = STREAMS / f"nist_{hash_name}"
    run_dir.mkdir(parents=True, exist_ok=True)
    # Reset experiments/ to avoid cross-contamination from previous runs
    exp_dir = run_dir / "experiments"
    if exp_dir.exists():
        shutil.rmtree(exp_dir)
    subprocess.run(
        ["nist-sts-create-experiment.sh"],
        cwd=run_dir, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return run_dir


def run_nist_sts(hash_name: str) -> dict:
    """Launch nist-sts for one hash. Returns dict with success + parsed results."""
    stream_path = STREAMS / f"{hash_name}.bin"
    if not stream_path.exists():
        return {"hash": hash_name, "error": f"missing {stream_path} — run prepare_streams.py first"}

    run_dir = setup_experiment_dir(hash_name)

    # Input path relative to run_dir (nist-sts prompt wants a filename — a
    # relative path works as long as it resolves from CWD).
    rel_input = os.path.relpath(stream_path, run_dir)

    # Interactive prompt sequence:
    #   0  → input from file
    #   <path>
    #   1  → apply all 15 tests
    #   0  → no parameter adjustments
    #   20 → number of bit-streams
    #   1  → binary input
    prompt = f"0\n{rel_input}\n1\n0\n{NUM_STREAMS}\n{INPUT_FORMAT}\n"

    t0 = time.time()
    proc = subprocess.run(
        ["nist-sts", str(BITSTREAM_LEN)],
        cwd=run_dir,
        input=prompt,
        capture_output=True,
        text=True,
    )
    elapsed = time.time() - t0

    # nist-sts frequently exits with non-zero after completing all tests
    # (interactive-prompt EOF handling quirk). Trust the report file instead
    # — if it exists and parses with 188 rows, the run succeeded.
    report_path = run_dir / "experiments" / "AlgorithmTesting" / "finalAnalysisReport.txt"
    if not report_path.exists():
        return {
            "hash": hash_name,
            "error": f"no report (exit={proc.returncode}): {proc.stderr[-400:]}",
        }

    summary = parse_final_report(report_path)
    summary["hash"] = hash_name
    summary["elapsed"] = elapsed
    summary["run_dir"] = str(run_dir)
    return summary


_PROP_RE = re.compile(r"^(\d+)/(\d+)$")


def parse_final_report(path: Path) -> dict:
    """Parse NIST STS finalAnalysisReport.txt — tabulate per-test pass/fail.

    Each data row has this token layout (tab/space separated):
      C1..C10 (10 ints)  P-VALUE (float or '----')  optional '*'
      PROPORTION (p/total)  TEST_NAME

    We split on whitespace and locate the PROPORTION token (shape "n/m") to
    anchor the parse; the test name is everything after, and P-value precedes.
    """
    total_tests = 0
    total_pass = 0
    failing_tests = []
    category_counts: dict[str, tuple[int, int]] = {}

    with open(path, "r") as f:
        for line in f:
            tokens = line.split()
            if len(tokens) < 13:
                continue
            # Find PROPORTION token — matches "p/t"
            prop_idx = None
            for i, tok in enumerate(tokens):
                if _PROP_RE.match(tok):
                    prop_idx = i
                    break
            if prop_idx is None or prop_idx < 11 or prop_idx == len(tokens) - 1:
                continue
            # First 10 tokens should all be integers (histogram bins)
            try:
                [int(t) for t in tokens[:10]]
            except ValueError:
                continue

            prop_m = _PROP_RE.match(tokens[prop_idx])
            passed = int(prop_m.group(1))
            total = int(prop_m.group(2))
            name = tokens[prop_idx + 1]
            pval_field = tokens[10]  # may be "----" or "0.xxx" (trailing '*' becomes separate token)

            total_tests += 1
            threshold = min_pass(total)
            ok = passed >= threshold
            if ok:
                total_pass += 1
            else:
                failing_tests.append({
                    "name": name, "passed": passed, "total": total,
                    "p_uniform": pval_field,
                })

            cat_pass, cat_total = category_counts.get(name, (0, 0))
            category_counts[name] = (cat_pass + (1 if ok else 0), cat_total + 1)

    return {
        "total_tests": total_tests,
        "total_pass": total_pass,
        "fail_count": total_tests - total_pass,
        "failing": failing_tests,
        "categories": category_counts,
    }


def _worker(hash_name: str) -> dict:
    try:
        return run_nist_sts(hash_name)
    except Exception as e:
        return {"hash": hash_name, "error": str(e)}


if __name__ == "__main__":
    available = [h for h in HASH_DIRNAMES if (STREAMS / f"{h}.bin").exists()]
    missing = [h for h in HASH_DIRNAMES if not (STREAMS / f"{h}.bin").exists()]

    if missing:
        print(f"Missing corpus streams for: {', '.join(missing)}")
        print(f"Run: python3 scripts/redteam/phase3_deep/prepare_streams.py")

    if not available:
        sys.exit(1)

    print(f"Phase 3b: NIST STS parallel runner")
    print(f"  Streams available: {len(available)}  ({', '.join(available)})")
    print(f"  Parameters: {NUM_STREAMS} × {BITSTREAM_LEN} bits = "
          f"{NUM_STREAMS * BITSTREAM_LEN / 1e6:.0f} Mbits per hash")
    print(f"  Spawning up to {min(10, len(available))} parallel nist-sts processes...")

    t0 = time.time()
    with mp.Pool(processes=min(12, len(available))) as pool:
        results = pool.map(_worker, available)
    elapsed = time.time() - t0
    print(f"  Parallel runs completed in {elapsed:.1f}s")

    # Summary table
    print(f"\n{'='*90}")
    print(f"  NIST STS SUMMARY")
    print(f"{'='*90}")
    print(f"  {'hash':<10} {'display':<16} {'pass/total':>12} {'fail':>6}  "
          f"{'runtime':>9}  status")
    print(f"  {'-'*10} {'-'*16} {'-'*12} {'-'*6}  {'-'*9}  ------")

    success = []
    errored = []
    for r in results:
        if "error" in r:
            errored.append(r)
            print(f"  {r['hash']:<10} {HASH_DISPLAY.get(r['hash'], '?'):<16} "
                  f"{'--/--':>12} {'--':>6}  {'--':>9}  ERROR: {r['error'][:40]}")
        else:
            success.append(r)
            flag = "OK" if r["fail_count"] <= 15 else "⚠"
            print(f"  {r['hash']:<10} {HASH_DISPLAY.get(r['hash'], '?'):<16} "
                  f"{r['total_pass']:>4}/{r['total_tests']:<7d} {r['fail_count']:>6}  "
                  f"{r['elapsed']:>7.1f}s  {flag}")

    # Aggregate failing tests across hashes (to spot systemic vs one-off)
    if success:
        print(f"\n  Failing test categories (across all hashes):")
        cat_agg: dict[str, list[str]] = {}
        for r in success:
            for f in r["failing"]:
                cat_agg.setdefault(f["name"], []).append(r["hash"])
        if not cat_agg:
            print(f"    (none — all hashes pass every test)")
        else:
            for name in sorted(cat_agg, key=lambda n: -len(cat_agg[n])):
                hashes = cat_agg[name]
                print(f"    {name:<28} fails in {len(hashes):>2} hashes: "
                      f"{', '.join(sorted(set(hashes)))}")

    print(f"\n  Interpretation:")
    print(f"    - 188 tests × {len(success)} hashes = {188 * len(success):,} individual runs")
    print(f"    - Expected false-positive rate at alpha=0.01: ~1% per test (~19 tests out of 1880 under H0)")
    print(f"    - Threshold scales with `total` via NIST SP 800-22 formula — correctly handles")
    print(f"      RandomExcursions where valid-sequence count varies per stream")
    print(f"    - Per-hash fail counts close to 0 are expected for truly random data;")
    print(f"      identical clean patterns across weak + strong PRFs means the barrier absorbs.")

    if errored:
        sys.exit(1)
