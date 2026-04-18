#!/usr/bin/env python3
"""ITB red-team suite orchestrator.

Cleans tmp/, regenerates the corpus at the requested mode + BarrierFill,
runs applicable analyzer phases, and writes per-phase logs to
tmp/results/<mode>_bf<N>/.

Usage:
    python3 scripts/redteam/run_suite.py single [--barrier-fill 1|2|4|8|16|32]
    python3 scripts/redteam/run_suite.py triple [--barrier-fill 1|2|4|8|16|32]

Notes:
    - `single` uses Single Ouroboros (3 seeds: noise, data, start). All five
      empirical phases run: 1 (structural), 2b (candidate distinguisher),
      2c (startPixel enumeration), 3a (rotation-invariant), 3b (NIST STS).
    - `triple` uses Triple Ouroboros (7 seeds: 1 noise + 3 data + 3 start).
      Only phases that don't need plaintext-to-ciphertext alignment run:
      Phase 1 and Phase 3b. Phases 2b / 2c / 3a are skipped because their
      analyzers assume a single startPixel and continuous plaintext layout;
      Triple's 3-partition splitTriple interleaving requires an analyzer
      rewrite not yet done.
    - BarrierFill default is 1 (shipped ITB default). Pass 32 for the
      maximum-CSPRNG-fill configuration used in the earlier high-fill run.
    - tmp/encrypted, tmp/plain, tmp/seeds, tmp/streams are wiped before
      corpus regeneration. tmp/results/<mode>_bf<N>/ is preserved and
      appended to.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PROJ = Path(__file__).resolve().parents[2]
TMP = PROJ / "tmp"


def clean_corpus_dirs() -> None:
    """Remove stale corpus/streams; keep tmp/results for historical logs."""
    for sub in ("encrypted", "plain", "seeds", "streams"):
        target = TMP / sub
        if target.exists():
            shutil.rmtree(target)
    (TMP / "results").mkdir(parents=True, exist_ok=True)


def run_step(
    name: str,
    cmd: list[str],
    log_path: Path,
    env: dict[str, str] | None = None,
    tail_lines: int = 10,
) -> tuple[bool, float]:
    """Run one pipeline step, stream-tee stdout+stderr to log_path, print tail.

    Returns (ok, elapsed_seconds).
    """
    sep = "=" * 70
    print(f"\n{sep}\n  {name}\n{sep}")
    print(f"  cmd: {' '.join(cmd)}")
    print(f"  log: {log_path.relative_to(PROJ)}")
    t0 = time.time()
    with open(log_path, "w") as f:
        proc = subprocess.run(
            cmd,
            cwd=PROJ,
            env=env,
            stdout=f,
            stderr=subprocess.STDOUT,
        )
    elapsed = time.time() - t0
    ok = proc.returncode == 0
    print(f"  -> exit={proc.returncode}  elapsed={elapsed:.1f}s  ok={ok}")
    # Echo tail of log for at-a-glance verification
    try:
        with open(log_path) as f:
            lines = f.readlines()
        tail = lines[-tail_lines:]
        print(f"  --- last {len(tail)} line(s) ---")
        for ln in tail:
            print(f"  | {ln.rstrip()}")
    except FileNotFoundError:
        pass
    return ok, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the full ITB red-team validation suite.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "mode",
        choices=["single", "triple"],
        help="Ouroboros mode: 'single' runs all 5 empirical phases; "
             "'triple' runs Phase 1 + Phase 3b only (2b / 2c / 3a need "
             "a 3-partition-aware analyzer rewrite)",
    )
    parser.add_argument(
        "--barrier-fill",
        type=int,
        choices=[1, 2, 4, 8, 16, 32],
        default=1,
        help="ITB BarrierFill value (default: 1, ITB shipped default)",
    )
    parser.add_argument(
        "--nist-streams",
        type=int,
        choices=[20, 30, 50, 100],
        default=20,
        help="Number of 1-Mbit sequences for NIST STS "
             "(default: 20, NIST SP 800-22 example). Higher values stress "
             "the uniformity-of-p-values test so a single-bin cluster on "
             "near-uniform output becomes statistically implausible rather "
             "than merely bad-luck bin-routing.",
    )
    parser.add_argument(
        "--skip-mega",
        action="store_true",
        help="Skip mega-stream generation for NIST STS (prepare_streams uses "
             "the regular corpus — this flag is a no-op kept for forwards "
             "compatibility)",
    )
    args = parser.parse_args()

    bf = args.barrier_fill
    triple = args.mode == "triple"
    results_dir = TMP / "results" / f"{args.mode}_bf{bf}"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Phase count in the step labels changes with mode: single runs 7 steps,
    # triple runs 4 (corpus + Phase 1 + prepare_streams + Phase 3b).
    total_steps = 4 if triple else 7

    print(f"\n{'#' * 70}")
    print(f"#  ITB RED-TEAM SUITE — mode={args.mode}  BarrierFill={bf}  "
          f"nist-streams={args.nist_streams}")
    print(f"#  Results -> {results_dir.relative_to(PROJ)}/")
    if triple:
        print(f"#  Triple mode: Phases 2b / 2c / 3a SKIPPED (analyzer rewrite required")
        print(f"#  for Triple's 3-partition splitTriple layout; flagged as future work)")
    print(f"{'#' * 70}")

    t_suite = time.time()

    # Step 1: corpus regeneration
    print("\n[cleanup] Wiping tmp/encrypted, tmp/plain, tmp/seeds, tmp/streams ...")
    clean_corpus_dirs()

    go_env = os.environ.copy()
    go_env["ITB_REDTEAM"] = "1"
    go_env["ITB_BARRIER_FILL"] = str(bf)
    go_env["ITB_REDTEAM_MODE"] = args.mode

    step = 1
    ok, _ = run_step(
        f"{step}/{total_steps}  Generate corpus (mode={args.mode}, BarrierFill={bf})",
        ["go", "test", "-run", "TestRedTeamGenerate", "-v", "-timeout", "60m"],
        results_dir / "01_corpus.log",
        env=go_env,
    )
    if not ok:
        print("Corpus generation failed; aborting.", file=sys.stderr)
        return 1
    step += 1

    # Phase 1 structural — mode-agnostic
    run_step(
        f"{step}/{total_steps}  Phase 1 — structural (per-channel chi² + nonce-collision)",
        ["python3", "scripts/redteam/phase1_sanity/analyze.py"],
        results_dir / "02_phase1.log",
    )
    step += 1

    if not triple:
        # Phase 2b KL distinguisher — requires single-startPixel alignment
        run_step(
            f"{step}/{total_steps}  Phase 2b — per-pixel candidate KL distinguisher (parallel 8 workers)",
            ["python3", "-u", "scripts/redteam/phase2_theory/distinguisher.py"],
            results_dir / "04_phase2b.log",
            tail_lines=15,
        )
        step += 1

        # Phase 2c startPixel enumeration — semantic mismatch under Triple (3 startPixels)
        run_step(
            f"{step}/{total_steps}  Phase 2c — startPixel enumeration (parallel 8 workers)",
            ["python3", "-u", "scripts/redteam/phase2_theory/startpixel_multisample.py"],
            results_dir / "05_phase2c.log",
            tail_lines=20,
        )
        step += 1

        # Phase 3a rotation-invariant — needs plaintext alignment
        run_step(
            f"{step}/{total_steps}  Phase 3a — rotation-invariant edge case",
            ["python3", "scripts/redteam/phase3_deep/rotation_invariant.py"],
            results_dir / "03_phase3a.log",
            tail_lines=20,
        )
        step += 1

    # prepare streams for NIST STS — concatenation, mode-agnostic
    ok, _ = run_step(
        f"{step}/{total_steps}  Prepare NIST STS streams (corpus-concat)",
        ["python3", "scripts/redteam/phase3_deep/prepare_streams.py"],
        results_dir / "06_prepare.log",
    )
    if not ok:
        print("prepare_streams failed; NIST STS skipped.", file=sys.stderr)
        return 1
    step += 1

    # Phase 3b NIST STS — stream level, mode-agnostic
    nist_env = os.environ.copy()
    nist_env["ITB_NIST_STREAMS"] = str(args.nist_streams)
    run_step(
        f"{step}/{total_steps}  Phase 3b — NIST STS (10 parallel nist-sts, {args.nist_streams} × 1 Mbit each)",
        ["python3", "-u", "scripts/redteam/phase3_deep/nist_sts_runner.py"],
        results_dir / "07_phase3b.log",
        env=nist_env,
        tail_lines=30,
    )

    total = time.time() - t_suite
    print(f"\n{'#' * 70}")
    print(f"#  SUITE COMPLETE — mode={args.mode}  BarrierFill={bf}  "
          f"wall-clock={total/60:.1f} min")
    print(f"#  Logs under: {results_dir.relative_to(PROJ)}/")
    print(f"{'#' * 70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
