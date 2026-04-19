#!/usr/bin/env python3
"""Probe 1 (nonce-reuse attack simulation) orchestrator.

Drives the full Probe 1 pipeline across a (primitive, BF, N, attacker_mode)
matrix:

  for each cell in matrix:
      1. Generate ciphertext corpus via TestRedTeamGenerateNonceReuse
         (Go test, env-vars drive hash / N / mode / plaintext size).
      2. Run nonce_reuse_demask.py on pair (ct_0000, ct_0001) with
         --brute-force-startpixel + --validate + --emit-datahash.
      3. Reconstructed dataHash stream lands under
         tmp/attack/nonce_reuse/reconstructed/...
      4. If --cleanup-ciphertexts-after-emission: safe_rmtree the cell's
         corpus directory to reclaim disk (keep reconstructed + logs).
      5. Per-cell summary appended to results_dir/summary.jsonl.

Separate from run_suite.py (the existing validation suite orchestrator) —
never shares tmp/ directories or results log format. Lives under
tmp/attack/nonce_reuse/... exclusively.

Safety discipline (see .REDPLAN.md "Safety discipline for deletion
operations" — MANDATORY):

  - Every deletion is gated through attack_common.safe_rmtree with a
    whitelist check. Raises ValueError on any escape.
  - Pre-run wipe is bounded to tmp/attack/nonce_reuse/{corpus,
    reconstructed}. The results subdirectory is never touched by the
    orchestrator — users delete it manually if they want.
  - No shell rm -rf. No subprocess.run with user-supplied path
    interpolation.
  - Every intended deletion prints [cleanup] ... line BEFORE executing.

Usage:
    python3 scripts/redteam/run_attack_nonce_reuse.py \\
        --plaintext-size 65536 \\
        --hashes fnv1a,md5 \\
        --barrier-fill 1 \\
        --collision-counts 2 \\
        --attacker-modes known \\
        --validate
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

# scripts/redteam/ on sys.path
_THIS = Path(__file__).resolve()
sys.path.insert(0, str(_THIS.parent))

from attack_common import safe_rmtree  # noqa: E402

PROJ = _THIS.parents[2]
TMP_ATTACK = PROJ / "tmp" / "attack" / "nonce_reuse"
CORPUS_DIR = TMP_ATTACK / "corpus"
RECONSTRUCTED_DIR = TMP_ATTACK / "reconstructed"
CLASSICAL_DECRYPT_DIR = TMP_ATTACK / "classical_decrypt"
RESULTS_DIR = TMP_ATTACK / "results"

# Safety whitelist — orchestrator may only ever delete under these.
DELETION_WHITELIST = [CORPUS_DIR, RECONSTRUCTED_DIR]

# Supported hash primitives — all 10 ITB corpus primitives across 128 / 256 /
# 512-bit widths. The Go test dispatches to the appropriate NewSeed{128,256,512}
# based on hashWidthForName(name).
SUPPORTED_HASHES = [
    # 128-bit family
    "fnv1a", "md5", "aescmac", "siphash24",
    # 256-bit family
    "chacha20", "areion256", "blake2s", "blake3",
    # 512-bit family
    "blake2b", "areion512",
]
ALLOWED_N = [2, 8, 32, 128]
ALLOWED_BF = [1, 32]
ALLOWED_MODES = ["same", "known", "blind", "partial"]
ALLOWED_PLAINTEXT_KINDS = [
    "random",
    # Structured kinds for Partial KPA. `json_structured` is an alias for
    # `json_structured_80` accepted by the Go test for backwards compatibility
    # with the first-pass Run B corpus scripts.
    "json_structured",
    "json_structured_80",
    "json_structured_50",
    "json_structured_25",
    "html_structured_80",
    "html_structured_50",
    "html_structured_25",
    # Random-plaintext Partial KPA: independent random plaintexts per sample
    # + a shared random byte-position mask at the target coverage. No
    # structural framing, so no same-plaintext degeneracy on known channels.
    "random_masked_25",
    "random_masked_50",
    "random_masked_80",
]

# Per-kind record byte length + approximate known-coverage. Mirrors the Go
# `structuredPlaintextSpecs` table. Used to auto-tune the helper's --n-probe
# and --min-known-channels when the attacker does not set them explicitly.
# The attacker is assumed to know these from public protocol knowledge.
STRUCTURED_KIND_HINTS = {
    "json_structured":    {"record_bytes": 137, "coverage_pct": 80},
    "json_structured_80": {"record_bytes": 137, "coverage_pct": 80},
    "json_structured_50": {"record_bytes": 228, "coverage_pct": 50},
    "json_structured_25": {"record_bytes": 456, "coverage_pct": 25},
    "html_structured_80": {"record_bytes": 250, "coverage_pct": 80},
    "html_structured_50": {"record_bytes": 400, "coverage_pct": 50},
    "html_structured_25": {"record_bytes": 800, "coverage_pct": 25},
    # random_masked_<N> has no record period (each byte independently masked);
    # record_bytes is not meaningful — auto_n_probe falls back to the default
    # Partial-KPA probe depth (50) which is fine since there is no periodic
    # d_xor pattern to anchor around.
    "random_masked_25": {"record_bytes": 0, "coverage_pct": 25},
    "random_masked_50": {"record_bytes": 0, "coverage_pct": 50},
    "random_masked_80": {"record_bytes": 0, "coverage_pct": 80},
}


def auto_n_probe(kind: str, plaintext_size: int) -> int:
    """Public-info heuristic for choosing the helper's --n-probe under
    Partial KPA. The attacker knows the plaintext format (kind) and the
    ciphertext size; this formula picks n_probe such that probe pixels
    span at least 3 record periods — required so per-record varying
    sequence-number bytes can anchor the true startPixel.

    Cap at ~1 / 5 of total pixels so Layer 2 doesn't spend absurd time
    on small plaintexts where n_probe >= data_pixels is impossible.
    """
    hint = STRUCTURED_KIND_HINTS.get(kind)
    if hint is None:
        # Random-kind attacker — fall back to the historical Partial-KPA
        # default that works on JSON 80 % at mid-size plaintexts.
        return 50
    expected_record_pixels = max(1, hint["record_bytes"] // 7)
    probe_for_period = 3 * expected_record_pixels
    approx_total_pixels = max(1, (plaintext_size * 8) // 56)
    cap_by_stream = max(10, approx_total_pixels // 5)
    return max(50, min(cap_by_stream, probe_for_period))


def auto_min_known_channels(kind: str) -> int:
    """Public-info heuristic for --min-known-channels under Partial KPA.
    Lower coverage → higher K to keep per-wrong-candidate Layer 2 FP-rate
    below ~1 % across n_probe probe pixels. Rough rule: coverage ≤ 35 % →
    K=3; otherwise K=2.
    """
    hint = STRUCTURED_KIND_HINTS.get(kind)
    if hint is None:
        return 2
    return 3 if hint["coverage_pct"] <= 35 else 2


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Probe 1 (nonce-reuse) orchestrator — drives corpus generation + "
                    "demasking + reconstruction across a (hash, BF, N, mode) matrix.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--plaintext-size",
        type=int,
        default=65536,
        help="Plaintext size in bytes (default: 65536 = 64 KB for MVP runs; "
             "bump to 2097152 = 2 MB for full Probe 1 matrix — see .REDPLAN.md).",
    )
    p.add_argument(
        "--hashes",
        type=str,
        default="fnv1a,md5",
        help=f"Comma-separated hash names or 'all'. Default: fnv1a,md5. "
             f"Supported: {','.join(SUPPORTED_HASHES)}",
    )
    p.add_argument(
        "--barrier-fill",
        type=str,
        default="1",
        help="Comma-separated BF values or 'both'. Default: 1. Allowed: 1,32.",
    )
    p.add_argument(
        "--collision-counts",
        type=str,
        default="2",
        help="Comma-separated N values. Default: 2. Allowed subset of {2,8,32,128}.",
    )
    p.add_argument(
        "--attacker-modes",
        type=str,
        default="known",
        help="Comma-separated modes. Default: known. Allowed subset of {same,known,blind}.",
    )
    p.add_argument(
        "--validate",
        action="store_true",
        help="Pass --validate to the helper (diff recovered config against ground truth).",
    )
    p.add_argument(
        "--cleanup-ciphertexts-after-emission",
        action="store_true",
        help="After a cell's reconstructed stream is emitted, delete its corpus "
             "subdirectory via safe_rmtree. Reclaims ~N × plaintext_size × 1.25 per cell.",
    )
    p.add_argument(
        "--no-pre-wipe",
        action="store_true",
        help="Do NOT wipe tmp/attack/nonce_reuse/{corpus,reconstructed} before the run. "
             "Use for debugging after a partial failure. Default: pre-wipe enabled.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned cell matrix and disk estimate; do not execute.",
    )
    p.add_argument(
        "--results-tag",
        type=str,
        default=None,
        help="Label for this run's results subdirectory. Default: UTC timestamp.",
    )
    p.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Keep processing remaining cells after a per-cell failure. Default: fail fast.",
    )
    p.add_argument(
        "--plaintext-kind",
        type=str,
        default="random",
        choices=ALLOWED_PLAINTEXT_KINDS,
        help="Plaintext generation kind. 'random' (default) = uniform CSPRNG bytes "
             "(used by known/same/blind modes). Structured kinds (required for mode=partial): "
             "'json_structured_{25,50,80}' or 'html_structured_{25,50,80}' — the trailing "
             "number is target attacker-known byte coverage %%. 'json_structured' is an "
             "alias for 'json_structured_80'.",
    )
    p.add_argument(
        "--n-probe",
        type=str,
        default="auto",
        help="Helper Layer 2 brute-force probe count. Integer or 'auto' (default). "
             "Auto-scale picks 3 × record-period-in-pixels from the plaintext_kind "
             "so probes span multiple records (needed for per-record sequence-number "
             "bytes to anchor the true startPixel under periodic plaintexts). Public-"
             "info choice: the attacker knows the plaintext format and ciphertext size, "
             "so they would naturally tune n_probe to their corpus.",
    )
    p.add_argument(
        "--min-known-channels",
        type=str,
        default="auto",
        help="Helper Partial-KPA --min-known-channels threshold. Integer or 'auto' "
             "(default). Auto-scale: K=3 for coverage ≤ 35 %% (to keep Layer 2 FP rate "
             "below 1 %% over n_probe probes), K=2 otherwise. Public-info choice: the "
             "attacker sees the expected coverage from the plaintext_kind.",
    )
    p.add_argument(
        "--classical-decrypt",
        action="store_true",
        help="After demasking, run classical_decrypt.py on each cell — apply the "
             "recovered config map (keystream-equivalent for this (seeds, nonce)) "
             "back to both colliding ciphertexts and COBS-decode the result. "
             "Emits recovered_plaintext_P{1,2}.bin + groundtruth_plaintext_P{1,2}.bin "
             "into tmp/attack/nonce_reuse/classical_decrypt/<tag>/<cell>/ so a "
             "crypto-analyst can diff recovered vs original directly. Incompatible "
             "with --cleanup-ciphertexts-after-emission (needs plaintexts).",
    )
    return p.parse_args()


def parse_hashes(s: str) -> List[str]:
    if s == "all":
        return list(SUPPORTED_HASHES)
    out = [x.strip() for x in s.split(",") if x.strip()]
    for h in out:
        if h not in SUPPORTED_HASHES:
            raise SystemExit(f"unknown hash {h!r}; supported: {SUPPORTED_HASHES}")
    return out


def parse_bfs(s: str) -> List[int]:
    if s == "both":
        return list(ALLOWED_BF)
    out = [int(x) for x in s.split(",") if x.strip()]
    for bf in out:
        if bf not in ALLOWED_BF:
            raise SystemExit(f"unknown BF {bf}; allowed: {ALLOWED_BF}")
    return out


def parse_ns(s: str) -> List[int]:
    out = [int(x) for x in s.split(",") if x.strip()]
    for n in out:
        if n not in ALLOWED_N:
            raise SystemExit(f"unknown N {n}; allowed: {ALLOWED_N}")
    return out


def parse_modes(s: str) -> List[str]:
    out = [x.strip() for x in s.split(",") if x.strip()]
    for m in out:
        if m not in ALLOWED_MODES:
            raise SystemExit(f"unknown mode {m!r}; allowed: {ALLOWED_MODES}")
    return out


# ----------------------------------------------------------------------------
# Disk estimation
# ----------------------------------------------------------------------------

def estimate_cell_size_bytes(plaintext_size: int, n: int, bf: int) -> int:
    """Rough per-cell disk footprint: N × ciphertext_size + sidecars + stream."""
    # Ciphertext ≈ plaintext_size × 1.04 to 1.15 depending on BF (container overhead)
    overhead = 1.10 if bf == 1 else 1.18
    ct_bytes = int(plaintext_size * overhead)
    # N ciphertexts + N plaintexts + sidecar files
    per_cell = n * (ct_bytes + plaintext_size) + 700_000  # ~700KB sidecar budget
    # Reconstructed stream: data_pixels × 7 bytes ≈ plaintext_size × 1.0
    per_cell += plaintext_size
    return per_cell


def free_disk_bytes(path: Path) -> int:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


# ----------------------------------------------------------------------------
# Per-cell execution
# ----------------------------------------------------------------------------

def generate_cell_corpus(
    hash_name: str,
    bf: int,
    n: int,
    mode: str,
    plaintext_size: int,
    plaintext_kind: str,
    log_file: Path,
) -> Tuple[bool, float]:
    """Shell out to the Go test to produce a cell's corpus. Returns (ok, elapsed)."""
    env = os.environ.copy()
    env["ITB_NONCE_REUSE_HASH"] = hash_name
    env["ITB_NONCE_REUSE_N"] = str(n)
    env["ITB_NONCE_REUSE_MODE"] = mode
    env["ITB_NONCE_REUSE_SIZE"] = str(plaintext_size)
    env["ITB_BARRIER_FILL"] = str(bf)
    env["ITB_NONCE_REUSE_PLAINTEXT_KIND"] = plaintext_kind
    # Deterministic nonce seed per cell so reruns are reproducible.
    # Hash-dependent so different hashes use different nonces (seeds are fresh).
    env["ITB_NONCE_REUSE_NONCE_SEED"] = str(0xA17B1CE ^ hash(f"{hash_name}{bf}{n}{mode}{plaintext_kind}") & 0xFFFFFFFF)

    cmd = [
        "go", "test",
        "-run", "TestRedTeamGenerateNonceReuse",
        "-v",
        "-timeout", "30m",
    ]
    t0 = time.time()
    with open(log_file, "w") as f:
        proc = subprocess.run(cmd, cwd=PROJ, env=env, stdout=f, stderr=subprocess.STDOUT)
    elapsed = time.time() - t0
    return proc.returncode == 0, elapsed


def demask_cell(
    cell_dir: Path,
    pair: Tuple[str, str],
    attacker_mode_cli: str,
    validate: bool,
    datahash_out: Path,
    log_file: Path,
    n_probe: int = 10,
    min_known_channels: int = 2,
) -> Tuple[bool, float]:
    """Run nonce_reuse_demask.py on one pair. Returns (ok, elapsed)."""
    cmd = [
        sys.executable,
        str(PROJ / "scripts/redteam/phase2_theory/nonce_reuse_demask.py"),
        "--cell-dir", str(cell_dir),
        "--pair", pair[0], pair[1],
        "--mode", attacker_mode_cli,
        "--brute-force-startpixel",
        "--n-probe", str(n_probe),
        "--min-known-channels", str(min_known_channels),
        "--emit-datahash", str(datahash_out),
    ]
    if validate:
        cmd.append("--validate")
    t0 = time.time()
    with open(log_file, "w") as f:
        proc = subprocess.run(cmd, cwd=PROJ, stdout=f, stderr=subprocess.STDOUT)
    elapsed = time.time() - t0
    return proc.returncode == 0, elapsed


# ----------------------------------------------------------------------------
# Per-cell cleanup (whitelist-gated)
# ----------------------------------------------------------------------------

def classical_decrypt_cell(
    cell_dir: Path,
    pair: Tuple[str, str],
    out_dir: Path,
    log_file: Path,
    n_probe: int = 10,
) -> Tuple[bool, float]:
    """Run classical_decrypt.py on one cell — Full-KPA config extraction
    followed by classical keystream-reuse decryption of both ciphertexts.
    Emits recovered_cobs_P{1,2}.bin + recovered_plaintext_P{1,2}.bin +
    groundtruth_plaintext_P{1,2}.bin into `out_dir`.
    Returns (ok, elapsed).
    """
    cmd = [
        sys.executable,
        str(PROJ / "scripts/redteam/phase2_theory/classical_decrypt.py"),
        "--cell-dir", str(cell_dir),
        "--pair", pair[0], pair[1],
        "--emit-decrypted", str(out_dir),
        "--n-probe", str(n_probe),
    ]
    t0 = time.time()
    with open(log_file, "w") as f:
        proc = subprocess.run(cmd, cwd=PROJ, stdout=f, stderr=subprocess.STDOUT)
    elapsed = time.time() - t0
    # classical_decrypt returns 0 on 100% match, 1 on partial — both emit
    # artefacts, so orchestrator treats 1 as "incomplete but artefacts valid".
    ok = proc.returncode in (0, 1)
    return ok, elapsed


def cleanup_cell_corpus(cell_dir: Path) -> None:
    """Remove the ciphertext corpus for one cell once its reconstructed stream
    has been emitted. Reconstructed artefact is preserved.

    Routed through safe_rmtree with CORPUS_DIR as expected_parent, so any
    attempt to delete outside CORPUS_DIR raises ValueError.
    """
    safe_rmtree(cell_dir, CORPUS_DIR)


def pre_run_wipe() -> None:
    """Wipe corpus + reconstructed directories at run start. Preserves results."""
    for target in (CORPUS_DIR, RECONSTRUCTED_DIR):
        safe_rmtree(target, TMP_ATTACK)


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------

def main() -> int:
    args = parse_args()

    hashes = parse_hashes(args.hashes)
    bfs = parse_bfs(args.barrier_fill)
    ns = parse_ns(args.collision_counts)
    modes = parse_modes(args.attacker_modes)

    # Attacker-mode → helper CLI mode translation.
    # Helper's --mode is one of {known-plaintext, same-plaintext, blind,
    # partial-plaintext}; the Go test's modes are {known, same, blind, partial}.
    # Translate here so neither piece has to know about the naming scheme of
    # the other.
    mode_to_helper = {
        "known": "known-plaintext",
        "same": "same-plaintext",
        "blind": "blind",
        "partial": "partial-plaintext",
    }

    # Build the cell matrix.
    cells: List[Tuple[str, int, int, str]] = []
    for h in hashes:
        for bf in bfs:
            for n in ns:
                for m in modes:
                    cells.append((h, bf, n, m))

    # Disk estimate.
    per_cell_bytes = sum(
        estimate_cell_size_bytes(args.plaintext_size, n, bf) for _, bf, n, _ in cells
    )
    free_bytes = free_disk_bytes(PROJ)
    print("=" * 72)
    print(f"Probe 1 nonce-reuse orchestrator")
    print("=" * 72)
    print(f"Matrix cells      : {len(cells)}  ({len(hashes)} hashes × {len(bfs)} BFs × "
          f"{len(ns)} N × {len(modes)} modes)")
    print(f"Plaintext size    : {args.plaintext_size:,} bytes "
          f"({args.plaintext_size / (1024 * 1024):.1f} MB)")
    print(f"Est. total disk   : {per_cell_bytes / (1024 ** 3):.2f} GB "
          f"(peak during run; cleanup flag reclaims ciphertexts post-emission)")
    print(f"Free disk at start: {free_bytes / (1024 ** 3):.2f} GB")
    print(f"Pre-wipe          : {'SKIP' if args.no_pre_wipe else 'enabled'}")
    print(f"Cleanup after     : {'yes' if args.cleanup_ciphertexts_after_emission else 'no'}")
    print(f"Validate          : {'yes' if args.validate else 'no'}")
    if args.dry_run:
        print()
        print("Planned cells (dry-run — nothing executed):")
        for h, bf, n, m in cells:
            print(f"  {h:10s}  BF={bf:<2d}  N={n:<3d}  mode={m}")
        return 0

    # Sanity: require free disk ≥ estimated usage × 1.2 (headroom).
    if free_bytes < per_cell_bytes * 1.2:
        print(f"\nERROR: free disk ({free_bytes / (1024 ** 3):.2f} GB) is less than 1.2× "
              f"estimated usage ({per_cell_bytes * 1.2 / (1024 ** 3):.2f} GB). Aborting.",
              file=sys.stderr)
        print(f"       Use --cleanup-ciphertexts-after-emission to reduce peak, or reduce "
              f"the matrix (--hashes, --collision-counts) or --plaintext-size.",
              file=sys.stderr)
        return 2

    # Pre-run wipe.
    if not args.no_pre_wipe:
        print()
        print("Pre-run wipe:")
        pre_run_wipe()

    # Ensure directories exist.
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    RECONSTRUCTED_DIR.mkdir(parents=True, exist_ok=True)

    # Results subdirectory tagged with timestamp or user-provided label.
    tag = args.results_tag or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RESULTS_DIR / tag
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.jsonl"
    print(f"Run results dir   : {run_dir.relative_to(PROJ)}")
    print()

    # Run the cells sequentially.
    t_total = time.time()
    fails: List[dict] = []
    summary_entries: List[dict] = []
    with open(summary_path, "w") as summary_f:
        for idx, (h, bf, n, m) in enumerate(cells, 1):
            print("-" * 72)
            print(f"Cell {idx}/{len(cells)}: hash={h}  BF={bf}  N={n}  mode={m}")
            # Partial-mode cells go into a per-kind subdirectory of corpus/ and
            # a kind-labelled filename for the reconstructed stream so the
            # default random-plaintext runs never collide with json_structured
            # Partial-KPA runs.
            mode_seg = m if m != "partial" else f"partial_{args.plaintext_kind}"
            name_tag = m if m != "partial" else f"partial_{args.plaintext_kind}"
            cell_dir = CORPUS_DIR / h / f"BF{bf}" / f"N{n}" / mode_seg
            gen_log = run_dir / f"cell_{idx:03d}_{h}_BF{bf}_N{n}_{name_tag}.gen.log"
            demask_log = run_dir / f"cell_{idx:03d}_{h}_BF{bf}_N{n}_{name_tag}.demask.log"
            datahash_out = RECONSTRUCTED_DIR / f"{h}_BF{bf}_N{n}_{name_tag}.datahash.bin"

            entry = {
                "cell_idx": idx,
                "hash": h, "bf": bf, "n": n, "mode": m,
                "plaintext_size": args.plaintext_size,
                "plaintext_kind": args.plaintext_kind,
                "cell_dir": str(cell_dir.relative_to(PROJ)),
                "datahash_out": str(datahash_out.relative_to(PROJ)),
            }

            # Step 1: corpus generation.
            ok_gen, t_gen = generate_cell_corpus(
                h, bf, n, m, args.plaintext_size, args.plaintext_kind, gen_log,
            )
            entry["gen_ok"] = ok_gen
            entry["gen_elapsed_s"] = round(t_gen, 2)
            total_steps_label = "4" if args.classical_decrypt else "3"
            print(f"  [1/{total_steps_label}] generate corpus : {'OK' if ok_gen else 'FAIL'}  "
                  f"({t_gen:.2f}s; log {gen_log.relative_to(run_dir)})")
            if not ok_gen:
                fails.append({**entry, "stage": "generate"})
                if not args.continue_on_error:
                    print(f"\nFATAL: corpus generation failed; aborting. "
                          f"Pass --continue-on-error to process remaining cells.")
                    summary_f.write(json.dumps(entry) + "\n")
                    return 3
                summary_f.write(json.dumps(entry) + "\n")
                continue

            # Step 2: demask + emit reconstruction.
            helper_mode = mode_to_helper[m]
            if m == "blind":
                # Helper does not support blind mode yet — skip demasking gracefully.
                print(f"  [2/{total_steps_label}] demask          : SKIP (blind mode not implemented in helper MVP)")
                entry["demask_ok"] = None
                entry["demask_elapsed_s"] = None
                entry["datahash_emitted"] = False
                summary_entries.append(entry)
                summary_f.write(json.dumps(entry) + "\n")
                continue

            # Partial-KPA with periodic plaintexts needs n_probe sized to span
            # multiple record periods — so per-record varying sequence-number
            # bytes break the d_xor periodicity and anchor the TRUE startPixel.
            # The attacker knows the plaintext kind and the ciphertext size,
            # so picking n_probe is public-info tuning (not a secret-dependent
            # advantage). `auto` resolves via the auto_n_probe heuristic above.
            if m == "partial":
                if args.n_probe == "auto":
                    n_probe_cell = auto_n_probe(args.plaintext_kind, args.plaintext_size)
                else:
                    n_probe_cell = int(args.n_probe)
                if args.min_known_channels == "auto":
                    min_known_cell = auto_min_known_channels(args.plaintext_kind)
                else:
                    min_known_cell = int(args.min_known_channels)
                print(f"        Partial-KPA helper params: n_probe={n_probe_cell} "
                      f"(auto={args.n_probe == 'auto'}), min_known_channels={min_known_cell} "
                      f"(auto={args.min_known_channels == 'auto'})")
            else:
                # Full-KPA / same / blind keep the long-standing default.
                n_probe_cell = 10
                min_known_cell = 2

            ok_demask, t_demask = demask_cell(
                cell_dir, ("0000", "0001"), helper_mode, args.validate,
                datahash_out, demask_log,
                n_probe=n_probe_cell, min_known_channels=min_known_cell,
            )
            entry["n_probe"] = n_probe_cell
            entry["min_known_channels"] = min_known_cell
            entry["demask_ok"] = ok_demask
            entry["demask_elapsed_s"] = round(t_demask, 2)
            entry["datahash_emitted"] = datahash_out.exists()
            entry["datahash_size_bytes"] = datahash_out.stat().st_size if datahash_out.exists() else 0
            print(f"  [2/{total_steps_label}] demask+emit     : {'OK' if ok_demask else 'FAIL'}  "
                  f"({t_demask:.2f}s; log {demask_log.relative_to(run_dir)})")
            if entry["datahash_emitted"]:
                print(f"        datahash stream : {entry['datahash_size_bytes']:,} bytes "
                      f"({entry['datahash_size_bytes'] * 8:,} bits)")
            if not ok_demask:
                fails.append({**entry, "stage": "demask"})
                if not args.continue_on_error:
                    print(f"\nFATAL: demask failed; aborting.")
                    summary_f.write(json.dumps(entry) + "\n")
                    return 4

            # Step 2.5: optional classical decrypt (must run BEFORE cleanup
            # because classical_decrypt.py reads plaintext + ciphertext files).
            if args.classical_decrypt and ok_demask:
                classical_out = CLASSICAL_DECRYPT_DIR / args.results_tag / f"{h}_BF{bf}_N{n}_{name_tag}"
                classical_log = run_dir / f"cell_{idx:03d}_{h}_BF{bf}_N{n}_{name_tag}.classical_decrypt.log"
                ok_cd, t_cd = classical_decrypt_cell(
                    cell_dir, ("0000", "0001"), classical_out, classical_log,
                    n_probe=n_probe_cell,
                )
                entry["classical_decrypt_ok"] = ok_cd
                entry["classical_decrypt_elapsed_s"] = round(t_cd, 2)
                entry["classical_decrypt_dir"] = str(classical_out.relative_to(PROJ))
                print(f"  [3/4] classical       : {'OK' if ok_cd else 'FAIL'}  "
                      f"({t_cd:.2f}s; log {classical_log.relative_to(run_dir)})")
                if ok_cd:
                    print(f"        artefacts       : {classical_out.relative_to(PROJ)}/")
                    print(f"        diff recovered vs groundtruth plaintexts to verify "
                          f"classical keystream-reuse decryption works independently of PRF grade.")
            elif args.classical_decrypt:
                print(f"  [3/4] classical       : SKIP (demask failed)")

            # Final step: optional ciphertext cleanup.
            cleanup_label = f"[{total_steps_label}/{total_steps_label}]"
            if args.cleanup_ciphertexts_after_emission:
                cleanup_cell_corpus(cell_dir)
                print(f"  {cleanup_label} cleanup corpus  : OK (safe_rmtree)")
            else:
                print(f"  {cleanup_label} cleanup corpus  : SKIP (--cleanup-ciphertexts-after-emission off)")

            summary_entries.append(entry)
            summary_f.write(json.dumps(entry) + "\n")
            summary_f.flush()

    # Final summary.
    total_elapsed = time.time() - t_total
    print()
    print("=" * 72)
    print(f"Run complete in {total_elapsed:.1f}s ({total_elapsed / 60:.1f} min)")
    print("=" * 72)
    print(f"Cells attempted : {len(cells)}")
    ok_count = sum(1 for e in summary_entries if e.get("demask_ok") is True)
    print(f"Cells succeeded : {ok_count}")
    print(f"Cells failed    : {len(fails)}")
    print(f"Summary JSONL   : {summary_path.relative_to(PROJ)}")

    if fails:
        print()
        print("Failed cells:")
        for f in fails:
            print(f"  {f['stage']:10s}  {f['hash']}/BF{f['bf']}/N{f['n']}/{f['mode']}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
