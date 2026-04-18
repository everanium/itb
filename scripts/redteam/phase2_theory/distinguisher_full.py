#!/usr/bin/env python3
"""Phase 2b (full-container): per-pixel candidate distinguisher without
startPixel or plaintext knowledge — models a realistic attacker.

Sibling script to `distinguisher.py`. That script runs the idealised
Phase 2b: the analyzer reads `startPixel` from the `.pixel` sidecar,
aligns to data-carrying pixels only, and XORs with the known plaintext
to expose the 56 candidate XOR masks per pixel. That corresponds to an
attacker who somehow *knows* where the data region starts and ends
inside the container — an assumption obstacle (2) of Proof 4a
specifically does not grant.

This script models the realistic case:

  - No `startPixel` lookup (pixel 0 is as good a starting guess as any).
  - No plaintext — the attacker has no reliable alignment between
    plaintext bytes and container pixels once `startPixel` is unknown.
  - Iterate over **all P container pixels** (data + CSPRNG fill — the
    two are indistinguishable to the attacker by construction).
  - Enumerate 56 `(noisePos, rotation)` extractions per pixel as
    *raw 7-bit values* (no XOR), accumulate byte distributions across
    all 56 candidates.
  - Pairwise KL divergence between the 56 candidate distributions at
    the end — does any extraction strategy stand out on raw ciphertext?

Under the information-theoretic barrier claim (and Proof 10's CSPRNG
residue), the raw 7-bit values under any fixed `(noisePos, rotation)`
strategy should be uniform over [0, 128), and the 56 strategies should
be statistically indistinguishable from each other. At N = P × 8
observations per candidate (with P ≫ data_pixels because CSPRNG fill
dominates the container), the finite-sample KL floor is tighter than
the idealised Mode A analyzer — so this is in fact the *stricter* test,
not a weaker one.

Parallelization: same `mp.Pool(8)` map-reduce as distinguisher.py.
One worker per (hash, sample); partial accumulators reduced by
(hash, kind); output format and summary table identical so the two
scripts produce directly-comparable logs.

This tests Proof 1 (P(v|h) = 1/2), Proof 7 (bias neutralisation), and
Proof 10 (CSPRNG residue) jointly *under the realistic threat model
where obstacle (2) — unknown startPixel — is active*.
"""

import os
import re
import sys
import glob
import time
import multiprocessing as mp
from pathlib import Path

import numpy as np
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import (
    HASH_DIRNAMES, HASH_DISPLAY, KINDS,
    HEADER_SIZE, CHANNELS,
)

PROJ = Path(__file__).resolve().parents[3]
ROOT = PROJ / "tmp"
ENCRYPTED = ROOT / "encrypted"

# Precomputed lookup tables for vectorized candidate enumeration
# (identical to distinguisher.py).
_extract_tbl = np.zeros((8, 256), dtype=np.uint8)
for _np_val in range(8):
    _mask_low = (1 << _np_val) - 1
    for _b in range(256):
        _low = _b & _mask_low
        _high = _b >> (_np_val + 1)
        _extract_tbl[_np_val, _b] = _low | (_high << _np_val)
_rot_tbl = np.zeros((7, 128), dtype=np.uint8)
for _r in range(7):
    for _v in range(128):
        _rot_tbl[_r, _v] = ((_v >> _r) | (_v << (7 - _r))) & 0x7F


def load_container(hash_name: str, base: str):
    """Load container pixel bytes only — no plaintext, no startPixel.

    Returns (container_bytes, total_pixels).
    """
    bin_path = ENCRYPTED / hash_name / f"{base}.bin"
    pix_path = ENCRYPTED / hash_name / f"{base}.pixel"

    ciphertext = bin_path.read_bytes()

    # We still peek at total_pixels from the sidecar because ciphertext
    # length already encodes it via the header (W * H), but using the
    # sidecar is simpler and introduces no attacker-favourable info
    # (the container dimensions are trivially readable from bytes 16-19
    # of every ciphertext, which a real attacker sees).
    meta = {}
    for line in pix_path.read_text().strip().split("\n"):
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        meta[k] = v
    total_pixels = int(meta["total_pixels"])

    container = ciphertext[HEADER_SIZE:HEADER_SIZE + total_pixels * CHANNELS]
    return container, total_pixels


def process_sample(hash_name: str, base: str) -> dict:
    """Compute per-candidate accumulators for one sample over ALL P pixels,
    without plaintext XOR.

    Returns:
      bit_count[8,7,7]  — count of 1-bits at each of 7 bit positions per
                          candidate (flat 7, not 56, because we're counting
                          raw 7-bit values with no cross-channel mask)
      byte_dist[8,7,128] — distribution of raw 7-bit values per candidate
      total_pixels       — N observations per channel (before × 8)
    """
    container, total_pixels = load_container(hash_name, base)
    container_arr = np.frombuffer(container, dtype=np.uint8).reshape(total_pixels, CHANNELS)

    # All P pixels — no startPixel, no wrap. aligned shape (P, 8).
    aligned = container_arr

    # (8_np, P, 8_ch) -> (P, 8_ch, 8_np)
    extracted = _extract_tbl[:, aligned]
    extracted = np.transpose(extracted, (1, 2, 0))

    # (7_rot, P, 8_ch, 8_np) -> (P, 8_ch, 8_np, 7_rot)
    unrotated = _rot_tbl[:, extracted]
    unrotated = np.transpose(unrotated, (1, 2, 3, 0))

    # No XOR with plaintext — treat unrotated as the raw candidate value.
    cand_raw = unrotated  # shape (P, 8_ch, 8_np, 7_rot), values 0..127

    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)
    for np_val in range(8):
        for rot in range(7):
            vals = cand_raw[:, :, np_val, rot].ravel()
            byte_dist[np_val, rot] = np.bincount(vals, minlength=128)

    # Raw 7-bit values: accumulate bit balance per bit-position-within-7bits
    # per candidate. Shape (8_np, 7_rot, 7_bits).
    bit_count = np.zeros((8, 7, 7), dtype=np.int64)
    for bit in range(7):
        bit_vals = ((cand_raw >> bit) & 1).sum(axis=(0, 1)).astype(np.int64)
        # shape: (8_np, 7_rot)
        bit_count[:, :, bit] = bit_vals

    return {
        "bit_count": bit_count,
        "byte_dist": byte_dist,
        "pixels": total_pixels,
    }


_KIND_RE = re.compile(r"^(.+)_\d{3}$")


def kind_of(base: str) -> str:
    m = _KIND_RE.match(base)
    return m.group(1) if m else "unknown"


def list_samples(kind: str, hash_name: str) -> list[str]:
    pat = re.compile(rf"^{re.escape(kind)}_\d{{3}}\.bin$")
    files = sorted((ENCRYPTED / hash_name).glob(f"{kind}_*.bin"))
    return [Path(f).stem for f in files if pat.match(Path(f).name)]


def _worker_task(args):
    hash_name, base = args
    try:
        r = process_sample(hash_name, base)
        r["hash_name"] = hash_name
        r["kind"] = kind_of(base)
        r["sample"] = base
        return r
    except Exception as e:
        return {"error": str(e), "hash_name": hash_name, "sample": base, "kind": kind_of(base)}


def reduce_group(group: list[dict]) -> dict:
    bit_count = np.zeros((8, 7, 7), dtype=np.int64)
    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)
    total_pixels = 0
    for r in group:
        if "error" in r:
            continue
        bit_count += r["bit_count"]
        byte_dist += r["byte_dist"]
        total_pixels += r["pixels"]
    # Each candidate accumulates pixels × 8 channels observations
    totals = np.full((8, 7), total_pixels * CHANNELS, dtype=np.int64)
    return {
        "samples": len(group),
        "pixels": total_pixels,
        "bit_count": bit_count,
        "totals": totals,
        "byte_dist": byte_dist,
    }


def report(hash_name: str, kind: str, results: dict):
    print(f"\n{'-' * 70}")
    print(f"  {HASH_DISPLAY.get(hash_name, hash_name):<16}  kind={kind:<12}  "
          f"samples={results['samples']:>3}  container pixels={results['pixels']:>8}  "
          f"candidates=56")
    print(f"{'-' * 70}")

    bit_count = results["bit_count"]    # (8, 7, 7) — 7 bit positions within 7-bit value
    totals = results["totals"]          # (8, 7) — per-candidate observations
    byte_dist = results["byte_dist"]    # (8, 7, 128)

    if totals[0, 0] == 0:
        print(f"  (no pixels — skipping)")
        return {"hash": hash_name, "kind": kind, "bit_exceed": 0, "p_lt_01": 0,
                "p_lt_001": 0, "chi2_mean": 0.0, "kl_max": 0.0}

    # Test 1: per-candidate bit balance across the 7 bit positions
    bit_fraction = bit_count / totals[:, :, np.newaxis]   # (8, 7, 7)
    n = totals[0, 0]
    worst_per_candidate = np.abs(bit_fraction - 0.5).max(axis=-1)
    mean_fraction = bit_fraction.mean()
    ci95 = 1.96 * np.sqrt(0.25 / n)
    # Bonferroni for max across 7 bit positions per candidate
    ci95_max7 = np.sqrt(0.25 / n) * stats.norm.ppf(1 - 0.05 / (2 * 7))
    exceeding = int((worst_per_candidate > ci95_max7).sum())
    print(f"  [T1] mean bit-fraction={mean_fraction:.6f}  max|frac-0.5|={worst_per_candidate.max():.6f}  "
          f"CI95±{ci95:.6f}  Bonferroni±{ci95_max7:.6f}  exceed={exceeding}/56")

    # Test 2: per-candidate chi-square over 128 byte values
    total_per_cand = byte_dist.sum(axis=-1, keepdims=True)
    expected = total_per_cand / 128
    safe_exp = np.where(expected == 0, 1, expected)
    chi2 = ((byte_dist - expected) ** 2 / safe_exp).sum(axis=-1).ravel()
    p_values = 1 - stats.chi2.cdf(chi2, df=127)
    lt001 = int((p_values < 0.001).sum())
    lt01 = int((p_values < 0.01).sum())
    print(f"  [T2] chi² min={chi2.min():.1f}  mean={chi2.mean():.1f}  "
          f"max={chi2.max():.1f}  (df=127)  "
          f"p<0.01: {lt01}/56  p<0.001: {lt001}/56")

    # Test 3: inter-candidate KL divergence
    flat = byte_dist.reshape(56, -1).astype(np.float64)
    row_sum = flat.sum(axis=1, keepdims=True)
    row_sum = np.where(row_sum == 0, 1.0, row_sum)
    probs = flat / row_sum
    kl_matrix = np.zeros((56, 56))
    for i in range(56):
        P = probs[i]
        for j in range(56):
            if i == j:
                continue
            Q = probs[j]
            mask = (P > 0) & (Q > 0)
            if mask.any():
                kl_matrix[i, j] = (P[mask] * np.log(P[mask] / Q[mask])).sum()
    non_diag = kl_matrix[~np.eye(56, dtype=bool)]
    kl_max = non_diag.max() if non_diag.size else 0.0
    pairs_exceeding = int((non_diag > 0.05).sum() // 2)
    print(f"  [T3] pairwise KL: min={non_diag.min():.6f}  mean={non_diag.mean():.6f}  "
          f"max={kl_max:.6f}  pairs>0.05: {pairs_exceeding}/1540")

    return {
        "hash": hash_name,
        "kind": kind,
        "bit_exceed": exceeding,
        "chi2_mean": float(chi2.mean()),
        "p_lt_01": lt01,
        "p_lt_001": lt001,
        "kl_max": float(kl_max),
    }


if __name__ == "__main__":
    print(f"Phase 2b-full: Per-pixel Candidate Distinguisher — no startPixel, no plaintext")
    print(f"Corpus: {ENCRYPTED}")
    print(f"Testing: realistic-attacker model (obstacle (2) active — startPixel unknown,")
    print(f"         plaintext alignment unknown, CSPRNG fill indistinguishable from data).")

    tasks = []
    for h in HASH_DIRNAMES:
        for k in KINDS:
            for s in list_samples(k, h):
                tasks.append((h, s))

    if not tasks:
        print(f"\n  No samples found under {ENCRYPTED} — run TestRedTeamGenerate first.")
        sys.exit(1)

    print(f"  Total tasks: {len(tasks)}  across {len(HASH_DIRNAMES)} hashes × {len(KINDS)} kinds")
    print(f"  Spawning 8-worker pool...")

    t0 = time.time()
    with mp.Pool(processes=8) as pool:
        all_results = []
        for i, r in enumerate(pool.imap_unordered(_worker_task, tasks, chunksize=1), 1):
            all_results.append(r)
            if i % 40 == 0 or i == len(tasks):
                elapsed = time.time() - t0
                print(f"    {i}/{len(tasks)} done  ({elapsed:.1f}s elapsed)")
    t1 = time.time()
    print(f"  Parallel pool done in {t1 - t0:.1f}s")

    grouped: dict[tuple[str, str], list[dict]] = {}
    errors: list[dict] = []
    for r in all_results:
        if "error" in r:
            errors.append(r)
            continue
        key = (r["hash_name"], r["kind"])
        grouped.setdefault(key, []).append(r)
    if errors:
        print(f"\n  !! {len(errors)} sample errors — showing first 5:")
        for r in errors[:5]:
            print(f"     {r['hash_name']}/{r['sample']}: {r['error']}")

    summary = []
    for h in HASH_DIRNAMES:
        print(f"\n{'#' * 70}")
        print(f"#  HASH: {HASH_DISPLAY[h]} ({h})")
        print(f"{'#' * 70}")
        for k in KINDS:
            key = (h, k)
            group = grouped.get(key)
            if not group:
                continue
            agg = reduce_group(group)
            s = report(h, k, agg)
            summary.append(s)

    print(f"\n{'=' * 90}")
    print(f"  SUMMARY TABLE")
    print(f"{'=' * 90}")
    print(f"  {'hash':<16} {'kind':<12} {'bit_exc':>8} {'chi2μ':>8} "
          f"{'p<0.01':>7} {'p<0.001':>8} {'kl_max':>10}  status")
    for s in summary:
        flag = "OK"
        if s["bit_exceed"] > 10 or s["p_lt_001"] > 3 or s["kl_max"] > 0.1:
            flag = "⚠"
        print(f"  {HASH_DISPLAY[s['hash']]:<16} {s['kind']:<12} "
              f"{s['bit_exceed']:>8} {s['chi2_mean']:>8.1f} "
              f"{s['p_lt_01']:>7} {s['p_lt_001']:>8} {s['kl_max']:>10.6f}  {flag}")

    print(f"\n{'=' * 70}")
    print(f"  INTERPRETATION (full-container / realistic-attacker model)")
    print(f"{'=' * 70}")
    print(f"  PASS conditions:")
    print(f"    Test 1: bit_exceed close to expected ~3/56 (Bonferroni false-positive rate)")
    print(f"    Test 2: chi² mean ≈ 127, p-values uniformly distributed")
    print(f"    Test 3: kl_max at finite-sample floor ≈ bins/N")
    print(f"  The realistic-attacker model uses N = container_pixels × 8, which is")
    print(f"  tighter than the idealised Mode A (N = data_pixels × 8). So this is")
    print(f"  the STRICTER of the two Phase 2b variants, not the weaker one.")
