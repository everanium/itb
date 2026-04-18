#!/usr/bin/env python3
"""Phase 2b: per-pixel candidate distinguisher (parallel 8 workers).

For each pixel in every ciphertext, enumerate all 56 candidate configurations
(8 noisePos × 7 rotation). Each candidate implies a specific 56-bit XOR mask
derived from known plaintext + observed ciphertext.

Test 1: uniformity of candidate XOR mask bits
  - For each of 56 candidates, collect XOR mask bits across all pixels
  - Compute bit-balance (fraction of 1s)
  - Under signal/noise 1:1: all 56 candidates equally uniform (each bit ~50%)
  - Detect: does ANY candidate show distinguishable bias?

Test 2: candidate-pair correlation
  - If candidates produced structured bit patterns, pairwise correlation
    between candidates at same pixel would deviate from expected
  - Under theory: correlations should be consistent with uniform random

Test 3: chi-square on candidate XOR mask byte distribution
  - Per-candidate: distribution of 8-bit bytes should be uniform
  - Under theory: all 56 candidates pass chi-square

Parallelization: one worker per (hash, sample). Workers return partial
accumulators; reducer sums by (hash, kind). Same I/O model as Phase 2c.

This tests Proof 1 (P(v|h)=1/2), Proof 4 (7 rotation candidates
indistinguishable), and the Theorem 4a obstacle (3) claim:
'all candidates are equiprobable conditional on the observation'.
"""

import os
import re
import sys
import glob
import time
import struct
import multiprocessing as mp
from pathlib import Path

import numpy as np
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import (
    HASH_DIRNAMES, HASH_DISPLAY, KINDS,
    HEADER_SIZE, CHANNELS, DATA_BITS_PER_CHANNEL, DATA_BITS_PER_PIXEL,
)

PROJ = Path(__file__).resolve().parents[3]
ROOT = PROJ / "tmp"
PLAIN_DIR = ROOT / "plain"
ENCRYPTED = ROOT / "encrypted"

# Precomputed lookup tables for vectorized candidate enumeration.
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


def get_plaintext_channels(plaintext: bytes, n_pixels: int) -> np.ndarray:
    """Return (n_pixels, 8) array of 7-bit plaintext values per channel."""
    out = np.zeros((n_pixels, CHANNELS), dtype=np.uint8)
    total_bits = len(plaintext) * 8
    for p in range(n_pixels):
        bit_index = p * DATA_BITS_PER_PIXEL
        for ch in range(CHANNELS):
            if bit_index >= total_bits:
                break
            byte_idx = bit_index // 8
            bit_off = bit_index % 8
            raw = plaintext[byte_idx]
            if byte_idx + 1 < len(plaintext):
                raw |= plaintext[byte_idx + 1] << 8
            out[p, ch] = (raw >> bit_off) & 0x7F
            bit_index += DATA_BITS_PER_CHANNEL
    return out


def load_sample(hash_name: str, base: str):
    """Load plaintext, ciphertext pixel bytes, startPixel, total_pixels."""
    plain_path = PLAIN_DIR / f"{base}.txt"
    bin_path = ENCRYPTED / hash_name / f"{base}.bin"
    pix_path = ENCRYPTED / hash_name / f"{base}.pixel"

    plaintext = plain_path.read_bytes()
    ciphertext = bin_path.read_bytes()

    meta = {}
    for line in pix_path.read_text().strip().split("\n"):
        k, v = line.split("=", 1)
        meta[k] = v
    start_pixel = int(meta["start_pixel"])
    total_pixels = int(meta["total_pixels"])

    container = ciphertext[HEADER_SIZE:HEADER_SIZE + total_pixels * CHANNELS]
    return plaintext, container, start_pixel, total_pixels


def process_sample(hash_name: str, base: str) -> dict:
    """Compute per-candidate accumulators for one sample.

    Returns dict with:
      - bit_count: (8, 7, 56) count of 1-bits per candidate per bit-position
      - byte_dist: (8, 7, 128) byte distribution per candidate (7-bit values)
      - data_pixels: int
    """
    plaintext, container, start_pixel, total_pixels = load_sample(hash_name, base)

    total_bits = len(plaintext) * 8
    data_pixels = (total_bits + DATA_BITS_PER_PIXEL - 1) // DATA_BITS_PER_PIXEL
    if data_pixels > total_pixels:
        data_pixels = total_pixels

    container_arr = np.frombuffer(container, dtype=np.uint8).reshape(total_pixels, CHANNELS)
    # Roll container so that the data window starts at index 0 (respecting wraparound).
    indices = (start_pixel + np.arange(data_pixels)) % total_pixels
    aligned = container_arr[indices]  # (data_pixels, 8)

    pt_channels = get_plaintext_channels(plaintext, data_pixels)  # (data_pixels, 8)

    extracted = _extract_tbl[:, aligned]                    # (8_np, data_pixels, 8_ch)
    extracted = np.transpose(extracted, (1, 2, 0))          # (data_pixels, 8_ch, 8_np)

    unrotated = _rot_tbl[:, extracted]                      # (7_rot, data_pixels, 8_ch, 8_np)
    unrotated = np.transpose(unrotated, (1, 2, 3, 0))       # (data_pixels, 8_ch, 8_np, 7_rot)

    cand_xor = unrotated ^ pt_channels[:, :, np.newaxis, np.newaxis]
    # cand_xor shape: (data_pixels, 8_ch, 8_np, 7_rot), values in 0..127

    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)
    for np_val in range(8):
        for rot in range(7):
            vals = cand_xor[:, :, np_val, rot].ravel()
            byte_dist[np_val, rot] = np.bincount(vals, minlength=128)

    bit_count = np.zeros((8, 7, 56), dtype=np.int64)
    for ch in range(CHANNELS):
        for bit in range(7):
            bit_idx = ch * 7 + bit
            bit_vals = ((cand_xor[:, ch, :, :] >> bit) & 1).sum(axis=0).astype(np.int64)
            bit_count[:, :, bit_idx] += bit_vals

    return {
        "bit_count": bit_count,
        "byte_dist": byte_dist,
        "data_pixels": data_pixels,
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
    """Sum per-sample accumulators into (hash, kind) totals."""
    bit_count = np.zeros((8, 7, 56), dtype=np.int64)
    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)
    total_data_pixels = 0
    for r in group:
        if "error" in r:
            continue
        bit_count += r["bit_count"]
        byte_dist += r["byte_dist"]
        total_data_pixels += r["data_pixels"]
    totals = np.full((8, 7), total_data_pixels, dtype=np.int64)
    return {
        "samples": len(group),
        "data_pixels": total_data_pixels,
        "bit_count": bit_count,
        "totals": totals,
        "byte_dist": byte_dist,
    }


def report(hash_name: str, kind: str, results: dict):
    print(f"\n{'-'*70}")
    print(f"  {HASH_DISPLAY.get(hash_name, hash_name):<16}  kind={kind:<12}  "
          f"samples={results['samples']:>3}  data pixels={results['data_pixels']:>7}  "
          f"candidates=56")
    print(f"{'-'*70}")

    bit_count = results["bit_count"]
    totals = results["totals"]
    byte_dist = results["byte_dist"]

    if totals[0, 0] == 0:
        print(f"  (no data pixels — skipping)")
        return {"hash": hash_name, "kind": kind, "p_test1_ratio": 0.0, "p_test2_lt_001": 0,
                "kl_max": 0.0}

    # Test 1: per-candidate bit balance
    bit_fraction = bit_count / totals[:, :, np.newaxis]
    n = totals[0, 0]
    worst_per_candidate = np.abs(bit_fraction - 0.5).max(axis=-1)   # (8, 7)
    mean_fraction = bit_fraction.mean()
    ci95 = 1.96 * np.sqrt(0.25 / n)
    ci95_max56 = np.sqrt(0.25 / n) * stats.norm.ppf(1 - 0.05 / (2 * 56))
    exceeding = int((worst_per_candidate > ci95_max56).sum())
    print(f"  [T1] mean bit-fraction={mean_fraction:.6f}  max|frac-0.5|={worst_per_candidate.max():.6f}  "
          f"CI95±{ci95:.6f}  Bonferroni±{ci95_max56:.6f}  exceed={exceeding}/56")

    # Test 2: per-candidate chi-square over 128 byte values
    total_per_cand = byte_dist.sum(axis=-1, keepdims=True)
    expected = total_per_cand / 128
    # Guard against zero rows
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
    print(f"Phase 2b: Per-pixel Candidate Distinguisher (parallel 8 workers)")
    print(f"Corpus: {ENCRYPTED}")
    print(f"Testing theorem: signal/noise 1:1 — all 56 per-pixel candidates")
    print(f"                 equally consistent with the observation")

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

    # Group by (hash, kind)
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
        print(f"\n{'#'*70}")
        print(f"#  HASH: {HASH_DISPLAY[h]} ({h})")
        print(f"{'#'*70}")
        for k in KINDS:
            key = (h, k)
            group = grouped.get(key)
            if not group:
                continue
            agg = reduce_group(group)
            s = report(h, k, agg)
            summary.append(s)

    # Summary table
    print(f"\n{'='*90}")
    print(f"  SUMMARY TABLE")
    print(f"{'='*90}")
    print(f"  {'hash':<16} {'kind':<12} {'bit_exc':>8} {'chi2μ':>8} "
          f"{'p<0.01':>7} {'p<0.001':>8} {'kl_max':>10}  status")
    for s in summary:
        flag = "OK"
        if s["bit_exceed"] > 10 or s["p_lt_001"] > 3 or s["kl_max"] > 0.1:
            flag = "⚠"
        print(f"  {HASH_DISPLAY[s['hash']]:<16} {s['kind']:<12} "
              f"{s['bit_exceed']:>8} {s['chi2_mean']:>8.1f} "
              f"{s['p_lt_01']:>7} {s['p_lt_001']:>8} {s['kl_max']:>10.6f}  {flag}")

    print(f"\n{'='*70}")
    print(f"  INTERPRETATION")
    print(f"{'='*70}")
    print(f"  PASS conditions (signal/noise 1:1 holds empirically):")
    print(f"    Test 1: bit_exceed close to expected ~3/56 (Bonferroni false-positive rate)")
    print(f"    Test 2: chi²_mean ≈ 127, p-values uniformly distributed")
    print(f"    Test 3: kl_max remains small (<0.05 typical)")
    print(f"  FAIL conditions (distinguisher exists):")
    print(f"    Consistent bias across samples within (hash, kind) — replicate before calling it.")
    print(f"  Comparison across 10 hashes:")
    print(f"    Weak PRFs (FNV-1a, MD5) and strong PRFs should all look identical")
    print(f"    (barrier absorbs hash weakness; same per-pixel uniformity).")
