#!/usr/bin/env python3
"""Phase 3a: rotation-invariant edge case test.

SCIENCE.md §2.9.2 discusses an edge case: 7-bit values where all rotations
produce the same result. For 7-bit values, only 0000000 (0x00) and 1111111
(0x7F) are rotation-invariant. Under uniform distribution, their combined
probability is 2/128 = 1.5625%.

The concern: if rotation-invariant values appeared at elevated rate, an
attacker could detect them (7 rotation candidates collapse to 1), gaining
information about the configuration.

Theoretical prediction (Theorem 1 + Theorem 7 + signal/noise 1:1):
  - Under any hash primitive (even biased MD5/MD4), the 7-bit extract at
    every noisePos should produce rotation-invariant values at rate ~1.56%
  - Wrong noisePos gives random 7-bit extract → 1.56% by construction
  - Correct noisePos + correct rotation + correct xor mask produces
    data_bits XOR xor_mask, where xor_mask is pseudorandom → 1.56%
  - Correct noisePos + wrong rotation/xor: still random → 1.56%
  - Barrier absorbs any hash-level deviation → rate stays uniform

Method:
  - For each ciphertext, for each data-carrying pixel, for each channel byte,
    for each noisePos (0-7): extract the 7-bit value, check if it's 0 or 127
  - Aggregate rate per (hash, kind, noisePos)
  - Compare to 1.5625% under chi-square

Speed: pure byte-level enumeration, no candidate products. Vectorized in
numpy. Expected runtime: seconds across full corpus.
"""

import sys
import glob
import struct
from pathlib import Path

import numpy as np
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import (
    HASH_DIRNAMES, HASH_DISPLAY, KINDS,
    HEADER_SIZE, CHANNELS, DATA_BITS_PER_PIXEL,
)

PROJ = Path(__file__).resolve().parents[3]
ROOT = PROJ / "tmp"
PLAIN_DIR = ROOT / "plain"
ENCRYPTED = ROOT / "encrypted"

EXPECTED_RATE = 2 / 128  # 0.015625

# Precomputed extract table: _extract_tbl[noise_pos, byte] = 7-bit data
_extract_tbl = np.zeros((8, 256), dtype=np.uint8)
for _np in range(8):
    _mask_low = (1 << _np) - 1
    for _b in range(256):
        _low = _b & _mask_low
        _high = _b >> (_np + 1)
        _extract_tbl[_np, _b] = _low | (_high << _np)


def list_samples(kind: str, hash_name: str) -> list[str]:
    import re
    pat = re.compile(rf"^{re.escape(kind)}_(\d{{3}})\.bin$")
    files = sorted((ENCRYPTED / hash_name).glob(f"{kind}_*.bin"))
    return [Path(f).stem for f in files if pat.match(Path(f).name)]


def analyze_sample(hash_name: str, base: str) -> np.ndarray:
    """Return (8_np,) array of rotation-invariant counts across all channel bytes.
    Also return total observations count."""
    bin_path = ENCRYPTED / hash_name / f"{base}.bin"
    plain_path = PLAIN_DIR / f"{base}.txt"

    plaintext_len = plain_path.stat().st_size
    ciphertext = bin_path.read_bytes()

    nonce_size = 16
    w = int.from_bytes(ciphertext[nonce_size:nonce_size + 2], "big")
    h = int.from_bytes(ciphertext[nonce_size + 2:nonce_size + 4], "big")
    total_pixels = w * h

    container = ciphertext[HEADER_SIZE:HEADER_SIZE + total_pixels * CHANNELS]
    container_arr = np.frombuffer(container, dtype=np.uint8)

    # Determine data-carrying pixels
    total_bits = plaintext_len * 8
    data_pixels = (total_bits + DATA_BITS_PER_PIXEL - 1) // DATA_BITS_PER_PIXEL
    if data_pixels > total_pixels:
        data_pixels = total_pixels

    # startPixel from sidecar
    pix_path = ENCRYPTED / hash_name / f"{base}.pixel"
    meta = {}
    for line in pix_path.read_text().strip().split("\n"):
        k, v = line.split("=", 1)
        meta[k] = v
    start_pixel = int(meta["start_pixel"])

    # Extract the linear array of channel bytes for data-carrying pixels
    # (respecting startPixel wraparound)
    aligned_bytes = np.zeros(data_pixels * CHANNELS, dtype=np.uint8)
    for p in range(data_pixels):
        linear_idx = (start_pixel + p) % total_pixels
        aligned_bytes[p * CHANNELS:(p + 1) * CHANNELS] = \
            container_arr[linear_idx * CHANNELS:(linear_idx + 1) * CHANNELS]

    # For each noise_pos 0..7, extract 7-bit values and count rotation-invariants
    # extracts[noise_pos, i] = _extract_tbl[noise_pos, aligned_bytes[i]]
    extracts = _extract_tbl[:, aligned_bytes]  # (8_np, n_bytes)
    rot_invariant_mask = (extracts == 0) | (extracts == 127)  # (8_np, n_bytes)
    counts = rot_invariant_mask.sum(axis=1)  # (8_np,)

    total_bytes = aligned_bytes.size
    return counts, total_bytes


def analyze_hash_kind(hash_name: str, kind: str):
    samples = list_samples(kind, hash_name)
    if not samples:
        return None

    per_np_counts = np.zeros(8, dtype=np.int64)
    total_bytes = 0
    for s in samples:
        counts, nb = analyze_sample(hash_name, s)
        per_np_counts += counts
        total_bytes += nb

    # Rate per noise_pos
    rates = per_np_counts / total_bytes
    overall_count = per_np_counts.sum()
    overall_total = total_bytes * 8  # 8 noisePos extracts per byte
    overall_rate = overall_count / overall_total

    # Chi-square: observed counts vs expected (binomial np.total_bytes, p=2/128)
    # For each noise_pos: 2-cell chi² (invariant vs non-invariant)
    chi2_per_np = []
    p_per_np = []
    for np_val in range(8):
        observed = per_np_counts[np_val]
        expected = total_bytes * EXPECTED_RATE
        # Chi² with 1 df
        if expected > 0 and total_bytes - expected > 0:
            chi2 = (observed - expected) ** 2 / expected + \
                   ((total_bytes - observed) - (total_bytes - expected)) ** 2 / (total_bytes - expected)
            p_val = 1 - stats.chi2.cdf(chi2, df=1)
        else:
            chi2, p_val = 0.0, 1.0
        chi2_per_np.append(float(chi2))
        p_per_np.append(float(p_val))

    # Overall chi² (pooled across noisePos)
    overall_chi2 = (overall_count - overall_total * EXPECTED_RATE) ** 2 / (overall_total * EXPECTED_RATE) + \
                   ((overall_total - overall_count) - (overall_total * (1 - EXPECTED_RATE))) ** 2 / (overall_total * (1 - EXPECTED_RATE))
    overall_p = 1 - stats.chi2.cdf(overall_chi2, df=1)

    return {
        "hash": hash_name,
        "kind": kind,
        "n_samples": len(samples),
        "total_bytes": total_bytes,
        "total_extracts": total_bytes * 8,
        "per_np_counts": per_np_counts.tolist(),
        "per_np_rates": rates.tolist(),
        "per_np_chi2": chi2_per_np,
        "per_np_p": p_per_np,
        "overall_rate": overall_rate,
        "overall_chi2": float(overall_chi2),
        "overall_p": float(overall_p),
    }


if __name__ == "__main__":
    import time
    print("Phase 3a: rotation-invariant edge case test")
    print(f"  Expected rate under H0 (uniform 7-bit values): {EXPECTED_RATE*100:.4f}%")
    print(f"  Testing whether barrier absorbs hash-level bias even at rotation-invariant edge case")

    t0 = time.time()
    all_results = []
    for h in HASH_DIRNAMES:
        for k in KINDS:
            r = analyze_hash_kind(h, k)
            if r is not None:
                all_results.append(r)

    t1 = time.time()
    print(f"\n  Runtime: {t1 - t0:.2f}s across {len(all_results)} hash×kind combinations")

    # Print per-kind-hash table
    print(f"\n{'='*100}")
    print(f"  Per (hash, kind) rotation-invariant rate")
    print(f"{'='*100}")
    print(f"  {'hash':<5} {'kind':<12} {'n':>3} {'bytes':>8} {'extracts':>10} "
          f"{'rate %':>9} {'dev from 1.5625%':>18} {'chi2':>10} {'p':>10}")
    for r in all_results:
        sig = ""
        if r["overall_p"] < 0.05:
            sig = " ⚠"
        if r["overall_p"] < 0.001:
            sig = " ⚠⚠⚠"
        print(f"  {r['hash']:<5} {r['kind']:<12} {r['n_samples']:>3} "
              f"{r['total_bytes']:>8} {r['total_extracts']:>10} "
              f"{r['overall_rate']*100:>8.4f}% "
              f"{(r['overall_rate'] - EXPECTED_RATE)*100:>+17.4f}% "
              f"{r['overall_chi2']:>10.3f} {r['overall_p']:>10.4f}{sig}")

    # Per-noisePos breakdown for flagged kinds
    print(f"\n{'='*100}")
    print(f"  Per noisePos detail for hash×kind with p<0.05 (if any)")
    print(f"{'='*100}")
    flagged = [r for r in all_results if r["overall_p"] < 0.05]
    if not flagged:
        print(f"  (none — all 27 combinations pass p>0.05)")
    else:
        for r in flagged:
            print(f"\n  {r['hash']} / {r['kind']} (p_overall={r['overall_p']:.4f}):")
            for np_val in range(8):
                rate = r["per_np_rates"][np_val] * 100
                p = r["per_np_p"][np_val]
                flag = " ⚠" if p < 0.05 else ""
                print(f"    noisePos={np_val}: rate={rate:.4f}%  chi2={r['per_np_chi2'][np_val]:.3f}  p={p:.4f}{flag}")

    # Aggregate per-hash
    print(f"\n{'='*100}")
    print(f"  Aggregate per hash (pooled across all kinds)")
    print(f"{'='*100}")
    for h in HASH_DIRNAMES:
        hash_results = [r for r in all_results if r["hash"] == h]
        if not hash_results:
            continue
        total_count = sum(sum(r["per_np_counts"]) for r in hash_results)
        total_extracts = sum(r["total_extracts"] for r in hash_results)
        rate = total_count / total_extracts
        dev = rate - EXPECTED_RATE
        # Chi²
        expected = total_extracts * EXPECTED_RATE
        chi2 = (total_count - expected) ** 2 / expected + \
               ((total_extracts - total_count) - (total_extracts - expected)) ** 2 / (total_extracts - expected)
        p_val = 1 - stats.chi2.cdf(chi2, df=1)
        print(f"  {h:<10} ({HASH_DISPLAY[h]:<15}): {total_extracts:>10} extracts, "
              f"rate={rate*100:.4f}% (dev {dev*100:+.4f}%), chi2={chi2:.3f}, p={p_val:.4f}")
    print(f"\n  Expected under theory: {EXPECTED_RATE*100:.4f}%")
    print(f"  Interpretation:")
    print(f"    rate ≈ 1.5625% and p > 0.05 → theory holds, barrier absorbs bias at edge case")
    print(f"    rate significantly elevated → bias leaks through, signal/noise < 1:1 at edge")
