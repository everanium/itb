#!/usr/bin/env python3
"""Phase 1 sanity: ITB-specific structural checks.

NIST STS (Phase 3b) covers the generic randomness tests — global byte
uniformity, entropy, lag-correlation — across 188 tests on 20 Mbits per
hash. Phase 1 is pared down to the two structural checks that NIST STS does
NOT do because they depend on ITB's layout:

  [A] Per-channel-position chi² — the 8-channel RGBWYOPA packing means byte
      offset ≡ k (mod 8) all belong to channel k. A bias that leaks only in
      one channel gets diluted 8× in the flattened stream NIST STS sees, so
      we test each channel separately here.

  [B] Nonce-independence collision scan — same-position byte matches between
      pairs of ciphertexts. Under fresh nonce + fresh seeds, expected match
      rate is 1/256; a sustained ratio >1 would indicate nonce-dependent
      structure unique to the ITB construction.

Red flags:
  - One channel's chi² stands out against the other seven (per-channel bias)
  - Collision ratio materially different from 1.0 (nonce dependence)
  - Weak PRFs (MD5, FNV-1a) diverge from strong PRFs (barrier failing)
"""

import os
import sys
import glob
from pathlib import Path

import numpy as np
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import HASH_DIRNAMES, HASH_DISPLAY, HEADER_SIZE, CHANNELS

PROJ = Path(__file__).resolve().parents[3]
ROOT = PROJ / "tmp"
ENCRYPTED = ROOT / "encrypted"


def load_container_bytes(hash_name: str) -> list[bytes]:
    """Load all .bin files for a hash variant, returning just the pixel bytes
    (header stripped)."""
    bins = sorted(glob.glob(str(ENCRYPTED / hash_name / "*.bin")))
    containers = []
    for b in bins:
        data = open(b, "rb").read()
        containers.append(data[HEADER_SIZE:])
    return containers


def chi_square_uniform(byte_counts: np.ndarray) -> tuple[float, float]:
    """Chi-square test for uniformity over 256 bytes.
    Returns (chi2_statistic, p_value)."""
    n = byte_counts.sum()
    expected = n / 256
    if expected < 5:
        return (float("nan"), float("nan"))
    chi2 = ((byte_counts - expected) ** 2 / expected).sum()
    p = 1 - stats.chi2.cdf(chi2, df=255)
    return (chi2, p)


def analyze_hash(hash_name: str) -> dict:
    print(f"\n{'='*70}")
    print(f"  HASH VARIANT: {HASH_DISPLAY.get(hash_name, hash_name)} ({hash_name})")
    print(f"{'='*70}")
    containers = load_container_bytes(hash_name)
    if not containers:
        print(f"  (no samples)")
        return {}

    total_samples = len(containers)
    total_bytes = sum(len(c) for c in containers)
    print(f"  samples: {total_samples}, total bytes: {total_bytes}")

    # [A] Per-channel-position chi²
    # Container layout: [P pixels × 8 channels × 8 bits]. Byte at offset i
    # belongs to channel (i mod 8). Bias restricted to one channel would be
    # 8× diluted in the flat stream NIST STS sees — test each channel here.
    print(f"\n  [A] Per-channel marginal distribution (8 channels, chi² df=255)")
    per_channel = []
    min_p = 1.0
    for ch in range(CHANNELS):
        ch_counts = np.zeros(256, dtype=np.int64)
        for c in containers:
            arr = np.frombuffer(c, dtype=np.uint8)
            ch_bytes = arr[ch::CHANNELS]
            cc = np.bincount(ch_bytes, minlength=256)
            ch_counts += cc
        chi2_ch, p_ch = chi_square_uniform(ch_counts)
        per_channel.append({"ch": ch, "chi2": float(chi2_ch), "p": float(p_ch)})
        min_p = min(min_p, p_ch)
        flag = "" if p_ch > 0.01 else " ⚠"
        print(f"      channel {ch}: chi² = {chi2_ch:8.2f}  p = {p_ch:.4f}{flag}")
    # Under uniform H0: chi² ≈ 255 ± 22.6, p ≈ 0.5 expected
    # Bonferroni-corrected α for 8 channels: 0.01/8 ≈ 0.00125
    bonf_fail = sum(1 for r in per_channel if r["p"] < 0.01 / CHANNELS)
    print(f"      Bonferroni-corrected failures (p < {0.01/CHANNELS:.5f}): {bonf_fail}/{CHANNELS}")

    # [B] Same-position byte matches across samples
    # Under fresh nonce + fresh seeds: expected match rate 1/256 per byte pos.
    # Sustained ratio > 1 indicates nonce-dependent structure.
    print(f"\n  [B] Nonce-independence: same-position byte matches across sample pairs")
    prefix_len = 256
    prefixes = [c[:prefix_len] for c in containers if len(c) >= prefix_len]
    collision_ratio = float("nan")
    if len(prefixes) >= 2:
        # Stack into (n, prefix_len) uint8 array; for each position count pair
        # matches via histogram — avoids quadratic byte-level loop.
        arr = np.array([np.frombuffer(p, dtype=np.uint8) for p in prefixes])
        n = arr.shape[0]
        pairs = n * (n - 1) // 2
        matches = 0
        for k in range(prefix_len):
            col = arr[:, k]
            counts = np.bincount(col, minlength=256)
            # pairs matching at this position: sum over v of C(count_v, 2)
            matches += int((counts * (counts - 1) // 2).sum())
        expected = pairs * prefix_len / 256
        collision_ratio = matches / expected if expected > 0 else float("nan")
        flag = "" if 0.80 < collision_ratio < 1.20 else " ⚠"
        print(f"      samples: {n}  pairs: {pairs}  prefix: {prefix_len} bytes")
        print(f"      matches: {matches}   expected under H0: {expected:.1f}")
        print(f"      ratio actual/expected: {collision_ratio:.4f}{flag}  (target ≈ 1.0)")

    return {
        "hash": hash_name,
        "n_samples": total_samples,
        "per_channel": per_channel,
        "min_channel_p": float(min_p),
        "bonf_fail": bonf_fail,
        "collision_ratio": float(collision_ratio),
    }


if __name__ == "__main__":
    print(f"Phase 1 (structural): per-channel uniformity + nonce independence")
    print(f"Corpus: {ENCRYPTED}")
    print(f"(Generic uniformity / entropy / lag-correlation covered by NIST STS Phase 3b.)")

    results = {}
    for h in HASH_DIRNAMES:
        results[h] = analyze_hash(h)

    print(f"\n{'='*85}")
    print(f"  SUMMARY")
    print(f"{'='*85}")
    print(f"  {'hash':<10} {'display':<16} {'n':>4} "
          f"{'min chan p':>12} {'bonf fail':>10} {'coll ratio':>11}   status")
    for h in HASH_DIRNAMES:
        r = results.get(h) or {}
        if not r:
            continue
        flag = "OK"
        if r["bonf_fail"] > 0 or not (0.80 < r["collision_ratio"] < 1.20):
            flag = "⚠"
        print(f"  {h:<10} {HASH_DISPLAY[h]:<16} {r['n_samples']:>4} "
              f"{r['min_channel_p']:>12.4f} {r['bonf_fail']:>10d} "
              f"{r['collision_ratio']:>11.4f}   {flag}")
    print()
    print("Interpretation:")
    print("  - Per-channel p > 0.01/8 (Bonferroni) → no channel leaks structural bias")
    print("  - Collision ratio in [0.8, 1.2] → same-position matches are random coincidence")
    print("  - Weak PRFs (FNV-1a, MD5) should look identical to strong PRFs (barrier absorbs)")
