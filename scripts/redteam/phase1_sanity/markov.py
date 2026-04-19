#!/usr/bin/env python3
"""Phase 1 — Markov / cross-channel conditional distributions.

Ciphertext bytes should be pairwise independent: `P(byte_n | byte_{n−1})
= 1/256` per transition. Not tested by NIST STS in this exact formulation.

Tests:
  [A] Adjacent-byte Markov on the flat stream — single χ² over the full
      65 536-cell transition matrix vs uniform 1/65 536 per cell.
  [B] Adjacent-channel Markov within each pixel — for each channel pair
      (k, k+1) at the same pixel position, a separate 65 536-cell χ² so
      that a single channel-pair dependency is not diluted 7× by pooling.

Mode-agnostic — works identically on Single and Triple Ouroboros
(byte-level statistic; Triple region boundaries affect only 2 of ~M
transitions, invisible to χ²).

Expected outcome:
  - Adjacent-byte χ² p-value > 0.01 for every hash
  - All 7 within-pixel channel-pair p-values > Bonferroni α=0.01/7
  - Weak + strong PRFs statistically identical (barrier absorbs bias)
"""

import sys
import time
from pathlib import Path

import numpy as np
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import HASH_DIRNAMES, HASH_DISPLAY, CHANNELS

PROJ = Path(__file__).resolve().parents[3]
STREAMS = PROJ / "tmp" / "streams"

BONF_ALPHA = 0.01 / 7  # 7 adjacent-channel pairs per pixel


def uniform_chi2(pair_counts: np.ndarray) -> tuple[float, float]:
    """χ² of a 65 536-cell transition count array against uniform 1/65 536.

    Returns (chi2, p_value). Returns (NaN, NaN) if the stream is too
    short for the χ² asymptotic approximation to hold.
    """
    N = int(pair_counts.sum())
    expected = N / 65536.0
    if expected < 1.0:
        return (float("nan"), float("nan"))
    chi2 = float(((pair_counts - expected) ** 2 / expected).sum())
    p = float(1.0 - stats.chi2.cdf(chi2, df=65535))
    return chi2, p


def adjacent_byte_chi2(data: np.ndarray) -> tuple[float, float, int]:
    """Test [A]: adjacent-byte Markov on the flat stream."""
    # Pack (byte_{n−1}, byte_n) as a 16-bit integer then bincount.
    pairs = data[:-1].astype(np.int32) * 256 + data[1:].astype(np.int32)
    counts = np.bincount(pairs, minlength=65536)
    chi2, p = uniform_chi2(counts)
    return chi2, p, int(counts.sum())


def adjacent_channel_chi2(pixels: np.ndarray) -> list[dict]:
    """Test [B]: adjacent-channel Markov within each pixel."""
    results = []
    for k in range(CHANNELS - 1):
        pairs = pixels[:, k].astype(np.int32) * 256 + pixels[:, k + 1].astype(np.int32)
        counts = np.bincount(pairs, minlength=65536)
        chi2, p = uniform_chi2(counts)
        results.append({
            "pair": f"{k}->{k + 1}",
            "chi2": chi2,
            "p": p,
            "N": int(counts.sum()),
        })
    return results


def analyze_hash(hash_name: str) -> dict:
    stream_path = STREAMS / f"{hash_name}.bin"
    if not stream_path.exists():
        return {"hash": hash_name, "error": f"missing {stream_path}"}

    data = np.frombuffer(stream_path.read_bytes(), dtype=np.uint8)
    if data.size < 131072:
        return {"hash": hash_name, "error": f"stream too short ({data.size} bytes)"}

    byte_chi2, byte_p, byte_N = adjacent_byte_chi2(data)

    n_pixels = data.size // CHANNELS
    pixels = data[:n_pixels * CHANNELS].reshape(n_pixels, CHANNELS)
    per_channel = adjacent_channel_chi2(pixels)

    channel_ps = [r["p"] for r in per_channel if not np.isnan(r["p"])]
    channel_min_p = float(min(channel_ps)) if channel_ps else float("nan")
    bonf_fails = int(sum(1 for p in channel_ps if p < BONF_ALPHA))

    return {
        "hash": hash_name,
        "byte_chi2": byte_chi2,
        "byte_p": byte_p,
        "byte_N": byte_N,
        "n_pixels": n_pixels,
        "channel_pairs": per_channel,
        "channel_min_p": channel_min_p,
        "bonf_fails": bonf_fails,
    }


def main():
    print(f"Phase 1 — Markov / cross-channel conditional distributions")
    print(f"Streams: {STREAMS}")
    print(f"Testing: P(byte_n | byte_{{n-1}}) = 1/256 (adjacent-byte + adjacent-channel)")
    print(f"Mode-agnostic — Single and Triple Ouroboros analysed identically.")

    if not STREAMS.exists():
        print(f"\n  No streams found at {STREAMS} — run prepare_streams.py first.")
        sys.exit(1)

    t0 = time.time()
    results = [analyze_hash(h) for h in HASH_DIRNAMES]
    elapsed = time.time() - t0
    print(f"\n  Analyzed {len(results)} hash streams in {elapsed:.2f}s")

    print(f"\n{'=' * 110}")
    print(f"  MARKOV SUMMARY  (χ² df=65535; uniform 1/65536 per cell expected)")
    print(f"{'=' * 110}")
    print(f"  {'hash':<10} {'display':<16} {'adj-byte N':>12} {'adj-byte χ²':>14} "
          f"{'byte p':>10} {'ch min-p':>10} {'Bonf fails':>11}  status")
    for r in results:
        if "error" in r:
            print(f"  {r['hash']:<10} ERROR: {r['error']}")
            continue
        flag = "OK"
        if r["byte_p"] < 0.01:
            flag = "⚠ byte"
        if r["bonf_fails"] > 0:
            flag = (flag + " ch") if flag != "OK" else f"⚠ ch ({r['bonf_fails']}/7)"
        print(f"  {r['hash']:<10} {HASH_DISPLAY[r['hash']]:<16} "
              f"{r['byte_N']:>12d} {r['byte_chi2']:>14.1f} "
              f"{r['byte_p']:>10.4f} {r['channel_min_p']:>10.4f} "
              f"{r['bonf_fails']:>11d}  {flag}")

    # Per-channel-pair breakdown for flagged hashes
    flagged = [
        r for r in results
        if "error" not in r and (r["byte_p"] < 0.01 or r["bonf_fails"] > 0)
    ]
    if flagged:
        print(f"\n{'=' * 110}")
        print(f"  Adjacent-channel breakdown for flagged hashes (Bonferroni α={BONF_ALPHA:.5f})")
        print(f"{'=' * 110}")
        for r in flagged:
            print(f"\n  {r['hash']} ({HASH_DISPLAY[r['hash']]}):")
            print(f"    adj-byte: χ²={r['byte_chi2']:.1f}  p={r['byte_p']:.6f}  N={r['byte_N']}")
            for cp in r["channel_pairs"]:
                cp_flag = " ⚠" if cp["p"] < BONF_ALPHA else ""
                print(f"    channel pair {cp['pair']}: χ²={cp['chi2']:.1f}  "
                      f"p={cp['p']:.6f}{cp_flag}")

    # Cross-hash spread
    good = [r for r in results if "error" not in r]
    if good:
        byte_ps = np.array([r["byte_p"] for r in good])
        ch_min_ps = np.array([r["channel_min_p"] for r in good])
        print(f"\n{'=' * 110}")
        print(f"  CROSS-HASH SPREAD  (uniform scatter across primitives = barrier absorbs)")
        print(f"{'=' * 110}")
        print(f"  adj-byte p   : min={byte_ps.min():.4f}  median={np.median(byte_ps):.4f}  "
              f"max={byte_ps.max():.4f}")
        print(f"  ch min-p     : min={ch_min_ps.min():.4f}  median={np.median(ch_min_ps):.4f}  "
              f"max={ch_min_ps.max():.4f}")

    print(f"\n  Interpretation:")
    print(f"    adj-byte p > 0.01 → no first-order Markov structure on flat stream")
    print(f"    Bonferroni fails = 0 → no within-pixel adjacent-channel dependence")
    print(f"    Weak + strong PRFs indistinguishable at this test → barrier absorbs bias")


if __name__ == "__main__":
    main()
