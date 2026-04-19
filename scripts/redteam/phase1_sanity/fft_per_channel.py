#!/usr/bin/env python3
"""Phase 1 — per-channel FFT / spectral flatness.

NIST STS DFT (Phase 3b) runs on the flat byte stream. In the 8-channel
RGBWYOPA packing, a period-8 bias on a single channel is diluted 8× in
the flat stream. This test demultiplexes each `tmp/streams/<hash>.bin`
into 8 per-channel streams (byte at offset i → channel i mod 8) and
computes spectral flatness per channel plus cross-channel Pearson
correlation.

Mode-agnostic — works identically on Single and Triple Ouroboros
(byte-level statistic, no pixel alignment or startPixel required;
Triple region boundaries are invisible at this granularity under the
PRF assumption).

Expected outcome:
  - flatness ≈ 1.0 on every (hash, channel) — white-noise signature
  - max |off-diagonal Pearson| ≲ 0.005 across all 28 channel pairs
  - weak + strong PRFs produce statistically identical flatness
    (barrier absorbs primitive-level bias)
"""

import sys
import time
from pathlib import Path

import numpy as np
from scipy import signal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import HASH_DIRNAMES, HASH_DISPLAY, CHANNELS

PROJ = Path(__file__).resolve().parents[3]
STREAMS = PROJ / "tmp" / "streams"

# Heuristic flag thresholds (coarse; sign-consistency across replications
# is the real signal).
FLATNESS_FLAG_THRESHOLD = 0.95
CORR_FLAG_THRESHOLD = 0.01  # |r| above this on any channel pair is suspect


def spectral_flatness(x: np.ndarray, nperseg: int = 4096) -> float:
    """Welch power-spectral-density → geometric_mean / arithmetic_mean.

    Wiener entropy (spectral flatness): 1.0 for ideal white noise,
    closer to 0.0 for structured signals. Uses Welch segmented
    periodogram for a stable finite-sample estimate.
    """
    if x.size < nperseg * 4:
        nperseg = max(256, x.size // 4)
    _, psd = signal.welch(
        x.astype(np.float64),
        nperseg=nperseg,
        detrend="constant",
    )
    # Drop the DC bin — dominated by mean, not randomness structure.
    psd = psd[1:]
    psd = np.clip(psd, 1e-30, None)
    geom = float(np.exp(np.log(psd).mean()))
    arith = float(psd.mean())
    return geom / arith


def analyze_hash(hash_name: str) -> dict:
    stream_path = STREAMS / f"{hash_name}.bin"
    if not stream_path.exists():
        return {"hash": hash_name, "error": f"missing {stream_path}"}

    data = np.frombuffer(stream_path.read_bytes(), dtype=np.uint8)
    n_pixels = data.size // CHANNELS
    if n_pixels < 4096:
        return {"hash": hash_name, "error": f"stream too short ({n_pixels} pixels)"}

    # Reshape into (n_pixels, 8) so column k is channel k's time series.
    pixels = data[:n_pixels * CHANNELS].reshape(n_pixels, CHANNELS)

    flatness = np.array([spectral_flatness(pixels[:, ch]) for ch in range(CHANNELS)])

    # Cross-channel Pearson correlation as a coarse independence indicator.
    # Full coherence matrix per frequency would be expensive; zero-lag Pearson
    # catches the strongest cross-channel dependencies visible at this scale.
    corr = np.corrcoef(pixels.T.astype(np.float64))
    off_diag = corr[~np.eye(CHANNELS, dtype=bool)]
    max_abs_corr = float(np.abs(off_diag).max())
    mean_abs_corr = float(np.abs(off_diag).mean())

    return {
        "hash": hash_name,
        "n_pixels": n_pixels,
        "flatness_per_channel": flatness.tolist(),
        "flatness_min": float(flatness.min()),
        "flatness_mean": float(flatness.mean()),
        "flatness_max": float(flatness.max()),
        "max_abs_corr": max_abs_corr,
        "mean_abs_corr": mean_abs_corr,
    }


def main():
    print(f"Phase 1 — per-channel FFT / spectral flatness")
    print(f"Streams: {STREAMS}")
    print(f"Testing: does any of the 8 channels carry period-specific structure")
    print(f"         that the flat-stream NIST STS DFT could miss via 8x dilution?")
    print(f"Mode-agnostic — Single and Triple Ouroboros analysed identically.")

    if not STREAMS.exists():
        print(f"\n  No streams found at {STREAMS} — run prepare_streams.py first.")
        sys.exit(1)

    t0 = time.time()
    results = [analyze_hash(h) for h in HASH_DIRNAMES]
    elapsed = time.time() - t0
    print(f"\n  Analyzed {len(results)} hash streams in {elapsed:.2f}s")

    print(f"\n{'=' * 100}")
    print(f"  SPECTRAL FLATNESS SUMMARY  (expected ≈ 1.0 for white noise)")
    print(f"{'=' * 100}")
    print(f"  {'hash':<10} {'display':<16} {'N':>10} "
          f"{'flatness min':>14} {'flatness mean':>14} {'max|corr|':>12}  status")
    for r in results:
        if "error" in r:
            print(f"  {r['hash']:<10} ERROR: {r['error']}")
            continue
        flag = "OK"
        if r["flatness_min"] < FLATNESS_FLAG_THRESHOLD:
            flag = "⚠ flatness"
        if r["max_abs_corr"] > CORR_FLAG_THRESHOLD:
            flag = (flag + " corr") if flag != "OK" else "⚠ corr"
        print(f"  {r['hash']:<10} {HASH_DISPLAY[r['hash']]:<16} "
              f"{r['n_pixels']:>10d} "
              f"{r['flatness_min']:>14.6f} {r['flatness_mean']:>14.6f} "
              f"{r['max_abs_corr']:>12.6f}  {flag}")

    # Per-channel breakdown for any flagged hash
    flagged = [
        r for r in results
        if "error" not in r and (
            r["flatness_min"] < FLATNESS_FLAG_THRESHOLD
            or r["max_abs_corr"] > CORR_FLAG_THRESHOLD
        )
    ]
    if flagged:
        print(f"\n{'=' * 100}")
        print(f"  Per-channel breakdown for flagged hashes")
        print(f"{'=' * 100}")
        for r in flagged:
            print(f"\n  {r['hash']} ({HASH_DISPLAY[r['hash']]}):")
            for ch, f in enumerate(r["flatness_per_channel"]):
                ch_flag = " ⚠" if f < FLATNESS_FLAG_THRESHOLD else ""
                print(f"    channel {ch}: flatness = {f:.6f}{ch_flag}")

    # Cross-hash spread — real signal here is "all 10 primitives
    # indistinguishable at this test" = barrier absorbs primitive bias.
    good = [r for r in results if "error" not in r]
    if good:
        fmins = np.array([r["flatness_min"] for r in good])
        fmeans = np.array([r["flatness_mean"] for r in good])
        cmaxes = np.array([r["max_abs_corr"] for r in good])
        print(f"\n{'=' * 100}")
        print(f"  CROSS-HASH SPREAD  (narrow band across 10 primitives = barrier absorbs)")
        print(f"{'=' * 100}")
        print(f"  flatness  min: [{fmins.min():.6f}, {fmins.max():.6f}]  "
              f"spread {(fmins.max() - fmins.min()):.6f}")
        print(f"  flatness mean: [{fmeans.min():.6f}, {fmeans.max():.6f}]  "
              f"spread {(fmeans.max() - fmeans.min()):.6f}")
        print(f"  max|corr|    : [{cmaxes.min():.6f}, {cmaxes.max():.6f}]  "
              f"spread {(cmaxes.max() - cmaxes.min()):.6f}")

    print(f"\n  Interpretation:")
    print(f"    flatness ≈ 1.0 on every channel → no period-8 structure")
    print(f"    max|corr| small → channels independent at zero lag")
    print(f"    narrow spread across primitives → barrier absorbs bias uniformly")
    print(f"    sign-consistency across BF=1 / BF=32 replications is the real signal")


if __name__ == "__main__":
    main()
