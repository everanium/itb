#!/usr/bin/env python3
"""Output-uniformity screen for ChainHash<AES-ITB-128>: byte-value χ² and
per-bit bias of the lo lane (the lane ITB's encoding observes) and of the
full state, over N random data inputs under one fixed secret seed, at r = 1
(raw primitive) and every r ∈ R_SET.

  * chi2_max / chi2_mean — per-byte χ² against uniform over 256 values
                           (df = 255; mean 255, sd ~22.6). A byte whose χ²
                           sits far above the ceiling has a value
                           distribution an attacker can read off the wire.
  * bit_bias_max         — max over output bits of |P(bit = 1) − 0.5|; the
                           binomial sd is 0.5 / sqrt(N).
  * byte_ent_min         — minimum per-byte Shannon entropy (bits, ideal 8).

chi2_max and bit_bias_max are maxima over m = lane bytes (bits) × seeds
draws, so the flag ceiling is Bonferroni-corrected: per-draw tail
α / m with α = 0.01, normal quantile z_m, ceiling = mean + z_m · sd (χ²
via the normal approximation of its mean / sd). Both ceilings are printed.

This screen measures the marginal output distribution only. It does not
certify pseudorandomness; a primitive can read uniform here and still be
one-pair invertible (integral_aesitb128.py Screen B).
"""
import argparse
import math
import os
import sys
from pathlib import Path
from statistics import NormalDist

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import R_SET, depth_label, prim, random_comps  # noqa: E402


def stats(arr):
    n, nb = arr.shape
    chi2 = []
    ent = []
    for p in range(nb):
        counts = np.bincount(arr[:, p], minlength=256).astype(np.float64)
        exp = n / 256.0
        chi2.append(float(((counts - exp) ** 2 / exp).sum()))
        pr = counts[counts > 0] / n
        ent.append(float(-(pr * np.log2(pr)).sum()))
    bits = np.unpackbits(arr, axis=1)
    bias = np.abs(bits.mean(axis=0) - 0.5)
    return max(chi2), sum(chi2) / nb, float(bias.max()), min(ent)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", type=int, default=100_000)
    ap.add_argument("--data-len", type=int, default=15)
    ap.add_argument("--reps", type=int, default=4, help="random seeds per cell")
    args = ap.parse_args()
    n = args.samples
    alpha = 0.01
    ceil = {}
    for lane, nb in (("lo", 8), ("full", 16)):
        z_chi = NormalDist().inv_cdf(1 - alpha / (nb * args.reps))
        z_bit = NormalDist().inv_cdf(1 - alpha / (2 * 8 * nb * args.reps))
        ceil[lane] = (255 + z_chi * math.sqrt(2 * 255), z_bit * 0.5 / math.sqrt(n))

    print("=" * 92)
    print(f"Output uniformity of ChainHash<AES-ITB-128>  (N={n} random data/cell, "
          f"data_len={args.data_len}, {args.reps} seeds/cell)")
    print(f"χ² df=255 (mean 255) Bonferroni ceiling for the max, α={alpha}: "
          f"lo {ceil['lo'][0]:.1f}, full {ceil['full'][0]:.1f}; "
          f"bit-bias ceiling: lo {ceil['lo'][1]:.5f}, full {ceil['full'][1]:.5f}")
    print("=" * 92)
    print(f"{'rounds':>6} {'depth':>9} {'lane':>5} {'chi2_max':>9} {'chi2_mean':>10} "
          f"{'bit_bias_max':>13} {'byte_ent_min':>13}  verdict")
    print("-" * 92)
    for rounds in R_SET:
        acc = {"lo": [0.0, 0.0, 0.0, 9.0], "full": [0.0, 0.0, 0.0, 9.0]}
        for _ in range(args.reps):
            comps = random_comps(rounds)
            d = np.frombuffer(os.urandom(args.data_len * n), dtype=np.uint8).reshape(n, args.data_len)
            full = prim.chainhash_batch(d, comps, rounds=rounds, discard=False)
            for lane, arr in (("lo", full[:, :8]), ("full", full)):
                cm, cmean, bb, em = stats(arr)
                a = acc[lane]
                a[0] = max(a[0], cm); a[1] += cmean / args.reps
                a[2] = max(a[2], bb); a[3] = min(a[3], em)
        for lane in ("lo", "full"):
            cm, cmean, bb, em = acc[lane]
            flag = (cm > ceil[lane][0]) or (bb > ceil[lane][1])
            verdict = "BIASED" if flag else "uniform at this N"
            print(f"{rounds:>6} {depth_label(rounds):>9} {lane:>5} {cm:>9.1f} {cmean:>10.1f} "
                  f"{bb:>13.5f} {em:>13.4f}  {verdict}")
    print("-" * 92)
    print("chi2_max = worst byte over lanes x seeds; bit_bias_max = worst bit over seeds.")


if __name__ == "__main__":
    main()
