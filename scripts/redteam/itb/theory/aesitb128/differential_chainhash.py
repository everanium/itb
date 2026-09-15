#!/usr/bin/env python3
"""DATA-differential attack surface through ChainHash<AES-ITB-128> (aes2r
differential_chainhash.py port).

Attacker-realistic DATA differential: fix the secret seed, apply a
single-active-byte input difference Δ to `data`, over many random bases,
and measure two differential distinguishers of each observable:

  * max_dp   — max over (output byte, δ) of P(out_byte_diff = δ).  Random ~ 1/256.
  * zero_bytes — # output bytes that are ALWAYS unchanged (truncated
                 differential). A 1-active-byte Δ through one AES round
                 touches one column; through three full rounds it reaches
                 every byte, so at r = 1 the lab shape is expected to show
                 no truncated differential — unlike aes2r, whose final round
                 omits MixColumns.

r=1 = no ChainHash (baseline). discard ON = lo lane (8 bytes) only; the
`discard off, peeled` observable is the free P^-1 step (see screens_common).
"""
import argparse
import os
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import (  # noqa: E402
    OBSERVABLES, R_SET, depth_label, observables, random_comps,
)

N = 8192
DELTAS = [{0: 0x01}, {0: 0x80}, {0: 0xFF}]   # single active data byte, a few values


def diff_probe(comps, rounds, delta, n, data_len):
    d = np.frombuffer(os.urandom(data_len * n), dtype=np.uint8).reshape(n, data_len)
    d2 = d.copy()
    for i, dv in delta.items():
        d2[:, i] ^= dv
    o1 = observables(d, comps, rounds)
    o2 = observables(d2, comps, rounds)
    out = {}
    for k in OBSERVABLES:
        diff = o1[k] ^ o2[k]
        nbytes = diff.shape[1]
        max_dp = 0.0
        for p in range(nbytes):
            counts = np.bincount(diff[:, p], minlength=256)
            max_dp = max(max_dp, counts.max() / n)
        zero_bytes = int(np.count_nonzero(~np.any(diff != 0, axis=0)))
        out[k] = (max_dp, zero_bytes, nbytes)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-len", type=int, default=15)
    ap.add_argument("--samples", type=int, default=N)
    ap.add_argument("--reps", type=int, default=1,
                    help="random-comps replicates per (rounds, Δ) cell; best (worst-case) "
                         "aggregate is reported (default 1, matching the documented run)")
    args = ap.parse_args()

    print("=" * 88)
    print(f"DATA-differential through ChainHash<AES-ITB-128>  (N={args.samples} bases/Δ, "
          f"single active byte, data_len={args.data_len}, {args.reps} rep(s)/cell)")
    print("=" * 88)
    print(f"{'rounds':>6} {'depth':>9} {'observable':>20} {'out_b':>6} {'max_dp':>9} "
          f"{'rand':>8} {'zero_bytes':>11}  verdict")
    print("-" * 88)
    rand = 1 / 256
    for rounds in R_SET:
        best = {k: [0.0, 99, 0] for k in OBSERVABLES}
        for _ in range(args.reps):
            for delta in DELTAS:
                comps = random_comps(rounds)
                res = diff_probe(comps, rounds, delta, args.samples, args.data_len)
                for k, (dp, zb, nb) in res.items():
                    best[k][0] = max(best[k][0], dp)
                    best[k][1] = min(best[k][1], zb)
                    best[k][2] = nb
        for k in OBSERVABLES:
            dp, zb, nb = best[k]
            if rounds == 1 and k == "discard off, peeled":
                verdict = "KEY BLOCK (constant — recovered)"
            else:
                leak = (dp > rand * 4) or (zb > 0)
                verdict = "DIFFERENTIAL LEAK" if leak else "no differential signal"
            print(f"{rounds:>6} {depth_label(rounds):>9} {k:>20} {nb:>6} {dp:>9.4f} "
                  f"{rand:>8.4f} {zb:>11}  {verdict}")
    print("-" * 88)
    print("zero_bytes>0 = truncated-differential signature; max_dp>>1/256 = biased differential.")


if __name__ == "__main__":
    main()
