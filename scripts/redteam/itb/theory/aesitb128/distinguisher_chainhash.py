#!/usr/bin/env python3
"""
Does the AES-ITB-128 integral structure SURVIVE ChainHash wrapping?

Structure-agnostic distinguisher (the aes2r distinguisher_chainhash.py
port): feed a Λ-set (data byte 0 active, 256 values) through the cascade at
r ∈ {1, 2, 3, 4, 5, 6, 7, 8, 12, 16} primitive calls and measure, for each
attacker observable,
  * #active output bytes (vary over the set) — random fn ~= all bytes active
  * balanced? (every output byte XOR-sums to 0 over the 256 texts) — the
    integral signature; a random fn is balanced only by chance (P ~ 2^-8
    per byte)

Observables: `discard on` (raw lo lane), `discard off, raw` (full h_r),
`discard off, peeled` (P^-1 through the last call — the free attacker step
when the hi lane is visible; at r = 1 it yields the key block itself, so
that row shows 0 active / 16 balanced by construction).

The feed-forward k_i = seed_i ^ h_{i-1} XORs the previous output into the
next call's initial state — for this primitive that is the same XOR slot
the data occupies, so from r = 2 on the set entering P is no longer a
Λ-set. r = 1 = no ChainHash (baseline).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import (  # noqa: E402
    OBSERVABLES, R_SET, balance_stats, depth_label, lambda_set, observables,
    random_comps,
)

REPS = 8


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-len", type=int, default=15,
                    help="data bytes per text (15 = one-block lab shape; "
                         "20 / 36 / 68 = shipped per-pixel shapes)")
    ap.add_argument("--reps", type=int, default=REPS)
    args = ap.parse_args()

    print("=" * 84)
    print(f"Integral-survival distinguisher through ChainHash<AES-ITB-128>  "
          f"(data_len={args.data_len}, {args.reps} seeds/cell, 256 texts/set)")
    print("=" * 84)
    print(f"{'rounds':>6} {'depth':>9} {'observable':>20} {'out_b':>6} {'#active':>8} "
          f"{'#balanced':>10}  verdict")
    print("-" * 84)
    for rounds in R_SET:
        tot = {k: [0, 0, 0] for k in OBSERVABLES}
        for _ in range(args.reps):
            comps = random_comps(rounds)
            lam = lambda_set(1, args.data_len)
            obs = observables(lam, comps, rounds)
            for k, v in obs.items():
                a, b, nb = balance_stats(v)
                tot[k][0] += a; tot[k][1] += b; tot[k][2] = nb
        for k in OBSERVABLES:
            nb = tot[k][2]
            avg_a = tot[k][0] / args.reps
            avg_b = tot[k][1] / args.reps
            rand_bal = nb / 256.0
            structured = (avg_a < nb) or (avg_b > rand_bal + 1)
            if rounds == 1 and k == "discard off, peeled":
                verdict = "KEY BLOCK (constant — recovered)"
            else:
                verdict = "STRUCTURED (integral leak)" if structured else "looks random (no leak)"
            print(f"{rounds:>6} {depth_label(rounds):>9} {k:>20} {nb:>6} {avg_a:>8.1f} "
                  f"{avg_b:>10.1f}  {verdict}")
    print("-" * 84)
    print("r=1 = no ChainHash (baseline). random-fn expects #active=out_bytes, "
          "#balanced~=out_bytes/256. depth column: KeyBits at which r is the shipped cascade.")


if __name__ == "__main__":
    main()
