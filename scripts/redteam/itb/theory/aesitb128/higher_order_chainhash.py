#!/usr/bin/env python3
"""Higher-order integral probe (aes2r higher_order_chainhash.py port): does
a 2nd-order Λ-set (2 active data bytes, 2^16 texts) leave a balanced
signature through ChainHash<AES-ITB-128> at any r ∈ R_SET where the
1st-order integral died? Higher order reaches deeper rounds — the natural
escalation. Three observables per depth (see screens_common)."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import (  # noqa: E402
    OBSERVABLES, R_SET, balance_stats, depth_label, lambda_set, observables,
    random_comps,
)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-len", type=int, default=15)
    ap.add_argument("--reps", type=int, default=8, help="random seeds per cell")
    args = ap.parse_args()

    print(f"Higher-order (2nd) integral through ChainHash<AES-ITB-128>  "
          f"(2^16 texts/set, data_len={args.data_len}, {args.reps} seeds/cell)")
    print(f"{'rounds':>6} {'depth':>9} {'order':>5} {'observable':>20} "
          f"{'#balanced':>10} {'rand_exp':>9}  verdict")
    print("-" * 80)
    for rounds in R_SET:
        tot = {k: [0, 0] for k in OBSERVABLES}
        for _ in range(args.reps):
            comps = random_comps(rounds)
            lam = lambda_set(2, args.data_len)
            for k, v in observables(lam, comps, rounds).items():
                _, b, nb = balance_stats(v)
                tot[k][0] += b; tot[k][1] = nb
        for k in OBSERVABLES:
            nb = tot[k][1]
            bal = tot[k][0] / args.reps
            rexp = nb / 256.0
            if rounds == 1 and k == "discard off, peeled":
                v = "KEY BLOCK (constant — recovered)"
            else:
                v = "HIGHER-ORDER LEAK" if bal > rexp + 1 else "random (no 2nd-order leak)"
            print(f"{rounds:>6} {depth_label(rounds):>9} {2:>5} {k:>20} "
                  f"{bal:>10.2f} {rexp:>9.3f}  {v}")


if __name__ == "__main__":
    main()
