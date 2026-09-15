#!/usr/bin/env python3
"""3rd-order integral (aes2r order3_chainhash.py port): 2^24 texts per set
through ChainHash<AES-ITB-128> at every r ∈ R_SET, three observables per
depth. One set per cell; evaluated in 2^20-text chunks. Slow-ish (minutes
per deep cell); run detached and log."""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import (  # noqa: E402
    OBSERVABLES, R_SET, depth_label, lambda_set, random_comps, xor_reduce_chunked,
)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-len", type=int, default=15)
    ap.add_argument("--rounds", type=int, nargs="*", default=list(R_SET))
    args = ap.parse_args()

    print(f"3rd-order integral through ChainHash<AES-ITB-128>, 2^24 texts/set, "
          f"data_len={args.data_len}", flush=True)
    print(f"{'rounds':>6} {'depth':>9} {'observable':>20} {'#active':>8} "
          f"{'#balanced':>10} {'rand_exp':>9}  verdict", flush=True)
    print("-" * 82, flush=True)
    for rounds in args.rounds:
        t0 = time.time()
        comps = random_comps(rounds)
        lam = lambda_set(3, args.data_len)
        st = xor_reduce_chunked(lam, comps, rounds)
        for k in OBSERVABLES:
            a, b, nb = st[k]
            rexp = nb / 256.0
            if rounds == 1 and k == "discard off, peeled":
                tag = "KEY BLOCK (constant — recovered)"
            else:
                tag = "HIGHER-ORDER LEAK" if b > rexp + 1 else "random (no 3rd-order leak)"
            print(f"{rounds:>6} {depth_label(rounds):>9} {k:>20} {a:>8} {b:>10} "
                  f"{rexp:>9.3f}  {tag}", flush=True)
        print(f"  ({time.time() - t0:.0f} s)", flush=True)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
