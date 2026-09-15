#!/usr/bin/env python3
"""
Baseline screens on RAW AES-ITB-128 (r = 1, NO ChainHash): the Λ-set
integral distinguisher and the one-pair inversion key recovery.

Primitive: chainhashes.aesitb128 (bit-exact with aesitb.go). One call =
state = fixedKey XOR seed XOR pad(data), then `blocks + 2` full AES rounds
under public NUMS constants — a public permutation P of (key XOR data). The
seed enters once, by XOR, with no key schedule.

Threat model (no cheating): the attacker holds ONLY an oracle data -> output
(lo lane, or the full 16-byte state when the hi-lane discard is off) and
the public description of P (including fixedKey, granted). Ground-truth
comparison happens at the END, for reporting only.

Screen A — Λ-set integral. A Λ-set (data byte 0 active, 256 texts; higher
orders activate more bytes) through three full AES rounds is the textbook
Square distinguisher: every output byte XOR-sums to zero with probability 1,
for any key (the key only translates the set). The lab one-block shape
(data <= 15 bytes) is exactly three rounds; the shipped per-pixel shapes are
20 / 36 / 68 bytes = 4 / 5 / 7 rounds, so the same screen is repeated at
those lengths to see how far the extra absorbed blocks push the integral.

Screen B — inversion. With the hi lane visible (discard off) one known
(data, output) pair gives the whole 128-bit key block:
    fixedKey XOR seed = P^-1(output) XOR pad(data).
This is the standalone break — inversion, not an integral peel; aes2r's
`recover_k0_byte0` has no analogue here (there is no round key to guess).
With the discard on (lo lane only) the same inversion is a 2^64 enumeration
of the hidden hi lane (guess hi, invert, check against a second pair); it
is not executed — the measured P^-1 throughput gives the extrapolated cost.
"""
import argparse
import os
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import (  # noqa: E402
    balance_stats, lambda_set, prim, random_comps, xor_reduce_chunked,
)

SHAPES = (15, 20, 36, 68)   # one-block lab shape, then the shipped per-pixel shapes
REPS_DEFAULT = 8
TRIALS_DEFAULT = 5


def screen_integral(reps_default: int = REPS_DEFAULT):
    print("=" * 78)
    print("Screen A — Λ-set integral on RAW AES-ITB-128 (r = 1, no ChainHash)")
    print("=" * 78)
    print(f"{'data_len':>8} {'rounds':>6} {'order':>5} {'texts':>9} {'lane':>10} "
          f"{'#active':>8} {'#balanced':>10} {'rand_exp':>9}  verdict")
    print("-" * 78)
    for L in SHAPES:
        rounds = (L // 16 + 1) + 2
        for order in (1, 2, 3):
            n = 256 ** order
            reps = reps_default if order < 3 else 1
            tot = {"lo": [0, 0], "full": [0, 0]}
            for _ in range(reps):
                comps = random_comps(1)
                lam = lambda_set(order, L)
                if order < 3:
                    full = prim.chainhash_batch(lam, comps, rounds=1, discard=False)
                    a_lo, b_lo, _ = balance_stats(full[:, :8])
                    a_f, b_f, _ = balance_stats(full)
                else:
                    st = xor_reduce_chunked(lam, comps, 1)
                    a_lo, b_lo, _ = st["discard on"]
                    a_f, b_f, _ = st["discard off, raw"]
                tot["lo"][0] += a_lo; tot["lo"][1] += b_lo
                tot["full"][0] += a_f; tot["full"][1] += b_f
            for lane, nb in (("lo", 8), ("full", 16)):
                avg_a = tot[lane][0] / reps
                avg_b = tot[lane][1] / reps
                rexp = nb / 256.0
                structured = (avg_a < nb) or (avg_b > rexp + 1)
                verdict = "STRUCTURED (integral leak)" if structured else "looks random (no leak)"
                print(f"{L:>8} {rounds:>6} {order:>5} {n:>9} {lane:>10} "
                      f"{avg_a:>8.1f} {avg_b:>10.1f} {rexp:>9.3f}  {verdict}")
    print("-" * 78)
    print(f"{reps_default} random seeds per cell at orders 1-2, one set at order 3; "
          "random-fn expects #active = lane bytes, #balanced ~= lane bytes / 256.")


def screen_inversion(trials: int = TRIALS_DEFAULT):
    print()
    print("=" * 78)
    print("Screen B — one-pair inversion on RAW AES-ITB-128 (r = 1, discard off)")
    print("=" * 78)
    TRIALS = trials
    ok = 0
    for t in range(TRIALS):
        s0 = int.from_bytes(os.urandom(8), "little")
        s1 = int.from_bytes(os.urandom(8), "little")
        data = os.urandom(15)
        out = prim.hash_generic(prim.FIXED_KEY, data, s0, s1)      # the oracle answer
        r0, r1 = prim.invert_generic(prim.FIXED_KEY, data, out)     # attacker step
        # attacker-side verification on fresh oracle queries (no ground truth)
        verified = all(
            prim.hash_generic(prim.FIXED_KEY, d, r0, r1) == prim.hash_generic(prim.FIXED_KEY, d, s0, s1)
            for d in (os.urandom(15) for _ in range(4))
        )
        hit = verified and (r0, r1) == (s0, s1)   # ground truth: report only
        ok += hit
        print(f"  trial {t}: recovered seed block = {prim.seed_block(r0, r1).hex()}  "
              f"verified on 4 fresh pairs={verified}  {'OK' if hit else 'MISS'}  (1 query)")
    print(f"\nRESULT: {ok}/{TRIALS} full 128-bit seed blocks recovered from ONE known "
          "(data, output) pair, discard off.")

    # discard on: extrapolated cost of the hi-lane enumeration
    N = 1 << 18
    d = np.frombuffer(os.urandom(15 * N), dtype=np.uint8).reshape(N, 15)
    o = prim.chainhash_batch(d, random_comps(1), rounds=1, discard=False)
    t0 = time.time()
    prim.peel_last_batch(d, o)
    rate = N / (time.time() - t0)
    years = (2 ** 64 / rate) / (365.25 * 86400)
    print(f"  discard on: inversion needs the hidden hi lane -> 2^64 P^-1 evaluations; "
          f"measured batched P^-1 rate {rate:.2e}/s -> ~{years:.1e} core-years (not executed).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reps", type=int, default=REPS_DEFAULT,
                    help=f"random seeds per cell in Screen A orders 1-2 (default {REPS_DEFAULT})")
    ap.add_argument("--trials", type=int, default=TRIALS_DEFAULT,
                    help=f"one-pair-inversion trials in Screen B (default {TRIALS_DEFAULT})")
    args = ap.parse_args()
    screen_integral(reps_default=args.reps)
    screen_inversion(trials=args.trials)
