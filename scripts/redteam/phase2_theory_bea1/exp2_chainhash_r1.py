#!/usr/bin/env python3
"""EXPERIMENT 2 — wrap the trapdoored BEA-1 into ITB's ChainHash at rounds=1
(no feedforward) with an 80->64-bit per-lane truncation, and test whether the
partition trapdoor still recovers the lo-lane seed (seed0) despite the
truncation discarding 16 of the 80 output bits.

Run:  python3 exp2_chainhash_r1.py

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The cipher and constants are a CLEAN-ROOM reimplementation transcribed from the
published paper (no reference code vendored). This is a positive-control lab
demonstration (not for deployment) isolating the rounds=1 case: at ChainHash
rounds=1 the truncation alone is the only barrier, and whether it suffices is
bounded to the tested chosen-data budget. The feedforward (rounds>=2) case is
the subject of EXPERIMENT 3.

Setup
-----
A fresh 120-bit lo-lane seed (seed0) is drawn from the SYSTEM RNG (os.urandom),
never shared with the attack.  A hi-lane seed (seed1) is also drawn but is never
observed (the ITB encoder discards the hi lane), so it is not recoverable and is
not a target.  The oracle maps a CHOSEN data block (8 bundles) to ONLY the
truncated 64-bit lo-lane output:

    lo64 = truncate80to64( block_to_uint80( BEA1_encrypt(seed0, data) ) )

The attack (bea1_attack_truncated.PartitionAttackTruncated) consumes ONLY
(chosen data, lo64) pairs plus the public partition constants, and tries to
recover seed0.

Truncation analysis printed below: which 16 bits are dropped, which W-label lanes
survive, and whether the partial label is sufficient to cluster clean pairs.
"""
import os
import time
import random

import bea1 as B
import bea1_trapdoor as TD
import bea1_chainhash as CH
from bea1_attack_truncated import PartitionAttackTruncated, SURVIVING_LANES
import bea1_validate


def banner(s):
    print("\n" + "=" * 70)
    print(s)
    print("=" * 70)


def stage1_validate():
    banner("STAGE 1 — BEA-1 implementation correctness")
    return bea1_validate.main()


def stage2_trapdoor():
    banner("STAGE 2 — recover & verify the hidden partition trapdoor")
    td = TD.derive_trapdoor()
    return TD.verify(td, verbose=True)


def stage3_truncation_analysis():
    banner("STAGE 3 — 80->64 truncation analysis (which bits / W-label lanes survive)")
    print("Low-64 truncation keeps bits 0..63, drops the top 16 bits (64..79).")
    print("BEA-1 packing: bundle i occupies bits [10*(7-i) .. 10*(7-i)+9].\n")
    for i in range(8):
        lo = 10 * (7 - i); hi = lo + 9
        if lo >= 64:
            tag = "DROPPED in full      -> W-label lane UNREADABLE"
        elif hi >= 64:
            tag = f"SPLIT (low {64 - lo} bits kept) -> W-label lane UNREADABLE"
        else:
            tag = "survives             -> W-label lane readable"
        print(f"  bundle/lane {i}: bits [{lo:2d}..{hi:2d}]  {tag}")
    print(f"\nSurviving W-label lanes : {SURVIVING_LANES}  "
          f"({len(SURVIVING_LANES)} of 8 lanes, {5 * len(SURVIVING_LANES)} of 40 label bits)")
    print("The 40-bit W-coset label does NOT fully survive: lanes 0 and 1 are lost\n"
          "(bundle 0 entirely, bundle 1 keeps only its low 4 bits while its W-coordinate\n"
          "masks reference high bits).  The attack therefore clusters on the 30-bit\n"
          "partial label of lanes 2..7.")


def stage4_seed_recovery(n_cosets=10, per_coset=30000):
    banner("STAGE 4 — lo-lane seed (seed0) recovery under 80->64 truncation, rounds=1")

    # ---- fresh secrets from the SYSTEM RNG, not the attack's RNG ----
    sysrng = random.Random(int.from_bytes(os.urandom(16), "big"))
    seed0 = tuple(sysrng.randrange(1024) for _ in range(12))   # lo lane (target)
    seed1 = tuple(sysrng.randrange(1024) for _ in range(12))   # hi lane (discarded)
    rk0 = B.expand_key(seed0)
    rk1 = B.expand_key(seed1)

    # ---- lo-lane oracle: chosen data -> ONLY the truncated 64-bit lo output ----
    # The hi lane is computed but never returned (ITB encoder discards it), so the
    # attack cannot observe seed1 at all.  The oracle returns a single uint64.
    enc_count = [0]

    def oracle(data):
        enc_count[0] += 1
        lo64, _hi64 = CH.chainhash_r1(seed0, seed1, data, rk0, rk1)
        return lo64

    attack = PartitionAttackTruncated()
    print(f"recovering the 120-bit lo-lane seed0 from chosen (data, truncated-lo64)\n"
          f"pairs via the partition trapdoor ({n_cosets} input cosets x {per_coset} pairs),\n"
          f"clustering on the {len(SURVIVING_LANES)}-lane partial W-label ...")

    t0 = time.time()
    seed_rec, info = attack.recover(oracle, n_cosets=n_cosets, per_coset=per_coset, seed=12345)
    dt = time.time() - t0

    # ---- terminal-stage success report (ground truth used ONLY here) ----
    match = (seed_rec is not None and tuple(seed_rec) == seed0)
    bits_ok = 0
    if seed_rec is not None:
        for i in range(12):
            for t in range(10):
                if ((seed_rec[i] >> t) & 1) == ((seed0[i] >> t) & 1):
                    bits_ok += 1

    print(f"oracle queries (lo-lane encryptions): {enc_count[0]}")
    print(f"clean-pair counts per input coset    : {info.get('clean_sizes')}")
    print(f"k0 lane candidate-set sizes          : {info.get('k0_cand_sizes')}")
    print(f"k1 lane candidate-set sizes          : {info.get('k1_cand_sizes')}")
    print(f"recovered seed0 (12 bundles)         : {list(seed_rec) if seed_rec else None}")
    print(f"ground-truth seed0                   : {list(seed0)}")
    print(f"seed0 bits correct                   : {bits_ok}/120")
    print(f"FULL 120-bit seed0 recovery          : {match}")
    print(f"W-label survived truncation intact   : False (6 of 8 lanes; clustering on 30/40 bits)")
    print(f"attack wall-clock                    : {dt:.2f} s")
    return match, dt, enc_count[0], bits_ok


def main():
    t_all = time.time()
    s1 = stage1_validate()
    s2 = stage2_trapdoor()
    stage3_truncation_analysis()
    match, dt, enc, bits_ok = stage4_seed_recovery()

    banner("EXPERIMENT 2 SUMMARY")
    print(f"  cipher validated              : {s1}")
    print(f"  trapdoor verified             : {s2}")
    print(f"  W-label fully survived trunc. : False (lanes 0,1 lost; clusters on lanes 2..7)")
    print(f"  lo-lane seed0 recovered       : {match}  "
          f"({bits_ok}/120 bits, {dt:.2f}s, {enc} oracle queries)")
    print(f"  total wall-clock              : {time.time() - t_all:.1f}s")
    assert s1, "BEA-1 implementation failed validation"
    assert s2, "trapdoor verification failed"
    assert match, "lo-lane seed0 recovery failed under 80->64 truncation at rounds=1"
    print("\nEXP2 OK — at rounds=1 (no feedforward), the 80->64 truncation drops 2 of 8\n"
          "W-label lanes yet the partition trapdoor STILL recovers the full 120-bit\n"
          "lo-lane seed0 from (chosen-data, truncated-64-bit-output) pairs.\n"
          "Truncation alone is a weak barrier at r=1; feedforward (rounds>=2) is the\n"
          "mechanism expected to actually stop the trapdoor (EXPERIMENT 3).")


if __name__ == "__main__":
    main()
