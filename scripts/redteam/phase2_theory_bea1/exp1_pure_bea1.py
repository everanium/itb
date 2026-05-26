#!/usr/bin/env python3
"""EXPERIMENT 1 — reproduce the BEA-1 mathematical backdoor end-to-end against
bare BEA-1 and recover the full 120-bit master key.

Run:  python3 exp1_pure_bea1.py

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The cipher and constants are a CLEAN-ROOM reimplementation transcribed from the
published paper (no reference code vendored). This is the positive-control
baseline: against bare BEA-1 the trapdoor recovers the full key, which the
later experiments show ITB's ChainHash feedforward neutralises. A lab control,
not for deployment. Recovery is demonstrated at the tested chosen-plaintext
budget; it is not a security proof.

Stages
------
1. Validate the BEA-1 implementation against the paper's constants
   (S-box bijectivity, M.M^-1 = id, Encrypt/Decrypt involution, serialisation).
2. Recover and VERIFY the hidden partition trapdoor directly from the published
   S-boxes and linear map M (excess linear bias, per-S-box coset subspaces,
   exact MixColumns partition map).  See bea1_trapdoor.py.
3. Full key recovery: a random 120-bit key is drawn from the system RNG; the
   attack is handed an encryption oracle that maps a CHOSEN plaintext to its
   FINAL 11-round ciphertext under that key, plus the public design constants.
   The attack exploits the partition trapdoor to recover all 120 bits of the
   master key, which is asserted equal to the (terminal-stage-only) ground truth.

Attacker model (faithful to the paper).  BEA-1's backdoor is a chosen-plaintext
attack: "Pick roughly 40 plaintexts in the same coset and get the associated
ciphertexts" (ePrint 2016/493, §6.3).  Stage 3 therefore gives the attack an
ENCRYPTION ORACLE (chosen plaintext -> final ciphertext).  The attack's decision
path consumes ONLY (plaintext, final-ciphertext) pairs it requests from the
oracle and the public partition constants.  It never sees the master key, the
target key's key schedule, or any intermediate round state.  The ground-truth
key is read in this harness solely to (a) build the oracle and (b) print the
success line AFTER the attack has produced its answer.
"""
import os
import time
import random

import bea1 as B
import bea1_trapdoor as TD
from bea1_partition_attack import PartitionAttack
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
    ok = TD.verify(td, verbose=True)
    return ok


def stage3_full_key_recovery(n_cosets=10, per_coset=30000):
    banner("STAGE 3 — full 120-bit master-key recovery (partition trapdoor)")

    # ---- ground-truth secret key from the system RNG (NOT the attack's RNG) ----
    sysrng = random.Random(int.from_bytes(os.urandom(16), "big"))
    K_true = tuple(sysrng.randrange(1024) for _ in range(12))
    rk_true = B.expand_key(K_true)

    # ---- encryption oracle: chosen plaintext -> FINAL 11-round ciphertext ----
    # This is the ONLY channel from the attack to the secret key.  It returns the
    # full 11-round ciphertext (never an intermediate round state).
    enc_count = [0]

    def oracle(plaintext):
        enc_count[0] += 1
        return B.encrypt(K_true, plaintext, rk_true)

    attack = PartitionAttack()
    print(f"recovering the 120-bit master key from chosen (plaintext, final-ciphertext)\n"
          f"pairs via the partition trapdoor ({n_cosets} input cosets x {per_coset} pairs) ...")

    t0 = time.time()
    K_rec, info = attack.recover(oracle, n_cosets=n_cosets, per_coset=per_coset, seed=12345)
    dt = time.time() - t0

    # ---- terminal-stage success report (ground truth used ONLY here) ----
    match = (K_rec is not None and tuple(K_rec) == K_true)
    bits_ok = 0
    if K_rec is not None:
        for i in range(12):
            for t in range(10):
                if ((K_rec[i] >> t) & 1) == ((K_true[i] >> t) & 1):
                    bits_ok += 1

    print(f"oracle queries (encryptions)      : {enc_count[0]}")
    print(f"clean-pair counts per input coset : {info.get('clean_sizes')}")
    print(f"k0 lane candidate-set sizes       : {info.get('k0_cand_sizes')}")
    print(f"k1 lane candidate-set sizes       : {info.get('k1_cand_sizes')}")
    print(f"recovered master key (12 bundles) : {list(K_rec) if K_rec else None}")
    print(f"ground-truth master key           : {list(K_true)}")
    print(f"master-key bits correct           : {bits_ok}/120")
    print(f"FULL 120-bit recovery             : {match}")
    print(f"attack wall-clock                 : {dt:.2f} s")
    return match, dt, enc_count[0]


def main():
    t_all = time.time()
    s1 = stage1_validate()
    s2 = stage2_trapdoor()
    s3_match, s3_dt, s3_enc = stage3_full_key_recovery()

    banner("EXPERIMENT 1 SUMMARY")
    print(f"  cipher validated          : {s1}")
    print(f"  trapdoor verified         : {s2}")
    print(f"  full 120-bit key recovered: {s3_match}  ({s3_dt:.2f}s, {s3_enc} oracle queries)")
    print(f"  total wall-clock          : {time.time() - t_all:.1f}s")
    assert s1, "BEA-1 implementation failed validation"
    assert s2, "trapdoor verification failed"
    assert s3_match, "full 120-bit master-key recovery failed"
    print("\nEXP1 OK — backdoor reproduced; full 120-bit master key recovered from "
          "(plaintext, final-ciphertext) pairs.")


if __name__ == "__main__":
    main()
