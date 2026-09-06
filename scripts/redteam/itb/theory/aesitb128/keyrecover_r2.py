#!/usr/bin/env python3
"""Can the standalone AES-ITB-128 break be converted into KEY RECOVERY
through ChainHash? (aes2r keyrecover_r2.py port.) The standalone break is
the one-pair inversion (integral_aesitb128.py Screen B), so the engine here
is P^-1, not the integral peel.

Engine: from one (data, full output) pair compute
    K = P^-1(output) XOR pad(data) XOR fixedKey
and treat K as the candidate seed block; verify by re-querying the oracle
on fresh data and comparing against hash_generic under K. Control r = 1
must recover. At r >= 2 the same step exposes seed_r XOR h_{r-1} —
data-dependent, so a candidate from one pair fails verification on any
other pair. At r = 2 the peeled function is
c XOR P(k_1 XOR pad(data)), a two-key Even-Mansour over the public P: the
generic key-recovery bound is 2^64 data/time (n = 128), not measured here.

Engine 2 — Square key recovery on the peeled r = 2 observable. The
surviving r = 2 distinguisher (distinguisher_chainhash.py: the peeled
output is 16 / 16 balanced) is converted into recovery. After the peel,
    y = k2 XOR R_RC1(R_RC0(R_RC0(K1 XOR pad(data))))
with k2 = seed block 2 and K1 = fixedKey XOR seed block 1 both unknown —
three full AES rounds between two whitening keys. Over a Λ-set (data
byte 0 active) the state S2 entering the last round has, in every column,
four bytes that are GF(2^8)-affine in ONE variable (the column's single
active input byte after two rounds): S2[4c+j] = M[j][i]·v XOR d_j, so for
bytes j, j' of one column M[j'][i]·S2_j XOR M[j][i]·S2_j' is constant
over the set. With w = MC^-1(y) and κ = MC^-1(k2 XOR RC1), each S2 byte is
SB^-1(w[p] XOR κ[p]); guessing the two κ bytes of a pair (2^16) and
testing the constancy relation singles them out. Twelve pairs give all 16
κ bytes -> k2 -> P^-1 of one text gives seed block 1. Cost ~2^25, seconds.
At r >= 3 the input to the peeled permutation is h_{r-2} XOR pad(data) XOR
const — no Λ-set — and the same engine returns no consistent candidate.

discard OFF (full 128-bit output) is the easiest case for the attacker;
discard ON (lo lane only) removes the peel altogether — inversion needs the
hidden hi lane, 2^64 enumeration (integral_aesitb128.py reports the
extrapolated cost).
"""
import os
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import R_SET, depth_label, prim, random_comps  # noqa: E402
from chainhashes.aes2r import _gmul  # noqa: E402

TR = 5
DATA_LEN = 15

# MixColumns matrix: out[j] = XOR_i M[j][i] · in[i]
M = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
GMUL = np.array([[_gmul(a, b) for b in range(256)] for a in range(256)], dtype=np.uint8)
ISB = prim._ISB_T
RC1 = np.frombuffer(prim.RC[1], dtype=np.uint8)


def square_recover_r2(query_full, verify_query):
    """Attacker step on the peeled r = 2 observable: one Λ-set (256 chosen
    texts) -> (seed block 1, seed block 2) candidate, verified on fresh
    queries. Returns (candidate comps or None, n_verified_ok)."""
    fixed = os.urandom(DATA_LEN - 1)
    texts = [bytes([v]) + fixed for v in range(256)]
    Y = np.stack([np.frombuffer(prim.peel_last(t, query_full(t)), dtype=np.uint8)
                  for t in texts])                       # (256, 16)
    W = prim._inv_mix_batch(Y)                           # w = MC^-1(y)
    g = np.arange(256, dtype=np.uint8)
    cands = [None] * 16
    for c in range(4):
        i = (-c) % 4                                     # active input row of column c
        pos = [r + 4 * ((c - r) % 4) for r in range(4)]  # S2 (r, c) -> position in SR(SB(S2))
        # S2 byte candidates per κ guess: S[j][guess, text]
        S = [ISB[W[:, pos[j]][None, :] ^ g[:, None]] for j in range(4)]
        for j, j2 in ((0, 1), (1, 2), (2, 3), (0, 2), (1, 3), (0, 3)):
            A = GMUL[M[j2][i]][S[j]]
            A = A ^ A[:, :1]
            B = GMUL[M[j][i]][S[j2]]
            B = B ^ B[:, :1]
            rows = {}
            for gj in range(256):
                rows.setdefault(A[gj].tobytes(), set()).add(gj)
            pj, pj2 = set(), set()
            for gj2 in range(256):
                hit = rows.get(B[gj2].tobytes())
                if hit:
                    pj |= hit
                    pj2.add(gj2)
            for p, s in ((pos[j], pj), (pos[j2], pj2)):
                cands[p] = s if cands[p] is None else (cands[p] & s)
    if any(cs is None or len(cs) != 1 for cs in cands):
        return None, 0
    kappa = np.array([next(iter(cs)) for cs in cands], dtype=np.uint8)
    k2 = prim._mix_batch(kappa[None, :])[0] ^ RC1         # seed block 2
    s3 = (Y[0] ^ k2).tobytes()                           # h_1 of text 0
    s1_lo, s1_hi = prim.invert_generic(prim.FIXED_KEY, texts[0], s3)
    comps = [s1_lo, s1_hi,
             int.from_bytes(k2[:8].tobytes(), "little"),
             int.from_bytes(k2[8:].tobytes(), "little")]
    ok = sum(prim.chainhash_full(d, comps, rounds=2, discard=False).to_bytes(16, "little")
             == verify_query(d) for d in (os.urandom(DATA_LEN) for _ in range(4)))
    return comps, ok


def oracle_full(comps, rounds):
    def query(data: bytes) -> bytes:
        full = prim.chainhash_full(data, comps, rounds=rounds, discard=False)
        return full.to_bytes(16, "little")
    return query


def attack_inversion(query):
    """Attacker step: one pair -> candidate key block; verify on 4 fresh pairs."""
    d0 = os.urandom(DATA_LEN)
    cand = prim.peel_last(d0, query(d0))
    s0 = int.from_bytes(cand[:8], "little")
    s1 = int.from_bytes(cand[8:], "little")
    verified = all(
        prim.hash_generic(prim.FIXED_KEY, d, s0, s1) == query(d)
        for d in (os.urandom(DATA_LEN) for _ in range(4))
    )
    return cand, verified


def main():
    print("=" * 74)
    print("Inversion KEY-RECOVERY through ChainHash<AES-ITB-128>, discard off")
    print("=" * 74)
    for rounds in R_SET:
        hits = 0
        verified_n = 0
        for _ in range(TR):
            comps = random_comps(rounds)
            query = oracle_full(comps, rounds)
            cand, verified = attack_inversion(query)
            verified_n += verified
            # ground truth (report only): at r = 1 the candidate must equal
            # the seed block (seed_0 || seed_1)
            hits += verified and cand == prim.seed_block(comps[0], comps[1])
        tag = "RECOVERS key block" if hits >= TR - 1 else "fails (no key recovery)"
        print(f"  rounds={rounds:>2} {depth_label(rounds):>9}: verified {verified_n}/{TR}, "
              f"ground-truth match {hits}/{TR}  -> {tag}")
    print("-" * 74)
    print("discard on: no peel (hi lane hidden) -> 2^64 enumeration at every r; not run.")
    print("r=1 control recovers; r>=2 tests whether the feed-forward blocks the")
    print("inversion (the peeled block is seed_r ^ h_{r-1}, data-dependent).")

    print()
    print("=" * 74)
    print("Square KEY-RECOVERY on the peeled observable, discard off (1 Λ-set = 256 chosen texts)")
    print("=" * 74)
    for rounds in (2, 3, 4):
        hits = 0
        verified_n = 0
        for _ in range(TR):
            comps = random_comps(rounds)
            query = oracle_full(comps, rounds)
            cand, ok = square_recover_r2(query, query)
            verified_n += (ok == 4)
            # ground truth (report only): at r = 2 the candidate must equal comps[0:4]
            hits += (ok == 4) and cand == comps[:4]
        tag = "RECOVERS both seed blocks" if hits >= TR - 1 else "fails (no consistent candidate)"
        print(f"  rounds={rounds:>2} {depth_label(rounds):>9}: verified {verified_n}/{TR}, "
              f"ground-truth match {hits}/{TR}  -> {tag}")
    print("-" * 74)
    print("r=2: the peel leaves 3-round AES between two unknown whitenings and the")
    print("Λ-set survives to the last round (Square). r>=3: no Λ-set enters the peeled")
    print("permutation (its input is h_{r-2} ^ pad(data) ^ const), engine finds nothing.")


if __name__ == "__main__":
    main()
