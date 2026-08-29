#!/usr/bin/env python3
"""Correctness gate for the clean-room BEA-1 implementation (bea1.py).

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The cipher under test is a CLEAN-ROOM reimplementation transcribed from the
published paper (no reference code vendored); it serves as a positive-control
lab primitive, not for deployment. The arXiv / SciTePress papers publish the
full algorithm and constant tables but NO explicit numeric test vector (the
authors deliberately withheld worked examples as part of their public
challenge). The correctness gate is therefore:
  (a) S-box bijectivity (each is a permutation of the 1024 elements of F_2^10),
  (b) S o S^-1 = identity for all four S-boxes,
  (c) M o M^-1 = identity over GF(2) (the linear map transcription),
  (d) Encrypt then Decrypt = identity on random (key, plaintext) pairs,
  (e) byte<->bundle (de)serialisation round-trips.
"""
import random
import bea1 as B


def main():
    ok = True

    # (a),(b) S-boxes
    for k in range(4):
        S = B.SBOX[k]
        assert len(S) == 1024
        bij = sorted(S) == list(range(1024))
        inv = all(B.SBOX_INV[k][S[x]] == x for x in range(1024))
        print(f"S{k}: bijection over 1024 elems = {bij}; S o S^-1 = id : {inv}")
        ok &= bij and inv

    # (c) M . Minv = identity
    mok = True
    for _ in range(5000):
        a, b, c, d = (random.randrange(1024) for _ in range(4))
        if B.Minv(*B.M(a, b, c, d)) != (a, b, c, d):
            mok = False
            break
    print(f"M . M^-1 = identity (5000 random vectors): {mok}")
    ok &= mok

    # (d) encrypt/decrypt involution
    bad = 0
    NT = 5000
    for _ in range(NT):
        K = tuple(random.randrange(1024) for _ in range(12))
        p = [random.randrange(1024) for _ in range(8)]
        if B.decrypt(K, B.encrypt(K, p)) != p:
            bad += 1
    print(f"Decrypt(Encrypt(p)) == p : {NT - bad}/{NT}")
    ok &= (bad == 0)

    # (e) serialisation round-trips
    sok = True
    for _ in range(2000):
        kb = bytes(random.randrange(256) for _ in range(15))
        pb = bytes(random.randrange(256) for _ in range(10))
        if B.key_to_bytes(B.key_from_bytes(kb)) != kb:
            sok = False
            break
        if B.block_to_bytes(B.block_from_bytes(pb)) != pb:
            sok = False
            break
    print(f"byte<->bundle (de)serialisation round-trips: {sok}")
    ok &= sok

    print("\nBEA-1 IMPLEMENTATION VALIDATED" if ok else "\nVALIDATION FAILED")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)
