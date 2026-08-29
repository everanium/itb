#!/usr/bin/env python3
"""BEA-1 partition trapdoor — derives and verifies the hidden linear partition
directly from the published S-boxes and linear map M (no external secret).

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The S-boxes and linear map M consumed here come from `bea1_tables.py`, a
CLEAN-ROOM transcription of the published constant tables (no reference code
vendored). This module re-derives the designer's partition trapdoor from
those public constants alone.

Defensive framing
------------------
Part of a positive-control demonstration that ITB's ChainHash feedforward
neutralises even a deliberately-backdoored inner primitive (a lab control, not
for deployment). The trapdoor is real and published; deriving it here gives
the partition the attack runners exploit at ChainHash rounds=1.

What this module shows about the *published* BEA-1 constants
------------------------------------------------------------
1.  Linear bias above the stated bound. The paper states the S-boxes are
    "linearly 128-uniform" (max |LAT| <= 128, correlation 1/8). The
    transcribed S-boxes have max |LAT| = 256 (S0, S1, S2) / 252 (S3), i.e.
    correlation 1/4 — twice the stated bound. This excess is the trapdoor.

2.  Per-S-box mask subspaces. For each S-box S_k the set of strongly-biased
    linear masks (|LAT| >= 192) is exactly the set of nonzero vectors of a
    5-dimensional INPUT-mask subspace A_k and a 5-dimensional OUTPUT-mask
    subspace B_k (31 = 2^5 - 1 nonzero masks each).

3.  Coset partition. Define V_k = A_k^perp and W_k = B_k^perp, both 5-dim in
    F_2^10. Each S-box maps V_k-cosets to W_k-cosets with probability ~0.85
    (an exact map would be p=1; a random S-box would give p ~ |W|/1024 ~ 0.03).

4.  Linear-layer compatibility. MixColumns M maps the product partition
    (W_0 x W_1 x W_2 x W_3) EXACTLY (probability 1) onto
    (V_0 x V_1 x V_2 x V_3). This co-design lets the per-bundle partitions
    chain through the whole SPN: a 40-dimensional space of linear masks is
    closed under one full round (Sub then ShiftRows then MixColumns).

Together these constitute the partition-based trapdoor of Bannier-Bodin-Filiol:
a hidden, high-probability linear partition the designer can exploit, while the
cipher still passes generic differential / linear-uniformity checks. This
module derives all of the above from the constants and asserts each fact.
"""
import numpy as np
from bea1_tables import S0, S1, S2, S3, M_BITS
import bea1 as B

SB = (S0, S1, S2, S3)
STRONG_THRESHOLD = 192  # |LAT| cutoff that isolates the trapdoor masks (max is 256)


# ---------- GF(2) helpers ----------
def parity(v):
    return bin(v).count("1") & 1


def span_basis(vals):
    basis = []
    for v in vals:
        cur = v
        for b in basis:
            lead = b.bit_length() - 1
            if (cur >> lead) & 1:
                cur ^= b
        if cur:
            basis.append(cur)
            basis.sort(reverse=True)
    return basis


def span_set(basis):
    s = {0}
    for b in basis:
        s |= {e ^ b for e in s}
    return s


def fwht(a):
    a = a.copy().astype(np.int64)
    h = 1
    n = len(a)
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                u = a[j]
                v = a[j + h]
                a[j] = u + v
                a[j + h] = u - v
        h *= 2
    return a


def perp10(basis5):
    """Orthogonal complement (in F_2^10) of the subspace spanned by basis5."""
    return set(v for v in range(1024)
               if all(parity(a & v) == 0 for a in basis5))


# ---------- trapdoor derivation ----------
def strong_masks(S, thresh=STRONG_THRESHOLD):
    """Return list of (a, b, LAT) with |LAT| >= thresh for one S-box."""
    out = []
    for b in range(1, 1024):
        t = np.array([1 - 2 * (parity(b & S[x])) for x in range(1024)], dtype=np.int64)
        W = fwht(t)
        for a in range(1024):
            if abs(int(W[a])) >= thresh:
                out.append((a, b, int(W[a])))
    return out


def derive_trapdoor():
    """Derive per-S-box mask subspaces A_k, B_k and partition subspaces V_k, W_k."""
    A_basis, B_basis = [], []
    max_lat = []
    for S in SB:
        sm = strong_masks(S)
        a_set = sorted({a for a, b, w in sm})
        b_set = sorted({b for a, b, w in sm})
        A_basis.append(span_basis(a_set))
        B_basis.append(span_basis(b_set))
        max_lat.append(max(abs(w) for _, _, w in sm))
    V = [perp10(A_basis[k]) for k in range(4)]
    W = [perp10(B_basis[k]) for k in range(4)]
    return dict(A_basis=A_basis, B_basis=B_basis, V=V, W=W, max_lat=max_lat)


def M_col(v40):
    a, b, c, d = [(v40 >> (10 * i)) & 0x3FF for i in range(4)]
    r = B.M(a, b, c, d)
    return sum((r[i] & 0x3FF) << (10 * i) for i in range(4))


def verify(td, verbose=True):
    A_basis, B_basis, V, W = td["A_basis"], td["B_basis"], td["V"], td["W"]
    ok = True

    def log(*a):
        if verbose:
            print(*a)

    # 1. excess linear bias
    log("1. Max |LAT| per S-box (paper claims <=128):", td["max_lat"])
    ok &= all(m > 128 for m in td["max_lat"])

    # 2. mask subspace dimensions
    for k in range(4):
        da, db = len(A_basis[k]), len(B_basis[k])
        log(f"2. S{k}: strong input-mask subspace dim={da}, output-mask subspace dim={db}")
        ok &= (da == 5 and db == 5)

    # 3. per-S-box coset preservation probability
    for k in range(4):
        S = SB[k]
        Vl = sorted(V[k])
        Wset = set(W[k])
        good = tot = 0
        for x in range(1024):
            for v in Vl:
                tot += 1
                if (S[x ^ v] ^ S[x]) in Wset:
                    good += 1
        p = good / tot
        log(f"3. S{k}: P[S maps V{k}-coset within W{k}-coset] = {p:.4f}")
        ok &= (p > 0.75)  # far above random ~0.031

    # 4. MixColumns maps W-product partition EXACTLY onto V-product partition
    Wprod_basis = []
    Vprod_basis = []
    for j in range(4):
        for g in span_basis(sorted(W[j] - {0})):
            Wprod_basis.append(g << (10 * j))
        for g in span_basis(sorted(V[j] - {0})):
            Vprod_basis.append(g << (10 * j))
    img = span_basis([M_col(g) for g in Wprod_basis])
    exact = span_set(img) == span_set(Vprod_basis)
    log(f"4. dim W-product={len(Wprod_basis)}, dim M(W-product)={len(img)}, "
        f"M(W-product) == V-product : {exact}")
    ok &= exact and len(Wprod_basis) == 20 and len(img) == 20

    log("\nTRAPDOOR VERIFIED" if ok else "\nTRAPDOOR VERIFICATION FAILED")
    return ok


if __name__ == "__main__":
    td = derive_trapdoor()
    verify(td)
