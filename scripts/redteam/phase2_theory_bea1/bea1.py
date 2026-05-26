#!/usr/bin/env python3
"""BEA-1 block cipher — clean-room reimplementation from the published spec.

BEA-1 is a deliberately-backdoored block cipher: 80-bit block, 120-bit key,
11 rounds, AES-like SPN operating on 8 bundles of 10 bits each (elements of
(F_2^10)^8). Its design carries a partition-based mathematical trapdoor that
lets the designer recover the key with chosen plaintexts while the cipher
still passes generic differential / linear uniformity checks.

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The cipher and every constant table here are a CLEAN-ROOM reimplementation
transcribed from the published paper (Algorithms 1 / 2 / 3 and Appendix
Figures 3 / 4 / 5). No reference code was vendored. Constants live in
`bea1_tables.py`.

Defensive framing
-----------------
This module is part of a positive-control demonstration: ITB's ChainHash
feedforward neutralises even a deliberately-backdoored inner primitive. It is
a lab control, not for deployment — analogous in role to the below-spec
CRC128 / FNV-1a controls, but using a primitive with a real, published,
working key-recovery trapdoor instead of a merely below-spec hash. Results
reported by the experiment runners are bounded to the tested parameters and
budgets; they are demonstrations, not security proofs.

State / key representation
--------------------------
A block is a list of 8 ints in [0, 1024): (x0, x1, ..., x7). The master key K
is a tuple of 12 ints in [0, 1024): (K0, ..., K11). A round key kr is a list
of 8 ints.

MixColumns uses the linear map M : (F_2^10)^4 -> (F_2^10)^4, stored as a
basis-image table over 40-bit vectors (bundle i in bits 10i..10i+9).
"""
from bea1_tables import S0, S1, S2, S3, M_BITS, MINV_BITS

SBOX = (S0, S1, S2, S3)

# Build inverse S-boxes.
def _inv(s):
    inv = [0] * 1024
    for x, y in enumerate(s):
        inv[y] = x
    return tuple(inv)

SBOX_INV = tuple(_inv(s) for s in SBOX)

MASK10 = 0x3FF


# ----- linear map M over four bundles -----
def _bundles4_to_int(a, b, c, d):
    return (a & MASK10) | ((b & MASK10) << 10) | ((c & MASK10) << 20) | ((d & MASK10) << 30)


def _int_to_bundles4(v):
    return (v & MASK10, (v >> 10) & MASK10, (v >> 20) & MASK10, (v >> 30) & MASK10)


def _apply_linear(bits, v):
    """Apply the 40x40 GF(2) map (given as basis-image table) to 40-bit v."""
    y = 0
    b = 0
    while v:
        if v & 1:
            y ^= bits[b]
        v >>= 1
        b += 1
    return y


def M(a, b, c, d):
    return _int_to_bundles4(_apply_linear(M_BITS, _bundles4_to_int(a, b, c, d)))


def Minv(a, b, c, d):
    return _int_to_bundles4(_apply_linear(MINV_BITS, _bundles4_to_int(a, b, c, d)))


# ----- key schedule (Algorithm 1) -----
def expand_key(K):
    """K: 12-tuple of 10-bit ints. Returns list of 12 round keys, each an
    8-list of 10-bit ints (k0..k11)."""
    if len(K) != 12:
        raise ValueError("master key must be 12 bundles")
    # k is the working array of bundle-keys; index k[12i+j] per the algorithm.
    # We need indices up to 12*6+23 = 95, so allocate 96.
    k = [0] * 96
    for j in range(12):
        k[j] = K[j] & MASK10
    for i in range(7):
        # x <- M(k[12i+8..12i+11])
        base = 12 * i
        x = list(M(k[base + 8], k[base + 9], k[base + 10], k[base + 11]))
        # x <- (Sj(xj))_{0<=j<=3}
        x = [SBOX[j][x[j]] for j in range(4)]
        # x <- (x0 ^ (3^i mod 2^10), x1, x2, x3)   [round constant]
        x[0] ^= pow(3, i, 1024)
        # (k[12i+12..15]) <- (k[12i+0..3]) ^ x
        for j in range(4):
            k[base + 12 + j] = k[base + 0 + j] ^ x[j]
        # (k[12i+16..19]) <- (k[12i+4..7]) ^ (k[12i+12..15])
        for j in range(4):
            k[base + 16 + j] = k[base + 4 + j] ^ k[base + 12 + j]
        # (k[12i+20..23]) <- (k[12i+8..11]) ^ (k[12i+16..19])
        for j in range(4):
            k[base + 20 + j] = k[base + 8 + j] ^ k[base + 16 + j]
    # kr <- (k[8r+i])_{0<=i<=7}
    round_keys = []
    for r in range(12):
        round_keys.append([k[8 * r + i] for i in range(8)])
    return round_keys


# ----- round components -----
def _sub_bundles(x):
    return [SBOX[i % 4][x[i]] for i in range(8)]


def _inv_sub_bundles(x):
    return [SBOX_INV[i % 4][x[i]] for i in range(8)]


def _shift_rows(x):
    # (x0, x5, x2, x7, x4, x1, x6, x3)  -- involution
    return [x[0], x[5], x[2], x[7], x[4], x[1], x[6], x[3]]


# _shift_rows is its own inverse (involution).
_inv_shift_rows = _shift_rows


def _mix_columns(x):
    a = M(x[0], x[1], x[2], x[3])
    b = M(x[4], x[5], x[6], x[7])
    return [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]


def _inv_mix_columns(x):
    a = Minv(x[0], x[1], x[2], x[3])
    b = Minv(x[4], x[5], x[6], x[7])
    return [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]]


def _add_round_key(x, kr):
    return [x[i] ^ kr[i] for i in range(8)]


# ----- encrypt / decrypt (Algorithms 2 & 3) -----
def encrypt(K, p, round_keys=None):
    k = round_keys if round_keys is not None else expand_key(K)
    x = list(p)
    for r in range(10):
        x = _add_round_key(x, k[r])
        x = _sub_bundles(x)
        x = _shift_rows(x)
        x = _mix_columns(x)
    x = _add_round_key(x, k[10])
    x = _sub_bundles(x)
    x = _shift_rows(x)
    x = _add_round_key(x, k[11])
    return x


def decrypt(K, c, round_keys=None):
    k = round_keys if round_keys is not None else expand_key(K)
    x = list(c)
    x = _add_round_key(x, k[11])
    x = _inv_shift_rows(x)
    x = _inv_sub_bundles(x)
    x = _add_round_key(x, k[10])
    for r in range(9, -1, -1):
        x = _inv_mix_columns(x)
        x = _inv_shift_rows(x)
        x = _inv_sub_bundles(x)
        x = _add_round_key(x, k[r])
    return x


# ----- (de)serialisation helpers: 80-bit block <-> 8 bundles, 120-bit key -----
def block_from_bytes(b):
    """10 bytes -> 8 bundles of 10 bits (big-endian bit packing, bundle 0 = MSBs)."""
    if len(b) != 10:
        raise ValueError("block must be 10 bytes")
    v = int.from_bytes(b, "big")  # 80-bit integer
    out = [0] * 8
    for i in range(8):
        out[i] = (v >> (10 * (7 - i))) & MASK10
    return out


def block_to_bytes(x):
    v = 0
    for i in range(8):
        v |= (x[i] & MASK10) << (10 * (7 - i))
    return v.to_bytes(10, "big")


def key_from_bytes(b):
    if len(b) != 15:
        raise ValueError("key must be 15 bytes")
    v = int.from_bytes(b, "big")  # 120-bit
    return tuple(((v >> (10 * (11 - i))) & MASK10) for i in range(12))


def key_to_bytes(K):
    v = 0
    for i in range(12):
        v |= (K[i] & MASK10) << (10 * (11 - i))
    return v.to_bytes(15, "big")


if __name__ == "__main__":
    import random
    # consistency: S-boxes bijective, M.Minv = I (re-checked here too)
    for k in range(4):
        assert sorted(SBOX[k]) == list(range(1024))
        assert all(SBOX_INV[k][SBOX[k][x]] == x for x in range(1024))
    for _ in range(1000):
        a, b, c, d = (random.randrange(1024) for _ in range(4))
        assert Minv(*M(a, b, c, d)) == (a, b, c, d)
    # encrypt/decrypt roundtrip
    bad = 0
    for _ in range(2000):
        K = tuple(random.randrange(1024) for _ in range(12))
        p = [random.randrange(1024) for _ in range(8)]
        c = encrypt(K, p)
        d = decrypt(K, c)
        if d != p:
            bad += 1
    print("encrypt/decrypt roundtrip failures:", bad, "/ 2000")
    print("all internal consistency checks passed" if bad == 0 else "FAILED")
