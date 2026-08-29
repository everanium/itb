#!/usr/bin/env python3
"""2x BEA-1 parallel-lane ChainHash wrap with an 80->64-bit per-lane truncation
and an optional multi-round feedforward.

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The cipher and constants are a CLEAN-ROOM reimplementation transcribed from the
published paper (no reference code vendored). This module mirrors how ITB's
ChainHash packs an 80-bit-native primitive into a 64-bit lane and widens a short
seed into independently-keyed round-seeds with feedforward — the mechanism the
positive-control experiments exercise against the BEA-1 trapdoor. A lab control,
not for deployment.

Two independent BEA-1 instances run in parallel under two seeds (seed0 = lo
lane, seed1 = hi lane). Each produces an 80-bit ciphertext that is truncated to
64 bits before being packed into the ChainHash output.

At rounds=1 the ChainHash output is exactly this single keyed-hash call (NO
feedforward). The feedforward (rounds>=2) construction is defined further down.

Block / truncation convention
------------------------------
A BEA-1 block is 8 bundles of 10 bits (bea1.block_to_bytes):

    v80 = sum_i  bundle[i] << (10 * (7 - i))      # big-endian, bundle 0 = MSBs

so bundle 0 occupies bits [70..79], ..., bundle 7 occupies bits [0..9].

`truncate80to64` keeps the LOW 64 bits (bits 0..63) and drops the TOP 16 bits
(bits 64..79). In bundle terms that means:

    bundle 0 (bits 70..79) -- DROPPED in full   (10 bits lost)
    bundle 1 (bits 60..69) -- SPLIT: bits 64..69 (top 6) dropped,
                                       bits 60..63 (low 4) survive
    bundles 2..7 (bits 0..59) -- SURVIVE in full

Result is a single uint64 = v80 & ((1<<64) - 1).
"""
import bea1 as B

MASK10 = 0x3FF
MASK64 = (1 << 64) - 1


def block_to_uint80(x):
    """8 bundles -> 80-bit integer (same packing as bea1.block_to_bytes)."""
    v = 0
    for i in range(8):
        v |= (x[i] & MASK10) << (10 * (7 - i))
    return v


def truncate80to64(v80):
    """Keep low 64 bits (bits 0..63), drop the top 16 (bits 64..79)."""
    return v80 & MASK64


def bea1_lane(seed, data, round_keys=None):
    """One BEA-1 lane: encrypt `data` (8 bundles) under `seed` (12 bundles),
    pack to 80 bits, truncate to the low 64 bits."""
    c = B.encrypt(seed, data, round_keys)
    return truncate80to64(block_to_uint80(c))


def chainhash_r1(seed0, seed1, data, rk0=None, rk1=None):
    """2x BEA-1 ChainHash at rounds=1 (no feedforward).

    Returns (lo64, hi64):
        lo64 = truncate80to64(BEA1_encrypt(seed0, data))
        hi64 = truncate80to64(BEA1_encrypt(seed1, data))

    Per the ITB encoder's hi-lane discard, an attacker observes only `lo64`.
    """
    lo64 = bea1_lane(seed0, data, rk0)
    hi64 = bea1_lane(seed1, data, rk1)
    return lo64, hi64


# ----- multi-round ChainHash feedforward (rounds >= 2) -----
#
# ITB's ChainHash widens a short master seed into r independently-keyed BEA-1
# round-seeds and feeds the previous lane output forward into the next round's
# key.  Per lane (the lo lane the attacker observes is built exactly as below;
# the hi lane is the same construction under an independent seed list, and is
# discarded by the ITB encoder):
#
#     r = 1:  lo_1 = trunc80to64( BEA1( key = seed[0],                      data ) )
#     r >= 2: lo_k = trunc80to64( BEA1( key = seed[k-1] XOR extend120(lo_{k-1}), data ) )
#
# `seed[0..R-1]` are R independent 120-bit BEA-1 keys (the widened ChainHash
# seed list).  `extend120(x64)` injects the 64-bit feedforward into the 120-bit
# key.  CONVENTION (documented here, single source of truth):
#
#     extend120 places the 64-bit feedforward into the LOW 64 bits of the
#     120-bit BEA-1 key, i.e. into key bundles 5..11 (bundle 11 = bits 0..9,
#     ..., bundle 6 = bits 50..59, bundle 5 = bits 60..63 low 4 bits).  The
#     top 56 bits of the key (bundles 0..4 and the top 6 bits of bundle 5) are
#     left as seed[k-1]'s own bits.  This mirrors ITB placing the feedforward
#     into the low-order part of the next round's seed material.
#
# The feedforward is in the FULL 80-bit (here 120-bit key) space: lo_{k-1}
# depends on `data`, so the effective last-round key seed[k-1] XOR extend(lo_{k-1})
# is data-dependent.  That is the property the partition attack cannot survive.

MASK120 = (1 << 120) - 1


def key_to_uint120(seed):
    """12 bundles -> 120-bit integer (same packing as bea1.key_to_bytes)."""
    v = 0
    for i in range(12):
        v |= (seed[i] & MASK10) << (10 * (11 - i))
    return v


def uint120_to_key(v):
    """120-bit integer -> 12-bundle key tuple (inverse of key_to_uint120)."""
    return tuple((v >> (10 * (11 - i))) & MASK10 for i in range(12))


def extend120(x64):
    """Inject a 64-bit feedforward value into the LOW 64 bits of a 120-bit key
    space.  Returns a 120-bit integer whose low 64 bits are x64 and whose top
    56 bits are zero (so XOR-ing leaves seed[k-1]'s top 56 bits untouched)."""
    return x64 & MASK64


def chainhash_r_lane(seed_list, data, R):
    """One lane of the R-round ChainHash feedforward.

    seed_list : list of >= R independent 120-bit BEA-1 keys (12-bundle tuples).
    data      : 8-bundle BEA-1 input block (the chosen data).
    R         : number of rounds (>= 1).

    Returns the final truncated 64-bit lo value lo_R that an attacker observes.
    """
    if R < 1:
        raise ValueError("R must be >= 1")
    if len(seed_list) < R:
        raise ValueError("seed_list must contain at least R seeds")
    lo = None
    for k in range(R):
        if k == 0:
            eff_key = seed_list[0]
        else:
            # effective key = seed[k-1] XOR extend120(lo_{k-1})  (in 120-bit space)
            eff_v = key_to_uint120(seed_list[k - 1]) ^ extend120(lo)
            eff_key = uint120_to_key(eff_v & MASK120)
        lo = bea1_lane(eff_key, data)
    return lo


def effective_last_round_key(seed_list, data, R):
    """LAB-ONLY instrumentation: the effective BEA-1 key fed to the LAST round
    of the R-round chain for a given `data`.  For R=1 this is just seed[0]; for
    R>=2 it is seed[R-1] XOR extend120(lo_{R-1}), which depends on `data` through
    lo_{R-1}.  Used by the instrumentation in exp3_chainhash_feedforward.py to
    MEASURE the data-dependence of the effective last-round key (not an attack
    input)."""
    if R == 1:
        return tuple(seed_list[0])
    lo = None
    for k in range(R - 1):
        if k == 0:
            eff_key = seed_list[0]
        else:
            eff_v = key_to_uint120(seed_list[k - 1]) ^ extend120(lo)
            eff_key = uint120_to_key(eff_v & MASK120)
        lo = bea1_lane(eff_key, data)
    eff_v = key_to_uint120(seed_list[R - 2]) ^ extend120(lo)
    return uint120_to_key(eff_v & MASK120)


def chainhash_r(seed_list_lo, seed_list_hi, data, R):
    """R-round 2x-BEA-1 ChainHash with feedforward.

    seed_list_lo / seed_list_hi : lists of >= R independent 120-bit seeds for
        the lo and hi lanes respectively.
    data : 8-bundle BEA-1 input block.
    R    : number of rounds (1..4 used by the experiment).

    Returns (lo64, hi64); the ITB encoder exposes only lo64 to the attacker.
    At R=1 this reduces exactly to chainhash_r1(seed_list_lo[0], seed_list_hi[0], data).
    """
    lo64 = chainhash_r_lane(seed_list_lo, data, R)
    hi64 = chainhash_r_lane(seed_list_hi, data, R)
    return lo64, hi64


if __name__ == "__main__":
    import random
    rng = random.Random(0xBEA1)
    # Demonstrate the bundle layout under truncation on a few random blocks.
    print("bundle bit-ranges under 80->64 low-truncation:")
    for i in range(8):
        lo = 10 * (7 - i)
        hi = lo + 9
        tag = "DROPPED" if lo >= 64 else ("SPLIT (low 4 bits survive)" if hi >= 64 else "survives")
        print(f"  bundle {i}: bits [{lo:2d}..{hi:2d}]  {tag}")

    seed0 = tuple(rng.randrange(1024) for _ in range(12))
    seed1 = tuple(rng.randrange(1024) for _ in range(12))
    data = [rng.randrange(1024) for _ in range(8)]
    lo, hi = chainhash_r1(seed0, seed1, data)
    full = block_to_uint80(B.encrypt(seed0, data))
    print(f"\nlo64 = {lo:016x}  (full80 = {full:020x})")
    print(f"low-64 of full80 == lo64 : {(full & MASK64) == lo}")
    print(f"top-16 dropped           : {full >> 64:04x}")
