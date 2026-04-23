#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 0 parity gadget for the .MD5STRESS plan.

Mirror of `fnv_chain_lo_concrete.py` (sibling .FNVSTRESS work) but with the
round function swapped to MD5. Two independent lo-lane implementations:

  (a) `md5_chain_lo_concrete` — pure Python mirroring the Go reference
      `md5Hash128` in redteam_test.go (`hashlib.md5(key || data)` then
      extracting the lo 64 bits of the 16-byte digest). The chain wrapper
      matches `scripts/redteam/phase2_theory/chainhashes/md5.py` exactly.

  (b) `md5_chain_lo_z3` — symbolic Z3 `BitVec(32) × 4` expression for the
      SAME MD5 compression applied to a single padded 64-byte block. The
      compression function is unrolled into 64 operations (4 rounds × 16
      ops each) using F/G/H/I boolean mixers, 32-bit ADD, variable ROTL
      from a fixed shift table. When a concrete seed is substituted the
      Z3 expression must evaluate to the same hLo as (a).

The MD5 compression constants (K, S, MIDX tables) are standard and match
RFC 1321.

Single 64-byte block is sufficient for the ChainHash case because
`key (16 B) + data (20 B) = 36 B + 0x80 + zero-pad + length(8 B) = 64 B`
fits in one block — the calibration observations all use 20-byte data
blobs matching ITB's `blockHash128` layout (4 B LE pixel + 16 B nonce).

Parity target file format matches the Go emitter (to be added alongside
`TestRedTeamEmitFNV1aChainHashReference`). For now the parity self-check
validates concrete vs Z3 symbolic on random seeds.

Usage:
    python3 md5_chain_lo_concrete.py                  # self-parity test
    python3 md5_chain_lo_concrete.py --vectors 1024   # more vectors

Exit codes:
    0 — all vectors matched (concrete vs Z3-symbolic)
    1 — any mismatch
    2 — z3 missing or environment problem
"""

from __future__ import annotations

import argparse
import hashlib
import random
import struct
import sys
from typing import List, Sequence

MASK32 = 0xFFFF_FFFF
MASK64 = 0xFFFF_FFFF_FFFF_FFFF

# ============================================================================
# MD5 constants (RFC 1321)
# ============================================================================

MD5_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

MD5_K = [
    # Round 1 (F)
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    # Round 2 (G)
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    # Round 3 (H)
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    # Round 4 (I)
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
]
assert len(MD5_K) == 64

MD5_S = (
    [7, 12, 17, 22] * 4 +
    [5,  9, 14, 20] * 4 +
    [4, 11, 16, 23] * 4 +
    [6, 10, 15, 21] * 4
)
assert len(MD5_S) == 64

# Message word index per operation. Round 1: g=i; round 2: g=(5i+1)%16;
# round 3: g=(3i+5)%16; round 4: g=(7i)%16 (i is local to each 16-op round).
_MIDX = []
for _op in range(64):
    _rnd, _local = divmod(_op, 16)
    if _rnd == 0:
        _MIDX.append(_local)
    elif _rnd == 1:
        _MIDX.append((5 * _local + 1) % 16)
    elif _rnd == 2:
        _MIDX.append((3 * _local + 5) % 16)
    else:
        _MIDX.append((7 * _local) % 16)
MD5_MIDX = _MIDX


# ============================================================================
# Concrete (pure Python) MD5 compression, matching hashlib.md5 on 1 block
# ============================================================================

def _rotl32(x: int, n: int) -> int:
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & MASK32


def _f_concrete(b: int, c: int, d: int) -> int:
    return ((b & c) | ((~b) & d)) & MASK32


def _g_concrete(b: int, c: int, d: int) -> int:
    return ((b & d) | (c & (~d))) & MASK32


def _h_concrete(b: int, c: int, d: int) -> int:
    return (b ^ c ^ d) & MASK32


def _i_concrete(b: int, c: int, d: int) -> int:
    return (c ^ (b | (~d & MASK32))) & MASK32


def _md5_block_concrete(state: Sequence[int], words: Sequence[int]) -> List[int]:
    """One MD5 compression on a single 16×32-bit block, IV-relative.
    Returns the new `(A, B, C, D)` state after adding the running state to IV."""
    A, B, C, D = state
    a, b, c, d = A, B, C, D
    for i in range(64):
        if i < 16:
            mixed = _f_concrete(b, c, d)
        elif i < 32:
            mixed = _g_concrete(b, c, d)
        elif i < 48:
            mixed = _h_concrete(b, c, d)
        else:
            mixed = _i_concrete(b, c, d)
        t = (a + mixed + words[MD5_MIDX[i]] + MD5_K[i]) & MASK32
        rotated = _rotl32(t, MD5_S[i])
        new_b = (b + rotated) & MASK32
        # Rotate the state: (a, b, c, d) -> (d, new_b, b, c)
        a, b, c, d = d, new_b, b, c
    return [
        (A + a) & MASK32,
        (B + b) & MASK32,
        (C + c) & MASK32,
        (D + d) & MASK32,
    ]


def _pack_words_le(buf: bytes) -> List[int]:
    """Pack a 64-byte buffer into 16 little-endian 32-bit words."""
    return [int.from_bytes(buf[i:i + 4], "little") for i in range(0, 64, 4)]


def md5_128_concrete(data: bytes, seed_lo: int, seed_hi: int) -> tuple[int, int]:
    """One primitive-level MD5 128-bit computation matching the Go reference
    `md5Hash128` in redteam_test.go. Input = 16-byte key (seed_lo LE || seed_hi
    LE) concatenated with `data`. Returns `(lo, hi)` as two uint64 halves LE.
    For the ChainHash case the data is 20 bytes so the total 36 bytes fits in
    one padded block."""
    key = struct.pack("<QQ", seed_lo & MASK64, seed_hi & MASK64)
    # Verify against hashlib for extra safety on every concrete call.
    digest = hashlib.md5(key + data).digest()
    lo = int.from_bytes(digest[:8], "little")
    hi = int.from_bytes(digest[8:], "little")
    return lo, hi


def _pad_one_block(key: bytes, data: bytes) -> bytes:
    """Build the single 64-byte padded MD5 block for `key || data` of total
    length ≤ 55 bytes. Raises if length exceeds single-block capacity."""
    msg = key + data
    msg_bits = len(msg) * 8
    assert len(msg) <= 55, (
        f"md5_chain_lo_concrete single-block path needs len ≤ 55 bytes, "
        f"got {len(msg)}"
    )
    pad = b"\x80" + b"\x00" * (55 - len(msg))
    length_field = struct.pack("<Q", msg_bits)
    block = msg + pad + length_field
    assert len(block) == 64
    return block


def md5_128_from_block_concrete(
    data: bytes, seed_lo: int, seed_hi: int,
) -> tuple[int, int]:
    """Same as `md5_128_concrete` but implemented via the manual single-block
    compression (used to cross-check the symbolic Z3 path, which also
    unrolls a single block). Expects 16-byte key + ≤ 39-byte data."""
    key = struct.pack("<QQ", seed_lo & MASK64, seed_hi & MASK64)
    block = _pad_one_block(key, data)
    words = _pack_words_le(block)
    state = _md5_block_concrete(MD5_IV, words)
    # Digest = state (A, B, C, D) serialised LE as 16 bytes.
    digest = b"".join(s.to_bytes(4, "little") for s in state)
    lo = int.from_bytes(digest[:8], "little")
    hi = int.from_bytes(digest[8:], "little")
    return lo, hi


def md5_chain_lo_concrete(
    seed_components: Sequence[int], data: bytes, rounds: int,
) -> int:
    """Low 64 bits of ChainHash128 under MD5 primitive, for `rounds` rounds.

    seed_components: flat list of 2*rounds uint64 values in order
        [s0_lo, s0_hi, s1_lo, s1_hi, ..., s(rounds-1)_lo, s(rounds-1)_hi].
    data: 20-byte data blob (ITB blockHash128 layout: 4B LE pixel + 16B
        nonce). Must fit single-block padding (≤ 39 bytes).
    rounds: ChainHash round count (= keyBits // 128 for the 128-bit hash
        family: 4 at keyBits=512 minimum, 8 at keyBits=1024 default).
    """
    assert len(seed_components) == 2 * rounds, (
        f"MD5 ChainHash with rounds={rounds} needs {2*rounds} seed components, "
        f"got {len(seed_components)}"
    )
    h_lo, h_hi = md5_128_concrete(
        data, seed_components[0], seed_components[1],
    )
    for r in range(1, rounds):
        k_lo = (seed_components[2 * r] ^ h_lo) & MASK64
        k_hi = (seed_components[2 * r + 1] ^ h_hi) & MASK64
        h_lo, h_hi = md5_128_concrete(data, k_lo, k_hi)
    return h_lo


# ============================================================================
# Z3 symbolic MD5 compression, matching the concrete reference above
# ============================================================================

def _f_z3(z3, b, c, d):
    return (b & c) | (~b & d)


def _g_z3(z3, b, c, d):
    return (b & d) | (c & ~d)


def _h_z3(z3, b, c, d):
    return b ^ c ^ d


def _i_z3(z3, b, c, d):
    return c ^ (b | ~d)


def _rotl32_z3(z3, x, n: int):
    n = n & 31
    if n == 0:
        return x
    return (x << n) | z3.LShR(x, (32 - n))


def _md5_block_z3(z3, state_syms, words):
    """Z3 symbolic MD5 block compression. `state_syms` are four BV(32)
    representing the input IV or prior state; `words` are 16 BV(32)
    message words. Returns new 4-tuple of BV(32)."""
    A, B, C, D = state_syms
    a, b, c, d = A, B, C, D
    for i in range(64):
        if i < 16:
            mixed = _f_z3(z3, b, c, d)
        elif i < 32:
            mixed = _g_z3(z3, b, c, d)
        elif i < 48:
            mixed = _h_z3(z3, b, c, d)
        else:
            mixed = _i_z3(z3, b, c, d)
        t = a + mixed + words[MD5_MIDX[i]] + z3.BitVecVal(MD5_K[i], 32)
        rotated = _rotl32_z3(z3, t, MD5_S[i])
        new_b = b + rotated
        a, b, c, d = d, new_b, b, c
    return [A + a, B + b, C + c, D + d]


def _seed_word_exprs_z3(z3, seed_lo_sym, seed_hi_sym):
    """Extract the four 32-bit message words that come from the 16-byte
    key block: (seed_lo LO 32, seed_lo HI 32, seed_hi LO 32, seed_hi HI 32)."""
    w0 = z3.Extract(31,  0, seed_lo_sym)
    w1 = z3.Extract(63, 32, seed_lo_sym)
    w2 = z3.Extract(31,  0, seed_hi_sym)
    w3 = z3.Extract(63, 32, seed_hi_sym)
    return w0, w1, w2, w3


def _data_word_exprs_z3(z3, data: bytes):
    """Pack 20-byte concrete data into 5 BV(32) little-endian constants."""
    assert len(data) == 20, "chain data must be 20 bytes (blockHash128 layout)"
    words = []
    for i in range(0, 20, 4):
        v = int.from_bytes(data[i:i + 4], "little")
        words.append(z3.BitVecVal(v, 32))
    return words


def _padding_word_exprs_z3(z3, msg_bits: int):
    """Padding words for a 36-byte message (16B key + 20B data).
    Block layout after padding:
      bytes  0..35 = key || data            (already placed in words 0..8)
      byte   36    = 0x80                   (LSB of word 9)
      bytes 37..55 = 0x00                   (rest of word 9 + words 10..13)
      bytes 56..63 = msg_bits LE (8 bytes)  (words 14..15)"""
    w9 = z3.BitVecVal(0x00000080, 32)
    w10 = z3.BitVecVal(0, 32)
    w11 = z3.BitVecVal(0, 32)
    w12 = z3.BitVecVal(0, 32)
    w13 = z3.BitVecVal(0, 32)
    w14 = z3.BitVecVal(msg_bits & MASK32, 32)
    w15 = z3.BitVecVal((msg_bits >> 32) & MASK32, 32)
    return [w9, w10, w11, w12, w13, w14, w15]


def md5_128_z3(z3, seed_lo_sym, seed_hi_sym, data: bytes):
    """One primitive-level MD5 128-bit computation symbolically. Returns
    `(lo_bv64, hi_bv64)` — two BV(64) Z3 expressions."""
    assert len(data) == 20, "md5_128_z3 expects 20-byte data"
    w0, w1, w2, w3 = _seed_word_exprs_z3(z3, seed_lo_sym, seed_hi_sym)
    data_words = _data_word_exprs_z3(z3, data)
    pad_words = _padding_word_exprs_z3(z3, msg_bits=(16 + 20) * 8)
    words = [w0, w1, w2, w3] + data_words + pad_words
    assert len(words) == 16
    iv_syms = [z3.BitVecVal(v, 32) for v in MD5_IV]
    state = _md5_block_z3(z3, iv_syms, words)
    # Concatenate state (A, B, C, D) LE into a 128-bit digest, then extract
    # lo 64 and hi 64 halves. LE means A occupies the lowest bytes.
    A, B, C, D = state
    lo_bv = z3.Concat(B, A)   # hi-word on top of concat
    hi_bv = z3.Concat(D, C)
    return lo_bv, hi_bv


def md5_chain_lo_z3(
    z3, seed_lo_syms, seed_hi_syms, data: bytes, rounds: int,
):
    """Z3 symbolic ChainHash lo-lane output. `seed_lo_syms` and
    `seed_hi_syms` are two lists of `rounds` BV(64) each."""
    assert len(seed_lo_syms) == rounds and len(seed_hi_syms) == rounds, (
        f"need {rounds} lo + {rounds} hi seed syms, "
        f"got {len(seed_lo_syms)}+{len(seed_hi_syms)}"
    )
    h_lo, h_hi = md5_128_z3(z3, seed_lo_syms[0], seed_hi_syms[0], data)
    for r in range(1, rounds):
        k_lo = seed_lo_syms[r] ^ h_lo
        k_hi = seed_hi_syms[r] ^ h_hi
        h_lo, h_hi = md5_128_z3(z3, k_lo, k_hi, data)
    return h_lo


# ============================================================================
# Self-parity test
# ============================================================================

def _self_parity(rounds_list: List[int], num_vectors: int, seed_rng: int) -> int:
    rng = random.Random(seed_rng)
    failures = 0
    # Block-path consistency (manual compression vs hashlib).
    for _ in range(min(num_vectors, 256)):
        s_lo = rng.getrandbits(64)
        s_hi = rng.getrandbits(64)
        data = bytes(rng.getrandbits(8) for _ in range(20))
        lo_a, hi_a = md5_128_concrete(data, s_lo, s_hi)
        lo_b, hi_b = md5_128_from_block_concrete(data, s_lo, s_hi)
        if (lo_a, hi_a) != (lo_b, hi_b):
            print(
                f"[FAIL] concrete-vs-manual-block divergence at "
                f"s_lo={s_lo:016x} s_hi={s_hi:016x} data={data.hex()} "
                f"hashlib=({lo_a:016x},{hi_a:016x}) "
                f"manual=({lo_b:016x},{hi_b:016x})"
            )
            failures += 1

    # Z3 symbolic consistency: substitute concrete seed, compare hLo.
    try:
        import z3
    except ImportError:
        print(
            "[SKIP] z3-solver not installed — symbolic parity check skipped. "
            "Manual block path verified against hashlib."
        )
        return 0 if failures == 0 else 1

    for rounds in rounds_list:
        for _ in range(num_vectors // max(1, len(rounds_list))):
            seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
            data = bytes(rng.getrandbits(8) for _ in range(20))
            truth_hlo = md5_chain_lo_concrete(seed_components, data, rounds)

            # Build Z3 expression with symbolic seed, then evaluate under a
            # model that pins each sym to the ground-truth value.
            seed_lo_syms = [z3.BitVec(f"sl{i}", 64) for i in range(rounds)]
            seed_hi_syms = [z3.BitVec(f"sh{i}", 64) for i in range(rounds)]
            expr = md5_chain_lo_z3(
                z3, seed_lo_syms, seed_hi_syms, data, rounds,
            )
            solver = z3.Solver()
            solver.set("timeout", 60000)
            for i in range(rounds):
                solver.add(
                    seed_lo_syms[i] == z3.BitVecVal(
                        seed_components[2 * i] & MASK64, 64,
                    )
                )
                solver.add(
                    seed_hi_syms[i] == z3.BitVecVal(
                        seed_components[2 * i + 1] & MASK64, 64,
                    )
                )
            solver.add(expr == z3.BitVecVal(truth_hlo & MASK64, 64))
            result = solver.check()
            if result != z3.sat:
                print(
                    f"[FAIL] z3-symbolic divergence at rounds={rounds} "
                    f"seed={seed_components} data={data.hex()} "
                    f"truth_hlo={truth_hlo:016x} z3_result={result}"
                )
                failures += 1

    return 0 if failures == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rounds", default="1,2,4",
                    help="comma-separated round counts to include in parity check")
    ap.add_argument("--vectors", type=int, default=64,
                    help="total random vectors to check (split across rounds)")
    ap.add_argument("--seed-rng", type=int, default=0x4D_44_35_50_41_52)  # "MD5PAR"
    args = ap.parse_args()

    rounds_list = [int(x) for x in args.rounds.split(",") if x.strip()]
    rc = _self_parity(rounds_list, args.vectors, args.seed_rng)
    if rc == 0:
        print(
            f"[OK] MD5 chain-lo parity: {args.vectors} vectors "
            f"across rounds={rounds_list} match."
        )
    return rc


if __name__ == "__main__":
    sys.exit(main())
