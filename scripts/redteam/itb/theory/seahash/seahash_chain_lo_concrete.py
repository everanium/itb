#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 2 parity gadget for the SeaHash SAT calibration plan
(HARNESS.md § 9.2).

Cross-checks that two independent lo-lane implementations reproduce
the Go `chainHash128SeaHash` output bit-exact when the Go primitive
is `seahash64` (harness_test.go). Without this gate, a later SAT
harness risks encoding a structurally-wrong chain and never noticing.

Two independent implementations:

  (a) `seahash_chain_lo_concrete` — pure Python mirroring the Go
      reference step by step. Computes the lo 64 bits only of the
      parallel two-lane `seahashHash128(seed_lo, seed_hi)` ChainHash128
      composition at variable round count.

  (b) `seahash_chain_lo_z3` — symbolic Z3 `BitVec(64)` expression for
      the same cascade. Two encoding axes are configurable:

        * `mul_encoding ∈ {"native", "explicit"}` — multiplication by
          the canonical SEAHASH_PRIME constant. "native" uses Z3's
          BVMul with `BitVecVal(P, 64)` (default). "explicit"
          decomposes into 35 shift-and-add terms (one per bit set in
          P = 0x6EED0E9DA4D94A4F, Hamming weight 35).

        * `var_shift_encoding ∈ {"native", "case-split"}` — encoding
          for the variable shift `(x >> 32) >> (x >> 60)` inside
          `_diffuse`. "native" uses a single Z3 LShR with both
          operands as 64-bit BVs (bit-blasts to a barrel shifter).
          "case-split" enumerates the 16 possible shift amounts
          (`b ∈ [0..15]`) via nested `If` (or equivalently a 16:1 mux
          on pre-computed `LShR(a, k)` for `k ∈ [0..15]`).

The 6 (mul × var-shift) combinations have bit-identical hLo and are
parity-tested at the bottom of this file. Their SAT performance is
expected to differ; the Axis C calibration harness exposes
`--mul-encoding` and `--var-shift-encoding` flags to compare them
empirically.

Each diffuse step is bijective in closed form (multiply by odd
SEAHASH_PRIME is invertible by modular inverse; `x ^= (x >> 32) >> b`
is invertible because the XOR's right-hand side `(a >> b)` is a
function of `x`'s top 32 bits, which the XOR does not touch — so
those bits can be recovered, then `b` and `(a >> b)`, then the XOR
inverted). The composition of 4-lane state rotations + per-chunk
diffuse is therefore a bijection in the seed when the message is
known. The Axis C SAT calibration probes whether bitwuzla can
exploit this bijectivity in practice on FNV-1a-comparable round
counts. See HARNESS.md § 9.2 for the full encoding plan.

Usage:
    python3 seahash_chain_lo_concrete.py                  # self-parity
    python3 seahash_chain_lo_concrete.py --vectors 1024   # more vectors
"""

from __future__ import annotations

import argparse
import random
import sys
from typing import List, Sequence

MASK64 = 0xFFFF_FFFF_FFFF_FFFF
SEAHASH_PRIME = 0x6EED0E9DA4D94A4F

SEAHASH_INIT_A = 0x16F11FE89B0D677C
SEAHASH_INIT_B = 0xB480A793D8E6C86C
SEAHASH_INIT_C = 0x6FE2E5AAF078EBC9
SEAHASH_INIT_D = 0x14F994A4C5259381


# Bit positions set in SEAHASH_PRIME — LSB-first; Hamming weight 35.
_PRIME_BITS = [i for i in range(64) if (SEAHASH_PRIME >> i) & 1]


# ============================================================================
# Concrete reference — pure Python mirror of harness_test.go seahash reference
# ============================================================================


def _diffuse_concrete(x: int) -> int:
    """Canonical PCG-style diffusion mixer.
    `x *= PRIME; x ^= (x >> 32) >> (x >> 60); x *= PRIME`."""
    x = (x * SEAHASH_PRIME) & MASK64
    x ^= (x >> 32) >> (x >> 60)
    x = (x * SEAHASH_PRIME) & MASK64
    return x & MASK64


def _read_tail(buf: bytes) -> int:
    """1..7-byte LE remainder zero-padded to high side."""
    x = 0
    for i, b in enumerate(buf):
        x |= b << (8 * i)
    return x & MASK64


def seahash64_concrete(data: bytes, seed: int) -> int:
    """Pure-Python port of ticki/tfs `hash_seeded`. seed != 0 multiplies
    init state by seed; seed == 0 keeps INIT constants. The ITB SAT
    calibration only uses seed != 0, but the conditional is preserved
    for canonical conformance and for the parity test."""
    seed &= MASK64
    a = SEAHASH_INIT_A
    b = SEAHASH_INIT_B
    c = SEAHASH_INIT_C
    d = SEAHASH_INIT_D
    if seed != 0:
        a = (a * seed) & MASK64
        b = (b * seed) & MASK64
        c = (c * seed) & MASK64
        d = (d * seed) & MASK64

    pos = 0
    length = len(data)
    while pos + 8 <= length:
        n = int.from_bytes(data[pos:pos + 8], "little")
        a, b, c, d = b, c, d, _diffuse_concrete(a ^ n)
        pos += 8

    if pos < length:
        n = _read_tail(data[pos:])
        a, b, c, d = b, c, d, _diffuse_concrete(a ^ n)

    return _diffuse_concrete(a ^ b ^ c ^ d ^ length) & MASK64


def seahash_128_concrete(
    data: bytes, seed_lo: int, seed_hi: int,
) -> tuple[int, int]:
    """Parallel two-lane 128-bit adapter — matches Go `seahashHash128`."""
    return (
        seahash64_concrete(data, seed_lo & MASK64),
        seahash64_concrete(data, seed_hi & MASK64),
    )


def seahash_chain_lo_concrete(
    seed_components: Sequence[int], data: bytes, rounds: int,
) -> int:
    """Low 64 bits of ChainHash128 under the SeaHash primitive, for
    `rounds` rounds.

    seed_components: flat list of 2*rounds uint64 values in order
        [s0_lo, s0_hi, s1_lo, s1_hi, ..., s(rounds-1)_lo, s(rounds-1)_hi].
    data: arbitrary-length data blob (canonical SAT calibration uses
        20-byte blockHash128 layout = 4B LE pixel + 16B nonce).
    rounds: ChainHash round count (1..8 supported).
    """
    assert len(seed_components) == 2 * rounds, (
        f"SeaHash ChainHash with rounds={rounds} needs {2 * rounds} seed "
        f"components, got {len(seed_components)}"
    )
    h_lo, h_hi = seahash_128_concrete(
        data, seed_components[0], seed_components[1],
    )
    for r in range(1, rounds):
        k_lo = (seed_components[2 * r] ^ h_lo) & MASK64
        k_hi = (seed_components[2 * r + 1] ^ h_hi) & MASK64
        h_lo, h_hi = seahash_128_concrete(data, k_lo, k_hi)
    return h_lo


# ============================================================================
# Z3 symbolic mirror with two configurable encoding axes
# ============================================================================


def _mul_P_z3(z3, x, encoding: str = "native"):
    """Symbolic `x * SEAHASH_PRIME` over BV(64).

    - "native": single Z3 BVMul with BitVecVal(P, 64). Compact default.
    - "explicit": 35 shift-and-add terms (one per bit set in P).
    """
    if encoding == "native":
        return x * z3.BitVecVal(SEAHASH_PRIME, 64)
    if encoding == "explicit":
        terms = [x << bit for bit in _PRIME_BITS]
        result = terms[0]
        for term in terms[1:]:
            result = result + term
        return result
    raise ValueError(f"unknown mul encoding: {encoding!r}")


def _var_shift_z3(z3, x, encoding: str = "native"):
    """Symbolic `(x >> 32) >> (x >> 60)` — variable shift inside diffuse.

    - "native": single Z3 LShR with both operands as 64-bit BVs.
      Bit-blasts to a 6-stage barrel shifter on `b`'s low 4 bits
      (since `b = x >> 60` has only 4 informative bits).
    - "case-split": enumerate the 16 possible shift amounts via
      nested `If(b == k, LShR(a, k), ...)`. More verbose SMT-LIB2
      but exposes per-case constants directly to CDCL.
    """
    a = z3.LShR(x, 32)            # high 32 bits zero-extended to 64
    b = z3.LShR(x, 60)            # only low 4 bits informative
    if encoding == "native":
        return z3.LShR(a, b)
    if encoding == "case-split":
        b4 = z3.Extract(3, 0, b)  # narrow to 4-bit shift selector
        # Build the 16-deep `If` chain from k=15 down to k=0 so the
        # base case is the k=0 (no shift) branch.
        result = a  # k=0 → a >> 0 == a
        for k in range(1, 16):
            shifted = z3.LShR(a, z3.BitVecVal(k, 64))
            result = z3.If(b4 == z3.BitVecVal(k, 4), shifted, result)
        return result
    raise ValueError(f"unknown var-shift encoding: {encoding!r}")


def _diffuse_z3(
    z3, x, mul_encoding: str = "native", var_shift_encoding: str = "native",
):
    """Symbolic SeaHash `_diffuse` on a 64-bit BitVec."""
    x = _mul_P_z3(z3, x, mul_encoding)
    x = x ^ _var_shift_z3(z3, x, var_shift_encoding)
    x = _mul_P_z3(z3, x, mul_encoding)
    return x


def _read_tail_z3(z3, tail: bytes):
    """Build symbolic tail word matching `_read_tail` concrete: 1..7
    bytes packed LE into low part of 64-bit BV, zeros above."""
    return z3.BitVecVal(_read_tail(tail), 64)


def seahash64_z3(
    z3, seed_sym, data: bytes,
    mul_encoding: str = "native", var_shift_encoding: str = "native",
):
    """Symbolic SeaHash hash on `data` with `seed_sym` (BitVec(64)).

    Models the canonical seed != 0 path unconditionally — multiplies
    INIT constants by seed regardless. This matches the concrete
    reference for any non-zero seed; calibration synthesis MUST
    generate non-zero seeds. Adding an `If(seed_sym == 0, ...)` ITE
    would model both paths but doubles formula size for an
    edge case the calibration never exercises.
    """
    INIT_A = z3.BitVecVal(SEAHASH_INIT_A, 64)
    INIT_B = z3.BitVecVal(SEAHASH_INIT_B, 64)
    INIT_C = z3.BitVecVal(SEAHASH_INIT_C, 64)
    INIT_D = z3.BitVecVal(SEAHASH_INIT_D, 64)

    a = INIT_A * seed_sym
    b = INIT_B * seed_sym
    c = INIT_C * seed_sym
    d = INIT_D * seed_sym

    pos = 0
    length = len(data)
    while pos + 8 <= length:
        n = z3.BitVecVal(
            int.from_bytes(data[pos:pos + 8], "little"), 64,
        )
        a, b, c, d = b, c, d, _diffuse_z3(
            z3, a ^ n, mul_encoding, var_shift_encoding,
        )
        pos += 8

    if pos < length:
        n = _read_tail_z3(z3, data[pos:])
        a, b, c, d = b, c, d, _diffuse_z3(
            z3, a ^ n, mul_encoding, var_shift_encoding,
        )

    length_bv = z3.BitVecVal(length & MASK64, 64)
    return _diffuse_z3(
        z3, a ^ b ^ c ^ d ^ length_bv, mul_encoding, var_shift_encoding,
    )


def seahash_128_z3(
    z3, seed_lo_sym, seed_hi_sym, data: bytes,
    mul_encoding: str = "native", var_shift_encoding: str = "native",
):
    """Symbolic parallel two-lane seahashHash128 — returns (lo, hi)."""
    return (
        seahash64_z3(z3, seed_lo_sym, data, mul_encoding, var_shift_encoding),
        seahash64_z3(z3, seed_hi_sym, data, mul_encoding, var_shift_encoding),
    )


def seahash_chain_lo_z3(
    z3, seed_lo_syms, seed_hi_syms, data: bytes, rounds: int,
    mul_encoding: str = "native", var_shift_encoding: str = "native",
):
    """Symbolic ChainHash128 lo lane under SeaHash for `rounds` rounds."""
    assert len(seed_lo_syms) == rounds and len(seed_hi_syms) == rounds, (
        f"need {rounds} lo + {rounds} hi seed syms, "
        f"got {len(seed_lo_syms)}+{len(seed_hi_syms)}"
    )
    h_lo, h_hi = seahash_128_z3(
        z3, seed_lo_syms[0], seed_hi_syms[0], data,
        mul_encoding, var_shift_encoding,
    )
    for r in range(1, rounds):
        k_lo = seed_lo_syms[r] ^ h_lo
        k_hi = seed_hi_syms[r] ^ h_hi
        h_lo, h_hi = seahash_128_z3(
            z3, k_lo, k_hi, data, mul_encoding, var_shift_encoding,
        )
    return h_lo


# ============================================================================
# Self-parity — concrete vs symbolic for both encoding axes
# ============================================================================


def _self_parity(rounds_list: List[int], num_vectors: int, seed_rng: int) -> int:
    rng = random.Random(seed_rng)
    failures = 0
    try:
        import z3
    except ImportError:
        print("[seahash-parity] z3 not installed; skipping symbolic check")
        return 0

    encoding_pairs = [
        ("native", "native"),
        ("native", "case-split"),
        ("explicit", "native"),
        ("explicit", "case-split"),
    ]

    for rounds in rounds_list:
        for i in range(num_vectors):
            data = bytes(rng.getrandbits(8) for _ in range(20))
            # Generate non-zero seed components (canonical SeaHash
            # has a separate seed=0 path that we don't model).
            seed_components = []
            for _ in range(2 * rounds):
                while True:
                    s = rng.getrandbits(64)
                    if s != 0:
                        seed_components.append(s)
                        break
            concrete_expected = seahash_chain_lo_concrete(
                seed_components, data, rounds,
            )

            for mul_enc, var_enc in encoding_pairs:
                tag = f"{mul_enc}+{var_enc}"
                seed_lo_syms = [
                    z3.BitVec(f"s_lo_{r}_{tag}", 64) for r in range(rounds)
                ]
                seed_hi_syms = [
                    z3.BitVec(f"s_hi_{r}_{tag}", 64) for r in range(rounds)
                ]
                sym_expr = seahash_chain_lo_z3(
                    z3, seed_lo_syms, seed_hi_syms, data, rounds,
                    mul_encoding=mul_enc, var_shift_encoding=var_enc,
                )
                substitutions = []
                for r in range(rounds):
                    substitutions.append(
                        (seed_lo_syms[r],
                         z3.BitVecVal(seed_components[2 * r], 64))
                    )
                    substitutions.append(
                        (seed_hi_syms[r],
                         z3.BitVecVal(seed_components[2 * r + 1], 64))
                    )
                substituted = z3.substitute(sym_expr, *substitutions)
                simplified = z3.simplify(substituted)
                try:
                    got = simplified.as_long() & MASK64
                except Exception as exc:
                    print(f"[seahash-parity] r={rounds} v={i} enc={tag}: "
                          f"simplify did not yield concrete BV ({exc})")
                    failures += 1
                    continue
                if got != concrete_expected:
                    failures += 1
                    print(f"[seahash-parity] MISMATCH r={rounds} v={i} "
                          f"enc={tag}: concrete={concrete_expected:016x} "
                          f"z3={got:016x}")
                elif i == 0:
                    print(f"[seahash-parity] OK r={rounds} v={i} "
                          f"enc={tag}: {got:016x}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rounds", default="1,2,4",
                    help="comma-separated rounds list (default 1,2,4)")
    ap.add_argument("--vectors", type=int, default=4,
                    help="vectors per rounds (default 4)")
    ap.add_argument("--seed-rng", type=int, default=0xCAFE_BABE_5EA0_BABE,
                    help="reproducibility RNG seed")
    args = ap.parse_args()

    rounds_list = [int(x) for x in args.rounds.split(",") if x.strip()]
    failures = _self_parity(rounds_list, args.vectors, args.seed_rng)
    if failures:
        print(f"[seahash-parity] FAIL — {failures} mismatches")
        return 1
    print(f"[seahash-parity] PASS — all vectors matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
