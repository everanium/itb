#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 2 parity gadget for the SipHash-1-3 SAT calibration plan
(HARNESS.md § 9.3).

Cross-checks that two independent lo-lane implementations reproduce
the Go `chainHash128Siphash13` output bit-exact when the Go primitive
is `siphash13Hash` (harness_test.go).

Two independent implementations:

  (a) `siphash13_chain_lo_concrete` — pure Python mirroring the Go
      reference step by step. Mirrors the existing
      `scripts/redteam/phase2_theory/chainhashes/siphash13.py` module
      (which is parity-validated against the Go reference at the 18
      sizes covered by `_parity_dump`).

  (b) `siphash13_chain_lo_z3` — symbolic Z3 `BitVec(64)` expression
      for the same cascade. SipHash-1-3 is pure ARX (add-rotate-xor),
      so no encoding-axis choices apply: `bvadd` is the only natural
      symbolic representation for the modular adds, rotations are
      constant amounts (mapped to `(x << n) | LShR(x, 64 - n)`), and
      XOR is trivial. The `--mul-encoding` and `--var-shift-encoding`
      flags from the mx3 / SeaHash harnesses are therefore absent.

ITB deployment fixes the high half of SipHash's 128-bit key to zero
(`k1 = 0`), driving the primitive from a single 64-bit seed component
per call. The chain composition is the standard ITB parallel two-lane
construction: `siphash13Hash128(seed_lo, seed_hi)` runs two
independent `siphash13Hash` calls. As with mx3 and SeaHash, only the
lo lane's `h_lo` is observed; `s_hi_*` symbols are dead variables in
the SAT formula at every round, and the harness re-emits their
declarations through `_force_declare_seed_syms` (mirroring the mx3
fix).

He & Yu (ePrint 2019/865) cryptanalyse SipHash-2-1 / 2-2 with
differential characteristics; SipHash-1-3 is NOT directly covered by
their key recovery, so this calibration probes the boundary
empirically. § 9.3 frames either outcome (Tier 3 → first published
key recovery; timeout → empirical lower bound on commodity SAT) as
publishable.

Usage:
    python3 siphash13_chain_lo_concrete.py                  # parity
    python3 siphash13_chain_lo_concrete.py --vectors 1024   # more
"""

from __future__ import annotations

import argparse
import random
import sys
from typing import List, Sequence

MASK64 = 0xFFFF_FFFF_FFFF_FFFF

_IV0 = 0x736F6D6570736575  # "somepseu"
_IV1 = 0x646F72616E646F6D  # "dorandom"
_IV2 = 0x6C7967656E657261  # "lygenera"
_IV3 = 0x7465646279746573  # "tedbytes"

SIP_C = 1
SIP_D = 3


# ============================================================================
# Concrete reference — pure Python mirror of harness_test.go siphash13 ref
# ============================================================================


def _rotl64_concrete(x: int, n: int) -> int:
    n &= 63
    if n == 0:
        return x & MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _sip_round_concrete(v0, v1, v2, v3):
    v0 = (v0 + v1) & MASK64
    v1 = _rotl64_concrete(v1, 13)
    v1 ^= v0
    v0 = _rotl64_concrete(v0, 32)

    v2 = (v2 + v3) & MASK64
    v3 = _rotl64_concrete(v3, 16)
    v3 ^= v2

    v0 = (v0 + v3) & MASK64
    v3 = _rotl64_concrete(v3, 21)
    v3 ^= v0

    v2 = (v2 + v1) & MASK64
    v1 = _rotl64_concrete(v1, 17)
    v1 ^= v2
    v2 = _rotl64_concrete(v2, 32)

    return v0, v1, v2, v3


def _read_u64_le(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 8], "little")


def siphash13_hash_concrete(data: bytes, seed: int) -> int:
    """SipHash-1-3 with ITB deployment choice k1 = 0."""
    k0 = seed & MASK64
    v0 = (k0 ^ _IV0) & MASK64
    v1 = _IV1
    v2 = (k0 ^ _IV2) & MASK64
    v3 = _IV3

    length = len(data)
    end_8 = length - (length % 8)

    pos = 0
    while pos < end_8:
        m = _read_u64_le(data, pos)
        v3 ^= m
        for _ in range(SIP_C):
            v0, v1, v2, v3 = _sip_round_concrete(v0, v1, v2, v3)
        v0 ^= m
        pos += 8

    # Final partial block: zero-pad to 7 bytes, byte 7 = length & 0xff.
    last = bytearray(8)
    rem = length - end_8
    if rem > 0:
        last[:rem] = data[end_8:]
    last[7] = length & 0xFF
    m = int.from_bytes(bytes(last), "little")
    v3 ^= m
    for _ in range(SIP_C):
        v0, v1, v2, v3 = _sip_round_concrete(v0, v1, v2, v3)
    v0 ^= m

    # Finalization.
    v2 ^= 0xFF
    for _ in range(SIP_D):
        v0, v1, v2, v3 = _sip_round_concrete(v0, v1, v2, v3)

    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


def siphash13_128_concrete(
    data: bytes, seed_lo: int, seed_hi: int,
) -> tuple[int, int]:
    """Parallel two-lane 128-bit adapter."""
    return (
        siphash13_hash_concrete(data, seed_lo & MASK64),
        siphash13_hash_concrete(data, seed_hi & MASK64),
    )


def siphash13_chain_lo_concrete(
    seed_components: Sequence[int], data: bytes, rounds: int,
) -> int:
    """Low 64 bits of ChainHash128 under SipHash-1-3 for `rounds` rounds."""
    assert len(seed_components) == 2 * rounds, (
        f"SipHash-1-3 ChainHash with rounds={rounds} needs {2 * rounds} "
        f"seed components, got {len(seed_components)}"
    )
    h_lo, h_hi = siphash13_128_concrete(
        data, seed_components[0], seed_components[1],
    )
    for r in range(1, rounds):
        k_lo = (seed_components[2 * r] ^ h_lo) & MASK64
        k_hi = (seed_components[2 * r + 1] ^ h_hi) & MASK64
        h_lo, h_hi = siphash13_128_concrete(data, k_lo, k_hi)
    return h_lo


# ============================================================================
# Z3 symbolic mirror — pure ARX, no encoding-axis choices
# ============================================================================


def _rotl64_z3(z3, x, n: int):
    n &= 63
    if n == 0:
        return x
    return (x << n) | z3.LShR(x, 64 - n)


def _sip_round_z3(z3, v0, v1, v2, v3):
    v0 = v0 + v1
    v1 = _rotl64_z3(z3, v1, 13)
    v1 = v1 ^ v0
    v0 = _rotl64_z3(z3, v0, 32)

    v2 = v2 + v3
    v3 = _rotl64_z3(z3, v3, 16)
    v3 = v3 ^ v2

    v0 = v0 + v3
    v3 = _rotl64_z3(z3, v3, 21)
    v3 = v3 ^ v0

    v2 = v2 + v1
    v1 = _rotl64_z3(z3, v1, 17)
    v1 = v1 ^ v2
    v2 = _rotl64_z3(z3, v2, 32)

    return v0, v1, v2, v3


def _data_word_u64_z3(z3, data: bytes, pos: int):
    return z3.BitVecVal(_read_u64_le(data, pos), 64)


def _final_block_word_z3(z3, data: bytes):
    """Build the symbolic final-block word matching the concrete
    `last[:rem] = data[end_8:]; last[7] = length & 0xff`."""
    length = len(data)
    end_8 = length - (length % 8)
    last = bytearray(8)
    rem = length - end_8
    if rem > 0:
        last[:rem] = data[end_8:]
    last[7] = length & 0xFF
    return z3.BitVecVal(int.from_bytes(bytes(last), "little"), 64)


def siphash13_hash_z3(z3, seed_sym, data: bytes):
    """Symbolic SipHash-1-3 hash on `data` with `seed_sym` (BitVec(64)).

    The ITB deployment choice `k1 = 0` is hardcoded (matching concrete),
    which simplifies init: v0 = seed_sym ^ IV0; v1 = IV1; v2 = seed_sym
    ^ IV2; v3 = IV3.
    """
    IV0 = z3.BitVecVal(_IV0, 64)
    IV1 = z3.BitVecVal(_IV1, 64)
    IV2 = z3.BitVecVal(_IV2, 64)
    IV3 = z3.BitVecVal(_IV3, 64)

    v0 = seed_sym ^ IV0
    v1 = IV1
    v2 = seed_sym ^ IV2
    v3 = IV3

    length = len(data)
    end_8 = length - (length % 8)

    pos = 0
    while pos < end_8:
        m = _data_word_u64_z3(z3, data, pos)
        v3 = v3 ^ m
        for _ in range(SIP_C):
            v0, v1, v2, v3 = _sip_round_z3(z3, v0, v1, v2, v3)
        v0 = v0 ^ m
        pos += 8

    m = _final_block_word_z3(z3, data)
    v3 = v3 ^ m
    for _ in range(SIP_C):
        v0, v1, v2, v3 = _sip_round_z3(z3, v0, v1, v2, v3)
    v0 = v0 ^ m

    v2 = v2 ^ z3.BitVecVal(0xFF, 64)
    for _ in range(SIP_D):
        v0, v1, v2, v3 = _sip_round_z3(z3, v0, v1, v2, v3)

    return v0 ^ v1 ^ v2 ^ v3


def siphash13_128_z3(z3, seed_lo_sym, seed_hi_sym, data: bytes):
    """Symbolic parallel two-lane siphash13Hash128 — returns (lo, hi)."""
    return (
        siphash13_hash_z3(z3, seed_lo_sym, data),
        siphash13_hash_z3(z3, seed_hi_sym, data),
    )


def siphash13_chain_lo_z3(
    z3, seed_lo_syms, seed_hi_syms, data: bytes, rounds: int,
):
    """Symbolic ChainHash128 lo lane under SipHash-1-3 for `rounds` rounds."""
    assert len(seed_lo_syms) == rounds and len(seed_hi_syms) == rounds, (
        f"need {rounds} lo + {rounds} hi seed syms, "
        f"got {len(seed_lo_syms)}+{len(seed_hi_syms)}"
    )
    h_lo, h_hi = siphash13_128_z3(z3, seed_lo_syms[0], seed_hi_syms[0], data)
    for r in range(1, rounds):
        k_lo = seed_lo_syms[r] ^ h_lo
        k_hi = seed_hi_syms[r] ^ h_hi
        h_lo, h_hi = siphash13_128_z3(z3, k_lo, k_hi, data)
    return h_lo


# ============================================================================
# Self-parity — concrete vs symbolic on random vectors
# ============================================================================


def _self_parity(rounds_list: List[int], num_vectors: int, seed_rng: int) -> int:
    rng = random.Random(seed_rng)
    failures = 0
    try:
        import z3
    except ImportError:
        print("[siphash13-parity] z3 not installed; skipping symbolic check")
        return 0

    for rounds in rounds_list:
        for i in range(num_vectors):
            data = bytes(rng.getrandbits(8) for _ in range(20))
            seed_components = [rng.getrandbits(64) for _ in range(2 * rounds)]
            concrete_expected = siphash13_chain_lo_concrete(
                seed_components, data, rounds,
            )

            seed_lo_syms = [z3.BitVec(f"s_lo_{r}", 64) for r in range(rounds)]
            seed_hi_syms = [z3.BitVec(f"s_hi_{r}", 64) for r in range(rounds)]
            sym_expr = siphash13_chain_lo_z3(
                z3, seed_lo_syms, seed_hi_syms, data, rounds,
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
                print(f"[siphash13-parity] r={rounds} v={i}: simplify did "
                      f"not yield concrete BV ({exc})")
                failures += 1
                continue
            if got != concrete_expected:
                failures += 1
                print(f"[siphash13-parity] MISMATCH r={rounds} v={i}: "
                      f"concrete={concrete_expected:016x} z3={got:016x}")
            elif i == 0:
                print(f"[siphash13-parity] OK r={rounds} v={i}: {got:016x}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rounds", default="1,2,4",
                    help="comma-separated rounds list (default 1,2,4)")
    ap.add_argument("--vectors", type=int, default=4,
                    help="vectors per rounds (default 4)")
    ap.add_argument("--seed-rng", type=int, default=0xCAFE_BABE_5113_5113,
                    help="reproducibility RNG seed")
    args = ap.parse_args()

    rounds_list = [int(x) for x in args.rounds.split(",") if x.strip()]
    failures = _self_parity(rounds_list, args.vectors, args.seed_rng)
    if failures:
        print(f"[siphash13-parity] FAIL — {failures} mismatches")
        return 1
    print(f"[siphash13-parity] PASS — all vectors matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
