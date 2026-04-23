#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 0 parity gadget for the .FNVSTRESS plan.

Cross-checks that two independent lo-lane implementations reproduce the
Go `Seed128.ChainHash128` output bit-exact when the Go primitive is
`fnv1a128` (redteam_test.go). Without this gate, a later SAT harness
risks encoding a structurally-wrong chain and never noticing.

Two independent implementations:

  (a) `fnv_chain_lo_concrete` - pure Python, mirrors the Go code step by
      step but computes the lo 64 bits only. Relies on FNV-1a's
      carry-up-only property: state_lo_new depends exclusively on
      state_lo_old (and the byte XOR) because multiplication mod 2^128
      propagates carries UP, not down.

  (b) `fnv_chain_lo_z3` (optional - only when z3-solver is installed) -
      symbolic Z3 `BitVec(64)` expression for the same cascade, using
      the explicit shift-and-XOR decomposition of `* 0x13B` that the
      SAT harness will depend on later:

          state * 0x13B == (state << 8) ^ (state << 5) ^ (state << 4)
                         ^ (state << 3) ^ state   (all mod 2^64)

      When a concrete seed is substituted the Z3 expression must evaluate
      to the same hLo as (a). If Z3 is not available, (b) is skipped and
      the script still succeeds on (a).

Reference file format matches the Go emitter
`TestRedTeamEmitFNV1aChainHashReference` (redteam_lab_test.go).

Usage:
    python3 fnv_chain_lo_concrete.py [--reference PATH]
    # default PATH: tmp/attack/fnv_parity/reference.json

Exit codes:
    0 - all vectors matched
    1 - any mismatch (parity violation)
    2 - environment problem (missing reference, bad JSON, etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

MASK64 = 0xFFFF_FFFF_FFFF_FFFF
P_LO = 0x13B
"""Low 64 bits of FNV_PRIME_128 = 2^88 + 2^8 + 0x3B.

The 2^88 term lives in bits 64..127 and never reaches hLo via
multiplication mod 2^64 (carry-up-only). So only 2^8 + 0x3B = 0x13B
matters for the lo-lane.
"""


def mul_p_lo_pure(state_lo: int) -> int:
    """`state_lo * 0x13B mod 2^64` via explicit shift-and-ADD.

    Decomposition used verbatim by the SAT harness so a parity failure
    here also flags a symbolic-layer bug. 0x13B = bits {0,1,3,4,5,8},
    Hamming weight 6.

    Critical: the adds must be modular integer additions (`+`) with
    automatic carry propagation, NOT GF(2) XORs. `state * P mod 2^64`
    is Z/2^64 arithmetic; shift-and-XOR would compute multiplication
    over GF(2)[x]/(x^64) which is a different (carry-free) algebra and
    produces different outputs bit-by-bit. An earlier agent summary
    suggested XOR; that suggestion is wrong and this gadget catches it.
    """
    # 0x13B = (1<<8) + (1<<5) + (1<<4) + (1<<3) + (1<<1) + 1
    #      = 256 + 32 + 16 + 8 + 2 + 1 = 315
    assert (
        (1 << 8) + (1 << 5) + (1 << 4) + (1 << 3) + (1 << 1) + 1
    ) == 0x13B, "P_LO bit decomposition invariant broken"
    s = state_lo & MASK64
    return (
        (s << 8)
        + (s << 5)
        + (s << 4)
        + (s << 3)
        + (s << 1)
        + s
    ) & MASK64


def mul_p_lo_native(state_lo: int) -> int:
    """Reference: straight arithmetic `state_lo * 0x13B mod 2^64`.

    Used to verify `mul_p_lo_pure` is algebraically identical.
    """
    return (state_lo * P_LO) & MASK64


def fnv_round_lo(state_lo: int, data_bytes: bytes) -> int:
    """One ChainHash round, lo 64 bits only.

    Mirrors the Go body:
        for _, b := range data {
            state = (state ^ b) * FNV_PRIME_128 mod 2^128
        }
    projected onto lo.
    """
    s = state_lo & MASK64
    for b in data_bytes:
        s = mul_p_lo_pure(s ^ (b & 0xFF))
    return s


def fnv_chain_lo_concrete(
    lo_lane_seeds: List[int], data_bytes: bytes, rounds: int
) -> int:
    """Compute hLo of ChainHash128<fnv1a128> on `data_bytes` in pure Python.

    `lo_lane_seeds[k]` is s[2k].lo from the Go seed components - the
    only ones that enter the lo-lane cascade. The hi-lane seeds
    (s[1], s[3], ...) are unused by hLo under FNV-1a carry-up-only.

    Replicates the Go logic:
        round 0: state_lo = lo_lane_seeds[0]
        round k>=1: state_lo = lo_lane_seeds[k] ^ hLo_prev
    """
    if len(lo_lane_seeds) < rounds:
        raise ValueError(
            f"need {rounds} lo-lane seeds, got {len(lo_lane_seeds)}"
        )
    h_prev_lo = 0
    for round_idx in range(rounds):
        s_lo = lo_lane_seeds[round_idx] & MASK64
        state_lo = s_lo if round_idx == 0 else (s_lo ^ h_prev_lo)
        h_prev_lo = fnv_round_lo(state_lo, data_bytes)
    return h_prev_lo


def _check_mul_equivalence() -> None:
    """Smoke-check that shift-XOR and native multiplications agree.

    Runs on a handful of pseudo-random 64-bit values. Exits code 2 if
    the two implementations diverge - that would be a Python-level bug
    before any Go comparison begins.
    """
    import random

    rng = random.Random(0xA11CE_1337)
    for _ in range(1024):
        x = rng.getrandbits(64)
        a = mul_p_lo_pure(x)
        b = mul_p_lo_native(x)
        if a != b:
            print(
                f"[FATAL] mul_p_lo_pure != mul_p_lo_native on x=0x{x:016x}: "
                f"pure=0x{a:016x} native=0x{b:016x}",
                file=sys.stderr,
            )
            sys.exit(2)


def _try_z3():
    """Return the z3 module if installed, else None."""
    try:
        import z3  # type: ignore

        return z3
    except ImportError:
        return None


def fnv_chain_lo_z3(z3, lo_lane_seeds_syms, data_bytes: bytes, rounds: int):
    """Build a Z3 BitVec(64) expression for hLo.

    `lo_lane_seeds_syms[k]` is a Z3 BitVec(64) for s[2k].lo. The
    returned value is a Z3 BitVec(64) expression that, when all seeds
    are substituted with concrete values, evaluates to the same integer
    that `fnv_chain_lo_concrete` returns.

    Decomposition of `* 0x13B mod 2^64` uses explicit shift-XOR - the
    same five shifts the SAT harness will later rely on.
    """
    BitVecVal = z3.BitVecVal

    def mul_z3(state):
        # Modular addition of shifted copies, NOT XOR (see pure-Python
        # counterpart for the reasoning). `+` on Z3 BitVec(64) wraps
        # mod 2^64, which is exactly the semantics we need.
        return (
            (state << 8)
            + (state << 5)
            + (state << 4)
            + (state << 3)
            + (state << 1)
            + state
        )

    h_prev = BitVecVal(0, 64)
    for round_idx in range(rounds):
        s = lo_lane_seeds_syms[round_idx]
        state = s if round_idx == 0 else (s ^ h_prev)
        for b in data_bytes:
            state = mul_z3(state ^ BitVecVal(b & 0xFF, 64))
        h_prev = state
    return h_prev


def _check_z3(z3, reference: dict) -> bool:
    """Return True if every reference vector also matches under Z3.

    Each vector is substituted concretely into a fresh Z3 expression and
    the 64-bit constant is extracted via `simplify`. If the constant
    differs from the pure-Python result the harness is broken.
    """
    from z3 import BitVec, BitVecVal, simplify

    lo_lane_seeds = [int(h, 16) for h in reference["lo_lane_seeds_hex"]]
    rounds = int(reference["rounds"])

    # One symbolic seed vector, reused across all vectors after simplification.
    syms = [BitVec(f"s_lo_{i}", 64) for i in range(rounds)]

    mismatches = 0
    for v in reference["vectors"]:
        data = bytes.fromhex(v["data_hex"])
        expected = int(v["h_lo_hex"], 16)
        expr = fnv_chain_lo_z3(
            __import__("z3"), syms, data, rounds
        )
        # Substitute concrete seed values and simplify to a constant.
        subs = [(syms[i], BitVecVal(lo_lane_seeds[i], 64)) for i in range(rounds)]
        concrete = simplify(z3.substitute(expr, *subs))
        if not concrete.size() == 64:
            print(
                f"[FATAL] z3 produced non-64-bit result for vector {v['index']}",
                file=sys.stderr,
            )
            return False
        val = concrete.as_long() & MASK64
        if val != expected:
            print(
                f"[MISMATCH z3] vector {v['index']}: got 0x{val:016x} "
                f"expected 0x{expected:016x}",
                file=sys.stderr,
            )
            mismatches += 1
    if mismatches:
        print(f"[FAIL] z3 parity: {mismatches} mismatches", file=sys.stderr)
        return False
    print(
        f"[OK] z3 parity: all {len(reference['vectors'])} vectors match"
    )
    return True


def _check_concrete(reference: dict) -> bool:
    """Return True if every reference vector matches the pure-Python impl."""
    lo_lane_seeds = [int(h, 16) for h in reference["lo_lane_seeds_hex"]]
    rounds = int(reference["rounds"])

    mismatches = 0
    for v in reference["vectors"]:
        data = bytes.fromhex(v["data_hex"])
        expected = int(v["h_lo_hex"], 16)
        got = fnv_chain_lo_concrete(lo_lane_seeds, data, rounds)
        if got != expected:
            print(
                f"[MISMATCH concrete] vector {v['index']}: "
                f"got 0x{got:016x} expected 0x{expected:016x}",
                file=sys.stderr,
            )
            mismatches += 1
    if mismatches:
        print(
            f"[FAIL] pure-Python parity: {mismatches} mismatches",
            file=sys.stderr,
        )
        return False
    print(
        f"[OK] pure-Python parity: all {len(reference['vectors'])} vectors match"
    )
    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="FNV-1a ChainHash128 lo-lane parity gadget"
    )
    ap.add_argument(
        "--reference",
        default="tmp/attack/fnv_parity/reference.json",
        help="Path to JSON reference emitted by the Go harness",
    )
    ap.add_argument(
        "--skip-z3",
        action="store_true",
        help="Skip the Z3 symbolic parity check even if z3 is installed",
    )
    args = ap.parse_args()

    _check_mul_equivalence()

    ref_path = Path(args.reference)
    if not ref_path.is_file():
        print(
            f"[FATAL] reference not found: {ref_path}\n"
            "  generate it first with:\n"
            "  ITB_FNV_REF=1 go test -run TestRedTeamEmitFNV1aChainHashReference -v",
            file=sys.stderr,
        )
        return 2
    try:
        reference = json.loads(ref_path.read_text())
    except json.JSONDecodeError as e:
        print(f"[FATAL] bad JSON: {e}", file=sys.stderr)
        return 2

    if reference.get("hash") != "fnv1a":
        print(
            f"[FATAL] reference hash is {reference.get('hash')!r}, "
            f"expected 'fnv1a'",
            file=sys.stderr,
        )
        return 2

    print(
        f"reference: hash={reference['hash']} keyBits={reference['key_bits']} "
        f"rounds={reference['rounds']} vectors={len(reference['vectors'])}"
    )

    concrete_ok = _check_concrete(reference)

    z3_ok = True
    if args.skip_z3:
        print("[skip] Z3 symbolic parity (disabled via --skip-z3)")
    else:
        z3_mod = _try_z3()
        if z3_mod is None:
            print(
                "[skip] z3-solver not installed - pure-Python parity only. "
                "Install z3-solver to enable the symbolic check.",
                file=sys.stderr,
            )
        else:
            z3_ok = _check_z3(z3_mod, reference)

    return 0 if (concrete_ok and z3_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
