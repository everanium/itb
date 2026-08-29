#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FNV-1a lo-lane SAT probe against the v0.3.0 barrier + Triple layout.

Companion to the Go probes in `redteam_broken_fnv1a_sat_test.go`.
Reads the JSON corpus emitted by `TestRedTeamBrokenFNV1aCribKPAEmitCorpus`
under `tmp/redteam/fnv1a_sat/f6_corpus_bundle.json` and runs a Bitwuzla
SAT instance encoding the naive-crib SAT anchoring premise on both the
pre-v0.3.0 without-barrier control and the v0.3.0 Triple/barrier
ciphertext.

Adapted from `scripts/redteam/itb/theory/fnv1a/sat_harness_4round.py`
(1666 lines encoding the full pre-v0.3.0 SAT). This compact form
isolates the CORE claim — does any (seed_lo, np, r) tuple
make the naive-crib xor_mask56 recovered from the container bytes
consistent with the FNV-1a chain output at the anchored stream index?

Threat-model framing.

The v0.3.0 closure is multi-seed joint coupling, not single-seed
inversion. Attacker-visible bytes are the SUM of contributions from
noiseSeed (np positions), lockSeed (per-chunk mask triple), dataSeed_i
(xor_mask + rotation), startSeed_i (per-snake sp_i). Full 8-chain
symbolic SAT would encode each of the four chains and the interlock
mask derivation as symbolic constraints — beyond the single-cycle
scope. The probe below implements the STRONGEST-ATTACKER upper bound:
grant true (np, r, sp_i) values as lab peek (5 of 8 chains inverted for
free) and ask whether the remaining single dataSeed_i chain admits a
naive-crib SAT anchor. Under the barrier the answer is UNSAT because
the crib bytes are at wrong positions; even the maximum-peek attacker
cannot recover.

Encoding (per pixel p in [0, n_pixels)):
  - Read container bytes at (sp + p) mod snake_pixels.
  - Compute candidate_xor_mask56 over the 56 (np, r) tuples.
  - Assert: fnv_chain_lo(seed_lo, LE32(p)||nonce) >> 3
            ∈ {candidate_xor_mask56 for (np, r) in 56}
            AND rotation constraint fnv_chain_lo % 7 == r.

Solver: Bitwuzla 0.9.x, native bitvector reasoning (no CDCL over Z3
clauses). Multi-pixel joint SAT chains the same 4 seed_lo lanes across
constraints; a truly satisfying assignment requires all N pixels'
recovered xor_mask56 values to lie on the same FNV chain. Under
barrier displacement this probability is ≈ (56 * 2^-56)^{N-1} per
seed_lo lane tuple → essentially zero for N ≥ 3.

Attacker-realism scoping:
  - Barrier probe (primary): reads only attacker-visible bytes plus
    true (np, r) values — this maximum-peek posture is the STRONGEST
    attacker upper bound. Real attacker (with unknown noiseSeed +
    dataSeed_i + interlock masks) is definitionally weaker.
  - Control probe (sanity): grants true (np, r, sp) — same posture as
    the pre-v0.3.0 Concession 1 harness — and expects SAT.
  - Ground-truth dataSeed_i values are read only in terminal-stage
    validation printouts (SAT model comparison), never in a decision
    path.

Usage:
    python3 sat_probe.py [--corpus-json PATH]
                        [--n-crib-pixels 3]
                        [--timeout-sec 1800]
                        [--json-report PATH]

Exit codes: 0 on completion (SAT and UNSAT are both success values;
which one occurred is in the JSON report); 1 on unexpected error.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Reuse the vetted symbolic FNV-1a lo-lane chain from the pre-v0.3.0
# arsenal. The concrete evaluator gives us cross-check parity; the
# symbolic form is re-implemented against Bitwuzla below (the
# arsenal's symbolic implementation targets Z3).
_ARSENAL = Path(__file__).resolve().parents[2] / "itb" / "theory" / "fnv1a"
if str(_ARSENAL) not in sys.path:
    sys.path.insert(0, str(_ARSENAL))

from fnv_chain_lo_concrete import (  # type: ignore  # noqa: E402
    MASK64,
    fnv_chain_lo_concrete,
)

# ITB pixel-encoding constants — mirror the Go itb.go values.
CHANNELS = 8
DATA_BITS_PER_CHANNEL = 7
DATA_ROTATION_BITS = 3


def rotate_bits_7(v: int, r: int) -> int:
    """Rotate low 7 bits of v left by r. Mirror of itb.rotateBits7."""
    v &= 0x7F
    r = r % 7
    return ((v << r) | (v >> (7 - r))) & 0x7F


def extract7(cb: int, np: int) -> int:
    """Remove noise bit at np from container byte. Mirror of extract7Broken."""
    low = cb & ((1 << np) - 1)
    high = cb >> (np + 1)
    return (low | (high << np)) & 0x7F


def recover_xor_mask56(pixel_bytes: bytes, np: int, r: int, crib_bits: List[int]) -> int:
    """Recover the 56-bit compound (dataHash.lo >> 3) under one (np, r)
    guess and the assumed crib byte alignment.

    Mirror of recoverXorMask56FNV in redteam_broken_fnv1a_sat_test.go.
    """
    xor56 = 0
    for ch in range(CHANNELS):
        ext = extract7(pixel_bytes[ch], np)
        unrot = rotate_bits_7(ext, (7 - r) % 7)
        cx = unrot ^ (crib_bits[ch] & 0x7F)
        xor56 |= cx << (ch * DATA_BITS_PER_CHANNEL)
    return xor56


def naive_snake_crib_bits(plain: bytes, snake_idx: int, snake_pixel: int) -> List[int]:
    """Attacker's naive-crib bits per channel under every-3rd-byte split.

    Mirror of naiveSnakeCribBits in the Go probe file.
    """
    bits = [0] * CHANNELS
    for ch in range(CHANNELS):
        bit_idx = snake_pixel * (CHANNELS * DATA_BITS_PER_CHANNEL) + ch * DATA_BITS_PER_CHANNEL
        byte_idx = bit_idx // 8
        bit_off = bit_idx % 8
        abs0 = snake_idx + 3 * byte_idx
        abs1 = snake_idx + 3 * (byte_idx + 1)
        if abs0 >= len(plain):
            return bits
        raw = plain[abs0]
        if abs1 < len(plain):
            raw |= plain[abs1] << 8
        bits[ch] = (raw >> bit_off) & 0x7F
    return bits


def load_corpus(path: Path) -> Dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def decode_wire(ct_hex: str) -> Dict[str, Any]:
    """Slice the Triple ciphertext into three snake regions per the
    public wire header. Attacker-visible bytes only.
    """
    ct = bytes.fromhex(ct_hex)
    nonce_size = 64  # DefaultNonceBits/8 in v0.3.0
    nonce = ct[:nonce_size]
    w = int.from_bytes(ct[nonce_size:nonce_size + 2], "big")
    h = int.from_bytes(ct[nonce_size + 2:nonce_size + 4], "big")
    total = w * h
    third = total // 3
    third3 = total - 2 * third
    body = ct[nonce_size + 4:]
    return {
        "nonce": nonce,
        "total_pixels": total,
        "snake_pixels": [third, third, third3],
        "snake_bodies": [
            body[0:third * CHANNELS],
            body[third * CHANNELS:2 * third * CHANNELS],
            body[2 * third * CHANNELS:total * CHANNELS],
        ],
    }


# =============================================================================
# Bitwuzla symbolic FNV-1a chain and per-pixel SAT constraint construction.
# =============================================================================


def make_bitwuzla(timeout_sec: int):
    import bitwuzla
    tm = bitwuzla.TermManager()
    opt = bitwuzla.Options()
    opt.set(bitwuzla.Option.PRODUCE_MODELS, True)
    opt.set(bitwuzla.Option.TIME_LIMIT_PER, timeout_sec * 1000)
    bw = bitwuzla.Bitwuzla(tm, opt)
    return bitwuzla, tm, bw


def bv_const(tm, val: int, width: int):
    import bitwuzla
    return tm.mk_bv_value(tm.mk_bv_sort(width), val & ((1 << width) - 1))


def fnv_chain_lo_bw(bitwuzla, tm, seed_lanes_syms, data_bytes: bytes, rounds: int):
    """Symbolic Bitwuzla term for hLo(fnv_chain(seed_lanes, data_bytes, rounds)).

    Mirrors fnv_chain_lo_z3 in fnv_chain_lo_concrete.py — same shift-and-
    add decomposition of `* 0x13B mod 2^64` (bits {0,1,3,4,5,8}). All
    arithmetic is BitVec(64).
    """
    Kind = bitwuzla.Kind
    sort64 = tm.mk_bv_sort(64)

    def mul_p_lo(state):
        # state * 0x13B mod 2^64 via shift-and-add.
        shifts = []
        for k in (8, 5, 4, 3, 1, 0):
            if k == 0:
                shifts.append(state)
            else:
                shift_val = tm.mk_bv_value(sort64, k)
                shifts.append(tm.mk_term(Kind.BV_SHL, [state, shift_val]))
        acc = shifts[0]
        for s in shifts[1:]:
            acc = tm.mk_term(Kind.BV_ADD, [acc, s])
        return acc

    h_prev = tm.mk_bv_value(sort64, 0)
    for round_idx in range(rounds):
        s = seed_lanes_syms[round_idx]
        state = s if round_idx == 0 else tm.mk_term(Kind.BV_XOR, [s, h_prev])
        for b in data_bytes:
            state = mul_p_lo(tm.mk_term(Kind.BV_XOR, [state, bv_const(tm, b & 0xFF, 64)]))
        h_prev = state
    return h_prev


MASK56 = (1 << 56) - 1


def _enum_candidates(xor56: int, r: int) -> List[int]:
    """Enumerate concrete 64-bit chain-output values satisfying:
    (val >> 3) & mask56 == xor56  AND  val % 7 == r.

    Free variables: bits 0..2 (low3, 8 options) and bits 59..63 (top5,
    32 options). The rotation constraint val % 7 == r selects ~256/7
    ≈ 37 satisfying combinations per (xor56, r).

    Concrete enumeration avoids symbolic URem which is expensive on
    Bitwuzla's bitvector backend. The 37-clause disjunction per pixel
    replaces the URem operator; joint N-pixel SAT is O(37^N).
    """
    out = []
    base = (xor56 & MASK56) << 3
    for top5 in range(32):
        for low3 in range(8):
            val = ((top5 << 59) | base | low3) & MASK64
            if val % 7 == (r % 7):
                out.append(val)
    return out


def constrain_pixel_true_npr(
    bitwuzla, tm, bw, chain_expr, pixel_bytes: bytes, crib_bits: List[int],
    true_np: int, true_r: int,
):
    """Add the per-pixel SAT constraint under GIVEN true (np, r) —
    the strongest-attacker upper bound where noiseSeed / dataSeed
    rotation are granted as lab peek.
    """
    Kind = bitwuzla.Kind
    xor56 = recover_xor_mask56(pixel_bytes, true_np, true_r, crib_bits) & MASK56
    cands = _enum_candidates(xor56, true_r)
    if not cands:
        bw.assert_formula(tm.mk_bv_value(tm.mk_bool_sort(), 0))
        return 0
    or_terms = [tm.mk_term(Kind.EQUAL, [chain_expr, bv_const(tm, c, 64)])
                for c in cands]
    if len(or_terms) == 1:
        bw.assert_formula(or_terms[0])
    else:
        bw.assert_formula(tm.mk_term(Kind.OR, or_terms))
    return len(cands)


def constrain_pixel_all_npr(
    bitwuzla, tm, bw, chain_expr, pixel_bytes: bytes, crib_bits: List[int],
):
    """Add the per-pixel SAT constraint over ALL 56 (np, r) tuples —
    real-attacker regime where (np, r) are unknown symbolic bits.
    Encoded as Or_{(np, r), top5, low3} [chain_expr == candidate].
    """
    Kind = bitwuzla.Kind
    all_cands: set[int] = set()
    for np in range(8):
        for r in range(7):
            xor56 = recover_xor_mask56(pixel_bytes, np, r, crib_bits) & MASK56
            for c in _enum_candidates(xor56, r):
                all_cands.add(c)
    if not all_cands:
        bw.assert_formula(tm.mk_bv_value(tm.mk_bool_sort(), 0))
        return 0
    or_terms = [tm.mk_term(Kind.EQUAL, [chain_expr, bv_const(tm, c, 64)])
                for c in sorted(all_cands)]
    if len(or_terms) == 1:
        bw.assert_formula(or_terms[0])
    else:
        bw.assert_formula(tm.mk_term(Kind.OR, or_terms))
    return len(or_terms)


# =============================================================================
# Probe entry points.
# =============================================================================


def sat_probe_control(
    corpus: Dict[str, Any],
    n_pixels: int,
    timeout_sec: int,
    rounds: int,
    regime: str,
) -> Dict[str, Any]:
    """Run SAT on the single-snake, no-barrier control ciphertext.

    regime == "true_npr": grants attacker true (np, r) per pixel plus
    true sp (Concession 1 posture). Expected: SAT within seconds.
    regime == "all_npr": grants only true sp; enumerates 56 (np, r)
    tuples per pixel. Slower but attacker-realistic.
    """
    ctrl_bytes = bytes.fromhex(corpus["control_bytes"])
    plain = bytes.fromhex(corpus["plaintext_hex"])
    nonce = bytes.fromhex(corpus["nonce_hex"])
    total_pixels_ctrl = int(corpus["control_pixels"])

    # startPixel derived from startSeed1.deriveStartPixel (matches
    # Concession 1 of the pre-v0.3.0 harness).
    dom = bytes([0x02]) + nonce
    seed_lo_lanes = [int(h, 16) for h in corpus["seed_components"]["start1"][::2]]
    hlo = fnv_chain_lo_concrete(seed_lo_lanes, dom, rounds)
    ctrl_sp = hlo % total_pixels_ctrl
    print(f"[control] startPixel = {ctrl_sp} of {total_pixels_ctrl}", flush=True)

    def ctrl_crib(p: int) -> List[int]:
        bits = [0] * CHANNELS
        for ch in range(CHANNELS):
            bit_idx = p * (CHANNELS * DATA_BITS_PER_CHANNEL) + ch * DATA_BITS_PER_CHANNEL
            byte_idx = bit_idx // 8
            bit_off = bit_idx % 8
            if byte_idx >= len(plain):
                return bits
            raw = plain[byte_idx]
            if byte_idx + 1 < len(plain):
                raw |= plain[byte_idx + 1] << 8
            bits[ch] = (raw >> bit_off) & 0x7F
        return bits

    # Lab-peek true (np, r) per pixel for the "true_npr" regime.
    ns_lanes = [int(h, 16) for h in corpus["seed_components"]["noise"][::2]]
    d1_lanes = [int(h, 16) for h in corpus["seed_components"]["data1"][::2]]
    def true_np_at(p: int) -> int:
        return fnv_chain_lo_concrete(ns_lanes, struct.pack("<I", p) + nonce, rounds) & 7
    def true_r_at(p: int) -> int:
        return fnv_chain_lo_concrete(d1_lanes, struct.pack("<I", p) + nonce, rounds) % 7

    bitwuzla, tm, bw = make_bitwuzla(timeout_sec)
    sort64 = tm.mk_bv_sort(64)
    seed_syms = [tm.mk_const(sort64, f"ctrl_s_{i}") for i in range(rounds)]

    per_pixel = []
    for p in range(n_pixels):
        pix = (ctrl_sp + p) % total_pixels_ctrl
        pix_bytes = ctrl_bytes[pix * CHANNELS:(pix + 1) * CHANNELS]
        crib_bits = ctrl_crib(p)
        chain_expr = fnv_chain_lo_bw(bitwuzla, tm, seed_syms, struct.pack("<I", p) + nonce, rounds)
        if regime == "true_npr":
            n_cands = constrain_pixel_true_npr(
                bitwuzla, tm, bw, chain_expr, pix_bytes, crib_bits,
                true_np_at(p), true_r_at(p),
            )
        else:
            n_cands = constrain_pixel_all_npr(
                bitwuzla, tm, bw, chain_expr, pix_bytes, crib_bits,
            )
        per_pixel.append({"pixel": p, "candidates": n_cands})

    t0 = time.time()
    r = bw.check_sat()
    dt = time.time() - t0
    result = str(r)
    print(f"[control regime={regime}] result={result} wall={dt:.2f}s pixels={n_pixels}", flush=True)

    audit: Dict[str, Any] = {}
    if result == "sat" or result == "Result.SAT":
        try:
            recovered = []
            for s in seed_syms:
                v = bw.get_value(s)
                v_str = str(v).replace("#b", "")
                if len(v_str) == 64:
                    recovered.append(int(v_str, 2))
                else:
                    recovered.append(0)
            true_lanes = [int(h, 16) for h in corpus["seed_components"]["data1"][::2]]
            bit63_mask = ~(1 << 63) & MASK64
            matches = sum(1 for a, b in zip(recovered, true_lanes)
                          if (a & bit63_mask) == (b & bit63_mask))
            audit = {
                "recovered_lo_lanes_hex": [f"{v:016x}" for v in recovered],
                "true_lo_lanes_hex":       [f"{v:016x}" for v in true_lanes],
                "bit0_62_matches":         matches,
                "lanes_total":             rounds,
            }
        except Exception as e:
            audit = {"model_read_error": str(e)}
    return {
        "config": "single_ouroboros_barrier_off",
        "regime": regime,
        "startpixel_disclosed": ctrl_sp,
        "n_pixels": n_pixels,
        "rounds": rounds,
        "result": result,
        "wall_sec": dt,
        "per_pixel": per_pixel,
        "audit": audit,
    }


def sat_probe_barrier(
    corpus: Dict[str, Any],
    snake_idx: int,
    n_pixels: int,
    timeout_sec: int,
    rounds: int,
    regime: str,
    sp_override: int = -1,
) -> Dict[str, Any]:
    """Run SAT on the v0.3.0 barrier ciphertext at snake `snake_idx`
    under the naive-crib alignment premise. sp_override < 0 → enumerate
    a fast-scan subset of snake_pixels; sp_override >= 0 → fix to that.

    regime == "true_npr": grants true (np, r) per pixel (5-of-8 chains
    peeked) — strongest attacker upper bound. Expected: UNSAT for
    every candidate startPixel because crib bytes are displaced.
    regime == "all_npr": enumerates all 56 (np, r) per pixel — real
    attacker regime.
    """
    geom = decode_wire(corpus["ciphertext_hex"])
    plain = bytes.fromhex(corpus["plaintext_hex"])
    nonce = geom["nonce"]
    snake_body = geom["snake_bodies"][snake_idx]
    snake_pixels = geom["snake_pixels"][snake_idx]

    # For the [lab-peek: sp_i] variant (Layer 3), derive true sp_i.
    seed_start_key = f"start{snake_idx + 1}"
    ss_lanes = [int(h, 16) for h in corpus["seed_components"][seed_start_key][::2]]
    dom = bytes([0x02]) + nonce
    true_sp = fnv_chain_lo_concrete(ss_lanes, dom, rounds) % snake_pixels

    if sp_override >= 0:
        sp_list = [sp_override]
    elif sp_override == -2:
        sp_list = [true_sp]  # [lab-peek: sp_i] — Layer 3 posture
    else:
        # Enumerate a fast-scan sample of the sp range. Full-range
        # scans are gated by ITB_FNV1A_SAT_FULL=1.
        cap = int(os.environ.get("ITB_FNV1A_SAT_CAP", "8"))
        step = max(1, snake_pixels // cap)
        sp_list = list(range(0, snake_pixels, step))[:cap]

    # Lab-peek per-snake noiseSeed / dataSeed_i lanes for "true_npr".
    ns_lanes = [int(h, 16) for h in corpus["seed_components"]["noise"][::2]]
    seed_data_key = f"data{snake_idx + 1}"
    di_lanes = [int(h, 16) for h in corpus["seed_components"][seed_data_key][::2]]

    def true_np_at(p: int) -> int:
        return fnv_chain_lo_concrete(ns_lanes, struct.pack("<I", p) + nonce, rounds) & 7

    def true_r_at(p: int) -> int:
        return fnv_chain_lo_concrete(di_lanes, struct.pack("<I", p) + nonce, rounds) % 7

    per_sp_results = []
    for sp in sp_list:
        bitwuzla, tm, bw = make_bitwuzla(timeout_sec)
        sort64 = tm.mk_bv_sort(64)
        seed_syms = [tm.mk_const(sort64, f"bar_s_{snake_idx}_{sp}_{i}") for i in range(rounds)]

        per_pixel = []
        for p in range(n_pixels):
            snake_pix = (sp + p) % snake_pixels
            pix_bytes = snake_body[snake_pix * CHANNELS:(snake_pix + 1) * CHANNELS]
            crib_bits = naive_snake_crib_bits(plain, snake_idx, p)
            chain_expr = fnv_chain_lo_bw(bitwuzla, tm, seed_syms, struct.pack("<I", p) + nonce, rounds)
            if regime == "true_npr":
                n_cands = constrain_pixel_true_npr(
                    bitwuzla, tm, bw, chain_expr, pix_bytes, crib_bits,
                    true_np_at(p), true_r_at(p),
                )
            else:
                n_cands = constrain_pixel_all_npr(
                    bitwuzla, tm, bw, chain_expr, pix_bytes, crib_bits,
                )
            per_pixel.append({"pixel": p, "candidates": n_cands})

        t0 = time.time()
        r = bw.check_sat()
        dt = time.time() - t0
        result = str(r)
        print(f"[barrier snake={snake_idx} sp={sp} regime={regime}] "
              f"result={result} wall={dt:.2f}s pixels={n_pixels}", flush=True)

        entry: Dict[str, Any] = {
            "sp": sp,
            "regime": regime,
            "result": result,
            "wall_sec": dt,
            "per_pixel": per_pixel,
        }
        # If SAT was returned on the barrier, cross-validate on a
        # non-SAT pixel to check for spurious model.
        if result in ("sat", "Result.SAT") and n_pixels < 8:
            try:
                recovered = []
                for s in seed_syms:
                    v = str(bw.get_value(s)).replace("#b", "")
                    recovered.append(int(v, 2) if len(v) == 64 else 0)
                xval_pixel = n_pixels
                snake_pix_x = (sp + xval_pixel) % snake_pixels
                crib_bits_x = naive_snake_crib_bits(plain, snake_idx, xval_pixel)
                pix_bytes_x = snake_body[snake_pix_x * CHANNELS:(snake_pix_x + 1) * CHANNELS]
                true_chain_x = fnv_chain_lo_concrete(
                    recovered, struct.pack("<I", xval_pixel) + nonce, rounds,
                )
                target = (true_chain_x >> DATA_ROTATION_BITS) & ((1 << 56) - 1)
                hit = False
                for np in range(8):
                    for r_g in range(7):
                        if recover_xor_mask56(pix_bytes_x, np, r_g, crib_bits_x) == target \
                                and (true_chain_x % 7) == r_g:
                            hit = True
                            break
                    if hit:
                        break
                entry["cross_validation"] = {
                    "xval_pixel": xval_pixel,
                    "cross_matches": hit,
                    "note": "cross_matches=False → model is spurious (barrier UNSAT verdict corroborated)",
                }
            except Exception as e:
                entry["cross_validation_error"] = str(e)
        per_sp_results.append(entry)

    n_sat = sum(1 for r in per_sp_results if r["result"] in ("sat", "Result.SAT"))
    n_unsat = sum(1 for r in per_sp_results if r["result"] in ("unsat", "Result.UNSAT"))
    n_unknown = len(per_sp_results) - n_sat - n_unsat
    return {
        "config": "v030_triple_barrier",
        "snake": snake_idx,
        "regime": regime,
        "snake_pixels": snake_pixels,
        "n_pixels": n_pixels,
        "rounds": rounds,
        "true_sp": true_sp,
        "sp_scan_count": len(per_sp_results),
        "sat": n_sat,
        "unsat": n_unsat,
        "unknown": n_unknown,
        "per_sp": per_sp_results,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-json", type=Path,
                    default=Path("tmp/redteam/fnv1a_sat/f6_corpus_bundle.json"))
    ap.add_argument("--n-crib-pixels", type=int, default=3)
    ap.add_argument("--timeout-sec", type=int, default=600)
    ap.add_argument("--rounds", type=int, default=4,
                    help="ChainHash round count for the FNV-1a lo-lane "
                         "(keyBits=512 → 4 rounds).")
    ap.add_argument("--regime", default="true_npr", choices=["true_npr", "all_npr"],
                    help="true_npr grants lab-peek true (np, r) per pixel — "
                         "strongest attacker upper bound. all_npr enumerates all 56.")
    ap.add_argument("--json-report", type=Path,
                    default=Path("tmp/redteam/fnv1a_sat/sat_probe.json"))
    ap.add_argument("--barrier-only", action="store_true")
    ap.add_argument("--control-only", action="store_true")
    ap.add_argument("--barrier-sp-peek", action="store_true",
                    help="Layer 3: probe barrier at true sp_i per snake only.")
    args = ap.parse_args(argv)

    if not args.corpus_json.is_file():
        print(f"[FATAL] corpus JSON not found: {args.corpus_json}", file=sys.stderr)
        print("Run `go test -run TestRedTeamBrokenFNV1aCribKPAEmitCorpus -v ./` first.",
              file=sys.stderr)
        return 1

    corpus = load_corpus(args.corpus_json)

    report: Dict[str, Any] = {
        "corpus":         str(args.corpus_json),
        "n_crib_pixels":  args.n_crib_pixels,
        "rounds":         args.rounds,
        "timeout_sec":    args.timeout_sec,
        "regime":         args.regime,
    }

    if not args.barrier_only:
        print("\n=== Control (pre-v0.3.0, barrier off) ===")
        report["control"] = sat_probe_control(
            corpus, args.n_crib_pixels, args.timeout_sec, args.rounds, args.regime,
        )

    if not args.control_only:
        print("\n=== Barrier (v0.3.0 Triple + always-on 48-bit interlock) ===")
        report["barrier"] = []
        for snake_idx in range(3):
            print(f"\n--- Snake {snake_idx} ---")
            sp_override = -2 if args.barrier_sp_peek else -1
            snake_report = sat_probe_barrier(
                corpus, snake_idx, args.n_crib_pixels,
                args.timeout_sec, args.rounds, args.regime,
                sp_override=sp_override,
            )
            report["barrier"].append(snake_report)

    args.json_report.parent.mkdir(parents=True, exist_ok=True)
    with args.json_report.open("w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[report] written to {args.json_report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
