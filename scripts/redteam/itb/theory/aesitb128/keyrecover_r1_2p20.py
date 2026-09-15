#!/usr/bin/env python3
"""Structured lo-lane KEY RECOVERY on standalone AES-ITB-128 (r = 1), the
one-block lab shape — ≈ 2²⁰ work, chosen-text, lo lane only.

The standalone table in HARNESS.md § 3.10 records two r = 1 breaks: the
one-pair inversion (full 128-bit seed block from one *full*-output query,
`keyrecover_r2.py` `attack_inversion`) and, on the lo lane, a 2⁶⁴ hi-lane
enumeration for that same inversion. This script measures a *third* r = 1
break the enumeration figure hides: a Square-style guess-and-determine that
recovers the whole effective key block `K = fixedKey ⊕ seed` (hence the
seed) from the **lo lane alone**, without ever seeing the hi lane, at
≈ 2²⁰ chosen-text work — a factor of 2⁴⁴ (13 decimal orders of magnitude)
below 2⁶⁴.

Structure (one-block input, ≤ 15 bytes → three full AES rounds P under the
public constants RC0, RC0, RC1; `chainhashes/aesitb128.py` docstring):

    out = R_RC1( R_RC0( R_RC0( x ) ) ),   x = K ⊕ pad(data),   K = fixedKey ⊕ seed

`R` is a full AESENC (MixColumns on every round). The lo lane is
`out[0:8]` = columns 0, 1 of the column-major state. Peel the last round on
those two columns — the last round key RC1 is public, InvMixColumns is
per-column — and InvSubBytes recovers 8 bytes of the round-2 output state
`y2` at the two state diagonals `prim._SR_IDX[:8] = {0,5,10,15,4,9,14,3}`
(ShiftRows relabels the two peeled columns onto those positions; no
full-state InvShiftRows is needed, so the hi lane is never touched).

Over a Λ-set active in one *input* byte `b` (a chosen data byte), a single
byte diffuses to exactly one round-1 column, ShiftRows spreads that column
across all four columns of round 2, and every `y2` byte becomes

    y2_byte(v) = m · S( a · S(k_b ⊕ v) ⊕ c ) ⊕ e

with `k_b = K[b]` unknown, `a ∈ {1,2,3}` a round-1 MixColumns coefficient,
`m` a round-2 MixColumns coefficient, and `c, e` constant over the set.
Guessing `(k_b, a, c)` (2⁸ · 3 · 2⁸ ≈ 2¹⁷·6) and solving `(m, e)` from the
GF(2⁸)-affine relation to the observed byte singles out `k_b`. One Λ-set
recovers one key byte; 15 Λ-sets (input bytes 0–14; byte 15 is the pad
constant) plus a 2⁸ brute force of `K[15]` recover all of K.

Attacker cost (headline): **1 byte × 2¹⁶ guesses × 15 positions + 2⁸ ≈ 2²⁰**,
3840 chosen texts. The per-byte cost is exactly 2¹⁶ over `(k_b, c)`: the
`a ∈ {1,2,3}` loop below is a 3× redundancy (the AES S-box's multiplicative
self-equivalence `S(a·t ⊕ c) = A_a(S(t ⊕ a⁻¹c))` folds the `a` scaling into
the outer affine the search already solves), and one recovered byte fixes
`k_b` uniquely — the S-box has no translation self-equivalence, so no wrong
`k_b` admits an affine fit (the per-position score margin printed below
confirms this empirically: the true `k_b` scores 8, every other guess < 8).
This script uses all 8 peeled bytes per Λ-set for consensus — that is
robustness overhead, not part of the minimum attacker cost, and the margin
report separates the two.

Reused from the aes2r-era engines (sibling scripts in this directory tree):
the peel / InvMixColumns / S-box tables from
`_common/chainhashes/aesitb128.py` (`_inv_mix_batch` L244, `_ISB_T` L225,
`_SR_IDX` L228, `_RC_ARR` L230, `hash_generic` for the oracle); the
Λ-set / oracle / TR=5-seed harness shape from this directory's
`keyrecover_r2.py` (`oracle_full` / `square_recover_r2`); GF helpers from
`chainhashes/aes2r.py` (`_gmul`). The r ≥ 2 negative control mirrors
`keyrecover_r2.py`'s r-sweep: the same engine is run against the r = 2
lo-lane oracle and must fail (the value entering P from r = 2 is
`pad(data) ⊕ seed_2 ⊕ h_1(data)`, not a Λ-set — § 3.10 Mechanism).

This is a lab measurement on the attacker-favourable one-block shape. The
shipped per-pixel shapes are 20 / 36 / 68 bytes (4 / 5 / 7 rounds); the
single-variable round-2 structure this attack needs is gone there, and no
claim is made about them.
"""
import argparse
import os
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import prim  # noqa: E402
from chainhashes.aes2r import _gmul  # noqa: E402

TR = 5                      # seeds per cell, matching keyrecover_r2.py
DATA_LEN = 15              # one-block lab shape (three AES rounds); pad = 1 byte 0x01
NPOS = DATA_LEN            # Λ-set active positions 0..14 (byte 15 = pad const)
A_SET = (1, 2, 3)         # round-1 MixColumns coefficients

# ---- GF(2^8) tables ---------------------------------------------------------
MULT = np.array([[_gmul(a, b) for b in range(256)] for a in range(256)], dtype=np.uint8)
GINV = np.zeros(256, dtype=np.uint8)
for _a in range(1, 256):
    for _b in range(1, 256):
        if _gmul(_a, _b) == 1:
            GINV[_a] = _b
            break

SB = prim._SB_T
ISB = prim._ISB_T
RC1 = prim._RC_ARR[1]
RC0 = prim._RC_ARR[0]
PEEL_POS = prim._SR_IDX[:8]      # y2 positions the two lo-lane columns land on
VARR = np.arange(256, dtype=np.uint8)
CARR = np.arange(256, dtype=np.uint8)


# ---- oracle -----------------------------------------------------------------
def lo_oracle(comps, rounds):
    """Chosen-text oracle returning the lo lane (8 bytes) only.

    rounds = 1 is the standalone primitive under attack; rounds = 2 is the
    negative-control cascade (keyrecover_r2.py oracle shape, discard on)."""
    if rounds == 1:
        s0, s1 = comps[0], comps[1]

        def query(data: bytes) -> np.ndarray:
            out = prim.hash_generic(prim.FIXED_KEY, data, s0, s1)
            return np.frombuffer(out[:8], dtype=np.uint8)
    else:
        def query(data: bytes) -> np.ndarray:
            full = prim.chainhash_full(data, comps, rounds=rounds, discard=False)
            return np.frombuffer(full.to_bytes(16, "little")[:8], dtype=np.uint8)
    return query


def true_y2(K, padded):
    """Ground-truth round-2 output state for x = K ⊕ padded (report-only)."""
    x = (np.frombuffer(K, dtype=np.uint8) ^ padded)[None, :]
    y1 = prim._round_batch(x, RC0)
    return prim._round_batch(y1, RC0)[0]


# ---- peel: lo lane (8 bytes) -> 8 bytes of y2 -------------------------------
def peel_lo(lo_arr):
    """(N, 8) lo-lane rows -> (N, 8) recovered y2 bytes at PEEL_POS order.

    Remove the public last round key RC1[0:8], InvMixColumns the two
    columns (pad to 16, InvMC is per-column), InvSubBytes."""
    n = lo_arr.shape[0]
    buf = np.zeros((n, 16), dtype=np.uint8)
    buf[:, :8] = lo_arr ^ RC1[:8]
    inv = prim._inv_mix_batch(buf)[:, :8]     # cols 0,1 of SR(SB(y2))
    return ISB[inv]                           # y2 bytes at PEEL_POS


# ---- per-byte structural test ----------------------------------------------
def kb_scores(y2rec):
    """y2rec: (256, 8) recovered y2 bytes over a Λ-set active in one input
    byte. Returns (256,) score = # of the 8 peeled bytes for which some
    (a, c, m, e) fits y2_byte(v) = m·S(a·S(k_b⊕v)⊕c)⊕e, per k_b guess."""
    score = np.zeros(256, dtype=np.int32)
    do_all = y2rec ^ y2rec[0:1, :]            # (256v, 8)  do per byte
    for kb in range(256):
        w = SB[kb ^ VARR]                     # (256,)  S(k_b ⊕ v)
        hit = 0
        for bcol in range(8):
            do = do_all[:, bcol]              # (256,)
            if not np.any(do):
                hit += 1                      # degenerate (constant) — vacuously fits
                continue
            ok_byte = False
            for a in A_SET:
                base = MULT[a, w]             # a·S(k_b⊕v)
                z = SB[base[None, :] ^ CARR[:, None]]      # (256c, 256v)
                dz = z ^ z[:, 0:1]                          # (256c, 256v), dz[:,v>0]!=0
                m = MULT[do[1], GINV[dz[:, 1]]]            # (256c,)
                pred = MULT[m[:, None], dz]                 # (256c, 256v)
                if np.any((m != 0) & np.all(pred == do[None, :], axis=1)):
                    ok_byte = True
                    break
            hit += ok_byte
        score[kb] = hit
    return score


def recover_key_byte(query, b, verify_y2=None):
    """Recover K[b] from one Λ-set active in input byte b. Returns
    (kb, peel_ok) where peel_ok reports the ground-truth y2 match."""
    fixed = bytearray(os.urandom(DATA_LEN))
    texts = []
    for v in range(256):
        d = bytearray(fixed)
        d[b] = v
        texts.append(bytes(d))
    lo = np.stack([query(t) for t in texts])          # (256, 8)
    y2rec = peel_lo(lo)                                # (256, 8)
    peel_ok = None
    if verify_y2 is not None:
        peel_ok = all(
            np.array_equal(y2rec[v], verify_y2(texts[v])[PEEL_POS])
            for v in (0, 1, 200)
        )
    score = kb_scores(y2rec)
    return int(np.argmax(score)), int(score.max()), peel_ok


def brute_last_byte(query, K14, comps):
    """K[0..14] known; recover K[15] (the pad-position byte) by matching a
    known chosen text's lo lane over 2^8 guesses."""
    d = os.urandom(DATA_LEN)
    obs = query(d)
    padded = np.frombuffer(prim.pkcs7(d), dtype=np.uint8)
    for g in range(256):
        K = bytes(K14) + bytes([g])
        x = (np.frombuffer(K, dtype=np.uint8) ^ padded)[None, :]
        s = prim._round_batch(x, RC0)
        s = prim._round_batch(s, RC0)
        out = prim._round_batch(s, RC1)[0]
        if np.array_equal(out[:8], obs):
            return g
    return None


def attack_lo_r1(comps, verify=True):
    """Full lo-lane K recovery at r = 1. Returns (K_recovered, timings)."""
    query = lo_oracle(comps, 1)
    K_true = prim.seed_block(comps[0], comps[1])
    K_true = bytes(prim.FIXED_KEY[i] ^ K_true[i] for i in range(16))

    def vy2(data):
        return true_y2(K_true, np.frombuffer(prim.pkcs7(data), dtype=np.uint8))

    K = bytearray(16)
    t_peel = 0.0
    t_search = 0.0
    peel_all_ok = True
    min_top = 8              # min over positions of the winning k_b score
    max_runner = 0          # max over positions of the runner-up score
    for b in range(NPOS):
        # split timing: query+peel vs search
        fixed = bytearray(os.urandom(DATA_LEN))
        texts = [bytes(fixed[:b]) + bytes([v]) + bytes(fixed[b + 1:]) for v in range(256)]
        t0 = time.perf_counter()
        lo = np.stack([query(t) for t in texts])
        y2rec = peel_lo(lo)
        t_peel += time.perf_counter() - t0
        if verify:
            peel_all_ok &= all(
                np.array_equal(y2rec[v], vy2(texts[v])[PEEL_POS]) for v in (0, 1, 200)
            )
        t0 = time.perf_counter()
        score = kb_scores(y2rec)
        t_search += time.perf_counter() - t0
        srt = np.sort(score)
        min_top = min(min_top, int(srt[-1]))
        max_runner = max(max_runner, int(srt[-2]))
        K[b] = int(np.argmax(score))
    g = brute_last_byte(query, bytes(K[:15]), comps)
    if g is not None:
        K[15] = g
    return bytes(K), K_true, dict(peel=t_peel, search=t_search, peel_ok=peel_all_ok,
                                  min_top=min_top, max_runner=max_runner)


def negative_control_r2(comps):
    """Run the same lo-lane engine against the r = 2 oracle. Expect failure:
    no Λ-set enters the primitive from r = 2, so k_b scores do not single
    out the true key and the recovered K fails to reproduce the oracle."""
    query = lo_oracle(comps, 2)
    K = bytearray(16)
    max_top = 0            # max winning k_b score over positions (discriminating vs r=1's 8)
    for b in range(NPOS):
        kb, top, _ = recover_key_byte(query, b)
        K[b] = kb
        max_top = max(max_top, top)
    # verify: does the recovered r=1-style K reproduce the r=2 lo lane?
    d = os.urandom(DATA_LEN)
    obs = query(d)
    reproduced = False
    for g in range(256):
        Kf = bytes(K[:15]) + bytes([g])
        s0 = int.from_bytes(Kf[:8], "little") ^ int.from_bytes(prim.FIXED_KEY[:8], "little")
        s1 = int.from_bytes(Kf[8:], "little") ^ int.from_bytes(prim.FIXED_KEY[8:], "little")
        out = prim.hash_generic(prim.FIXED_KEY, d, s0, s1)
        if np.array_equal(np.frombuffer(out[:8], dtype=np.uint8), obs):
            reproduced = True   # unexpectedly reproduced -> would be a finding
            break
    # engine_failed True (expected) when it neither found a full-8 consensus
    # nor reproduced the oracle. max_top ≪ 8 is the discriminating number:
    # at r = 1 every position scores 8; at r = 2 no Λ-set enters the primitive.
    return dict(reproduced=reproduced, max_top=max_top)


# ---- shape probe: the same engine on a shipped per-pixel shape --------------
def structured_probe_scores(query, b: int, data_len: int):
    """`recover_key_byte` at an arbitrary data length: one Λ-set active in
    data byte b (the other bytes a random constant), the two-column last-round
    peel, and the per-position k_b score. Returns (best k_b, top score,
    runner-up score). At a shipped shape (20 / 36 / 68 B, 4 / 5 / 7 rounds)
    the peeled bytes are round-3-plus outputs, not the single-variable round-2
    form the engine models, so the score margin is the engine-regime check —
    a low margin here is an engine-scope reading, not a security result."""
    fixed = bytearray(os.urandom(data_len))
    texts = []
    for v in range(256):
        d = bytearray(fixed)
        d[b] = v
        texts.append(bytes(d))
    lo = np.stack([query(t) for t in texts])
    y2rec = peel_lo(lo)
    score = kb_scores(y2rec)
    srt = np.sort(score)
    return int(np.argmax(score)), int(srt[-1]), int(srt[-2])


def shape_probe(data_len: int, rounds: int, positions, trials: int):
    """Score-margin probe of the r = 1 lab engine on a shipped shape at cascade
    depth `rounds`, lo lane only, Λ-sets confined to `positions` (the LE32(idx)
    bytes under the shipped nonce model). Reports the winning score margin per
    position; no key verification (the engine's model does not hold at these
    shapes, so a candidate K would be meaningless)."""
    print("=" * 78)
    print(f"Shape probe: r = 1 lo-lane engine at data_len={data_len}, rounds={rounds}, "
          f"positions={list(positions)}, lo lane only")
    print("=" * 78)
    worst_top, best_runner = 8, 0
    for trial in range(trials):
        comps = [int.from_bytes(os.urandom(8), "little") for _ in range(2 * rounds)]
        query = lo_oracle(comps, rounds)
        row = []
        for b in positions:
            _, top, runner = structured_probe_scores(query, b, data_len)
            row.append(f"{top}/{runner}")
            worst_top = min(worst_top, top)
            best_runner = max(best_runner, runner)
        print(f"  trial {trial}: score top/runner per position {row}")
    print("-" * 78)
    print(f"  winning-score floor {worst_top}/8, best runner-up {best_runner}/8 "
          f"(the r = 1 one-block reference scores 8/8 vs 0/8) -> "
          f"{'engine regime holds' if worst_top == 8 and best_runner < 8 else 'engine out of regime: no key candidate'}")



def main(trials: int = TR, run_positive: bool = True, run_negative: bool = True):
    if run_positive:
        main_positive(trials)
    if run_negative:
        main_negative(trials)


def main_positive(trials: int = TR):
    print("=" * 78)
    print("Lo-lane KEY RECOVERY on standalone AES-ITB-128, r = 1 (one-block lab shape)")
    print("≈ 2^20 chosen-text work, lo lane only — vs the 2^64 hi-lane inversion bound")
    print("=" * 78)
    hits = 0
    tot_peel = tot_search = 0.0
    peel_oks = 0
    worst_top = 8
    worst_runner = 0
    for trial in range(trials):
        comps = [int.from_bytes(os.urandom(8), "little") for _ in range(2)]
        t0 = time.perf_counter()
        Krec, Ktrue, tm = attack_lo_r1(comps)
        wall = time.perf_counter() - t0
        ok = Krec == Ktrue
        seed_rec = tuple(
            int.from_bytes(bytes(Krec[i] ^ prim.FIXED_KEY[i] for i in range(j, j + 8)), "little")
            for j in (0, 8)
        )
        hits += ok
        peel_oks += tm["peel_ok"]
        tot_peel += tm["peel"]
        tot_search += tm["search"]
        worst_top = min(worst_top, tm["min_top"])
        worst_runner = max(worst_runner, tm["max_runner"])
        print(f"  trial {trial}: K {'MATCH' if ok else 'MISS '} "
              f"seed_rec=({seed_rec[0]:016x},{seed_rec[1]:016x}) "
              f"peel_ok={tm['peel_ok']} margin(top/runner {tm['min_top']}/{tm['max_runner']}) "
              f"wall={wall:.1f}s (peel {tm['peel']:.1f}s / search {tm['search']:.1f}s)")
    print("-" * 78)
    print(f"  K byte-exact recovery: {hits}/{trials}   ground-truth y2 peel: {peel_oks}/{trials}")
    print(f"  score margin over all positions/trials: winning k_b = {worst_top} (of 8 bytes), "
          f"best runner-up = {worst_runner} -> single-byte uniqueness, per-byte cost = 2^16")
    print(f"  time: peel {tot_peel:.1f}s total, search {tot_search:.1f}s total "
          f"(15 Λ-sets/trial, 3840 chosen texts/trial)")
    print(f"  attacker headline cost: 1 byte × 2^16 × 15 pos + 2^8 ≈ 2^20;")
    print(f"  8-byte-consensus overhead here ≈ 2^23 (robustness, not minimum cost)")


def main_negative(trials: int = TR):
    print()
    print("=" * 78)
    print("Negative control: same engine against the r = 2 lo-lane oracle")
    print("=" * 78)
    fails = 0
    worst_max_top = 0
    for trial in range(trials):
        comps = [int.from_bytes(os.urandom(8), "little") for _ in range(4)]
        res = negative_control_r2(comps)
        engine_failed = not res["reproduced"]
        fails += engine_failed
        worst_max_top = max(worst_max_top, res["max_top"])
        print(f"  trial {trial}: engine {'FAILS (expected)' if engine_failed else 'RECOVERS (finding!)'} "
              f"  best k_b score {res['max_top']}/8 (r=1 scores 8; < 8 means no Λ-set survives)")
    print("-" * 78)
    print(f"  r = 2 engine failed to recover: {fails}/{trials} "
          f"(expected {trials}/{trials} — the feed-forward destroys the Λ-set); "
          f"best r=2 score {worst_max_top}/8 vs r=1's 8/8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="lo-lane structured key recovery, r = 1 one-block lab shape")
    ap.add_argument("--trials", type=int, default=TR, help="seeds per cell (default 5, the documented run)")
    ap.add_argument("--skip-negative", action="store_true", help="run the r = 1 recovery only")
    ap.add_argument("--only-negative", action="store_true", help="run the r = 2 negative control only")
    ap.add_argument("--shape-probe", type=int, default=0, metavar="DATA_LEN",
                    help="instead of the lab run: score-margin probe of the engine at a shipped shape (20 / 36 / 68)")
    ap.add_argument("--rounds", type=int, default=1, help="cascade depth for --shape-probe")
    ap.add_argument("--positions", default="0,1,2,3", help="active byte positions for --shape-probe (LE32(idx) bytes)")
    args = ap.parse_args()
    if args.shape_probe:
        shape_probe(args.shape_probe, args.rounds, [int(x) for x in args.positions.split(",")], args.trials)
    else:
        main(args.trials, run_positive=not args.only_negative, run_negative=not args.skip_negative)
