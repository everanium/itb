#!/usr/bin/env python3
"""Discard-off KEY RECOVERY through ChainHash<AES-ITB-128> at r = 2 on the
shipped 20-byte per-pixel shape — classical 4-round Square κ-byte engine.

The shipped per-pixel input is `LE32(idx) ‖ nonce` (`process_generic.go`);
at the 20-byte shape the primitive absorbs two 16-byte blocks and adds two
finaliser rounds, so one call is **T = 4** AES rounds from block 0 with the
seed entering by XOR ahead of a fixed public permutation P. Under the
discard-off attacker model (the full 128-bit ChainHash output is visible),
the peel of the last ChainHash call is the free step `P⁻¹` with the fixed
key removed, and the r = 2 observable becomes

    y = k₂ ⊕ h₁(d),   h₁(d) = P(K₁ ⊕ pad(d)),   P = T public AES rounds

where `k₂` is the seed block of the last ChainHash round, `K₁` is the first
round's `fixedKey ⊕ seed₁` whitening, and `d` is the chosen 20-byte input.
`sibling keyrecover_r2.py` runs the T = 3 case (one-block lab shape) with
the pair-constancy engine — where the state entering P's last round is
active in one byte per column (2¹⁶ per byte pair). This script runs the
T = 4 case (shipped 20-byte shape), where the state entering P's last round
is **balanced but not active** — the classical 4-round AES Square regime,
so a per-byte 2⁸ κ-byte engine applies instead.

Engine (`square_classic`, mirroring the sibling `keyrecover_r2.py` layout
against the shipped `chainhashes.aesitb128` mirror):

    W = MC⁻¹(y ⊕ RC_LAST),   RC_LAST = RC[1]   (the shipped 2-round finaliser)
    for each state byte position p, each κ-byte guess g:
        XOR_v SB⁻¹(W_v[p] ⊕ g) = 0 iff g == κ[p] = MC⁻¹(k₂)[p]

Three Λ-sets, active positions cycling through idx bytes 0 / 1 / 2 (the
attacker-controlled bytes of `LE32(idx)`; no nonce byte is ever chosen),
uniquely fix κ; then `k₂ = MC(κ)`, `h₁(d₀) = y₀ ⊕ k₂`, and one P⁻¹ on
h₁(d₀) recovers seed block 1. Both seed blocks of the last ChainHash round
are returned and verified by re-querying the oracle on 4 fresh chosen texts
(attacker-realism: the ground-truth match against `comps[:4]` is reported
only, never consulted by the engine).

Attacker cost / model:

  * Full KPA, **discard off** — the full 128-bit ChainHash output visible.
    In the shipped pipeline only `h[0]` reaches the encoder, so this attacker
    grant is a lab-only lift; the discard-on lo-lane observable at r = 2 is
    at the floor / 2⁶⁴ (`keyrecover_r2.py`, `keyrecover_r1_lo.py`).
  * Λ-set active bytes: `LE32(idx)` bytes 0 / 1 / 2 (pixel-index-only
    attacker; no nonce byte is chosen).
  * 3 Λ-sets × 256 chosen texts = **768 chosen texts** per trial.
  * ≈ 2¹³·⁶ κ guess-sums per trial (16 state bytes × 2⁸ guesses × 3 Λ-sets;
    ≈ 2¹² per Λ-set), seconds of wall time.
  * Recovers both seed blocks of the last ChainHash round; a second P⁻¹
    (public) then peels the first round to expose seed block 1.

The r = 3 and r = 4 negative controls run both engines (classic κ-byte and
pair-constancy) at the same shape and confirm 0 / 5 on each — from r = 3 the
input to the peeled permutation is `h_{r−2}(data) ⊕ pad(data) ⊕ const`, no
longer a Λ-set of any order, and neither engine finds a consistent κ.

Shipped-shape scope: the 36 / 68-byte per-pixel shapes have T = 5 / 7 AES
rounds per call and are outside either order-1 engine's regime; the classical
5-round Square distinguisher needs an order-4 diagonal set (2³² chosen
texts) to restore balance and is not run here. No claim is made about
those shapes.

Compound-stack framing: `aesitb128` ships as `Class = ClassNone` in
`hashes/registry.go` — intentionally weak standalone and safe only under
ITB's compound inner-PRF defence stack (ChainHash cascade + Interlocked
Barrier + Part 2 absorption). The measurement here quantifies the
standalone half of that classification at the shipped per-pixel shape;
the pipeline half — lockSeed cryptographic domain separation, the
combinadic-unrank barrier fill, and the Part 2 absorption layers — sits
above every ChainHash call and is not what this harness measures.

Shipped-observable mode (`--model realistic`): the same shape and cascade
depths under the attacker model the pipeline actually presents — the lo lane
`h[0]` only (the 8 bytes the encoder consumes; no full-state peel exists), the
Λ-set confined to the `LE32(idx)` bytes, and the other 16 data bytes a random
constant per set that the attacker sees but did not choose (a fresh nonce per
message). With the hi lane hidden the κ-byte engine has no `Y`; the one public
step left is the last finaliser round on the two visible state columns
(`RC[1]` known, InvMixColumns per column). The mode reports, per set, the raw
lo-lane balance and the column-peeled balance (g = 0 surviving the per-position
test `⊕ SB⁻¹(w[p] ⊕ g) = 0`, i.e. the state entering the last round balanced at
that position) together with the g-survivor count — a distinguisher, never a
recovery: no key-dependent quantity is peeled, and the residual recovery route
is the 2⁶⁴ hi-lane enumeration. The lab engine is run on the same seeds in the
same invocation as the positive control. The lo-lane oracle is itself an
attacker-favourable upper bound on the wire (a known-plaintext attacker reads
`h[0]` only through noisePos / rotation / xorMask across two seeds).

Reproduction:

    cd scripts/redteam/itb/theory/aesitb128
    python3 keyrecover_r2_20byte.py                     # lab grant (discard off)
    python3 keyrecover_r2_20byte.py --model realistic   # shipped observable (lo lane, idx-only sets, random nonce)
"""
import argparse
import os
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import depth_label, prim  # noqa: E402
from chainhashes.aes2r import _gmul  # noqa: E402

TR = 5
DATA_LEN = 20                     # shipped per-pixel shape: LE32(idx) ‖ 128-bit nonce
RC_LAST = np.frombuffer(prim.RC[1], dtype=np.uint8)   # shipped 2-round finaliser: RC[0], RC[1]

# MixColumns coefficient matrix (FIPS-197 § 5.1.3): out[j] = XOR_i M[j][i] · in[i].
M = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
GMUL = np.array([[_gmul(a, b) for b in range(256)] for a in range(256)], dtype=np.uint8)
ISB = prim._ISB_T


def oracle_full(comps, rounds):
    """Chosen-text oracle returning the full 128-bit ChainHash output."""
    def query(data: bytes) -> bytes:
        return prim.chainhash_full(data, comps, rounds=rounds, discard=False).to_bytes(16, "little")
    return query


def lam_set(active: int):
    """Λ-set active in one input byte (position `active`); the remaining
    19 bytes are a fresh random constant. Returns 256 chosen texts."""
    fixed = bytearray(os.urandom(DATA_LEN))
    texts = []
    for v in range(256):
        t = bytearray(fixed)
        t[active] = v
        texts.append(bytes(t))
    return texts


def peeled_set(query_full, texts):
    """P⁻¹ of the last ChainHash call (fixed key removed) → the r = 2
    observable y = k₂ ⊕ h₁(d) at each chosen text."""
    return np.stack([np.frombuffer(prim.peel_last(t, query_full(t)), dtype=np.uint8)
                     for t in texts])


def finish(query_full, texts, Y, k2):
    """κ → k₂ → h₁(text 0) → P⁻¹ → seed block 1; verify by re-querying the
    oracle on 4 fresh chosen texts and comparing full-output bytes."""
    h1 = (Y[0] ^ k2).tobytes()
    s1_lo, s1_hi = prim.invert_generic(prim.FIXED_KEY, texts[0], h1)
    comps = [s1_lo, s1_hi,
             int.from_bytes(k2[:8].tobytes(), "little"),
             int.from_bytes(k2[8:].tobytes(), "little")]
    ok = sum(prim.chainhash_full(d, comps, rounds=2, discard=False).to_bytes(16, "little")
             == query_full(d) for d in (os.urandom(DATA_LEN) for _ in range(4)))
    return comps, ok


def square_classic(query_full, n_sets=3):
    """Classical 4-round Square κ-byte engine: per κ byte, 2⁸ guesses tested
    by the XOR-sum of SB⁻¹(W[p] ⊕ g) over each Λ-set; intersect over `n_sets`
    to single out κ. Applies when the state entering P's last round is
    balanced but not active — i.e. T = 4 (shipped 20-byte shape at r = 2)."""
    g = np.arange(256, dtype=np.uint8)
    cands = [None] * 16
    sets = []
    for s in range(n_sets):
        texts = lam_set(active=s % min(DATA_LEN, 15))     # cycle through idx bytes 0 / 1 / 2
        Y = peeled_set(query_full, texts)
        W = prim._inv_mix_batch(Y ^ RC_LAST)              # (256 texts, 16)
        sets.append((texts, Y))
        for p in range(16):
            vals = ISB[W[:, p][None, :] ^ g[:, None]]     # (256 guesses, 256 texts)
            xs = np.bitwise_xor.reduce(vals, axis=1)      # (256 guesses,)
            c = set(np.nonzero(xs == 0)[0].tolist())
            cands[p] = c if cands[p] is None else (cands[p] & c)
    n_per_byte = [len(c) for c in cands]
    if any(n != 1 for n in n_per_byte):
        return None, 0, f"candidates/byte min {min(n_per_byte)} max {max(n_per_byte)}"
    kappa = np.array([next(iter(c)) for c in cands], dtype=np.uint8)
    k2 = prim._mix_batch(kappa[None, :])[0]
    texts, Y = sets[0]
    comps, ok = finish(query_full, texts, Y, k2)
    return comps, ok, "unique κ"


def square_pairconst(query_full):
    """T-1 == 2 engine (state active in one byte per column): 2¹⁶ per byte
    pair, one Λ-set. Fails at T = 4 (state balanced-but-not-active); ported
    from `keyrecover_r2.py` to back the r ≥ 3 negative control at shape 20."""
    texts = lam_set(active=0)
    Y = peeled_set(query_full, texts)
    W = prim._inv_mix_batch(Y ^ RC_LAST)
    g = np.arange(256, dtype=np.uint8)
    cands = [None] * 16
    for c in range(4):
        i = (-c) % 4
        pos = [r + 4 * ((c - r) % 4) for r in range(4)]
        S = [ISB[W[:, pos[j]][None, :] ^ g[:, None]] for j in range(4)]
        for j, j2 in ((0, 1), (1, 2), (2, 3), (0, 2), (1, 3), (0, 3)):
            A = GMUL[M[j2][i]][S[j]]
            A = A ^ A[:, :1]
            B = GMUL[M[j][i]][S[j2]]
            B = B ^ B[:, :1]
            rows = {}
            for gj in range(256):
                rows.setdefault(A[gj].tobytes(), set()).add(gj)
            pj, pj2 = set(), set()
            for gj2 in range(256):
                hit = rows.get(B[gj2].tobytes())
                if hit:
                    pj |= hit
                    pj2.add(gj2)
            for p, s in ((pos[j], pj), (pos[j2], pj2)):
                cands[p] = s if cands[p] is None else (cands[p] & s)
    if any(cs is None or len(cs) != 1 for cs in cands):
        return None, 0, "no unique κ"
    kappa = np.array([next(iter(cs)) for cs in cands], dtype=np.uint8)
    k2 = prim._mix_batch(kappa[None, :])[0]
    comps, ok = finish(query_full, texts, Y, k2)
    return comps, ok, "unique κ"


def run_cell(engine, rounds):
    hits = verified_n = 0
    notes = []
    t0 = time.perf_counter()
    for _ in range(TR):
        comps = [int.from_bytes(os.urandom(8), "little") for _ in range(2 * rounds)]
        query = oracle_full(comps, rounds)
        cand, ok, note = engine(query)
        verified_n += (ok == 4)
        hits += (ok == 4) and cand == comps[:4]
        notes.append(note)
    wall = time.perf_counter() - t0
    return hits, verified_n, wall, notes


# ---- shipped-observable mode (--model realistic) ----------------------------
IDX_BYTES = (0, 1, 2, 3)          # LE32(idx) — the only bytes the attacker sees enumerate
FLOOR = 8 / 256.0


def oracle_lo(comps, rounds):
    """Oracle returning lo(h_r) only — the 8 bytes the encoder consumes."""
    def query(data: bytes) -> bytes:
        return prim.chainhash_full(data, comps, rounds=rounds, discard=False).to_bytes(16, "little")[:8]
    return query


def lam_set_idx(active: int):
    """Λ-set active in one LE32(idx) byte; the 16 nonce bytes (and the other
    idx bytes) are a random constant the attacker did not choose."""
    assert active in IDX_BYTES
    return lam_set(active)


def lo_lane_screen(query_lo, texts):
    """Raw lo-lane balance and the column-peeled balance over one Λ-set.

    Peel: w = InvMixColumns(lo ⊕ RC[1][0:8]) on state columns 0, 1 — the two
    columns the lo lane exposes — giving 8 bytes of SR(SB(X')), X' the state
    entering the last finaliser round. Per position the survivor set of
    g ∈ 2⁸ under ⊕_texts SB⁻¹(w[p] ⊕ g) = 0 is returned; RC[1] is public, so
    the true post-whitening is g = 0 and "0 ∈ survivors" reads as "X' balanced
    at p". Returns (raw_balanced, peeled_balanced, survivors_per_position)."""
    lo = np.stack([np.frombuffer(query_lo(t), dtype=np.uint8) for t in texts])   # (256, 8)
    raw_bal = int(np.count_nonzero(np.bitwise_xor.reduce(lo, axis=0) == 0))
    buf = np.zeros((lo.shape[0], 16), dtype=np.uint8)
    buf[:, :8] = lo ^ RC_LAST[:8]
    W = prim._inv_mix_batch(buf)[:, :8]
    g = np.arange(256, dtype=np.uint8)
    surv = []
    for p in range(8):
        vals = ISB[W[:, p][None, :] ^ g[:, None]]
        xs = np.bitwise_xor.reduce(vals, axis=1)
        surv.append(set(np.nonzero(xs == 0)[0].tolist()))
    peeled_bal = sum(1 for s_ in surv if 0 in s_)
    return raw_bal, peeled_bal, [len(s_) for s_ in surv]


def run_realistic(rounds_list=(1, 2, 3, 4), n_sets=3):
    print("=" * 96)
    print("Shipped-observable screen through ChainHash<AES-ITB-128>, 20-byte pixel shape (T = 4)")
    print("=" * 96)
    print("  attacker model: lo lane h[0] only (no full-state peel); Λ-sets in LE32(idx) bytes 0 / 1 / 2;")
    print("  the 16 nonce bytes are a random constant per set the attacker sees but did not choose")
    print(f"  per set: raw balanced = lo bytes with zero XOR-sum; peeled balanced = g=0 survives the last-round")
    print(f"  column peel (state entering the last round balanced there); floor {FLOOR:.3f} per lane")
    print()
    summary = {}
    for rounds in rounds_list:
        t0 = time.perf_counter()
        tot_raw = tot_peeled = 0.0
        for _ in range(TR):
            comps = [int.from_bytes(os.urandom(8), "little") for _ in range(2 * rounds)]
            query = oracle_lo(comps, rounds)
            for s in range(n_sets):
                texts = lam_set_idx(IDX_BYTES[s % 3])
                raw_bal, peeled_bal, surv = lo_lane_screen(query, texts)
                tot_raw += raw_bal
                tot_peeled += peeled_bal
        n = TR * n_sets
        mean_raw, mean_peeled = tot_raw / n, tot_peeled / n
        tag_raw = "STRUCTURED" if mean_raw > FLOOR + 1 else "floor"
        tag_peeled = "STRUCTURED (after the column peel)" if mean_peeled > FLOOR + 1 else "floor"
        wall = time.perf_counter() - t0
        summary[rounds] = (mean_raw, mean_peeled)
        print(f"  r = {rounds} {depth_label(rounds):>8s}: raw lo balanced {mean_raw:4.2f}/8 ({tag_raw}), "
              f"peeled lo balanced {mean_peeled:4.2f}/8 ({tag_peeled}), "
              f"last survivors/pos {surv}, {n} sets, {wall:4.1f}s")
    print()
    print("  recovery on this observable: no candidate (structural) — both engines above need the full")
    print("  peeled Y = P⁻¹(h_r), which needs the hidden hi lane; residual route 2^64 hi-lane enumeration")
    print()
    print("-" * 96)
    print("Lab control (same script, discard OFF, the documented grant) — r = 2 classic engine must recover:")
    hits, verified_n, wall, notes = run_cell(square_classic, 2)
    tag = "RECOVERS both seed blocks" if hits >= TR - 1 else "fails"
    print(f"  classic 4-round Square r = 2 (768 chosen): verified {verified_n}/{TR}, ground truth {hits}/{TR}, "
          f"{wall:4.1f}s -> {tag}")
    print()
    print("Reading:")
    print("  * r = 1 (raw primitive, T = 4): the column peel exposes a balanced state — the 4-round Square")
    print("    distinguisher survives on the lo lane; no key is peeled (RC[1] public, seed at the front)")
    print("  * r >= 2: raw and peeled lo lane at the floor — the value entering the last call is")
    print("    pad(data) ⊕ seed_r ⊕ h_{r-1}(data), not a Λ-set; the discard-off recovery at r = 2 does not")
    print("    transfer: its peel needs the hi lane. Shipped depths r = 4 / 8 / 16 sit above r = 2.")



def main():
    print("=" * 96)
    print("Discard-off KEY RECOVERY through ChainHash<AES-ITB-128>, shipped 20-byte pixel shape (T = 4)")
    print("=" * 96)
    print(f"  shipped fin_rounds = 2 → RC_LAST = RC[1]; per-call rounds at L = 20 B: T = 4")
    print(f"  attacker model: Full KPA, discard OFF (full 128-bit output); Λ-sets in LE32(idx) bytes 0 / 1 / 2")
    print(f"  in the shipped pipeline only h[0] reaches the encoder — the lo-lane observable at r = 2 is at")
    print(f"  the floor / 2^64 (keyrecover_r2.py, keyrecover_r1_lo.py). This lift is a lab grant.")
    print()

    for name, engine, n_sets, chosen in (
            ("classic 4-round Square (2^8/byte)", square_classic, 3, 768),
            ("pair-constancy engine (2^16/pair)", square_pairconst, 1, 256)):
        for rounds in (2, 3, 4):
            hits, verified_n, wall, notes = run_cell(engine, rounds)
            tag = "RECOVERS both seed blocks" if hits >= TR - 1 else "fails"
            extra = "" if hits >= TR - 1 else f"  [{notes[0]}]"
            print(f"  {name:40s} r = {rounds} {depth_label(rounds):>8s} ({chosen:4d} chosen): "
                  f"verified {verified_n}/{TR}, ground truth {hits}/{TR}, {wall:5.1f}s -> {tag}{extra}")
        print()

    print("-" * 96)
    print("Reading:")
    print("  * classic engine at r = 2: 5/5 both seed blocks recovered (T - 1 = 3, state balanced)")
    print("  * pair-constancy engine at r = 2: 0/5 (T - 1 = 3, state not active in one byte per column)")
    print("  * both engines at r = 3 and r = 4: 0/5 (Λ-set lost through the second-round feed-forward)")
    print("  cost basis: 16 bytes × 2^8 guesses × 3 Λ-sets ≈ 2^13.6 XOR-sums (≈ 2^12 per Λ-set)")
    print()
    print("  shipped cascade depths: r = 4 (512-bit) / 8 (1024-bit) / 16 (2048-bit) — the r = 2 cell sits")
    print("  BELOW the shallowest shipped cascade; the shape-scoped result stands as a standalone-primitive")
    print("  measurement, not a shipped-pipeline recovery.")
    print()
    print("  shapes 36 / 68 (T = 5 / 7) are outside either order-1 engine's regime (state entering the last")
    print("  round is not balanced at order 1 — the classical 5-round Square set is order 4, 2^32 chosen")
    print("  texts, not run); no claim is made about those shapes.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="discard-off κ-byte key recovery (lab) / shipped-observable screen (realistic)")
    ap.add_argument("--model", choices=("lab", "realistic"), default="lab",
                    help="lab = discard off, the documented grant (default); "
                         "realistic = lo lane only, idx-only Λ-sets, random nonce per set")
    ap.add_argument("--rounds", type=int, nargs="*", default=[1, 2, 3, 4],
                    help="cascade depths for --model realistic")
    ap.add_argument("--sets", type=int, default=3, help="Λ-sets per trial for --model realistic")
    args = ap.parse_args()
    if args.model == "realistic":
        run_realistic(tuple(args.rounds), args.sets)
    else:
        main()
