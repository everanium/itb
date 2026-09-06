#!/usr/bin/env python3
"""
Round-count Square ladder on the aes2r control primitive — the aes2r mirror of
the AES-ITB-128 keyrecover_kbyte_go engine's classical-square-{3,4,5} modes.

Structural note (decides the target). aes2r is a raw secret-key block cipher:
one padded 16-byte block, NR standard-AES rounds, key = seed. It has NO
multi-block absorb, so the AES-ITB-128 per-pixel shape ladder (data-len
13/20/36/68 -> T=3/4/5/7) does NOT apply — aes2r's round count is the module
global NR (chainhashes.aes2r.set_rounds), not a data length. The AES-ITB-128
kappa-peel also does not port: aes2r rounds use secret expanded round keys, not
public round constants with an additive seed, so recovery here is the textbook
last-round-key Square (recover the last round key, invert the key schedule to
the master key = seed), not the k2 additive peel. The mirror therefore varies
NR to match the AES-ITB-128 T regimes:

    aes2r NR=3  ~  AES-ITB-128 T=3 (shape 13): last-round-key Square is VACUOUS
                   (state entering the last round is per-byte uniform after 2
                   rounds, so every key guess balances) — mirrors the T=3
                   kappa vacuity that needs the pair-constancy engine instead.
    aes2r NR=4  ~  AES-ITB-128 T=4 (shape 20): order-1 recovers (balanced after
                   3 rounds, textbook 4-round Square).
    aes2r NR=5  ~  AES-ITB-128 T=5 (shape 36): needs an order-4 2^32 diagonal
                   set (balanced after 4 rounds). At ~30 microseconds/text pure
                   Python that is ~36 h — INFEASIBLE here; the feasible path is
                   the companion Go program square5_go/, which recovers the full
                   aes2r master key from the 2^32 {1,6,11,12} diagonal in ~21 s
                   at 16 threads with AES-NI rounds (~97 s on the software
                   rounds; this script keeps only the Python-feasible NR=3/NR=4
                   cells).

ChainHash feed-forward (r >= 2) is run at NR=4 as the dissolution control: the
last call's round key is data-dependent (key = comps[2r-2:2r] ^ h_{r-1}(data)),
so a fixed-key last-round peel finds no consistent key and fails — the aes2r
analogue of keyrecover_r2.py at NR=2 and of the Go engine's r>=3 dissolution.

Threat model (no cheating): the attacker holds ONLY an oracle data -> output and
public-schema knowledge of the Lambda-set structure. Ground-truth comparison
happens at the END, for reporting (verification, not an attack input).
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "_common"))
from chainhashes.aes2r import (  # noqa: E402
    _aes2r_128, chainhash_full, MASK64, set_rounds,
)
from integral_aes2r import INV_SBOX, _ct16, inverse_key_schedule  # noqa: E402


def raw_oracle(seed_lo, seed_hi):
    def query(data: bytes):
        return _aes2r_128(data, seed_lo, seed_hi)
    return query


def chain_oracle(seed_comps, rounds):
    def query(data: bytes):
        full = chainhash_full(data, seed_comps, rounds=rounds, discard=False)
        return (full & MASK64, (full >> 64) & MASK64)
    return query


def last_round_key_mask(query, active_byte, rng=os.urandom):
    """One Lambda-set active in plaintext byte `active_byte`. For each output
    position the balance test XOR_texts InvSBOX(ct[pos] ^ g) == 0 singles out
    the last-round-key byte at that position. Returns a per-position survivor
    set (list of 256 candidate bytes each) — a position with a data-dependent
    key balances for no guess and returns an empty survivor list."""
    fixed = bytearray(rng(15))
    cts = []
    for v in range(256):
        d = bytearray(fixed)
        d[active_byte] = v
        cts.append(_ct16(query(bytes(d))))
    masks = []
    for pos in range(16):
        surv = []
        for g in range(256):
            x = 0
            for v in range(256):
                x ^= INV_SBOX[cts[v][pos] ^ g]
            if x == 0:
                surv.append(g)
        masks.append(surv)
    return masks


def recover_last_round_key(query, n_sets=4):
    """Intersect the per-position survivor sets across n_sets independent
    Lambda-sets. Returns (k_last or None, resolved_positions, total_queries)."""
    acc = [set(range(256)) for _ in range(16)]
    total = 0
    for s in range(n_sets):
        masks = last_round_key_mask(query, active_byte=s % 15)
        total += 256
        for pos in range(16):
            acc[pos] &= set(masks[pos])
    resolved = sum(1 for pos in range(16) if len(acc[pos]) == 1)
    if resolved != 16:
        return None, resolved, total
    return bytes(next(iter(acc[pos])) for pos in range(16)), 16, total


def raw_master_from_last_key(k_last, nr):
    """Invert the key schedule from the last (round-nr) key to the master key."""
    return inverse_key_schedule(k_last, nr)


if __name__ == "__main__":
    print("=" * 78)
    print("aes2r round-count Square ladder — mirror of keyrecover_kbyte_go square-{3,4,5}")
    print("=" * 78)

    TRIALS = 3

    # --- aes2r NR=3 (~ AES-ITB-128 T=3): last-round-key Square is vacuous ------
    set_rounds(3)
    vac = 0
    for t in range(TRIALS):
        slo = int.from_bytes(os.urandom(8), "big")
        shi = int.from_bytes(os.urandom(8), "big")
        masks = last_round_key_mask(raw_oracle(slo, shi), active_byte=0)
        # vacuous == every position keeps all 256 guesses (uniform state peel)
        allfull = all(len(m) == 256 for m in masks)
        vac += allfull
    print(f"NR=3 raw, order-1: {vac}/{TRIALS} trials VACUOUS "
          f"(all 16 positions keep 256 candidates) — last-round-key Square gives no "
          f"discrimination, mirrors the AES-ITB-128 T=3 kappa vacuity.")

    # --- aes2r NR=4 (~ AES-ITB-128 T=4): order-1 recovers ---------------------
    set_rounds(4)
    ok = 0
    for t in range(TRIALS):
        slo = int.from_bytes(os.urandom(8), "big")
        shi = int.from_bytes(os.urandom(8), "big")
        true_master = ((shi << 64) | slo).to_bytes(16, "big")
        k_last, resolved, nq = recover_last_round_key(raw_oracle(slo, shi), n_sets=4)
        master = raw_master_from_last_key(k_last, 4) if k_last is not None else None
        hit = master == true_master
        ok += hit
        print(f"  NR=4 raw trial {t}: last-key resolved {resolved}/16  "
              f"master {'OK' if hit else 'MISS'}  ({nq} chosen texts)")
    print(f"NR=4 raw, order-1: {ok}/{TRIALS} full master keys recovered "
          f"(4 Lambda-sets, 1024 chosen texts) — textbook 4-round Square, "
          f"mirrors the AES-ITB-128 T=4 order-1 recovery.")

    # --- aes2r NR=4 ChainHash r=2/3/4: last-round peel dissolves ---------------
    set_rounds(4)
    for rounds in (2, 3, 4):
        fails = 0
        for t in range(TRIALS):
            comps = [int.from_bytes(os.urandom(8), "big") for _ in range(2 * rounds)]
            k_last, resolved, _ = recover_last_round_key(chain_oracle(comps, rounds), n_sets=4)
            if k_last is None:
                fails += 1
        print(f"  NR=4 ChainHash r={rounds}: {fails}/{TRIALS} trials FAIL to resolve "
              f"a consistent last-round key (data-dependent call key) — "
              f"mirrors keyrecover_r2.py and the Go engine's r>=3 dissolution.")

    # --- aes2r NR=5 (~ AES-ITB-128 T=5): order-4 2^32 — Python-infeasible ------
    print("-" * 78)
    print("NR=5 raw, order-4 (2^32 diagonal set): balanced after 4 rounds -> recovers "
          "(5-round Square). ~36 h in pure Python (NOT RUN here); the companion Go "
          "program square5_go/ recovers the full aes2r master key from the 2^32 "
          "{1,6,11,12} diagonal in ~21 s at 16 threads (AES-NI rounds; ~97 s on the "
          "software rounds). The AES-ITB-128 T=5 order-4 2^32 cell runs in ~21 s at "
          "16 threads.")
    print("Attacker input: ONLY the oracle + public Lambda-set schema "
          "(ground-truth = verify only).")
