#!/usr/bin/env python3
"""
Baseline integral / algebraic key-recovery on RAW 2-round AES (r=1, NO
ChainHash). Establishes the attack machinery before wrapping in ChainHash.

Primitive: chainhashes.aes2r._aes2r_128(data, seed_lo, seed_hi) -> (lo, hi),
i.e. AES_2round(pad(data), key = seed_hi<<64 | seed_lo).

Threat model (no cheating): the attacker holds ONLY an oracle  data -> output;
it never sees the key. Ground-truth comparison happens at the END, for
reporting (verification, not an attack input).

Why the textbook integral DISTINGUISHES but does not RECOVER on 2 rounds: a
Λ-set (plaintext byte 0 active) yields 4 active + 12 constant output bytes —
both categories are trivially balanced (Σ over an active byte = perm of all
values = 0; Σ over a constant byte = 256 copies = 0), so peeling the last
AddRoundKey by a balance check gives no discrimination.

What DOES work on 2 rounds: the final round has NO MixColumns, so each active
output byte satisfies
    ct[pos] = SB( a · SB(pt0 ⊕ k0[0]) ⊕ C ) ⊕ k2[pos],   a ∈ {1,2,3}, C const.
Recover (k0[0], k2[pos], a) by the structural test: over the Λ-set,
    SB^{-1}(ct[pos] ⊕ k2g) ⊕ a·SB(pt0 ⊕ k0g)  is CONSTANT  iff the guess is right.
k0[0] is a master-key byte (k0 == master key for AES-128), recovered blind.
"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phase2_theory"))
from chainhashes.aes2r import SBOX, _aes2r_128, _key_expansion, _RCON, NR, _gmul

INV_SBOX = [0] * 256
for _x in range(256):
    INV_SBOX[SBOX[_x]] = _x


def make_oracle(seed_lo, seed_hi):
    def query(data: bytes):
        return _aes2r_128(data, seed_lo, seed_hi)
    return query


def _ct16(out):
    lo, hi = out
    return hi.to_bytes(8, "big") + lo.to_bytes(8, "big")


def recover_k0_byte0(query, n_lambda=1, rng=None):
    """Blind: recover master-key byte 0 from Λ-sets active in plaintext byte 0."""
    rng = rng or (lambda n: os.urandom(n))
    total_calls = 0
    k0_inter = None
    active_seen = []
    for _ in range(n_lambda):
        fixed = rng(14)
        cts = []
        for v in range(256):
            cts.append(_ct16(query(bytes([v]) + fixed)))
            total_calls += 1
        active = [p for p in range(16) if len({ct[p] for ct in cts}) > 1]
        active_seen = active
        k0_for_set = set()
        for pos in active:
            for a in (1, 2, 3):
                T = [_gmul(a, SBOX[v]) for v in range(256)]   # depends on k0g below
                for k0g in range(256):
                    Tk = [_gmul(a, SBOX[v ^ k0g]) for v in range(256)]
                    base_ct = cts[0][pos]
                    for k2g in range(256):
                        c0 = INV_SBOX[base_ct ^ k2g] ^ Tk[0]
                        good = True
                        for v in range(1, 256):
                            if (INV_SBOX[cts[v][pos] ^ k2g] ^ Tk[v]) != c0:
                                good = False
                                break
                        if good:
                            k0_for_set.add(k0g)
        k0_inter = k0_for_set if k0_inter is None else (k0_inter & k0_for_set)
    return k0_inter, total_calls, active_seen


def inverse_key_schedule(k_last: bytes, nr: int) -> bytes:
    W = {}
    for c in range(4):
        W[4 * nr + c] = list(k_last[4 * c:4 * c + 4])
    for i in range(4 * nr + 3, 3, -1):
        if i % 4 == 0:
            t = W[i - 1][1:] + W[i - 1][:1]
            t = [SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
            W[i - 4] = [W[i][j] ^ t[j] for j in range(4)]
        else:
            W[i - 4] = [W[i][j] ^ W[i - 1][j] for j in range(4)]
    return bytes(W[0] + W[1] + W[2] + W[3])


if __name__ == "__main__":
    print("=" * 70)
    print("Baseline integral key-recovery — RAW 2-round AES (no ChainHash)")
    print("=" * 70)
    TRIALS = 5
    ok = 0
    for t in range(TRIALS):
        seed_lo = int.from_bytes(os.urandom(8), "big")
        seed_hi = int.from_bytes(os.urandom(8), "big")
        true_master = ((seed_hi << 64) | seed_lo).to_bytes(16, "big")
        query = make_oracle(seed_lo, seed_hi)

        k0c, nq, active = recover_k0_byte0(query, n_lambda=1)
        true_k0_0 = true_master[0]   # k0 == master key for AES-128
        hit = (true_k0_0 in k0c) and (len(k0c) <= 4)
        ok += hit
        print(f"  trial {t}: active out-bytes={active}  "
              f"k0[0] candidates={sorted(k0c)}  true={true_k0_0}  "
              f"{'OK' if hit else 'MISS'}  ({nq} queries)")

    print(f"\nRESULT: {ok}/{TRIALS} recovered true master-key byte 0 blind "
          f"(candidate set <=4), 1 Λ-set (256 chosen-data queries) each.")
    print("Attacker input: ONLY the oracle. No key access (ground-truth = verify only).")
    if ok == TRIALS:
        print(">>> Raw 2-round AES leaks key bytes to the integral structure — "
              "machinery CONFIRMED. Next: wrap in ChainHash (discard on/off).")
