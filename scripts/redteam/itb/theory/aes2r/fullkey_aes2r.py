#!/usr/bin/env python3
"""
Full master-key recovery on RAW 2-round AES (r = 1, NO ChainHash) — the
16-Λ-set extension of integral_aes2r.py's single-byte engine, run to place
aes2r's standalone break on the same footing as the AES-ITB-128 one-pair
inversion (HARNESS.md § 3.10 retrospective).

integral_aes2r.py recovers master-key byte 0 from one Λ-set active in
plaintext byte 0. The same structural test applied to a Λ-set active in
plaintext byte b recovers k0[b] (k0 == master key for AES-128):
    SB^{-1}(ct[pos] ⊕ k2g) ⊕ a·SB(pt_b ⊕ k0g)  is CONSTANT  iff (k0g, k2g, a) is right,
for each active output byte pos. Plaintext byte 15 is the pad constant
(0x80) and cannot be made active, so k0[15] is brute-forced (2^8) against
one known (data, output) pair. Attacker input: the oracle only — 15 Λ-sets
(3840 chosen texts) plus one verification pair; ground truth compared at
the END for reporting.

Two oracle modes, as in keyrecover_r2.py: discard OFF (full 128-bit output)
and discard ON (lo lane only) — with the discard, a Λ-set whose four active
output bytes all fall in the hidden hi lane cannot yield its k0 byte, and
the count of recovered bytes is reported.
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "_common"))
from chainhashes.aes2r import SBOX, _gmul, _aes2r_128, MASK64, chainhash_full  # noqa: E402
from integral_aes2r import INV_SBOX, _ct16  # noqa: E402

GM = {a: [_gmul(a, x) for x in range(256)] for a in (1, 2, 3)}


def make_chain_oracle(seed_comps, rounds, discard):
    """Same oracle shape as keyrecover_r2.py (inlined: that script has no
    import guard). discard -> the attacker sees the lo lane only."""
    def query(data: bytes):
        full = chainhash_full(data, seed_comps, rounds=rounds, discard=False)
        if discard:
            full &= MASK64
        return (full & MASK64, (full >> 64) & MASK64)
    return query


def recover_k0_byte(query, b, rng=os.urandom):
    """Blind: recover master-key byte b from one Λ-set active in plaintext byte b."""
    fixed = bytearray(rng(15))
    cts = []
    for v in range(256):
        d = bytearray(fixed)
        d[b] = v
        cts.append(_ct16(query(bytes(d))))
    active = [p for p in range(16) if len({ct[p] for ct in cts}) > 1]
    k0c = set()
    for pos in active:
        for a in (1, 2, 3):
            ga = GM[a]
            base_ct = cts[0][pos]
            for k0g in range(256):
                Tk = [ga[SBOX[v ^ k0g]] for v in range(256)]
                for k2g in range(256):
                    c0 = INV_SBOX[base_ct ^ k2g] ^ Tk[0]
                    good = True
                    for v in range(1, 256):
                        if (INV_SBOX[cts[v][pos] ^ k2g] ^ Tk[v]) != c0:
                            good = False
                            break
                    if good:
                        k0c.add(k0g)
    return k0c, active


def recover_master(query, discard):
    """15 Λ-sets -> k0[0..14] candidates; k0[15] by 2^8 brute force against
    one known pair. Returns (recovered_bytes_count, master or None)."""
    cand = []
    for b in range(15):
        k0c, _ = recover_k0_byte(query, b)
        cand.append(sorted(k0c))
    known_d = os.urandom(15)
    known_out = query(known_d)
    unresolved = [b for b in range(15) if len(cand[b]) != 1]
    if unresolved:
        return 15 - len(unresolved), None
    prefix = bytes(c[0] for c in cand)
    for last in range(256):
        master = prefix + bytes([last])
        seed_hi = int.from_bytes(master[:8], "big")
        seed_lo = int.from_bytes(master[8:], "big")
        lo, hi = _aes2r_128(known_d, seed_lo, seed_hi)
        if discard:
            hi = 0
        if (lo, hi) == known_out:
            return 16, master
    return 15, None


if __name__ == "__main__":
    print("=" * 74)
    print("Full master-key recovery — RAW 2-round AES (r = 1, no ChainHash), 15 Λ-sets + 2^8")
    print("=" * 74)
    TRIALS = 3
    for discard in (False, True):
        ok = 0
        counts = []
        for t in range(TRIALS):
            seed_comps = [int.from_bytes(os.urandom(8), "big") for _ in range(2)]
            true_master = ((seed_comps[1] << 64) | seed_comps[0]).to_bytes(16, "big")
            query = make_chain_oracle(seed_comps, 1, discard)
            n, master = recover_master(query, discard)
            counts.append(n)
            hit = master == true_master
            ok += hit
            print(f"  discard={discard!s:>5} trial {t}: k0 bytes resolved {n}/16  "
                  f"{'OK' if hit else 'MISS'}  (3840 chosen + 1 known text)")
        print(f"RESULT discard={discard}: {ok}/{TRIALS} full 128-bit master keys recovered; "
              f"resolved bytes per trial {counts}.")
    print("-" * 74)
    print("Attacker input: ONLY the oracle. No key access (ground-truth = verify only).")
