#!/usr/bin/env python3
"""Direction 1: DATA-differential attack surface through ChainHash<2-round-AES>.

The differential pre-screen flagged aes2r (ddt8_max=1.0) on SEED differences;
here we measure the attacker-realistic DATA differential: fix the secret seed,
apply a single-active-byte input difference Δ to `data`, over many random bases,
and measure two differential distinguishers of the output:

  * max_dp   — max over (output byte, δ) of P(out_byte_diff = δ).  Random ~ 1/256.
  * zero_bytes — # output bytes that are ALWAYS unchanged (truncated
                 differential).  Raw 2-round AES: a 1-active-byte Δ spreads to
                 only 4 output bytes, so the other bytes are zero-diff w.p. 1 —
                 a probability-1 truncated differential. Does it survive ChainHash?

r=1 = no ChainHash (baseline). discard ON = lo lane (8 bytes) only.
"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phase2_theory"))
from chainhashes.aes2r import chainhash_full

def diff_probe(seed_comps, rounds, discard, delta, N):
    nbytes = 8 if discard else 16
    hist = [[0] * 256 for _ in range(nbytes)]
    nonzero_seen = [False] * nbytes
    for _ in range(N):
        d = bytearray(os.urandom(15))
        d2 = bytearray(d)
        for i, dv in delta.items():
            d2[i] ^= dv
        o1 = chainhash_full(bytes(d), seed_comps, rounds=rounds, discard=discard)
        o2 = chainhash_full(bytes(d2), seed_comps, rounds=rounds, discard=discard)
        diff = (o1 ^ o2).to_bytes(nbytes, "big")
        for p in range(nbytes):
            hist[p][diff[p]] += 1
            if diff[p] != 0:
                nonzero_seen[p] = True
    max_dp = max(max(h) / N for h in hist)
    zero_bytes = sum(1 for p in range(nbytes) if not nonzero_seen[p])
    return max_dp, zero_bytes, nbytes

N = 8192
DELTAS = [{0: 0x01}, {0: 0x80}, {0: 0xFF}]   # single active data byte, a few values
print("=" * 74)
print(f"DATA-differential through ChainHash<2-round-AES>  (N={N} bases/Δ, single active byte)")
print("=" * 74)
print(f"{'rounds':>6}{'discard':>8}{'out_b':>6}{'max_dp':>10}{'rand':>8}{'zero_bytes':>11}  verdict")
print("-" * 74)
for rounds in (1, 2, 4):
    for discard in (False, True):
        best_dp = 0.0
        min_zero = 99
        nb = 8 if discard else 16
        for delta in DELTAS:
            seed_comps = [int.from_bytes(os.urandom(8), "big") for _ in range(2 * rounds)]
            dp, zb, nb = diff_probe(seed_comps, rounds, discard, delta, N)
            best_dp = max(best_dp, dp)
            min_zero = min(min_zero, zb)
        rand = 1 / 256
        leak = (best_dp > rand * 4) or (min_zero > 0)
        verdict = "DIFFERENTIAL LEAK" if leak else "no differential signal"
        print(f"{rounds:>6}{str(discard):>8}{nb:>6}{best_dp:>10.4f}{rand:>8.4f}"
              f"{min_zero:>11}  {verdict}")
print("-" * 74)
print("zero_bytes>0 = truncated-differential signature; max_dp>>1/256 = biased differential.")
