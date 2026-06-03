#!/usr/bin/env python3
"""Higher-order integral probe: does a 2nd-order Λ-set (2 active data bytes,
2^16 texts) leave a balanced signature at r=4, where the 1st-order integral
died? Higher order reaches deeper rounds — the natural escalation."""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phase2_theory"))
from chainhashes.aes2r import chainhash_full

def ho_balance(seed_comps, rounds, discard, order=2):
    nbytes = 8 if discard else 16
    acc = [0] * nbytes
    fixed = bytearray(os.urandom(14))
    N = 256 ** order
    for idx in range(N):
        d = bytearray(fixed)
        x = idx
        for k in range(order):
            d[k] = x & 0xFF
            x >>= 8
        o = chainhash_full(bytes(d), seed_comps, rounds=rounds, discard=discard)
        ob = o.to_bytes(nbytes, "big")
        for p in range(nbytes):
            acc[p] ^= ob[p]
    return sum(1 for p in range(nbytes) if acc[p] == 0), nbytes, N

print("Higher-order (2nd) integral through ChainHash<2-round-AES>  (2^16 texts/set)")
print(f"{'rounds':>6}{'order':>6}{'discard':>8}{'#balanced':>10}{'rand_exp':>10}  verdict")
print("-" * 60)
for rounds in (2, 4):
    for discard in (False, True):
        seed_comps = [int.from_bytes(os.urandom(8), "big") for _ in range(2 * rounds)]
        bal, nb, N = ho_balance(seed_comps, rounds, discard, order=2)
        rexp = nb / 256.0
        v = "HIGHER-ORDER LEAK" if bal > rexp + 1 else "random (no 2nd-order leak)"
        print(f"{rounds:>6}{2:>6}{str(discard):>8}{bal:>10}{rexp:>10.3f}  {v}")
