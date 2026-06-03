#!/usr/bin/env python3
"""Direction 3 (background, ~1-2h): 3rd-order integral at r=4, 2^24 texts/set,
discard OFF and ON. Does a 3rd-order Λ-set leave a balanced signature at r=4
where 1st- and 2nd-order died? Slow on purpose; run detached."""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phase2_theory"))
from chainhashes.aes2r import chainhash_full

def ho_balance(seed_comps, rounds, discard, order):
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
        if (idx & 0xFFFFF) == 0:
            print(f"  ... {idx}/{N}", flush=True)
    return sum(1 for p in range(nbytes) if acc[p] == 0), nbytes

print("3rd-order integral, r=4, 2^24 texts/set (discard OFF then ON)", flush=True)
for discard in (False, True):
    seed_comps = [int.from_bytes(os.urandom(8), "big") for _ in range(8)]
    bal, nb = ho_balance(seed_comps, 4, discard, 3)
    rexp = nb / 256.0
    tag = "HIGHER-ORDER LEAK" if bal > rexp + 1 else "random (no 3rd-order leak)"
    print(f"RESULT r=4 order=3 discard={discard}: #balanced={bal} "
          f"rand_exp={rexp:.3f}  {tag}", flush=True)
print("DONE", flush=True)
