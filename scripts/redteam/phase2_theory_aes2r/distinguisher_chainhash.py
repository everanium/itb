#!/usr/bin/env python3
"""
Does the 2-round-AES integral structure SURVIVE ChainHash wrapping?

Structure-agnostic distinguisher: feed a Λ-set (data byte 0 active, 256 values)
through chainhash_full(rounds, discard) and measure
  * #active output bytes (vary over the set) — random fn ~= all bytes active
  * balanced? (every output byte XOR-sums to 0 over the 256 texts) — the integral
    signature; a random fn is balanced only by chance (P ~ 2^-8 per byte)

The feed-forward k_i = seed_i ^ h_{i-1} makes each round's KEY data-dependent
(it varies across the Λ-set), which is exactly what should break the
"fixed key, structured plaintext" premise the integral needs. discard hHi
(lo-lane only) hides half the state on top. r=1 = no ChainHash (baseline).
"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phase2_theory"))
from chainhashes.aes2r import chainhash_full

def lam_outputs(seed_comps, rounds, discard):
    fixed = os.urandom(14)
    outs = []
    for v in range(256):
        data = bytes([v]) + fixed
        o = chainhash_full(data, seed_comps, rounds=rounds, discard=discard)
        nbytes = 8 if discard else 16
        outs.append(o.to_bytes(nbytes, "big"))
    return outs, nbytes

def analyze(outs, nbytes):
    active = sum(1 for p in range(nbytes) if len({o[p] for o in outs}) > 1)
    bal = sum(1 for p in range(nbytes)
              if (lambda s: s == 0)(__import__("functools").reduce(lambda a, o: a ^ o[p], outs, 0)))
    return active, bal

print("=" * 72)
print("Integral-survival distinguisher through ChainHash<2-round-AES>")
print("=" * 72)
print(f"{'rounds':>6} {'discard':>8} {'out_bytes':>10} {'#active':>8} {'#balanced':>10}  verdict")
print("-" * 72)

REPS = 8
for rounds in (1, 2, 4):
    for discard in (True, False):
        # average over several random seeds
        tot_active = tot_bal = 0
        nbytes = 8 if discard else 16
        for _ in range(REPS):
            seed_comps = [int.from_bytes(os.urandom(8), "big") for _ in range(2 * rounds)]
            outs, nbytes = lam_outputs(seed_comps, rounds, discard)
            a, b = analyze(outs, nbytes)
            tot_active += a; tot_bal += b
        avg_active = tot_active / REPS
        avg_bal = tot_bal / REPS
        # integral signature: NOT all bytes active AND all bytes balanced
        rand_bal = nbytes / 256.0   # expected balanced bytes for a random fn
        structured = (avg_active < nbytes) or (avg_bal > rand_bal + 1)
        verdict = "STRUCTURED (integral leak)" if structured else "looks random (no leak)"
        print(f"{rounds:>6} {str(discard):>8} {nbytes:>10} {avg_active:>8.1f} "
              f"{avg_bal:>10.1f}  {verdict}")

print("-" * 72)
print("r=1 = no ChainHash (baseline). random-fn expects #active=out_bytes, "
      "#balanced~=out_bytes/256.")
