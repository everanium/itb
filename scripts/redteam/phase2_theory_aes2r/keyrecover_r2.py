#!/usr/bin/env python3
"""Direction 2: can the surviving r=2 integral distinguisher be converted into
KEY RECOVERY? Run the working baseline integral attack (recover_k0_byte0)
against a ChainHash r=2 oracle. Control r=1 must recover; r=2 is the question.

discard OFF (full 128-bit output) is the easiest case for the attacker; if it
fails there, discard ON (lo lane only) is strictly harder.
"""
import os, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "phase2_theory"))
from chainhashes.aes2r import chainhash_full, MASK64
from integral_aes2r import recover_k0_byte0

def make_chain_oracle(seed_comps, rounds, discard):
    def query(data: bytes):
        full = chainhash_full(data, seed_comps, rounds=rounds, discard=False)  # need full for (lo,hi)
        if discard:
            full &= MASK64                          # attacker only sees lo lane
        return (full & MASK64, (full >> 64) & MASK64)
    return query

print("=" * 70)
print("Direction 2: integral KEY-RECOVERY through ChainHash r=1 (control) / r=2")
print("=" * 70)
for rounds in (1, 2):
    for discard in (False, True):
        hits = 0
        TR = 5
        for _ in range(TR):
            seed_comps = [int.from_bytes(os.urandom(8), "big") for _ in range(2 * rounds)]
            # round-0 key = seed_comps[1]<<64 | seed_comps[0]; master byte 0 = top of seed_hi
            true_b0 = (seed_comps[1] >> 56) & 0xFF
            query = make_chain_oracle(seed_comps, rounds, discard)
            k0c, nq, active = recover_k0_byte0(query, n_lambda=1)
            if k0c is not None and true_b0 in k0c and len(k0c) <= 4:
                hits += 1
        tag = "RECOVERS round-0 key byte" if hits >= TR - 1 else "fails (no key recovery)"
        print(f"  rounds={rounds} discard={discard}: {hits}/{TR}  "
              f"(last active out-bytes={active})  -> {tag}")
print("-" * 70)
print("r=1 control should recover; r=2 tests whether the feed-forward blocks the")
print("integral key-recovery peel (round-0 key masked by active input; round-1 key")
print("K1 = seed1 ^ ct0 is data-dependent, so the standard last-round peel fails).")
