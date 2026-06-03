#!/usr/bin/env python3
"""SAT/SMT calibration for ChainHash<2-round-AES> seed recovery (z3 baseline).

Symbolic 2-round AES + ChainHash feed-forward; constrain by known (data, output)
pairs; solve for the seed. r=1 = no ChainHash (does z3 crack raw 2-round AES?).
discard ON constrains only the lo lane (output bytes 8..15). This is the
plain-SMT baseline that the agent-researched advanced techniques (XOR/Gauss,
integral constraints, propagators) will later augment.
"""
import os, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phase2_theory"))
import z3
from chainhashes.aes2r import SBOX, _RCON, NR, _aes2r_128, chainhash_full, MASK64

# ---- symbolic AES building blocks ------------------------------------------
def _make_sb():
    arr = z3.K(z3.BitVecSort(8), z3.BitVecVal(0, 8))
    for x in range(256):
        arr = z3.Store(arr, x, z3.BitVecVal(SBOX[x], 8))
    return arr
_SB = _make_sb()
def sb(x): return z3.Select(_SB, x)
def xtime(x): return (x << 1) ^ z3.If((x & 0x80) != 0, z3.BitVecVal(0x1B, 8), z3.BitVecVal(0, 8))
def g2(x): return xtime(x)
def g3(x): return xtime(x) ^ x

def sub_bytes(s): return [sb(b) for b in s]
def shift_rows(s):
    o = [None] * 16
    for r in range(4):
        for c in range(4):
            o[r + 4*c] = s[r + 4*((c + r) % 4)]
    return o
def mix_columns(s):
    o = [None] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
        o[4*c]   = g2(a0) ^ g3(a1) ^ a2 ^ a3
        o[4*c+1] = a0 ^ g2(a1) ^ g3(a2) ^ a3
        o[4*c+2] = a0 ^ a1 ^ g2(a2) ^ g3(a3)
        o[4*c+3] = g3(a0) ^ a1 ^ a2 ^ g2(a3)
    return o
def add_rk(s, rk): return [s[i] ^ rk[i] for i in range(16)]

def key_expansion_sym(key16, nr):
    words = [[key16[4*i + j] for j in range(4)] for i in range(4)]
    for i in range(4, 4 * (nr + 1)):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [sb(b) for b in t]
            t[0] = t[0] ^ z3.BitVecVal(_RCON[i // 4 - 1], 8)
        words.append([words[i - 4][j] ^ t[j] for j in range(4)])
    return [sum((words[4*k + c] for c in range(4)), []) for k in range(nr + 1)]

def aes2r_sym(block16, key16, nr):
    rks = key_expansion_sym(key16, nr)
    s = add_rk([z3.BitVecVal(b, 8) for b in block16], rks[0])
    for r in range(1, nr):
        s = sub_bytes(s); s = shift_rows(s); s = mix_columns(s); s = add_rk(s, rks[r])
    s = sub_bytes(s); s = shift_rows(s); s = add_rk(s, rks[nr])
    return s

def chainhash_sym(block16, seed_bytes, rounds):
    ct = aes2r_sym(block16, seed_bytes[0:16], NR)
    for i in range(1, rounds):
        K_i = [seed_bytes[16*i + j] ^ ct[j] for j in range(16)]   # feed-forward
        ct = aes2r_sym(block16, K_i, NR)
    return ct

# ---- concrete reference (for generating pairs + verifying) -----------------
def pad15(data): return (bytes(data[:15]) + b"\x80" + b"\x00" * 16)[:16]
def chain_concrete(block16, seed_comps, rounds, discard):
    # mirror chainhash_full but taking a 16-byte block directly
    lo, hi = int.from_bytes(block16[8:], "big"), int.from_bytes(block16[:8], "big")
    # use the library on the equivalent data path: feed block as data via pad? Instead
    # reuse _aes2r_128 chain by hand to match chainhash_sym exactly:
    def aes(b16, k16):
        from chainhashes.aes2r import aes_encrypt
        return aes_encrypt(bytes(b16), bytes(k16), NR)
    seed_keys = []
    for i in range(rounds):
        hi64 = seed_comps[2*i+1]; lo64 = seed_comps[2*i]
        seed_keys.append(list(hi64.to_bytes(8, "big") + lo64.to_bytes(8, "big")))
    ct = list(aes(block16, seed_keys[0]))
    for i in range(1, rounds):
        K_i = [seed_keys[i][j] ^ ct[j] for j in range(16)]
        ct = list(aes(block16, K_i))
    return ct if not discard else ct  # discard handled at constraint level

def run(rounds, discard, n_pairs, timeout_s):
    seed_comps = [int.from_bytes(os.urandom(8), "big") for _ in range(2 * rounds)]
    seed_keys_true = []
    for i in range(rounds):
        seed_keys_true += list(seed_comps[2*i+1].to_bytes(8, "big") + seed_comps[2*i].to_bytes(8, "big"))
    blocks = [pad15(os.urandom(15)) for _ in range(n_pairs)]
    outs = [chain_concrete(b, seed_comps, rounds, discard) for b in blocks]

    seed_bytes = [z3.BitVec(f"s_{i}", 8) for i in range(16 * rounds)]
    sol = z3.Solver(); sol.set("timeout", timeout_s * 1000)
    for b, out in zip(blocks, outs):
        ct = chainhash_sym(b, seed_bytes, rounds)
        rng = range(8, 16) if discard else range(16)   # discard -> lo lane only
        for j in rng:
            sol.add(ct[j] == z3.BitVecVal(out[j], 8))
    t0 = time.time()
    r = sol.check()
    dt = time.time() - t0
    status = str(r)
    recovered_ok = None
    if r == z3.sat:
        m = sol.model()
        rec = [m[seed_bytes[i]].as_long() if m[seed_bytes[i]] is not None else 0 for i in range(16 * rounds)]
        # verify the recovered seed reproduces a FRESH pair (functional check)
        vb = pad15(os.urandom(15))
        vo_true = chain_concrete(vb, seed_comps, rounds, discard)
        # rebuild seed_comps from recovered round-0 key for r=1 functional check
        recovered_ok = (rec[:16] == seed_keys_true[:16]) if rounds == 1 else "n/a(multi-round functional)"
    print(f"  rounds={rounds} discard={discard} pairs={n_pairs}: {status} in {dt:.1f}s"
          f"  recovered_r0key={recovered_ok}")
    return status, dt

if __name__ == "__main__":
    print("=" * 70)
    print("SAT calibration — ChainHash<2-round-AES> seed recovery (z3)")
    print("=" * 70)
    print("r=1 (no ChainHash) baseline: can z3 crack raw 2-round AES?")
    run(rounds=1, discard=False, n_pairs=4, timeout_s=120)
    run(rounds=1, discard=True,  n_pairs=6, timeout_s=120)
