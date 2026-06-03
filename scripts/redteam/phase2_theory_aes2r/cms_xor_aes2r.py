#!/usr/bin/env python3
"""CryptoMiniSat (XOR + Gauss-Jordan) seed recovery for ChainHash<2-round-AES>.

Encoding: every bit is an affine GF(2) term (set of SAT vars XOR a constant);
linear layers (MixColumns/ShiftRows/AddRoundKey/key-schedule XOR/feed-forward)
combine terms for free; terms are MATERIALIZED into SAT vars only at S-box
inputs (and outputs). S-boxes -> CNF clauses (CDCL); everything linear ->
XOR clauses (CMS Gauss-Jordan). r=1 pilot: does CMS crack raw 2-round AES
key recovery where plain z3 timed out at 120s?
"""
import os, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phase2_theory"))
from chainhashes.aes2r import SBOX, _RCON, NR, _gmul, aes_encrypt
from pycryptosat import Solver

# GF(2) matrices for gmul by 1,2,3 (bit i of gmul(c,x) = XOR over set M[c][i] of x bits)
def _gf_matrix(c):
    M = [[0]*8 for _ in range(8)]
    for j in range(8):
        y = _gmul(c, 1 << j)
        for i in range(8):
            M[i][j] = (y >> i) & 1
    return M
GF = {c: _gf_matrix(c) for c in (1, 2, 3)}

class Enc:
    def __init__(self):
        self.nv = 0
        self.clauses = []
        self.xors = []          # (vars list, rhs bool)
    def newvar(self):
        self.nv += 1
        return self.nv
    # term = (frozenset of var ids, const 0/1)
    @staticmethod
    def const(c): return (frozenset(), c & 1)
    def var_term(self):
        v = self.newvar(); return (frozenset([v]), 0)
    @staticmethod
    def xor(t1, t2): return (t1[0] ^ t2[0], t1[1] ^ t2[1])
    def materialize(self, term):
        vs, c = term
        if not vs:
            v = self.newvar(); self.clauses.append([v if c else -v]); return v
        if len(vs) == 1 and c == 0:
            return next(iter(vs))
        v = self.newvar()
        self.xors.append((list(vs) + [v], bool(c)))   # XOR(vs) ^ v = c
        return v
    def sbox(self, in_bits):     # in_bits: 8 terms -> 8 out terms (single fresh vars)
        iv = [self.materialize(t) for t in in_bits]
        ov = [self.newvar() for _ in range(8)]
        for val in range(256):
            base = [(-iv[j] if (val >> j) & 1 else iv[j]) for j in range(8)]
            sv = SBOX[val]
            for k in range(8):
                self.clauses.append(base + [ov[k] if (sv >> k) & 1 else -ov[k]])
        return [(frozenset([o]), 0) for o in ov]

# byte = list of 8 terms (bit 0..7)
def byte_const(e, b): return [Enc.const((b >> k) & 1) for k in range(8)]
def byte_xor(e, A, B): return [Enc.xor(A[k], B[k]) for k in range(8)]
def gmul_byte(e, c, B):
    M = GF[c]
    out = []
    for i in range(8):
        t = Enc.const(0)
        for j in range(8):
            if M[i][j]:
                t = Enc.xor(t, B[j])
        out.append(t)
    return out

def sub_bytes(e, st): return [e.sbox(st[i]) for i in range(16)]
def shift_rows(st):
    o = [None]*16
    for r in range(4):
        for c in range(4):
            o[r+4*c] = st[r+4*((c+r) % 4)]
    return o
def mix_columns(e, st):
    o = [None]*16
    for c in range(4):
        a = [st[4*c+r] for r in range(4)]
        o[4*c]   = byte_xor(e, byte_xor(e, gmul_byte(e,2,a[0]), gmul_byte(e,3,a[1])), byte_xor(e, a[2], a[3]))
        o[4*c+1] = byte_xor(e, byte_xor(e, a[0], gmul_byte(e,2,a[1])), byte_xor(e, gmul_byte(e,3,a[2]), a[3]))
        o[4*c+2] = byte_xor(e, byte_xor(e, a[0], a[1]), byte_xor(e, gmul_byte(e,2,a[2]), gmul_byte(e,3,a[3])))
        o[4*c+3] = byte_xor(e, byte_xor(e, gmul_byte(e,3,a[0]), a[1]), byte_xor(e, a[2], gmul_byte(e,2,a[3])))
    return o
def add_rk(e, st, rk): return [byte_xor(e, st[i], rk[i]) for i in range(16)]

def key_expansion(e, key_bytes, nr):   # key_bytes: 16 byte-terms -> (nr+1) round keys
    words = [[key_bytes[4*i+j] for j in range(4)] for i in range(4)]
    for i in range(4, 4*(nr+1)):
        t = [list(b) for b in words[i-1]]
        if i % 4 == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [e.sbox(b) for b in t]              # SubWord
            t[0] = byte_xor(e, t[0], byte_const(e, _RCON[i//4-1]))
        words.append([byte_xor(e, words[i-4][j], t[j]) for j in range(4)])
    return [sum((words[4*k+c] for c in range(4)), []) for k in range(nr+1)]

def aes2r(e, pt_bytes, key_bytes, nr):
    rks = key_expansion(e, key_bytes, nr)
    st = add_rk(e, pt_bytes, rks[0])
    for r in range(1, nr):
        st = sub_bytes(e, st); st = shift_rows(st); st = mix_columns(e, st); st = add_rk(e, st, rks[r])
    st = sub_bytes(e, st); st = shift_rows(st); st = add_rk(e, st, rks[nr])
    return st

def chainhash(e, pt_bytes, seed_keys, rounds):   # seed_keys: list of rounds x (16 byte-terms)
    ct = aes2r(e, pt_bytes, seed_keys[0], NR)
    for i in range(1, rounds):
        K_i = [byte_xor(e, seed_keys[i][b], ct[b]) for b in range(16)]
        ct = aes2r(e, pt_bytes, K_i, NR)
    return ct

def pad15(d): return (bytes(d[:15]) + b"\x80" + b"\x00"*16)[:16]

def run(rounds, discard, n_pairs, timeout_s):
    e = Enc()
    # shared unknown seed: rounds x 16 bytes of fresh vars
    seed_keys = [[e.var_term() for _ in range(8)] for _ in range(16*rounds)]
    seed_keys = [[seed_keys[16*r + b] for b in range(16)] for r in range(rounds)]
    seed_bit_vars = [list(seed_keys[r][b][k][0])[0] for r in range(rounds) for b in range(16) for k in range(8)]

    # ground truth
    seed_concrete = [os.urandom(16) for _ in range(rounds)]
    def concrete_chain(pt):
        ct = list(aes_encrypt(pt, seed_concrete[0], NR))
        for i in range(1, rounds):
            K = bytes(seed_concrete[i][b] ^ ct[b] for b in range(16))
            ct = list(aes_encrypt(pt, K, NR))
        return ct

    blocks = [pad15(os.urandom(15)) for _ in range(n_pairs)]
    for blk in blocks:
        out = concrete_chain(blk)
        pt_terms = [byte_const(e, blk[i]) for i in range(16)]
        ct_terms = chainhash(e, pt_terms, seed_keys, rounds)  # rebuilds per pair (fresh interm vars, shared seed)
        rng = range(8, 16) if discard else range(16)
        for bi in rng:
            for k in range(8):
                v = e.materialize(ct_terms[bi][k])
                bit = (out[bi] >> k) & 1
                e.clauses.append([v if bit else -v])

    s = Solver(threads=4)
    for cl in e.clauses:
        s.add_clause(cl)
    for vs, rhs in e.xors:
        s.add_xor_clause(vs, rhs)
    t0 = time.time()
    sat, sol = s.solve()  # pycryptosat has no per-call timeout; rely on outer timeout wrapper
    dt = time.time() - t0
    if not sat:
        print(f"  rounds={rounds} discard={discard} pairs={n_pairs}: UNSAT in {dt:.1f}s (?!)")
        return
    # recover round-0 seed and verify functionally
    rec0 = bytes(sum(((1 if sol[list(seed_keys[0][b][k][0])[0]] else 0) << k) for k in range(8)) for b in range(16))
    ok = (rec0 == seed_concrete[0])
    print(f"  rounds={rounds} discard={discard} pairs={n_pairs}: SAT in {dt:.1f}s  "
          f"round0_key_recovered={ok}  vars={e.nv} clauses={len(e.clauses)} xors={len(e.xors)}")

if __name__ == "__main__":
    print("=" * 72)
    print("CMS-XOR seed recovery — pilot r=1 (does CMS crack what z3 timed out on?)")
    print("=" * 72)
    run(rounds=1, discard=False, n_pairs=4, timeout_s=120)
    run(rounds=1, discard=True,  n_pairs=6, timeout_s=120)
