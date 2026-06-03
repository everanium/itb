"""Round-reduced AES (default 2 rounds) as a pluggable ChainHash inner
primitive — the deliberately-broken *strong-primitive-too-few-rounds* control,
the mirror of fnv1a (a weak primitive that survives the envelope).

2-round AES is textbook-broken in isolation (integral / Square key recovery
from a handful of chosen plaintexts). The research question this module sets
up: does ITB's ChainHash wrapper (XOR feed-forward + lo-lane hHi discard)
defeat that integral break the way it turns FNV-1a into a SAT problem — even
though 2-round AES is NOT a carry-up T-function (no plane-by-plane hook)?

Primitive interface (matches chainhashes.fnv1a):
  * `_aes2r_128(data, seed_lo, seed_hi) -> (lo, hi)` — 2-lane adapter for the
    avalanche / differential screens. key = seed_hi<<64 | seed_lo (16 BE
    bytes); plaintext block = pad(data) to 16 bytes; ct = AES_{NR}(pt, key);
    return (lo = last 8 BE bytes, hi = first 8 BE bytes) of the 128-bit ct.
  * `chainhash_lo(data, seed_components)` — discard ON (h[0] only).
  * `chainhash_full(data, seed_components, rounds, discard)` — research hook:
    discard ON returns lo only; discard OFF returns (lo<<64 | hi) full state.

NR (AES round count) is module-global, default 2; override via set_rounds().
"""
from __future__ import annotations
from typing import Sequence

MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1

# Not a carry-up T-function — the S-box is a GF(2^8) inverse + affine map, no
# triangular plane-by-plane hook. The Phase 2g SAT/tsolver route does not apply;
# the open question is whether an integral/algebraic attack survives ChainHash.
INVERTIBLE = False
N_SEED_COMPONENTS = 16  # 8 rounds x 2 uint64, matching the 1024-bit-key layout

# ---- GF(2^8) and AES S-box (generated, then verified against known values) --
def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def _build_sbox() -> list[int]:
    # multiplicative inverse in GF(2^8) (0 -> 0), then the AES affine transform
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    sbox = [0] * 256
    for x in range(256):
        b = inv[x]
        s = 0
        for i in range(8):
            bit = ((b >> i) & 1) ^ ((b >> ((i + 4) % 8)) & 1) ^ \
                  ((b >> ((i + 5) % 8)) & 1) ^ ((b >> ((i + 6) % 8)) & 1) ^ \
                  ((b >> ((i + 7) % 8)) & 1) ^ ((0x63 >> i) & 1)
            s |= bit << i
        sbox[x] = s
    return sbox

SBOX = _build_sbox()
assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7C and SBOX[0x53] == 0xED \
    and SBOX[0xFF] == 0x16, "S-box generation mismatch"

# ---- AES core (state = 16 bytes, column-major: index = row + 4*col) ---------
def _sub_bytes(s): return [SBOX[b] for b in s]

def _shift_rows(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return o

def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
        o[4*c]   = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        o[4*c+1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        o[4*c+2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        o[4*c+3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
    return o

def _add_round_key(s, rk): return [s[i] ^ rk[i] for i in range(16)]

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def _key_expansion(key16: bytes, nr: int):
    """AES-128 key schedule -> (nr+1) round keys of 16 bytes each."""
    words = [list(key16[4*i:4*i+4]) for i in range(4)]
    total = 4 * (nr + 1)
    for i in range(4, total):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [SBOX[b] for b in t]                # SubWord
            t[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ t[j] for j in range(4)])
    rks = []
    for k in range(nr + 1):
        rk = []
        for c in range(4):
            rk += words[4 * k + c]
        rks.append(rk)
    return rks

def aes_encrypt(block16: bytes, key16: bytes, nr: int) -> bytes:
    rks = _key_expansion(key16, nr)
    s = _add_round_key(list(block16), rks[0])
    for r in range(1, nr):
        s = _sub_bytes(s); s = _shift_rows(s); s = _mix_columns(s)
        s = _add_round_key(s, rks[r])
    s = _sub_bytes(s); s = _shift_rows(s)           # final round, no MixColumns
    s = _add_round_key(s, rks[nr])
    return bytes(s)

# FIPS-197 Appendix B / C.1 known-answer test (validates SBOX/MC/SR/keyexp).
_KAT_KEY = bytes(range(16))
_KAT_PT  = bytes.fromhex("00112233445566778899aabbccddeeff")
assert aes_encrypt(_KAT_PT, _KAT_KEY, 10).hex() == \
    "69c4e0d86a7b0430d8cdb78070b4c55a", "AES-128 KAT mismatch"

# ---- module-global round count ----------------------------------------------
NR = 2
def set_rounds(n: int):
    global NR
    NR = n

# ---- ChainHash primitive interface ------------------------------------------
def _pad_block(data: bytes) -> bytes:
    """One-block injective pad of `data` (<=15 bytes) into an AES plaintext
    block. data || 0x80 || 0x00...  (attacker controls data bytes 0..len-1)."""
    d = bytes(data[:15])
    return (d + b"\x80" + b"\x00" * 16)[:16]

def _aes2r_128(data: bytes, seed_lo: int, seed_hi: int):
    key = ((seed_hi & MASK64) << 64 | (seed_lo & MASK64)).to_bytes(16, "big")
    ct = aes_encrypt(_pad_block(data), key, NR)
    hi = int.from_bytes(ct[:8], "big")
    lo = int.from_bytes(ct[8:], "big")
    return lo, hi

def _chain(data, seed_components, rounds):
    """ChainHash with XOR feed-forward. Returns (lo, hi) of final round."""
    lo, hi = _aes2r_128(data, seed_components[0], seed_components[1])
    for i in range(2, 2 * rounds, 2):
        k_lo = (seed_components[i] ^ lo) & MASK64
        k_hi = (seed_components[i + 1] ^ hi) & MASK64
        lo, hi = _aes2r_128(data, k_lo, k_hi)
    return lo, hi

def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Discard ON: low 64 bits of the ChainHash output (h[0]), 8 rounds."""
    assert len(seed_components) == N_SEED_COMPONENTS
    lo, _ = _chain(data, seed_components, N_SEED_COMPONENTS // 2)
    return lo

def chainhash_full(data: bytes, seed_components: Sequence[int],
                   rounds: int = 4, discard: bool = True) -> int:
    """Research hook. discard=True -> lo only (hHi discarded); discard=False ->
    full 128-bit state (lo<<64 | hi). `rounds` = number of primitive calls."""
    lo, hi = _chain(data, seed_components, rounds)
    return lo if discard else ((hi << 64) | lo)

if __name__ == "__main__":
    print("AES KAT ok; SBOX ok. NR =", NR)
    print("sample _aes2r_128(b'\\x01\\x02\\x03\\x04\\x05', 0xdead, 0xbeef) =",
          [hex(x) for x in _aes2r_128(b"\x01\x02\x03\x04\x05", 0xdead, 0xbeef)])
