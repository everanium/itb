"""AES-ITB-128 as a pluggable ChainHash inner primitive — the shipped
reduced-round AES chain absorption (`aesitb.go` `aesITB128GenericHash`, reference
`aesitb/aesitb.go` `HashGeneric`), mirrored here so the HARNESS.md
reduced-round-primitive screens (the aes2r control) can be run against
the primitive that actually ships in the registry.

Construction (per call, nonce-free):

    state  = fixedKey XOR (LE64(seed0) || LE64(seed1))
    padded = data || PKCS#7 padding to a 16-byte multiple (always >= 1 byte)
    state  = AESRound(state XOR block_i, RC[i mod 8])    for each block i < b
    out    = AESRound(AESRound(state, RC[b mod 8]), RC[(b+1) mod 8])
    (lo, hi) = (LE64(out[0:8]), LE64(out[8:16]))

with b the number of padded blocks: the two finalising rounds continue the
constant cycle, so the last-round constant depends on the shape —
`final_rc(nblk)` returns the (second-to-last, last) pair: one-block lab
shape RC[1], RC[2]; 20 B RC[2], RC[3]; 36 B RC[3], RC[4]; 68 B RC[5], RC[6].

AESRound is the AESENC semantic (SubBytes, ShiftRows, MixColumns,
AddRoundKey) — every round, including the last, carries MixColumns. The
eight round constants are the NUMS table from `aesitb.go`
(`aesITBRoundConstants`: the first eight 128-bit words of the hexadecimal
fractional expansion of pi, each loaded big-endian — the word's first
byte is AES state byte 0; the import self-check rebuilds them from pi). The state
is column-major (`s[4*col + row]`, FIPS-197 § 3.4); byte order of the seed
and output lanes is little-endian, matching `encoding/binary.LittleEndian`
in the Go reference — NOT the big-endian packing of chainhashes.aes2r.

Structural facts the screens rely on (verified by the self-test below):

  * The seed enters ONCE, by XOR, before a fixed public permutation. There
    is no key schedule. For a one-block input (data <= 15 bytes) the call is
    exactly three full AES rounds under the public constants RC0, RC1, RC2
    — a public permutation P applied to (fixedKey XOR seed XOR pad(data)).
  * P is invertible; `invert_generic` implements P^-1 (InvMixColumns /
    InvShiftRows / InvSubBytes, constants in reverse order) and recovers
    the 128-bit seed block from one (data, full-output) pair.
  * The shipped per-pixel inputs are 20 / 36 / 68 bytes (LE32(idx) || nonce)
    -> 2 / 3 / 5 blocks -> 4 / 5 / 7 AES rounds per call. The one-block lab
    shape (3 rounds) is therefore strictly attacker-favourable.

Primitive interface (matches chainhashes.aes2r):
  * `_aesitb128_128(data, seed_lo, seed_hi) -> (lo, hi)` — 2-lane adapter
    for avalanche_screen.py / differential_screen.py (resolved by name).
  * `chainhash_lo(data, seed_components)` — discard ON (h[0] only), 8 rounds.
  * `chainhash_full(data, seed_components, rounds, discard)` — research hook:
    discard ON returns lo only; discard OFF returns (hi<<64 | lo).
  * `chainhash_batch(data_arr, seed_components, rounds, discard)` — numpy
    evaluator over N inputs at once, bit-exact with chainhash_full (checked
    on import); used by the Λ-set / differential / uniformity loops.
  * `peel_last(data, out16)` / `peel_last_batch` — the discard-OFF
    attacker step: P^-1 of the final call (fixedKey removed), exposing
    seed_r XOR h_{r-1} — at r = 1 the seed block itself.

FIXED_KEY is pinned to the reference key of `aesitb/aesitb_test.go`
(`refKey`) and treated as attacker-known — generous to the attacker: in the
shipped pipeline the fixed key is drawn from crypto/rand per seed and stored
in the blob, so it is secret material, but the r = 1 inversion recovers
(fixedKey XOR seed) as one block regardless, so key secrecy adds nothing at
that depth.

AES building blocks (S-box, ShiftRows, MixColumns, GF(2^8) multiply) are
imported from chainhashes.aes2r — the FIPS-197-validated set the aes2r
control uses — so both controls share one provenance.
"""
from __future__ import annotations

import os
from typing import Sequence

from chainhashes.aes2r import (  # noqa: E402  (FIPS-197-validated building blocks)
    SBOX,
    _add_round_key,
    _gmul,
    _mix_columns,
    _shift_rows,
    _sub_bytes,
)

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None

MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1

# Not a carry-up T-function (AES S-box: GF(2^8) inverse + affine). The seed
# map is a public permutation composed with XOR, so the cheap structural
# inverse IS present — one (data, full output) pair inverts to the seed.
INVERTIBLE = True
N_SEED_COMPONENTS = 16  # 8 rounds x 2 uint64, matching the 1024-bit-key layout

# ---- NUMS round constants (aesitb.go aesITBRoundConstants) -----------------
# Word i = fractional hex digits 32i+1 .. 32i+32 of pi, big-endian bytes.
RC = [bytes.fromhex(h) for h in (
    "243f6a8885a308d313198a2e03707344",
    "a4093822299f31d0082efa98ec4e6c89",
    "452821e638d01377be5466cf34e90c6c",
    "c0ac29b7c97c50dd3f84d5b5b5470917",
    "9216d5d98979fb1bd1310ba698dfb5ac",
    "2ffd72dbd01adfb7b8e1afed6a267e96",
    "ba7c9045f12c7f9924a19947b3916cf7",
    "0801f2e2858efc16636920d871574e69",
)]


def _pi_words(n: int = 8) -> list[bytes]:
    """The first n 128-bit words of pi's hexadecimal fraction (Machin)."""
    bits = 128 * n + 64
    one = 1 << bits

    def atan_inv(x: int) -> int:
        total, term, k, sign = 0, one // x, 1, 1
        while term:
            total += sign * (term // k)
            term //= x * x
            k += 2
            sign = -sign
        return total

    frac = (16 * atan_inv(5) - 4 * atan_inv(239) - 3 * one) >> 64
    raw = frac.to_bytes(16 * n, "big")
    return [raw[16 * i:16 * i + 16] for i in range(n)]


assert RC == _pi_words(), "aesitb128 round constants differ from pi"


def nblocks(data_len: int) -> int:
    """Padded block count of a data_len-byte input (PKCS#7, always >= 1 pad byte)."""
    return data_len // 16 + 1


def final_rc(nblk: int) -> tuple[bytes, bytes]:
    """(second-to-last, last) round constants of a call absorbing nblk blocks."""
    return RC[nblk % 8], RC[(nblk + 1) % 8]


# Reference fixed key of aesitb/aesitb_test.go (refKey) — attacker-known here.
FIXED_KEY = bytes(range(0x00, 0x100, 0x11))
assert len(FIXED_KEY) == 16

INV_SBOX = [0] * 256
for _x in range(256):
    INV_SBOX[SBOX[_x]] = _x


# ---- scalar reference --------------------------------------------------------
def _aes_round(s: list[int], rc: bytes) -> list[int]:
    return _add_round_key(_mix_columns(_shift_rows(_sub_bytes(s))), rc)


def _inv_shift_rows(s):
    o = [0] * 16
    for r in range(4):
        for c in range(4):
            o[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return o


def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        o[4 * c] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        o[4 * c + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        o[4 * c + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        o[4 * c + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)
    return o


def _inv_aes_round(s: list[int], rc: bytes) -> list[int]:
    s = _add_round_key(s, rc)
    s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    return [INV_SBOX[b] for b in s]


def pkcs7(data: bytes) -> bytes:
    pad = 16 - len(data) % 16
    return bytes(data) + bytes([pad]) * pad


def seed_block(seed0: int, seed1: int) -> bytes:
    return (seed0 & MASK64).to_bytes(8, "little") + (seed1 & MASK64).to_bytes(8, "little")


def hash_generic(fixed_key: bytes, data: bytes, seed0: int, seed1: int) -> bytes:
    """Scalar mirror of aesitb.HashGeneric / itb.aesITB128GenericHash."""
    sb = seed_block(seed0, seed1)
    state = [fixed_key[i] ^ sb[i] for i in range(16)]
    padded = pkcs7(data)
    nblk = len(padded) // 16
    for i in range(nblk):
        blk = padded[16 * i:16 * i + 16]
        state = [state[j] ^ blk[j] for j in range(16)]
        state = _aes_round(state, RC[i % 8])
    rc_a, rc_b = final_rc(nblk)
    state = _aes_round(state, rc_a)
    state = _aes_round(state, rc_b)
    return bytes(state)


def invert_generic(fixed_key: bytes, data: bytes, out16: bytes) -> tuple[int, int]:
    """P^-1: recover (seed0, seed1) from one (data, full 16-byte output) pair.

    Walks the finaliser and every absorbed block backwards; the only
    unknown is the initial seed block, which falls out as
    state_0 XOR fixedKey."""
    padded = pkcs7(data)
    nblk = len(padded) // 16
    rc_a, rc_b = final_rc(nblk)
    state = list(out16)
    state = _inv_aes_round(state, rc_b)
    state = _inv_aes_round(state, rc_a)
    for i in range(nblk - 1, -1, -1):
        state = _inv_aes_round(state, RC[i % 8])
        blk = padded[16 * i:16 * i + 16]
        state = [state[j] ^ blk[j] for j in range(16)]
    sb = bytes(state[j] ^ fixed_key[j] for j in range(16))
    return int.from_bytes(sb[:8], "little"), int.from_bytes(sb[8:], "little")


def _aesitb128_128(data: bytes, seed_lo: int, seed_hi: int):
    out = hash_generic(FIXED_KEY, data, seed_lo, seed_hi)
    return int.from_bytes(out[:8], "little"), int.from_bytes(out[8:], "little")


def _chain(data, seed_components, rounds):
    """ChainHash with XOR feed-forward (seed128.go ChainHash128).
    Returns (lo, hi) of the final round."""
    lo, hi = _aesitb128_128(data, seed_components[0], seed_components[1])
    for i in range(2, 2 * rounds, 2):
        k_lo = (seed_components[i] ^ lo) & MASK64
        k_hi = (seed_components[i + 1] ^ hi) & MASK64
        lo, hi = _aesitb128_128(data, k_lo, k_hi)
    return lo, hi


def chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int:
    """Discard ON: low 64 bits of the ChainHash output (h[0]), 8 rounds."""
    assert len(seed_components) == N_SEED_COMPONENTS
    lo, _ = _chain(data, seed_components, N_SEED_COMPONENTS // 2)
    return lo


def chainhash_full(data: bytes, seed_components: Sequence[int],
                   rounds: int = 4, discard: bool = True) -> int:
    """Research hook. discard=True -> lo only (hHi discarded); discard=False ->
    full 128-bit state (hi<<64 | lo). `rounds` = number of primitive calls."""
    lo, hi = _chain(data, seed_components, rounds)
    return lo if discard else ((hi << 64) | lo)


def peel_last(data: bytes, out16: bytes) -> bytes:
    """Discard-OFF attacker step on a ChainHash output at depth r: invert the
    last primitive call (fixedKey known, removed). Returns the 16-byte block
    (LE64(seed_{2r-2}) || LE64(seed_{2r-1})) XOR h_{r-1}
    (at r = 1: the seed block itself — full key recovery)."""
    s0, s1 = invert_generic(FIXED_KEY, data, out16)
    return seed_block(s0, s1)


# ---- numpy batched evaluator -------------------------------------------------
if np is not None:
    _SB_T = np.array(SBOX, dtype=np.uint8)
    _ISB_T = np.array(INV_SBOX, dtype=np.uint8)
    _MUL = {m: np.array([_gmul(x, m) for x in range(256)], dtype=np.uint8)
            for m in (2, 3, 9, 11, 13, 14)}
    _SR_IDX = np.array([r + 4 * ((c + r) % 4) for c in range(4) for r in range(4)])
    _ISR_IDX = np.array([r + 4 * ((c - r) % 4) for c in range(4) for r in range(4)])
    _RC_ARR = [np.frombuffer(rc, dtype=np.uint8) for rc in RC]
    _FK_ARR = np.frombuffer(FIXED_KEY, dtype=np.uint8)

    def _mix_batch(s):
        a = s.reshape(-1, 4, 4)  # [n, col, row]
        a0, a1, a2, a3 = a[:, :, 0], a[:, :, 1], a[:, :, 2], a[:, :, 3]
        m2, m3 = _MUL[2], _MUL[3]
        o = np.empty_like(a)
        o[:, :, 0] = m2[a0] ^ m3[a1] ^ a2 ^ a3
        o[:, :, 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
        o[:, :, 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
        o[:, :, 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]
        return o.reshape(-1, 16)

    def _inv_mix_batch(s):
        a = s.reshape(-1, 4, 4)
        a0, a1, a2, a3 = a[:, :, 0], a[:, :, 1], a[:, :, 2], a[:, :, 3]
        m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
        o = np.empty_like(a)
        o[:, :, 0] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
        o[:, :, 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
        o[:, :, 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
        o[:, :, 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
        return o.reshape(-1, 16)

    def _round_batch(s, rc):
        s = _SB_T[s]
        s = s[:, _SR_IDX]
        s = _mix_batch(s)
        return s ^ rc

    def _inv_round_batch(s, rc):
        s = s ^ rc
        s = _inv_mix_batch(s)
        s = s[:, _ISR_IDX]
        return _ISB_T[s]

    def pad_batch(data_arr):
        """PKCS#7 pad an (N, L) uint8 array to (N, nblk, 16)."""
        data_arr = np.asarray(data_arr, dtype=np.uint8)
        n, L = data_arr.shape
        pad = 16 - L % 16
        padded = np.empty((n, L + pad), dtype=np.uint8)
        padded[:, :L] = data_arr
        padded[:, L:] = pad
        return padded.reshape(n, -1, 16)

    def hash_generic_batch(seed_arr, padded, fixed_key=_FK_ARR):
        """seed_arr: (N, 16) uint8 seed blocks; padded: (N, nblk, 16)."""
        state = seed_arr ^ fixed_key
        nblk = padded.shape[1]
        for i in range(nblk):
            state = _round_batch(state ^ padded[:, i, :], _RC_ARR[i % 8])
        state = _round_batch(state, _RC_ARR[nblk % 8])
        state = _round_batch(state, _RC_ARR[(nblk + 1) % 8])
        return state

    def invert_generic_batch(out_arr, padded, fixed_key=_FK_ARR):
        """P^-1 over N rows: (N, 16) outputs -> (N, 16) seed blocks."""
        nblk = padded.shape[1]
        state = _inv_round_batch(out_arr, _RC_ARR[(nblk + 1) % 8])
        state = _inv_round_batch(state, _RC_ARR[nblk % 8])
        for i in range(nblk - 1, -1, -1):
            state = _inv_round_batch(state, _RC_ARR[i % 8]) ^ padded[:, i, :]
        return state ^ fixed_key

    def _comp_block(seed_components, i):
        return np.frombuffer(seed_block(seed_components[i], seed_components[i + 1]),
                             dtype=np.uint8)

    def chainhash_batch(data_arr, seed_components, rounds: int = 4,
                        discard: bool = True):
        """ChainHash over N inputs at once. data_arr: (N, L) uint8 (all rows
        the same length). Returns (N, 8) uint8 lo-lane bytes when discard,
        else the full (N, 16) uint8 state — little-endian byte order, so
        row[0:8] == LE64(lo)."""
        padded = pad_batch(data_arr)
        n = padded.shape[0]
        state = np.broadcast_to(_comp_block(seed_components, 0), (n, 16)).copy()
        state = hash_generic_batch(state, padded)
        for i in range(2, 2 * rounds, 2):
            state = hash_generic_batch(state ^ _comp_block(seed_components, i), padded)
        return state[:, :8].copy() if discard else state

    def peel_last_batch(data_arr, out_arr):
        """Batched peel_last over (N, 16) discard-OFF outputs."""
        return invert_generic_batch(np.asarray(out_arr, dtype=np.uint8),
                                    pad_batch(data_arr))


# ---- self-test on import -----------------------------------------------------
# aesitb/aesitb_test.go genericVectors — data = bytes(range(n)), refKey.
_GENERIC_KAT = [
    (0, 0x0, 0x0, "b184dc9639cb19463a318b5bdbef60b3"),
    (1, 0x0, 0x0, "98aa26e22213e0995747f26166741da1"),
    (15, 0x0, 0x0, "67ff582c8131e477e50a0d5ad8159ffa"),
    (16, 0x0, 0x0, "b525d15864f5da4095cac4878e734e65"),
    (17, 0x0, 0x0, "b83d1718c4886682779773e766da4740"),
    (31, 0x0, 0x0, "b4bb6ec276da61c523e83bdb6c71d283"),
    (32, 0x0, 0x0, "6bce525c8ccab6ef9397b24764613f7b"),
    (33, 0x0, 0x0, "12bf744bf5dc16db8fe26756e0bdfdc9"),
    (63, 0x0, 0x0, "b60baf0921ce4914e43c7d22742bc285"),
    (64, 0x0, 0x0, "1f43035d6a9e6d218803d2e171b9d4e1"),
    (0, 0x1, 0x0, "877c1a9b664408e3a0f05d6e0bc743d3"),
    (0, 0x0, 0x1, "3e3957b58667430747216ab9e87dd55a"),
    (5, 0x123456789abcdef, 0xfedcba9876543210, "4769146529998d0c4d2861b4bc1efdfe"),
    (16, 0xffffffffffffffff, 0xffffffffffffffff, "b0e1cbcf08246eb0a7f190fe1ad780dd"),
    (33, 0x7, 0x9, "57e01a09debb3f6a814a92505188b8d0"),
    (64, 0x8000000000000000, 0x1, "98876054889177dd47c546cd01811630"),
    (80, 0x0, 0x0, "bb2af2751c71a52fd0fc49c95ef350c0"),
    (96, 0x0, 0x0, "37d5acf4a140659dba5d810f10b62d0a"),
    (128, 0x123456789abcdef, 0xfedcba987654321, "71f22c5f6678b8026faabb5aa7bb6ee5"),
]

for _n, _s0, _s1, _want in _GENERIC_KAT:
    _data = bytes(range(_n))
    _got = hash_generic(FIXED_KEY, _data, _s0, _s1)
    assert _got.hex() == _want, f"aesitb128 generic KAT mismatch at len={_n}"
    assert invert_generic(FIXED_KEY, _data, _got) == (_s0, _s1), \
        f"aesitb128 P^-1 mismatch at len={_n}"

if np is not None:
    _rng = os.urandom
    for _L in (5, 13, 15, 20, 36, 68):
        _rows = [bytes(_rng(_L)) for _ in range(6)]
        _comps = [int.from_bytes(_rng(8), "little") for _ in range(6)]
        _arr = np.frombuffer(b"".join(_rows), dtype=np.uint8).reshape(6, _L)
        for _r in (1, 2, 3):
            _b = chainhash_batch(_arr, _comps, rounds=_r, discard=False)
            for _i, _row in enumerate(_rows):
                _full = chainhash_full(_row, _comps, rounds=_r, discard=False)
                assert _b[_i].tobytes() == _full.to_bytes(16, "little"), \
                    f"aesitb128 batch/scalar mismatch len={_L} r={_r}"
            _peeled = peel_last_batch(_arr, _b)
            for _i, _row in enumerate(_rows):
                assert _peeled[_i].tobytes() == peel_last(_row, _b[_i].tobytes()), \
                    f"aesitb128 batch/scalar peel mismatch len={_L} r={_r}"

if __name__ == "__main__":
    print(f"aesitb128 generic KAT ok ({len(_GENERIC_KAT)} vectors); P^-1 ok; batch/scalar parity ok")
    print("sample _aesitb128_128(b'\\x01\\x02\\x03\\x04\\x05', 0xdead, 0xbeef) =",
          [hex(x) for x in _aesitb128_128(b"\x01\x02\x03\x04\x05", 0xdead, 0xbeef)])
