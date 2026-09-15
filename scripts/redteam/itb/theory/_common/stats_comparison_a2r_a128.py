#!/usr/bin/env python3
"""Head-to-head statistical uniformity / bias comparison of the two
reduced-round AES primitives on the HARNESS shelf — the shipped AES-ITB-128
sponge (`chainhashes.aesitb128`, bit-exact with `aesitb.go`) and the 2-round
AES lab control (`chainhashes.aes2r`) — measured RAW (no ChainHash cascade,
no ITB envelope) under ONE harness, ONE sample size, ONE seed stream and ONE
set of input configurations, so the two primitives can be compared cell by
cell instead of across the differently-configured screens that produced the
numbers already on file.

Question answered: which primitive's raw output reads cleaner as an entropy
source for the downstream ITB consumers (Interlocked Barrier fill, Pixel
Barrier, rotate7 + xor-mask ciphertext derivation) — bounded to the measures,
sample sizes and shapes below. Marginal statistics are necessary, not
sufficient: a primitive can read uniform on every column here and still be
one-pair invertible (aesitb128 standalone) or integral-broken (aes2r).

PRIMITIVES (both take a 16-byte key block and an L-byte data buffer)
----------------------------------------------------------------------
  * aesitb128 — `hash_generic_batch` from the mirror (seed block = the 16 key
                bytes XORed into fixedKey; PKCS#7 pad; one AESENC round per
                absorbed block under the NUMS constants; two finaliser
                rounds). lo lane = out[0:8] (LE64(lo)), the lane the encoder
                consumes.
  * aes2r     — 2-round AES-128 (key schedule from the 16 key bytes; round 1
                with MixColumns; final round without), batched here in numpy
                (`aes2r_batch`) and gated on import against the scalar
                `chainhashes.aes2r.aes_encrypt` and the FIPS-197 KAT through
                the same code path at NR = 10. lo lane = ct[8:16], matching
                `chainhashes.aes2r._aes2r_128`.
  * urandom   — os.urandom bytes through the identical statistics: the
                sampling-floor control every ceiling is read against.
  * fnv1a     — the FNV-1a-128 below-spec control (`chainhashes.fnv1a`,
                128-bit state = key bytes big-endian, per-byte XOR then
                multiply by 2^88 + 0x13B mod 2^128). Reference row for the
                half-cross diffusion axis: the multiply is a carry-up
                T-function, so a hi-half input bit can never reach the lo
                output half. Output packed big-endian (hi first), so
                lo lane = out[8:16], matching `_fnv1a128`. Pure-Python
                evaluator (scalar mirror per row); block shape only by
                default.

HALF CONVENTION (used by the half-cross axis and the lo-lane columns)
--------------------------------------------------------------------
Each primitive's "lo half" is the 8 bytes its ChainHash adapter reports as
the lo lane, applied uniformly to key, data (byte position mod 16) and
output: aesitb128 bytes 0..7 (LE64(seed0) / out[0:8]); aes2r and fnv1a bytes
8..15 (big-endian packing: seed_lo is the last 8 key bytes, lo = ct[8:16]).
For aes2r the lo half is therefore state columns 2 / 3 on input and output
alike.

INPUT SHAPES
------------
  * block — 15 data bytes, the one-block shape both shipped adapters accept
            (aesitb128: PKCS#7 -> data || 0x01, three AES rounds;
            aes2r: `_pad_block` -> data || 0x80, its native block). Same
            120 varying bits, same data array, fed to both.
  * 13 / 20 / 36 / 68 — the shipped per-pixel / fill shapes. aesitb128 runs
            its native sponge (1 / 2 / 3 / 5 absorbed blocks -> 3 / 4 / 5 / 7
            rounds). aes2r has NO shipping multi-block shape; it is taken
            through a LAB WRAPPER — CBC-MAC-style absorption under key = seed
            (state = AES2r_K(state XOR PKCS#7 block_i), zero IV). The wrapper
            is a measurement device for comparability only, not a shipped or
            proposed construction; every aes2r row at these shapes is
            labelled `lab wrapper`.

CONFIGURATIONS (same RNG stream per trial -> byte-identical inputs for both
primitives)
------------
  * rand_pt   — fixed key, N random data rows (plaintext-driven marginals).
  * rand_key  — fixed data, N random keys (key-driven marginals).
  * counter   — fixed key, data = LE32(i) || fixed nonce, i = 0..N-1 (shapes
                block / 20 / 36 / 68; the shipped per-pixel pattern), or
                0x03 || LE64(i) || 0^4 at shape 13 (the shipped fill
                pattern). This is the input the downstream consumers
                actually present.
  * aval_data — M random (key, data) bases; every data bit flipped in turn;
                output-difference statistics (data avalanche + low-byte DDT).
  * aval_key  — M random bases; every key bit flipped in turn (key avalanche
                = the related-key single-bit differential in Hamming form).
                At the aesitb128 block shape a key-bit flip and a data-bit
                flip are the same operation (both XOR into the single block
                ahead of the public permutation P), so the two axes coincide
                there by construction.

STATISTICS
----------
Marginal cells (rand_pt / rand_key / counter), reported for the full 16-byte
output and the 8-byte lo lane, per `uniformity_chainhash.py`:
  * chi2_max / chi2_mean — per-byte chi-square against uniform over 256
    values (df 255, mean 255, sd sqrt(510)); Bonferroni ceiling for the max
    over bytes x trials at alpha = 0.01.
  * bit_bias_max — max over output bits of |P(bit = 1) - 0.5|; binomial sd
    0.5 / sqrt(N); Bonferroni ceiling over bits x trials.
  * ent_min — minimum per-byte Shannon entropy (bits; ideal 8).
  * minent_min — minimum per-byte min-entropy -log2(max_v p(v)) (ideal 8).
  * bday_zmax — truncated-window birthday test: four disjoint 24-bit windows
    (bytes 0-2, 4-6, 8-10, 12-14 of the full state; 0-2 and 4-6 of the lo
    lane); duplicates (N - #distinct) among N values against the exact
    uniform-occupancy mean and sd (`birthday_expect`); reported as the worst
    |z| over windows, Bonferroni ceiling over windows x trials. Tests joint 24-bit distribution beyond the
    marginals. (Full 128-bit collisions are 0 by construction at these N —
    aes2r under a fixed key is a permutation, the sponge collides at 2^-128
    — and are not reported.)
Avalanche cells (aval_data / aval_key):
  * avw_mean / avw_sd — Hamming weight of the output difference per single
    input-bit flip (ideal 64 / 5.657 on 128 bits; 32 / 4 on the lo lane).
  * sac_mean / sac_max — Strict Avalanche Criterion bias |P(flip) - 0.5| over
    (input bit, output bit) pairs; ceiling z * 0.5 / sqrt(M), Bonferroni over
    pairs x trials.
  * dead_pairs — (input bit, output bit) pairs whose flip probability is
    exactly 0 or 1 over all M bases (structurally missing diffusion).
  * ddt8_max / const8 — per `differential_screen.py`: worst low-byte
    output-difference bucket probability over input bits (lo-lane byte 0),
    and the fraction of input bits with a constant low-byte difference.
  * half-cross diffusion — the same flips split by input half and output
    half: for input bits in the lo half, the mean (and sd) number of output
    flips landing in the lo output half and in the hi output half; likewise
    for input bits in the hi half. Ideal 128-bit primitive: ~32 / ~32 in
    every cell (sd ~4). Half-independent (two parallel 64-bit lanes): ~32 /
    ~0 and ~0 / ~32. Carry-up T-function (fnv1a): lo-half input reaches
    both halves, hi-half input reaches the hi half only. Verdict thresholds
    are structural (means over M x 64 flips have sd < 0.02): `fully mixed`
    when every cell mean is within 30..34; `half-independent` when either
    cross-half mean is below 2; `partially mixed` otherwise.

Nothing here is an attack; every cell is a raw-primitive marginal / first-
order-diffusion statistic at the stated N. Read a clean row as "at the
sampling floor at this N", never as a security verdict.

Usage:
    # one cell
    python3 stats_comparison_a2r_a128.py --primitive aes2r --shape 20 \
        --config counter --samples 100000 --trials 3 --seed 1 \
        --json ~/scratch/aesitb/t34_cells.jsonl
    # the full matrix, then the summary tables
    python3 stats_comparison_a2r_a128.py --all --samples 100000 --trials 3 \
        --json ~/scratch/aesitb/t34_cells.jsonl
    python3 stats_comparison_a2r_a128.py --report ~/scratch/aesitb/t34_cells.jsonl
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from pathlib import Path
from statistics import NormalDist

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # chainhashes.<name>

from chainhashes import aes2r as a2r  # noqa: E402
from chainhashes import aesitb128 as a128  # noqa: E402
from chainhashes import fnv1a as fnv  # noqa: E402

PRIMITIVES = ("aesitb128", "aes2r", "urandom", "fnv1a")
SHAPES = ("block", "13", "20", "36", "68")
MARGINAL_CONFIGS = ("rand_pt", "rand_key", "counter")
AVAL_CONFIGS = ("aval_data", "aval_key")
CONFIGS = MARGINAL_CONFIGS + AVAL_CONFIGS
ALPHA = 0.01
NR = 2  # aes2r round count, pinned (the lab control is 2-round AES)

_SB = a128._SB_T
_SR = a128._SR_IDX
_RCON = np.array(a2r._RCON, dtype=np.uint8)


# ---- batched 2-round AES (numpy) --------------------------------------------
# Port of chainhashes.aes2r._key_expansion / aes_encrypt (aes2r.py:95-122):
# column-major state s[row + 4*col], round key k = words 4k..4k+3, SubBytes /
# ShiftRows / MixColumns shared with the aesitb128 mirror's batched tables
# (identical FIPS-197 building blocks — one provenance for both primitives).
def aes_keyexp_batch(keys: np.ndarray, nr: int) -> np.ndarray:
    """(N, 16) uint8 keys -> (N, nr + 1, 16) uint8 round keys."""
    keys = np.asarray(keys, dtype=np.uint8)
    n = keys.shape[0]
    total = 4 * (nr + 1)
    w = np.empty((n, total, 4), dtype=np.uint8)
    w[:, :4, :] = keys.reshape(n, 4, 4)
    for i in range(4, total):
        t = w[:, i - 1, :]
        if i % 4 == 0:
            t = _SB[np.roll(t, -1, axis=1)].copy()  # RotWord, SubWord
            t[:, 0] ^= _RCON[i // 4 - 1]
        w[:, i, :] = w[:, i - 4, :] ^ t
    return w.reshape(n, nr + 1, 16)


def aes_encrypt_batch(pt: np.ndarray, keys: np.ndarray, nr: int) -> np.ndarray:
    """(N, 16) plaintext blocks under (N, 16) keys, nr rounds (final round
    without MixColumns) -> (N, 16) ciphertext blocks."""
    rks = aes_keyexp_batch(keys, nr)
    s = np.asarray(pt, dtype=np.uint8) ^ rks[:, 0, :]
    for r in range(1, nr):
        s = a128._mix_batch(_SB[s][:, _SR]) ^ rks[:, r, :]
    s = _SB[s][:, _SR] ^ rks[:, nr, :]
    return s


def aes2r_batch(pt: np.ndarray, keys: np.ndarray) -> np.ndarray:
    return aes_encrypt_batch(pt, keys, NR)


def _selfcheck_aes2r_batch() -> None:
    rng = np.random.default_rng(20260906)
    keys = rng.integers(0, 256, size=(1000, 16), dtype=np.uint8)
    pts = rng.integers(0, 256, size=(1000, 16), dtype=np.uint8)
    got = aes_encrypt_batch(pts, keys, NR)
    for i in range(1000):
        want = a2r.aes_encrypt(pts[i].tobytes(), keys[i].tobytes(), NR)
        assert got[i].tobytes() == want, f"aes2r batch/scalar mismatch at row {i}"
    kat = aes_encrypt_batch(np.frombuffer(a2r._KAT_PT, dtype=np.uint8)[None, :],
                            np.frombuffer(a2r._KAT_KEY, dtype=np.uint8)[None, :], 10)
    assert kat[0].tobytes().hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", "AES-128 KAT mismatch"
    # 2-lane adapter parity: _aes2r_128 pads data || 0x80 and returns (lo, hi)
    # = (ct[8:16] BE, ct[0:8] BE).
    data = bytes(rng.integers(0, 256, size=15, dtype=np.uint8))
    key = bytes(rng.integers(0, 256, size=16, dtype=np.uint8))
    lo, hi = a2r._aes2r_128(data, int.from_bytes(key[8:], "big"), int.from_bytes(key[:8], "big"))
    ct = aes2r_batch(np.frombuffer(a2r._pad_block(data), dtype=np.uint8)[None, :],
                     np.frombuffer(key, dtype=np.uint8)[None, :])[0].tobytes()
    assert (int.from_bytes(ct[8:], "big"), int.from_bytes(ct[:8], "big")) == (lo, hi), \
        "aes2r batch / _aes2r_128 lane mismatch"


_selfcheck_aes2r_batch()


# ---- primitive evaluators (uniform interface) --------------------------------
def shape_len(shape: str) -> int:
    return 15 if shape == "block" else int(shape)


def pad80_batch(data: np.ndarray) -> np.ndarray:
    """aes2r._pad_block over rows: data (N, L <= 15) -> (N, 16) data||0x80||0."""
    n, L = data.shape
    assert L <= 15
    out = np.zeros((n, 16), dtype=np.uint8)
    out[:, :L] = data
    out[:, L] = 0x80
    return out


def eval_aesitb128(keys: np.ndarray, data: np.ndarray, shape: str) -> np.ndarray:
    return a128.hash_generic_batch(np.asarray(keys, dtype=np.uint8), a128.pad_batch(data))


def eval_aes2r(keys: np.ndarray, data: np.ndarray, shape: str) -> np.ndarray:
    keys = np.asarray(keys, dtype=np.uint8)
    if shape == "block":
        return aes2r_batch(pad80_batch(data), keys)
    # Lab wrapper: CBC-MAC-style absorption of the PKCS#7 blocks under a
    # fixed key (zero IV). Not a shipped construction.
    padded = a128.pad_batch(data)
    state = np.zeros((padded.shape[0], 16), dtype=np.uint8)
    for i in range(padded.shape[1]):
        state = aes2r_batch(state ^ padded[:, i, :], keys)
    return state


def eval_urandom(keys: np.ndarray, data: np.ndarray, shape: str) -> np.ndarray:
    return np.frombuffer(os.urandom(16 * data.shape[0]), dtype=np.uint8).reshape(-1, 16)


def eval_fnv1a(keys: np.ndarray, data: np.ndarray, shape: str) -> np.ndarray:
    """Scalar mirror per row (chainhashes.fnv1a._fnv1a128): state = key
    bytes big-endian (hi || lo); output packed big-endian (hi || lo)."""
    keys = np.asarray(keys, dtype=np.uint8)
    n = data.shape[0]
    out = np.empty((n, 16), dtype=np.uint8)
    kb = keys.tobytes()
    db = data.tobytes()
    L = data.shape[1]
    for i in range(n):
        k = kb[16 * i:16 * i + 16]
        lo, hi = fnv._fnv1a128(db[L * i:L * i + L], int.from_bytes(k[8:], "big"), int.from_bytes(k[:8], "big"))
        out[i, :8] = np.frombuffer(hi.to_bytes(8, "big"), dtype=np.uint8)
        out[i, 8:] = np.frombuffer(lo.to_bytes(8, "big"), dtype=np.uint8)
    return out


EVAL = {"aesitb128": eval_aesitb128, "aes2r": eval_aes2r, "urandom": eval_urandom, "fnv1a": eval_fnv1a}
LO_SLICE = {"aesitb128": slice(0, 8), "aes2r": slice(8, 16), "urandom": slice(0, 8), "fnv1a": slice(8, 16)}


def half_of_byte(prim: str, byte: int) -> str:
    """'lo' / 'hi' for a key / data / output byte position under the
    primitive's lane convention (data bytes classified by position mod 16)."""
    b = byte % 16
    return "lo" if LO_SLICE[prim].start <= b < LO_SLICE[prim].stop else "hi"


def lanes(prim: str, out: np.ndarray) -> dict:
    return {"full": out, "lo": out[:, LO_SLICE[prim]]}


# ---- input generation (primitive-independent, seeded) ------------------------
def gen_inputs(config: str, shape: str, n: int, seed: int):
    """Returns (keys (N,16) or (1,16) broadcast, data (N,L)) from one RNG
    stream, identical for every primitive at the same (config, shape, n,
    seed)."""
    rng = np.random.default_rng(seed)
    L = shape_len(shape)
    if config == "rand_pt":
        key = rng.integers(0, 256, size=(1, 16), dtype=np.uint8)
        data = rng.integers(0, 256, size=(n, L), dtype=np.uint8)
        return np.broadcast_to(key, (n, 16)), data
    if config == "rand_key":
        keys = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
        d = rng.integers(0, 256, size=(1, L), dtype=np.uint8)
        return keys, np.broadcast_to(d, (n, L))
    if config == "counter":
        key = rng.integers(0, 256, size=(1, 16), dtype=np.uint8)
        idx = np.arange(n, dtype=np.uint64)
        data = np.empty((n, L), dtype=np.uint8)
        if shape == "13":
            data[:, 0] = 0x03
            for k in range(8):
                data[:, 1 + k] = ((idx >> np.uint64(8 * k)) & np.uint64(0xFF)).astype(np.uint8)
            data[:, 9:] = 0
        else:
            for k in range(4):
                data[:, k] = ((idx >> np.uint64(8 * k)) & np.uint64(0xFF)).astype(np.uint8)
            data[:, 4:] = rng.integers(0, 256, size=(1, L - 4), dtype=np.uint8)
        return np.broadcast_to(key, (n, 16)), data
    raise ValueError(config)


# ---- statistics ---------------------------------------------------------------
def marginal_stats(arr: np.ndarray) -> dict:
    n, nb = arr.shape
    chi2, ent, minent = [], [], []
    exp = n / 256.0
    for p in range(nb):
        c = np.bincount(arr[:, p], minlength=256).astype(np.float64)
        chi2.append(float(((c - exp) ** 2 / exp).sum()))
        pr = c[c > 0] / n
        ent.append(max(0.0, float(-(pr * np.log2(pr)).sum())))
        minent.append(max(0.0, float(-math.log2(pr.max()))))
    bits = np.unpackbits(arr, axis=1)
    bias = np.abs(bits.mean(axis=0) - 0.5)
    # 24-bit window birthday counts: dup = N - #distinct values, read against
    # the exact uniform-occupancy expectation and sd (the pair approximation
    # N(N-1)/2^25 is 3.4 sd too high at N = 10^6 over 2^24 bins).
    e_dup, sd_dup = birthday_expect(n, 1 << 24)
    zs, dups = [], []
    for w0 in range(0, nb - 2, 4):
        v = (arr[:, w0].astype(np.uint32) << 16) | (arr[:, w0 + 1].astype(np.uint32) << 8) | arr[:, w0 + 2]
        dup = n - int(np.unique(v).shape[0])
        dups.append(dup)
        zs.append((dup - e_dup) / sd_dup)
    return {
        "chi2_max": max(chi2), "chi2_mean": sum(chi2) / nb, "chi2_argmax": int(np.argmax(chi2)),
        "bit_bias_max": float(bias.max()), "bit_bias_argmax": int(np.argmax(bias)),
        "ent_min": min(ent), "minent_min": min(minent),
        "bday_zmax": max(abs(z) for z in zs), "bday_z": zs, "bday_dups": dups,
        "bday_expect": e_dup, "bday_sd": sd_dup,
    }


def birthday_expect(n: int, bins: int) -> tuple[float, float]:
    """Exact mean and sd of (n - #distinct) for n uniform draws over `bins`
    (occupancy statistics; log1p / expm1 keep the variance's cancelling
    terms accurate)."""
    lq = n * math.log1p(-1.0 / bins)
    q = math.exp(lq)
    delta = n * (math.log1p(-2.0 / bins) - 2.0 * math.log1p(-1.0 / bins))
    var = bins * q * (1.0 - q) + bins * (bins - 1.0) * q * q * math.expm1(delta)
    return n - bins * (1.0 - q), math.sqrt(max(var, 1e-12))


def marginal_ceilings(n: int, nb: int, trials: int) -> dict:
    z_chi = NormalDist().inv_cdf(1 - ALPHA / (nb * trials))
    z_bit = NormalDist().inv_cdf(1 - ALPHA / (2 * 8 * nb * trials))
    nwin = len(range(0, nb - 2, 4))
    z_bday = NormalDist().inv_cdf(1 - ALPHA / (2 * nwin * trials))
    return {"chi2": 255 + z_chi * math.sqrt(510), "bit_bias": z_bit * 0.5 / math.sqrt(n), "bday_z": z_bday}


def run_marginal(prim: str, shape: str, config: str, n: int, seed: int) -> dict:
    keys, data = gen_inputs(config, shape, n, seed)
    t0 = time.time()
    out = EVAL[prim](keys, data, shape)
    dt = time.time() - t0
    res = {"lanes": {}}
    for lane, arr in lanes(prim, out).items():
        res["lanes"][lane] = marginal_stats(arr)
    res["eval_s"] = dt
    return res


def avalanche_stats(prim: str, shape: str, config: str, m: int, seed: int) -> dict:
    """M bases; flip every input bit (data bits for aval_data, key bits for
    aval_key); accumulate per-(in bit, out bit) flip counts and per-flip
    Hamming weights on the full state and the lo lane."""
    rng = np.random.default_rng(seed)
    L = shape_len(shape)
    keys = rng.integers(0, 256, size=(m, 16), dtype=np.uint8)
    data = rng.integers(0, 256, size=(m, L), dtype=np.uint8)
    if config == "aval_key":
        d0 = rng.integers(0, 256, size=(1, L), dtype=np.uint8)
        data = np.broadcast_to(d0, (m, L)).copy()
        nbits, flip_arr = 128, keys
    else:
        k0 = rng.integers(0, 256, size=(1, 16), dtype=np.uint8)
        keys = np.broadcast_to(k0, (m, 16)).copy()
        nbits, flip_arr = 8 * L, data
    ev = EVAL[prim]
    out0 = ev(keys, data, shape)
    flip_counts = {"full": np.zeros((nbits, 128), dtype=np.int64), "lo": np.zeros((nbits, 64), dtype=np.int64)}
    wsum = {"full": np.zeros(nbits), "lo": np.zeros(nbits)}
    wsq = {"full": np.zeros(nbits), "lo": np.zeros(nbits)}
    ddt_max = np.zeros(nbits)
    lo_sl = LO_SLICE[prim]
    # half-cross accumulators: per input bit, output flips landing in the lo
    # / hi output half (sum and sum of squares over the M bases).
    hsum = {"lo": np.zeros(nbits), "hi": np.zeros(nbits)}
    hsq = {"lo": np.zeros(nbits), "hi": np.zeros(nbits)}
    in_half = [half_of_byte(prim, b // 8) for b in range(nbits)]
    t0 = time.time()
    for b in range(nbits):
        byte, bit = divmod(b, 8)
        flipped = flip_arr.copy()
        flipped[:, byte] ^= np.uint8(1 << bit)
        if config == "aval_key":
            out1 = ev(flipped, data, shape)
        else:
            out1 = ev(keys, flipped, shape)
        if prim == "urandom":
            out1 = eval_urandom(keys, data, shape)  # fresh random: ideal reference
        d = out0 ^ out1
        wrow = {}
        for lane, arr in (("full", d), ("lo", d[:, lo_sl])):
            bits = np.unpackbits(arr, axis=1)
            flip_counts[lane][b] = bits.sum(axis=0)
            w = bits.sum(axis=1).astype(np.float64)
            wsum[lane][b] = w.sum()
            wsq[lane][b] = (w ** 2).sum()
            wrow[lane] = w
        w_lo = wrow["lo"]
        w_hi = wrow["full"] - w_lo
        hsum["lo"][b] = w_lo.sum()
        hsq["lo"][b] = (w_lo ** 2).sum()
        hsum["hi"][b] = w_hi.sum()
        hsq["hi"][b] = (w_hi ** 2).sum()
        # low byte of the lo lane (differential_screen.py convention)
        c = np.bincount(d[:, lo_sl][:, 0], minlength=256)
        ddt_max[b] = c.max() / m
    res = {"nbits": nbits, "bases": m, "eval_s": time.time() - t0, "lanes": {}}
    hc = {}
    for ih in ("lo", "hi"):
        sel = np.array([h == ih for h in in_half])
        cnt = int(sel.sum()) * m
        cell = {"n_in_bits": int(sel.sum())}
        for oh in ("lo", "hi"):
            if cnt == 0:
                cell[oh] = None
                continue
            mu = hsum[oh][sel].sum() / cnt
            var = hsq[oh][sel].sum() / cnt - mu ** 2
            cell[oh] = {"mean": float(mu), "sd": float(math.sqrt(max(var, 0.0)))}
        hc[ih] = cell
    res["halfcross"] = hc
    res["halfcross_verdict"] = halfcross_verdict(hc)
    for lane, nout in (("full", 128), ("lo", 64)):
        p = flip_counts[lane] / m
        bias = np.abs(p - 0.5)
        total = nbits * m
        mean = wsum[lane].sum() / total
        var = wsq[lane].sum() / total - mean ** 2
        dead = int(((flip_counts[lane] == 0) | (flip_counts[lane] == m)).sum())
        wi, wo = np.unravel_index(int(np.argmax(bias)), bias.shape)
        res["lanes"][lane] = {
            "avw_mean": float(mean), "avw_sd": float(math.sqrt(max(var, 0.0))),
            "sac_mean": float(bias.mean()), "sac_max": float(bias.max()),
            "sac_worst": [int(wi), int(wo)], "dead_pairs": dead, "pairs": int(nbits * nout),
            "ideal_avw": nout / 2, "ideal_sd": math.sqrt(nout) / 2,
        }
    res["ddt8_max"] = float(ddt_max.max())
    res["ddt8_mean"] = float(ddt_max.mean())
    res["const8"] = float((ddt_max == 1.0).mean())
    res["ddt8_uniform_edge"] = 1 / 256 + 3 * math.sqrt((1 / 256) * (255 / 256) / m)
    return res


def halfcross_verdict(hc: dict) -> str:
    means = []
    cross = []
    for ih in ("lo", "hi"):
        for oh in ("lo", "hi"):
            c = hc[ih][oh]
            if c is None:
                continue
            means.append(c["mean"])
            if ih != oh:
                cross.append(c["mean"])
    if not means:
        return "n/a"
    if all(30.0 <= x <= 34.0 for x in means):
        return "fully mixed"
    if any(x < 2.0 for x in cross):
        return "half-independent"
    return "partially mixed"


def aval_ceilings(m: int, nbits: int, trials: int) -> dict:
    out = {}
    for lane, nout in (("full", 128), ("lo", 64)):
        z = NormalDist().inv_cdf(1 - ALPHA / (2 * nbits * nout * trials))
        out[lane] = z * 0.5 / math.sqrt(m)
    return out


# ---- driver -------------------------------------------------------------------
def cell_label(prim: str, shape: str) -> str:
    if prim == "aes2r" and shape != "block":
        return f"{prim} (lab wrapper)"
    return prim


def run_cell(prim: str, shape: str, config: str, n: int, m: int, trials: int, seed: int, jsonl):
    rows = []
    for t in range(trials):
        s = seed + t
        if config in MARGINAL_CONFIGS:
            r = run_marginal(prim, shape, config, n, s)
            r.update({"kind": "marginal", "samples": n})
        else:
            r = avalanche_stats(prim, shape, config, m, s)
            r.update({"kind": "avalanche", "samples": m})
        r.update({"primitive": prim, "shape": shape, "config": config, "trial": t, "seed": s,
                  "nr": NR if prim == "aes2r" else None, "label": cell_label(prim, shape)})
        rows.append(r)
        if jsonl is not None:
            jsonl.write(json.dumps(r) + "\n")
            jsonl.flush()
        print_row(r, trials)
    return rows


def print_row(r: dict, trials: int) -> None:
    tag = f"{r['label']:<20} {r['shape']:>5} {r['config']:<9} N={r['samples']:<8} t={r['trial']} seed={r['seed']}"
    if r["kind"] == "marginal":
        for lane in ("full", "lo"):
            c = marginal_ceilings(r["samples"], 16 if lane == "full" else 8, trials)
            s = r["lanes"][lane]
            flag = "BIASED" if (s["chi2_max"] > c["chi2"] or s["bit_bias_max"] > c["bit_bias"]
                                or s["bday_zmax"] > c["bday_z"]) else "floor"
            print(f"{tag} {lane:>4} chi2 max {s['chi2_max']:7.1f} (ceil {c['chi2']:.1f}) mean {s['chi2_mean']:6.1f} "
                  f"bias {s['bit_bias_max']:.5f} (ceil {c['bit_bias']:.5f}) H {s['ent_min']:.4f} "
                  f"Hmin {s['minent_min']:.3f} bday|z| {s['bday_zmax']:.2f} (ceil {c['bday_z']:.2f})  {flag}  "
                  f"[{r['eval_s']:.1f}s]")
    else:
        cl = aval_ceilings(r["bases"], r["nbits"], trials)
        for lane in ("full", "lo"):
            s = r["lanes"][lane]
            flag = "BIASED" if s["sac_max"] > cl[lane] else "floor"
            print(f"{tag} {lane:>4} avw {s['avw_mean']:6.2f}+-{s['avw_sd']:.2f} (ideal {s['ideal_avw']:.0f}+-{s['ideal_sd']:.2f}) "
                  f"sac mean {s['sac_mean']:.4f} max {s['sac_max']:.3f} (ceil {cl[lane]:.3f}) dead {s['dead_pairs']}/{s['pairs']} "
                  f"{flag}  [{r['eval_s']:.1f}s]")
        print(f"{tag}  ddt8 max {r['ddt8_max']:.4f} mean {r['ddt8_mean']:.4f} const8 {r['const8']:.3f} "
              f"(uniform edge {r['ddt8_uniform_edge']:.4f})")
        print(f"{tag}  half-cross {_hc_str(r['halfcross'])}  -> {r['halfcross_verdict']}")


def _hc_cell(c) -> str:
    if c is None:
        return "n/a"
    return f"{c['lo']['mean']:.1f}+-{c['lo']['sd']:.1f} / {c['hi']['mean']:.1f}+-{c['hi']['sd']:.1f}"


def _hc_str(hc: dict) -> str:
    return (f"in-lo({hc['lo']['n_in_bits']}b) -> out lo/hi {_hc_cell(hc['lo'] if hc['lo']['lo'] else None)}; "
            f"in-hi({hc['hi']['n_in_bits']}b) -> out lo/hi {_hc_cell(hc['hi'] if hc['hi']['lo'] else None)}")


# ---- report -------------------------------------------------------------------
def _agg(rows, lane, key, how):
    v = [r["lanes"][lane][key] for r in rows]
    if how == "max":
        return max(v)
    if how == "min":
        return min(v)
    mu = sum(v) / len(v)
    sd = math.sqrt(sum((x - mu) ** 2 for x in v) / len(v)) if len(v) > 1 else 0.0
    return mu, sd


def report(path: str) -> None:
    rows = [json.loads(l) for l in open(path) if l.strip()]
    groups = {}
    for r in rows:
        groups.setdefault((r["kind"], r["config"], r["shape"], r["samples"], r["primitive"]), []).append(r)
    prim_order = {p: i for i, p in enumerate(PRIMITIVES)}
    shape_order = {s: i for i, s in enumerate(SHAPES)}
    keys = sorted(groups, key=lambda k: (k[0], CONFIGS.index(k[1]), shape_order[k[2]], k[3], prim_order[k[4]]))
    print("# T34 statistical comparison — aesitb128 vs aes2r (raw primitives, no cascade)\n")
    print("Cells aggregate over trials: chi2_max / bit_bias_max / bday|z|max / sac_max = worst over trials; "
          "means = mean over trials (+- sd across trials); ent / minent = min over trials. Ceilings are "
          f"Bonferroni at alpha = {ALPHA} over bytes (bits, windows, pairs) x trials. aes2r NR = {NR}. "
          "`lab wrapper` = CBC-MAC-style absorption under key = seed (not a shipped construction).\n")
    last = None
    for k in keys:
        kind, config, shape, n, prim = k
        rs = groups[k]
        trials = len(rs)
        hdr = (kind, config, shape, n)
        if hdr != last:
            last = hdr
            print(f"\n## {config} — shape {shape} — N = {n} — trials = {trials}\n")
            if kind == "marginal":
                print("| Primitive | lane | chi2 max (ceil) | chi2 mean | bit bias max (ceil) | H min | Hmin min | bday max\\|z\\| (ceil) | verdict |")
                print("|:--|:--|--:|--:|--:|--:|--:|--:|:--|")
            else:
                print("| Primitive | lane | avw mean +- sd (ideal) | sac mean | sac max (ceil) | dead pairs | ddt8 max (edge) | const8 | verdict |")
                print("|:--|:--|--:|--:|--:|--:|--:|--:|:--|")
        for lane in ("full", "lo"):
            if kind == "marginal":
                c = marginal_ceilings(n, 16 if lane == "full" else 8, trials)
                cm = _agg(rs, lane, "chi2_max", "max")
                cmean, csd = _agg(rs, lane, "chi2_mean", "mean")
                bb = _agg(rs, lane, "bit_bias_max", "max")
                em = _agg(rs, lane, "ent_min", "min")
                mm = _agg(rs, lane, "minent_min", "min")
                bz = _agg(rs, lane, "bday_zmax", "max")
                flag = "**BIASED**" if (cm > c["chi2"] or bb > c["bit_bias"] or bz > c["bday_z"]) else "at floor"
                print(f"| {rs[0]['label']} | {lane} | {cm:.1f} ({c['chi2']:.1f}) | {cmean:.1f} +- {csd:.1f} | "
                      f"{bb:.5f} ({c['bit_bias']:.5f}) | {em:.4f} | {mm:.3f} | {bz:.2f} ({c['bday_z']:.2f}) | {flag} |")
            else:
                cl = aval_ceilings(rs[0]["bases"], rs[0]["nbits"], trials)[lane]
                am, asd = _agg(rs, lane, "avw_mean", "mean")
                sdm, _ = _agg(rs, lane, "avw_sd", "mean")
                sm, _ = _agg(rs, lane, "sac_mean", "mean")
                sx = _agg(rs, lane, "sac_max", "max")
                dead = max(r["lanes"][lane]["dead_pairs"] for r in rs)
                pairs = rs[0]["lanes"][lane]["pairs"]
                ideal = rs[0]["lanes"][lane]["ideal_avw"]
                isd = rs[0]["lanes"][lane]["ideal_sd"]
                dm = max(r["ddt8_max"] for r in rs)
                c8 = max(r["const8"] for r in rs)
                edge = rs[0]["ddt8_uniform_edge"]
                flag = "**BIASED**" if (sx > cl or dead > 0) else "at floor"
                print(f"| {rs[0]['label']} | {lane} | {am:.2f} +- {sdm:.2f} ({ideal:.0f} +- {isd:.2f}) | {sm:.4f} | "
                      f"{sx:.3f} ({cl:.3f}) | {dead} / {pairs} | {dm:.4f} ({edge:.4f}) | {c8:.3f} | {flag} |")
    # Half-cross diffusion table (avalanche cells only), aggregated over trials.
    print("\n\n## Half-cross diffusion (input half -> output half; mean flips +- sd per single-bit flip; ideal 32 +- 4)\n")
    print("| Primitive | shape | flips | bit in lo -> out lo / out hi | bit in hi -> out lo / out hi | verdict |")
    print("|:--|:--|:--|--:|--:|:--|")
    for k in keys:
        kind, config, shape, n, prim = k
        if kind != "avalanche":
            continue
        rs = groups[k]
        cells = {}
        for ih in ("lo", "hi"):
            for oh in ("lo", "hi"):
                v = [r["halfcross"][ih][oh] for r in rs if r["halfcross"][ih][oh] is not None]
                cells[(ih, oh)] = (sum(x["mean"] for x in v) / len(v), sum(x["sd"] for x in v) / len(v)) if v else None
        verdicts = sorted({r["halfcross_verdict"] for r in rs})

        def fmt(ih):
            a, b = cells[(ih, "lo")], cells[(ih, "hi")]
            if a is None:
                return "n/a"
            return f"{a[0]:.1f} +- {a[1]:.1f} / {b[0]:.1f} +- {b[1]:.1f}"
        print(f"| {rs[0]['label']} | {shape} | {'data' if config == 'aval_data' else 'key'} | {fmt('lo')} | {fmt('hi')} | "
              f"{' / '.join(verdicts)} |")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--primitive", choices=PRIMITIVES + ("all",), default="all")
    ap.add_argument("--shape", choices=SHAPES + ("all",), default="all")
    ap.add_argument("--config", choices=CONFIGS + ("all", "marginal", "avalanche"), default="all")
    ap.add_argument("--all", action="store_true", help="full matrix (same as the defaults)")
    ap.add_argument("--samples", type=int, default=100_000, help="N per marginal cell")
    ap.add_argument("--bases", type=int, default=10_000, help="M random bases per avalanche cell")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--seed", type=int, default=1, help="trial t uses seed + t")
    ap.add_argument("--json", help="append one JSON line per (cell, trial)")
    ap.add_argument("--report", metavar="JSONL", help="summarise a JSONL file into Markdown tables and exit")
    args = ap.parse_args()
    if args.report:
        report(args.report)
        return 0
    prims = PRIMITIVES if args.primitive == "all" else (args.primitive,)
    shapes = SHAPES if args.shape == "all" else (args.shape,)
    if args.config == "all":
        configs = CONFIGS
    elif args.config == "marginal":
        configs = MARGINAL_CONFIGS
    elif args.config == "avalanche":
        configs = AVAL_CONFIGS
    else:
        configs = (args.config,)
    print(f"# stats_comparison_a2r_a128  N={args.samples} bases={args.bases} trials={args.trials} "
          f"seed={args.seed} aes2r NR={NR} alpha={ALPHA}")
    jsonl = open(args.json, "a") if args.json else None
    for config in configs:
        for shape in shapes:
            for prim in prims:
                if prim == "urandom" and shape != "block" and config in AVAL_CONFIGS:
                    continue  # the ideal reference does not depend on shape
                if prim == "fnv1a" and args.primitive == "all" and shape != "block":
                    continue  # control row at the block shape only unless asked for explicitly
                run_cell(prim, shape, config, args.samples, args.bases, args.trials, args.seed, jsonl)
    if jsonl is not None:
        jsonl.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
