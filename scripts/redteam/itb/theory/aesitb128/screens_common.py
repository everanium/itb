"""Shared plumbing for the AES-ITB-128 reduced-round-primitive screens.

Every screen in this directory evaluates the shipped aesitb128 sponge
(`chainhashes.aesitb128`, bit-exact with `aesitb.go`) standalone (r = 1, no
feedforward — the raw primitive) and under the ChainHash cascade at
r ∈ R_SET primitive calls, with three attacker observables per depth:

  * `discard on`          — lo lane only (8 bytes), what ITB's encoding
                            observes; raw h_r.
  * `discard off, raw`    — full 16-byte h_r.
  * `discard off, peeled` — full h_r inverted through the last primitive
                            call (P^-1 is public, fixedKey known): exposes
                            seed_r XOR h_{r-1}. At r = 1 this IS the seed
                            block; at r >= 2 it is depth r-1 plus one XOR
                            whitening. Discard-on has no peel — the
                            hi lane is hidden, so inversion costs 2^64.

Deployment depths: r = KeyBits / 128 -> 4 (512-bit), 8 (1024-bit),
16 (2048-bit). The lab data shape is one PKCS#7 block (<= 15 bytes, three
AES rounds per call) unless a screen sets `--data-len`; the shipped
per-pixel shapes are 20 / 36 / 68 bytes (4 / 5 / 7 rounds per call), so the
lab shape is the attacker-favourable one.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "_common"))

import numpy as np  # noqa: E402

from chainhashes import aesitb128 as prim  # noqa: E402

R_SET = (1, 2, 3, 4, 5, 6, 7, 8, 12, 16)
DEPLOYMENT_DEPTHS = {4: "512-bit", 8: "1024-bit", 16: "2048-bit"}
OBSERVABLES = ("discard on", "discard off, raw", "discard off, peeled")


def depth_label(r: int) -> str:
    if r == 1:
        return "raw"
    return DEPLOYMENT_DEPTHS.get(r, "")


def random_comps(rounds: int) -> list[int]:
    return [int.from_bytes(os.urandom(8), "little") for _ in range(2 * rounds)]


def observables(data_arr, comps, rounds: int) -> dict:
    """Evaluate the three attacker observables over an (N, L) uint8 array."""
    full = prim.chainhash_batch(data_arr, comps, rounds=rounds, discard=False)
    return {
        "discard on": full[:, :8],
        "discard off, raw": full,
        "discard off, peeled": prim.peel_last_batch(data_arr, full),
    }


def balance_stats(arr) -> tuple[int, int, int]:
    """(#active bytes, #balanced bytes, nbytes) over the rows of arr."""
    nbytes = arr.shape[1]
    active = int(sum(1 for p in range(nbytes) if len(np.unique(arr[:, p])) > 1))
    xor = np.bitwise_xor.reduce(arr, axis=0)
    balanced = int(np.count_nonzero(xor == 0))
    return active, balanced, nbytes


def lambda_set(order: int, data_len: int, rng=os.urandom):
    """Λ-set of order `order`: bytes 0..order-1 run over all 256^order
    values, the remaining data bytes are a random fixed constant."""
    n = 256 ** order
    fixed = np.frombuffer(rng(data_len), dtype=np.uint8)
    arr = np.broadcast_to(fixed, (n, data_len)).copy()
    idx = np.arange(n, dtype=np.uint64)
    for k in range(order):
        arr[:, k] = ((idx >> np.uint64(8 * k)) & np.uint64(0xFF)).astype(np.uint8)
    return arr


def xor_reduce_chunked(data_arr, comps, rounds: int, chunk: int = 1 << 20):
    """XOR-sum of every observable over a large Λ-set, chunked to bound
    memory; also returns per-observable active-byte flags."""
    n = data_arr.shape[0]
    acc = {k: None for k in OBSERVABLES}
    first = {}
    active = {k: None for k in OBSERVABLES}
    for start in range(0, n, chunk):
        obs = observables(data_arr[start:start + chunk], comps, rounds)
        for k, v in obs.items():
            x = np.bitwise_xor.reduce(v, axis=0)
            acc[k] = x if acc[k] is None else acc[k] ^ x
            if k not in first:
                first[k] = v[0].copy()
                active[k] = np.zeros(v.shape[1], dtype=bool)
            active[k] |= np.any(v != first[k], axis=0)
    return {k: (int(np.count_nonzero(active[k])), int(np.count_nonzero(acc[k] == 0)),
                int(acc[k].shape[0])) for k in OBSERVABLES}
