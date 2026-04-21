#!/usr/bin/env python3
"""/dev/urandom KL floor baseline for Phase 2b Mode B (realistic-attacker).

Takes a container size in bytes, reads that many bytes from /dev/urandom,
and runs the same 56-candidate pairwise-KL analysis that
`kl_massive_single_full.py` runs on an ITB ciphertext. Reports
observations per candidate, theoretical KL floor (`bins/N`), observed
KL max, ratio max / floor, max bit-fraction deviation, and per-candidate
χ² statistics.

Baseline for operational KL distinguishability: if `/dev/urandom` at the
same N lands in the same 1.0×–1.5× floor-ratio band as ITB ciphertext,
then ITB ciphertext sits at the sampling precision of the distinguisher
itself — the difference between the two observed KLs is below what any
measurement at this N can resolve.

Usage:
    python3 kl_urandom.py <size_bytes>

Size must be a multiple of 8 (pixel size). Memory ~500 MB regardless of
sample size thanks to chunked processing.
"""

from __future__ import annotations

import os
import sys
import time

import numpy as np

CHANNELS = 8
CHUNK_SIZE = 500_000  # pixels per chunk — matches kl_massive_single_full.py

# Lookup tables identical to distinguisher.py / kl_massive_single_full.py.
_extract_tbl = np.zeros((8, 256), dtype=np.uint8)
for _np_val in range(8):
    _mask_low = (1 << _np_val) - 1
    for _b in range(256):
        _low = _b & _mask_low
        _high = _b >> (_np_val + 1)
        _extract_tbl[_np_val, _b] = _low | (_high << _np_val)

_rot_tbl = np.zeros((7, 128), dtype=np.uint8)
for _r in range(7):
    for _v in range(128):
        _rot_tbl[_r, _v] = ((_v >> _r) | (_v << (7 - _r))) & 0x7F


def run_single(size_bytes: int, run_idx: int = 0) -> dict:
    if size_bytes % CHANNELS != 0:
        raise SystemExit(f"size must be a multiple of {CHANNELS}; got {size_bytes}")
    total_pixels = size_bytes // CHANNELS

    print(f"{'=' * 72}")
    print(f"  /dev/urandom KL baseline  (Phase 2b Mode B mirror) — run #{run_idx + 1}")
    print(f"{'=' * 72}")
    print(f"  size: {size_bytes:,} bytes   total pixels: {total_pixels:,}   candidates/pixel: 56")

    t0 = time.time()
    with open("/dev/urandom", "rb") as f:
        data = f.read(size_bytes)
    if len(data) != size_bytes:
        raise SystemExit(f"short read from /dev/urandom: got {len(data)}, need {size_bytes}")
    container_arr = np.frombuffer(data, dtype=np.uint8).reshape(total_pixels, CHANNELS)
    print(f"  read done in {time.time() - t0:.1f}s")

    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)
    bit_count = np.zeros((8, 7, 7), dtype=np.int64)
    totals = np.zeros((8, 7), dtype=np.int64)

    n_chunks = (total_pixels + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"\n  Chunked Phase 2b-full: chunk size {CHUNK_SIZE:,} px, {n_chunks} chunks")
    t_chunks = time.time()
    for chunk_start in range(0, total_pixels, CHUNK_SIZE):
        chunk_end = min(chunk_start + CHUNK_SIZE, total_pixels)
        aligned_ch = container_arr[chunk_start:chunk_end]

        extracted = _extract_tbl[:, aligned_ch]
        extracted = np.transpose(extracted, (1, 2, 0))
        unrotated = _rot_tbl[:, extracted]
        unrotated = np.transpose(unrotated, (1, 2, 3, 0))
        cand_raw = unrotated

        for np_val in range(8):
            for rot in range(7):
                vals = cand_raw[:, :, np_val, rot].ravel()
                byte_dist[np_val, rot] += np.bincount(vals, minlength=128)
        for bit in range(7):
            bit_vals = ((cand_raw >> bit) & 1).sum(axis=(0, 1)).astype(np.int64)
            bit_count[:, :, bit] += bit_vals
        totals += (chunk_end - chunk_start) * CHANNELS

        elapsed = time.time() - t_chunks
        pct = chunk_end / total_pixels * 100
        print(f"    chunk {chunk_start:>10,} .. {chunk_end:>10,}  "
              f"({pct:5.1f} %) elapsed {elapsed:6.1f}s", flush=True)

    print(f"  chunks done in {time.time() - t_chunks:.1f}s")

    n_obs = int(totals[0, 0])
    floor = 128 / n_obs

    flat = byte_dist.reshape(56, -1).astype(np.float64)
    row_sum = flat.sum(axis=1, keepdims=True)
    row_sum = np.where(row_sum == 0, 1.0, row_sum)
    probs = flat / row_sum
    kl_matrix = np.zeros((56, 56))
    for i in range(56):
        P = probs[i]
        for j in range(56):
            if i == j:
                continue
            Q = probs[j]
            mask = (P > 0) & (Q > 0)
            if mask.any():
                kl_matrix[i, j] = (P[mask] * np.log(P[mask] / Q[mask])).sum()
    non_diag = kl_matrix[~np.eye(56, dtype=bool)]

    bit_fraction = bit_count / totals[:, :, np.newaxis]
    worst_per_cand = np.abs(bit_fraction - 0.5).max(axis=-1)

    total_per_cand = byte_dist.sum(axis=-1, keepdims=True)
    expected = total_per_cand / 128
    chi2 = ((byte_dist - expected) ** 2 / expected).sum(axis=-1)

    kl_min = float(non_diag.min())
    kl_mean = float(non_diag.mean())
    kl_max = float(non_diag.max())
    ratio = kl_max / floor

    print(f"\n  {'=' * 68}")
    print(f"  KL / bit-balance / chi² statistics")
    print(f"  {'=' * 68}")
    print(f"  observations per candidate:     {n_obs:,}")
    print(f"  theoretical KL floor (bins/N):  {floor:.3e} nats")
    print(f"  observed pairwise KL (1 540 pairs):")
    print(f"    min  = {kl_min:.3e} nats")
    print(f"    mean = {kl_mean:.3e} nats")
    print(f"    max  = {kl_max:.3e} nats")
    print(f"  ratio max / floor:              {ratio:.2f}×")
    print(f"  max bit-fraction deviation:     {float(worst_per_cand.max()):.3e}")
    print(f"  mean bit fraction:              {float(bit_fraction.mean()):.10f}  (expected 0.5)")
    print(f"  χ² (df = 127; H0 mean = 127):   min={float(chi2.min()):.2f}  "
          f"mean={float(chi2.mean()):.2f}  max={float(chi2.max()):.2f}")

    return {
        "n_obs": n_obs,
        "floor": floor,
        "kl_min": kl_min,
        "kl_mean": kl_mean,
        "kl_max": kl_max,
        "ratio": ratio,
        "max_bit_dev": float(worst_per_cand.max()),
        "mean_bit_fraction": float(bit_fraction.mean()),
        "chi2_min": float(chi2.min()),
        "chi2_mean": float(chi2.mean()),
        "chi2_max": float(chi2.max()),
    }


def main():
    if len(sys.argv) not in (2, 3):
        print(f"Usage: {sys.argv[0]} <size_bytes> [<repeat_count>]", file=sys.stderr)
        print(f"  <size_bytes>   container size in bytes (must be multiple of 8)",
              file=sys.stderr)
        print(f"  <repeat_count> number of /dev/urandom runs to average (default 1)",
              file=sys.stderr)
        sys.exit(2)

    size_bytes = int(sys.argv[1])
    n_runs = int(sys.argv[2]) if len(sys.argv) == 3 else 1

    results = []
    for i in range(n_runs):
        r = run_single(size_bytes, run_idx=i)
        results.append(r)
        print()

    if n_runs == 1:
        return

    print(f"{'=' * 72}")
    print(f"  Aggregate over {n_runs} runs")
    print(f"{'=' * 72}")
    keys = ["floor", "kl_min", "kl_mean", "kl_max", "ratio",
            "max_bit_dev", "mean_bit_fraction",
            "chi2_min", "chi2_mean", "chi2_max"]
    means = {k: float(np.mean([r[k] for r in results])) for k in keys}
    stds = {k: float(np.std([r[k] for r in results], ddof=1)) for k in keys}
    print(f"  observations per candidate: {results[0]['n_obs']:,}")
    print(f"  theoretical KL floor:        {means['floor']:.3e} nats (identical across runs)")
    print(f"  pairwise KL max:   mean={means['kl_max']:.3e}  std={stds['kl_max']:.3e} nats")
    print(f"  pairwise KL mean:  mean={means['kl_mean']:.3e}  std={stds['kl_mean']:.3e} nats")
    print(f"  pairwise KL min:   mean={means['kl_min']:.3e}  std={stds['kl_min']:.3e} nats")
    print(f"  ratio max/floor:   mean={means['ratio']:.3f}×  std={stds['ratio']:.3f}×")
    print(f"  max bit dev:       mean={means['max_bit_dev']:.3e}  std={stds['max_bit_dev']:.3e}")
    print(f"  mean bit fraction: mean={means['mean_bit_fraction']:.10f}  "
          f"std={stds['mean_bit_fraction']:.2e}")
    print(f"  χ² mean:           mean={means['chi2_mean']:.3f}  std={stds['chi2_mean']:.3f}")
    print(f"  χ² max:            mean={means['chi2_max']:.3f}  std={stds['chi2_max']:.3f}")


if __name__ == "__main__":
    main()
