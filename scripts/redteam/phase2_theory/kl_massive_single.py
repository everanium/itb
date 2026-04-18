#!/usr/bin/env python3
"""Phase 2b KL floor probe on a single 63 MB ITB encryption.

One-off experiment complementing the regular Phase 2b run. At N ≈ 77 M
observations per candidate the theoretical finite-sample KL floor
(~bins/N = 128 / 77·10⁶ ≈ 1.7 × 10⁻⁶ nats) approaches the lower limit
of what's meaningfully distinguishable from zero on float64 histograms.

Single-threaded, chunked (memory ~500 MB regardless of sample size), so
any modern machine can run it.

Prerequisites:
    ITB_REDTEAM_MASSIVE=<hash> ITB_BARRIER_FILL=1 \\
      go test -run TestRedTeamGenerateSingleMassive -v -timeout 10m
    # produces tmp/massive/<hash>.{bin,plain,pixel}

Usage:
    python3 scripts/redteam/phase2_theory/kl_massive_single.py <hash>

Valid <hash> values match the 10 dirnames used elsewhere:
    fnv1a, md5, aescmac, siphash24, chacha20, areion256,
    blake2s, blake3, blake2b, areion512
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np

PROJ = Path(__file__).resolve().parents[3]
MASSIVE_DIR = PROJ / "tmp" / "massive"

# Container / extraction layout — same as distinguisher.py.
HEADER_SIZE = 20
CHANNELS = 8
DATA_BITS_PER_CHANNEL = 7
DATA_BITS_PER_PIXEL = 56

# Chunk size: 500k pixels × 8ch × 8np × 7rot × 1 byte = ~224 MB peak
# allocation for cand_xor. Safe on any machine with ≥ 1 GB free RAM.
CHUNK_SIZE = 500_000

# Lookup tables (copied verbatim from distinguisher.py).
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


def get_plaintext_channels(plaintext: bytes, n_pixels: int) -> np.ndarray:
    """(n_pixels, 8) array of 7-bit plaintext values per channel."""
    out = np.zeros((n_pixels, CHANNELS), dtype=np.uint8)
    total_bits = len(plaintext) * 8
    for p in range(n_pixels):
        bit_index = p * DATA_BITS_PER_PIXEL
        for ch in range(CHANNELS):
            if bit_index >= total_bits:
                break
            byte_idx = bit_index // 8
            bit_off = bit_index % 8
            raw = plaintext[byte_idx]
            if byte_idx + 1 < len(plaintext):
                raw |= plaintext[byte_idx + 1] << 8
            out[p, ch] = (raw >> bit_off) & 0x7F
            bit_index += DATA_BITS_PER_CHANNEL
    return out


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <hash_name>", file=sys.stderr)
        print(f"  Requires tmp/massive/<hash>.{{bin,plain,pixel}} from "
              f"TestRedTeamGenerateSingleMassive", file=sys.stderr)
        sys.exit(2)

    hash_name = sys.argv[1]
    bin_path = MASSIVE_DIR / f"{hash_name}.bin"
    plain_path = MASSIVE_DIR / f"{hash_name}.plain"
    pix_path = MASSIVE_DIR / f"{hash_name}.pixel"

    for p in (bin_path, plain_path, pix_path):
        if not p.exists():
            print(f"Missing {p}; run TestRedTeamGenerateSingleMassive first",
                  file=sys.stderr)
            sys.exit(1)

    # Parse sidecar metadata
    meta = {}
    for line in pix_path.read_text().strip().split("\n"):
        k, v = line.split("=", 1)
        meta[k] = v
    start_pixel = int(meta["start_pixel"])
    total_pixels = int(meta["total_pixels"])
    barrier_fill = int(meta.get("barrier_fill", "1"))

    print(f"{'=' * 72}")
    print(f"  Phase 2b KL floor probe on a single massive sample")
    print(f"{'=' * 72}")
    print(f"  hash: {hash_name}   BarrierFill: {barrier_fill}")

    # Load
    t0 = time.time()
    plaintext = plain_path.read_bytes()
    ciphertext = bin_path.read_bytes()
    container = ciphertext[HEADER_SIZE:HEADER_SIZE + total_pixels * CHANNELS]
    print(f"  plaintext : {len(plaintext):,} bytes ({len(plaintext) / 1024 / 1024:.1f} MB)")
    print(f"  ciphertext: {len(ciphertext):,} bytes ({len(ciphertext) / 1024 / 1024:.1f} MB)")
    print(f"  total pixels: {total_pixels:,}   start pixel: {start_pixel:,}")

    # Data-carrying pixel count
    total_bits = len(plaintext) * 8
    data_pixels = (total_bits + DATA_BITS_PER_PIXEL - 1) // DATA_BITS_PER_PIXEL
    if data_pixels > total_pixels:
        data_pixels = total_pixels
    print(f"  data pixels: {data_pixels:,}   candidates/pixel: 56")

    # Aligned container view with startPixel wrap
    container_arr = np.frombuffer(container, dtype=np.uint8).reshape(total_pixels, CHANNELS)
    indices = (start_pixel + np.arange(data_pixels)) % total_pixels
    aligned = container_arr[indices]
    print(f"  aligned array: {aligned.nbytes / 1024 / 1024:.1f} MB")

    pt_channels = get_plaintext_channels(plaintext, data_pixels)
    print(f"  pt_channels : {pt_channels.nbytes / 1024 / 1024:.1f} MB")
    print(f"  load done in {time.time() - t0:.1f}s")

    # Accumulators (tiny)
    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)
    bit_count = np.zeros((8, 7, 56), dtype=np.int64)
    totals = np.zeros((8, 7), dtype=np.int64)

    # Chunked Phase 2b
    n_chunks = (data_pixels + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"\n  Chunked Phase 2b: chunk size {CHUNK_SIZE:,} px, {n_chunks} chunks")
    t_chunks = time.time()
    for chunk_start in range(0, data_pixels, CHUNK_SIZE):
        chunk_end = min(chunk_start + CHUNK_SIZE, data_pixels)
        aligned_ch = aligned[chunk_start:chunk_end]
        pt_ch = pt_channels[chunk_start:chunk_end]

        extracted = _extract_tbl[:, aligned_ch]                    # (8_np, chunk, 8_ch)
        extracted = np.transpose(extracted, (1, 2, 0))             # (chunk, 8_ch, 8_np)
        unrotated = _rot_tbl[:, extracted]                         # (7_rot, chunk, 8_ch, 8_np)
        unrotated = np.transpose(unrotated, (1, 2, 3, 0))          # (chunk, 8_ch, 8_np, 7_rot)
        cand_xor = unrotated ^ pt_ch[:, :, np.newaxis, np.newaxis]

        for np_val in range(8):
            for rot in range(7):
                vals = cand_xor[:, :, np_val, rot].ravel()
                byte_dist[np_val, rot] += np.bincount(vals, minlength=128)
        for ch in range(CHANNELS):
            for bit in range(7):
                bit_idx = ch * 7 + bit
                bit_vals = ((cand_xor[:, ch, :, :] >> bit) & 1).sum(axis=0).astype(np.int64)
                bit_count[:, :, bit_idx] += bit_vals
        totals += (chunk_end - chunk_start)

        elapsed = time.time() - t_chunks
        pct = chunk_end / data_pixels * 100
        print(f"    chunk {chunk_start:>10,} .. {chunk_end:>10,}  "
              f"({pct:5.1f} %) elapsed {elapsed:6.1f}s", flush=True)

    print(f"  chunks done in {time.time() - t_chunks:.1f}s")

    # Analysis
    print(f"\n  {'=' * 68}")
    print(f"  KL / bit-balance / chi² statistics")
    print(f"  {'=' * 68}")

    # Observations per candidate (N)
    n_obs = int(totals[0, 0]) * CHANNELS
    floor = 128 / n_obs

    print(f"  observations per candidate: {n_obs:,}")
    print(f"  theoretical KL floor (bins/N): {floor:.3e} nats")

    # Pairwise KL over all (56 × 55 / 2 = 1 540) unique pairs
    flat = byte_dist.reshape(56, -1).astype(np.float64)
    row_sum = flat.sum(axis=1, keepdims=True)
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

    print(f"\n  Pairwise KL divergence (56×55 = 3 080 directed, 1 540 unique pairs)")
    print(f"    min  = {non_diag.min():.3e} nats")
    print(f"    mean = {non_diag.mean():.3e} nats")
    print(f"    max  = {non_diag.max():.3e} nats")
    print(f"    max / theoretical floor = {non_diag.max() / floor:.2f}×")

    # Bit-balance
    bit_fraction = bit_count / totals[:, :, np.newaxis]
    worst_per_cand = np.abs(bit_fraction - 0.5).max(axis=-1)
    print(f"\n  Per-candidate bit balance (max deviation from 0.5 per candidate)")
    print(f"    overall max = {worst_per_cand.max():.3e}")
    print(f"    mean bit fraction = {bit_fraction.mean():.10f}  (expected 0.5)")

    # Chi² per candidate (128 bins, df = 127)
    total_per_cand = byte_dist.sum(axis=-1, keepdims=True)
    expected = total_per_cand / 128
    chi2 = ((byte_dist - expected) ** 2 / expected).sum(axis=-1)
    print(f"\n  Per-candidate χ² (df = 127; H0 mean = 127)")
    print(f"    min  = {chi2.min():.2f}")
    print(f"    mean = {chi2.mean():.2f}")
    print(f"    max  = {chi2.max():.2f}")

    # Summary line (single-row table fodder for REDTEAM.md)
    print(f"\n  {'=' * 68}")
    print(f"  Summary row for REDTEAM.md:")
    print(f"  {'=' * 68}")
    print(f"  hash={hash_name}  N={n_obs:,}  floor={floor:.2e}  "
          f"KL_max={non_diag.max():.2e}  ratio={non_diag.max() / floor:.2f}×")


if __name__ == "__main__":
    main()
