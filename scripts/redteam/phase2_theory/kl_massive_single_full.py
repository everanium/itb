#!/usr/bin/env python3
"""Phase 2b KL floor probe on a single ITB encryption —
full-container / realistic-attacker variant.

Sibling of `kl_massive_single.py`. That script reads the .pixel
sidecar's startPixel and XORs with the known plaintext (attacker has
idealised alignment). This script models the realistic threat: no
startPixel, no plaintext XOR, iterate all P container pixels — data
AND CSPRNG fill indistinguishably — and accumulate the raw 7-bit
candidate distribution.

The container body on the v0.3.0 shipped wire is the barrier-permuted
Triple stream — three snakes distributed through the always-on 48-bit
Interlocked Barrier. The probe treats the body as one flat
8-byte-per-pixel stream (matching the coarse treatment
`raw_mode_common.py` uses); the barrier's structural complexity is
absorbed by the χ² / pairwise-KL metric aggregating over all pixels.

Single-threaded, chunked (memory ~500 MB regardless of sample size).

Prerequisites:
    ITB_REDTEAM_MASSIVE=<hash> ITB_BARRIER_FILL=1 \\
      ITB_REDTEAM_MASSIVE_SIZE=<bytes> ITB_REDTEAM_MASSIVE_OUTDIR=<dir> \\
      go test -tags redteam -run TestRedTeamGenerateTripleMassive -v -timeout 10m
    # produces <dir>/<hash>.{bin,plain,pixel}

Usage:
    python3 scripts/redteam/phase2_theory/kl_massive_single_full.py <hash>

Valid <hash> values match the shipped registry PRF-grade entries.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np

import os

PROJ = Path(__file__).resolve().parents[3]
# ITB_MASSIVE_DIR env var overrides the default tmp/massive lookup — used by
# kl_matrix.py to give parallel workers isolated output directories.
_MASSIVE_DIR_OVERRIDE = os.environ.get("ITB_MASSIVE_DIR", "")
MASSIVE_DIR = (
    Path(_MASSIVE_DIR_OVERRIDE).resolve()
    if _MASSIVE_DIR_OVERRIDE
    else PROJ / "tmp" / "massive"
)

CHANNELS = 8
CHUNK_SIZE = 500_000  # same memory budget as Mode A: ~224 MB cand_raw peak
# `header_size` is now read per-cell from the `.pixel` sidecar — the v0.3.0
# dual-nonce wire header is `2 * NonceSize + 4` bytes (132 at the default
# 512-bit nonce); the pre-v0.3.0 default of 20 remains as a last-resort
# fallback for legacy corpora that omit the field.
LEGACY_HEADER_SIZE = 20

# Lookup tables (identical to distinguisher.py / kl_massive_single.py).
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


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <hash_name>", file=sys.stderr)
        print(f"  Requires tmp/massive/<hash>.{{bin,pixel}} from "
              f"TestRedTeamGenerateSingleMassive", file=sys.stderr)
        sys.exit(2)

    hash_name = sys.argv[1]
    bin_path = MASSIVE_DIR / f"{hash_name}.bin"
    pix_path = MASSIVE_DIR / f"{hash_name}.pixel"

    for p in (bin_path, pix_path):
        if not p.exists():
            print(f"Missing {p}; run TestRedTeamGenerateSingleMassive first",
                  file=sys.stderr)
            sys.exit(1)

    # Read only container dimensions — no startPixel, no plaintext.
    meta = {}
    for line in pix_path.read_text().strip().split("\n"):
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        meta[k] = v
    total_pixels = int(meta["total_pixels"])
    barrier_fill = int(meta.get("barrier_fill", "1"))
    # v0.3.0 dual-nonce corpora carry `header_size` directly; fall back to
    # `2 * len(main_nonce) + 4` derived from `main_nonce_hex`, then to the
    # pre-v0.3.0 20-byte constant as a last resort. `Config.BarrierFill` is
    # the runtime knob (never `SetBarrierFill(...)` — no such API exists);
    # the corpus generator threads it via `ITB_BARRIER_FILL` into
    # `Encrypt3x128Cfg`'s `*Config`.
    if "header_size" in meta:
        header_size = int(meta["header_size"])
    else:
        nonce_hex = meta.get("main_nonce_hex") or meta.get("nonce_hex")
        if nonce_hex:
            header_size = 2 * (len(nonce_hex) // 2) + 4
        else:
            header_size = LEGACY_HEADER_SIZE

    print(f"{'=' * 72}")
    print(f"  Phase 2b-full KL floor probe on a single massive sample")
    print(f"  (no startPixel, no plaintext — realistic-attacker threat model)")
    print(f"{'=' * 72}")
    print(f"  hash: {hash_name}   BarrierFill: {barrier_fill}   header_size: {header_size}")

    t0 = time.time()
    ciphertext = bin_path.read_bytes()
    container = ciphertext[header_size:header_size + total_pixels * CHANNELS]
    print(f"  ciphertext: {len(ciphertext):,} bytes "
          f"({len(ciphertext) / 1024 / 1024:.1f} MB)")
    print(f"  total pixels: {total_pixels:,}   candidates/pixel: 56")

    container_arr = np.frombuffer(container, dtype=np.uint8).reshape(total_pixels, CHANNELS)
    print(f"  container view: {container_arr.nbytes / 1024 / 1024:.1f} MB")
    print(f"  load done in {time.time() - t0:.1f}s")

    # Accumulators
    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)
    # 7 bit positions per candidate (not 56 — there's no plaintext XOR so no
    # cross-channel bit mask). Test 1 is bit-balance within the 7-bit raw value.
    bit_count = np.zeros((8, 7, 7), dtype=np.int64)
    totals = np.zeros((8, 7), dtype=np.int64)

    n_chunks = (total_pixels + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"\n  Chunked Phase 2b-full: chunk size {CHUNK_SIZE:,} px, {n_chunks} chunks")
    t_chunks = time.time()
    for chunk_start in range(0, total_pixels, CHUNK_SIZE):
        chunk_end = min(chunk_start + CHUNK_SIZE, total_pixels)
        aligned_ch = container_arr[chunk_start:chunk_end]  # (chunk, 8)

        extracted = _extract_tbl[:, aligned_ch]                  # (8_np, chunk, 8_ch)
        extracted = np.transpose(extracted, (1, 2, 0))            # (chunk, 8_ch, 8_np)
        unrotated = _rot_tbl[:, extracted]                        # (7_rot, chunk, 8_ch, 8_np)
        unrotated = np.transpose(unrotated, (1, 2, 3, 0))         # (chunk, 8_ch, 8_np, 7_rot)
        # No plaintext XOR — treat unrotated as the raw 7-bit candidate value.
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

    print(f"\n  {'=' * 68}")
    print(f"  KL / bit-balance / chi² statistics (full-container model)")
    print(f"  {'=' * 68}")

    n_obs = int(totals[0, 0])
    floor = 128 / n_obs
    print(f"  observations per candidate: {n_obs:,}")
    print(f"  theoretical KL floor (bins/N): {floor:.3e} nats")

    # Pairwise KL across all 56 × 55 directed / 1 540 unique pairs
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

    print(f"\n  Pairwise KL divergence (56 × 55 = 3 080 directed, 1 540 unique pairs)")
    print(f"    min  = {non_diag.min():.3e} nats")
    print(f"    mean = {non_diag.mean():.3e} nats")
    print(f"    max  = {non_diag.max():.3e} nats")
    print(f"    max / theoretical floor = {non_diag.max() / floor:.2f}×")

    bit_fraction = bit_count / totals[:, :, np.newaxis]
    worst_per_cand = np.abs(bit_fraction - 0.5).max(axis=-1)
    print(f"\n  Per-candidate bit balance (max deviation from 0.5 per candidate over 7 bit positions)")
    print(f"    overall max = {worst_per_cand.max():.3e}")
    print(f"    mean bit fraction = {bit_fraction.mean():.10f}  (expected 0.5)")

    total_per_cand = byte_dist.sum(axis=-1, keepdims=True)
    expected = total_per_cand / 128
    chi2 = ((byte_dist - expected) ** 2 / expected).sum(axis=-1)
    print(f"\n  Per-candidate χ² (df = 127; H0 mean = 127)")
    print(f"    min  = {chi2.min():.2f}")
    print(f"    mean = {chi2.mean():.2f}")
    print(f"    max  = {chi2.max():.2f}")

    print(f"\n  {'=' * 68}")
    print(f"  Summary row for REDTEAM.md (full-container / realistic-attacker):")
    print(f"  {'=' * 68}")
    print(f"  hash={hash_name}  N={n_obs:,}  floor={floor:.2e}  "
          f"KL_max={non_diag.max():.2e}  ratio={non_diag.max() / floor:.2f}×")


if __name__ == "__main__":
    main()
