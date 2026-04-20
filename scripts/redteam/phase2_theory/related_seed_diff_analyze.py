#!/usr/bin/env python3
"""Phase 2e — related-seed differential analyzer.

For one corpus cell (two ciphertexts that share everything except a
known Δ applied to one of the three seeds), compute distributional
tests on D = ct_0 ⊕ ct_1 across the container body. Under PRF / any
non-GF(2)-linear primitive assumption, D is expected to be uniformly
random (KL divergence at the finite-sample floor, byte-distribution
χ² consistent with df=255, bit-level mutual information between D
and Δ ≈ 0). Under a GF(2)-linear primitive (CRC128) D should carry a
structured pattern related to Δ and the tests should register it.

Emits one JSON row on stdout + writes `stats.json` into the cell dir.

Usage:
    python3 related_seed_diff_analyze.py --cell-dir <path>
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

HEADER_SIZE = 20


def parse_body(ct_path: Path, total_pixels: int) -> bytes:
    raw = ct_path.read_bytes()
    need = HEADER_SIZE + total_pixels * 8
    if len(raw) < need:
        raise RuntimeError(
            f"{ct_path.name} too short: {len(raw)} bytes, need {need}"
        )
    return raw[HEADER_SIZE:need]


def byte_chi_squared(diff: bytes) -> tuple[float, int, float]:
    """Pearson χ² test on 256-bin byte distribution of D."""
    n = len(diff)
    if n == 0:
        return 0.0, 0, 1.0
    counts = Counter(diff)
    expected = n / 256.0
    chi2 = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))
    df = 255
    # Approximate p-value via Wilson-Hilferty transform for large df.
    # z ≈ ((chi2/df)**(1/3) - (1 - 2/(9*df))) / sqrt(2/(9*df))
    if df > 0:
        z = ((chi2 / df) ** (1.0 / 3.0) -
             (1 - 2.0 / (9.0 * df))) / math.sqrt(2.0 / (9.0 * df))
        p = 0.5 * math.erfc(z / math.sqrt(2.0))
    else:
        p = 1.0
    return chi2, df, p


def kl_uniform(diff: bytes) -> float:
    """KL divergence of D's byte distribution vs uniform 1/256, in nats."""
    n = len(diff)
    if n == 0:
        return 0.0
    counts = Counter(diff)
    kl = 0.0
    for b in range(256):
        c = counts.get(b, 0)
        if c == 0:
            continue
        p_obs = c / n
        p_uni = 1.0 / 256.0
        kl += p_obs * math.log(p_obs / p_uni)
    return kl


def bit_balance(diff: bytes) -> list[float]:
    """Per-bit probability(1) across byte positions, modulo 8."""
    counts = [0] * 8
    for b in diff:
        for bit in range(8):
            if (b >> bit) & 1:
                counts[bit] += 1
    n = len(diff)
    return [c / n if n else 0.5 for c in counts]


def max_deviation_from_half(balances: list[float]) -> float:
    return max(abs(p - 0.5) for p in balances) if balances else 0.0


def delta_correlation(diff: bytes, delta_bytes: bytes) -> dict:
    """Bit-level signed-correlation of D vs Δ tiled across D.

    Under PRF assumption: D and Δ are independent → correlation ≈ 0.
    Under GF(2)-linear primitive: D ≈ L(Δ) + noise → per-bit correlation
    measurable and Δ-dependent.
    """
    n = len(diff)
    dlen = len(delta_bytes)
    if n == 0 or dlen == 0:
        return {"mean_abs_corr": 0.0, "max_abs_corr": 0.0}
    # Tile Δ to length N, XOR with D, measure bit-balance of XOR.
    # If D and Δ are correlated, D⊕Δ has lower hamming weight than 0.5.
    tiled = bytearray(n)
    for i in range(n):
        tiled[i] = delta_bytes[i % dlen]
    xored = bytes(a ^ b for a, b in zip(diff, tiled))
    per_bit = bit_balance(xored)
    dev = [abs(p - 0.5) for p in per_bit]
    return {
        "mean_abs_corr": sum(dev) / len(dev),
        "max_abs_corr": max(dev),
        "per_bit": per_bit,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cell-dir", type=Path, required=True)
    ap.add_argument("--stdout-json", action="store_true",
                    help="Also print one-line JSON on stdout.")
    args = ap.parse_args()

    meta = json.loads((args.cell_dir / "cell.meta.json").read_text())
    total_pixels = meta["ciphertext_bytes"][0] // 8  # container bytes / 8
    # Recompute: actual container = ciphertext_bytes - header
    container_bytes = meta["ciphertext_bytes"][0] - HEADER_SIZE
    total_pixels = container_bytes // 8

    ct0_body = parse_body(args.cell_dir / "ct_0.bin", total_pixels)
    ct1_body = parse_body(args.cell_dir / "ct_1.bin", total_pixels)
    diff = bytes(a ^ b for a, b in zip(ct0_body, ct1_body))

    chi2, df, p_chi2 = byte_chi_squared(diff)
    kl = kl_uniform(diff)
    bits = bit_balance(diff)
    max_dev = max_deviation_from_half(bits)
    delta_bytes = bytes.fromhex(meta["delta_hex"])
    dc = delta_correlation(diff, delta_bytes)

    stats = {
        "hash": meta["hash"],
        "hash_width": meta["hash_width"],
        "axis": meta["axis"],
        "delta_kind": meta["delta_kind"],
        "plaintext_kind": meta["plaintext_kind"],
        "plaintext_size": meta["plaintext_size"],
        "barrier_fill": meta.get("barrier_fill", 1),
        "container_bytes": container_bytes,
        "byte_chi2": chi2,
        "byte_chi2_df": df,
        "byte_chi2_p": p_chi2,
        "kl_vs_uniform_nats": kl,
        "per_bit_balance": bits,
        "max_abs_bit_deviation": max_dev,
        "delta_corr_mean_abs": dc["mean_abs_corr"],
        "delta_corr_max_abs": dc["max_abs_corr"],
    }
    (args.cell_dir / "stats.json").write_text(json.dumps(stats, indent=2) + "\n")

    if args.stdout_json:
        print(json.dumps(stats, separators=(",", ":")))
    else:
        print(f"{meta['hash']:<10} axis={meta['axis']:<5} "
              f"Δ={meta['delta_kind']:<14} pt={meta['plaintext_kind']:<6} "
              f"chi2={chi2:>10.2f} (p={p_chi2:.4f}) "
              f"KL={kl:.2e} max_bit_dev={max_dev:.5f} "
              f"Δ-corr max_abs={dc['max_abs_corr']:.5f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
