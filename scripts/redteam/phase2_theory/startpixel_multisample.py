#!/usr/bin/env python3
"""Phase 2c: multi-sample startPixel enumeration, aggregated.

Phase 2c one-sample test showed marginal signal for MD5/MD4 (true startPixel
had slightly elevated chi² vs wrong guesses). This script replicates across
multiple samples per hash and aggregates the ranks to test whether the
directional signal holds with statistical confidence.

Speed optimizations over Phase 2c:
  - Vectorized candidate XOR computation via numpy broadcasts
  - Skip pairwise KL (expensive, not needed for signal detection)
  - Only compute chi² per candidate + aggregate

Output: for each hash, summary of true-rank distribution across N samples:
  - Mean rank / expected rank under H0 (P/2)
  - Sign test: fraction of samples where rank > P/2
  - Binomial p-value for sign test
"""

import sys
import glob
import json
from pathlib import Path

import numpy as np
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import (
    HASH_DIRNAMES, HASH_DISPLAY, KINDS_NO_GIANT,
    HEADER_SIZE, CHANNELS, DATA_BITS_PER_CHANNEL, DATA_BITS_PER_PIXEL,
)

PROJ = Path(__file__).resolve().parents[3]
ROOT = PROJ / "tmp"
PLAIN_DIR = ROOT / "plain"
ENCRYPTED = ROOT / "encrypted"
SEEDS_DIR = ROOT / "seeds"

# Precomputed: 7-bit rotate-right lookup. rot_tbl[r, v] = rotate7_right(v, r)
_rot_tbl = np.zeros((7, 128), dtype=np.uint8)
for r in range(7):
    for v in range(128):
        _rot_tbl[r, v] = ((v >> r) | (v << (7 - r))) & 0x7F

# Precomputed: extract 7-bit data from 8-bit byte given noise_pos
# extract_tbl[np, byte] = data bits
_extract_tbl = np.zeros((8, 256), dtype=np.uint8)
for np_val in range(8):
    mask_low = (1 << np_val) - 1
    for b in range(256):
        low = b & mask_low
        high = b >> (np_val + 1)
        _extract_tbl[np_val, b] = low | (high << np_val)


def get_plaintext_channels(plaintext: bytes, n_pixels: int) -> np.ndarray:
    """Return (n_pixels, 8) array of 7-bit plaintext values per channel."""
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


def analyze_guess_fast(
    container_arr: np.ndarray,
    plaintext_channels: np.ndarray,
    startpixel_guess: int,
    total_pixels: int,
) -> float:
    """Compute mean chi² across 56 candidates for one startPixel guess.
    Returns scalar mean chi² (over 56 candidates' byte distributions)."""
    n_probe = plaintext_channels.shape[0]

    # Aligned channel bytes: shape (n_probe, 8)
    aligned = np.zeros((n_probe, CHANNELS), dtype=np.uint8)
    for p in range(n_probe):
        linear_idx = (startpixel_guess + p) % total_pixels
        aligned[p] = container_arr[linear_idx]

    # Extract 7-bit data for all 8 noise_pos at once: (n_probe, 8, 8_np)
    # extracted[p, ch, np] = _extract_tbl[np, aligned[p, ch]]
    extracted = _extract_tbl[:, aligned]  # shape (8_np, n_probe, 8_ch)
    extracted = np.transpose(extracted, (1, 2, 0))  # (n_probe, 8_ch, 8_np)

    # Apply all 7 rotations: (n_probe, 8_ch, 8_np, 7_rot)
    unrotated = _rot_tbl[:, extracted]  # (7_rot, n_probe, 8_ch, 8_np)
    unrotated = np.transpose(unrotated, (1, 2, 3, 0))  # (n_probe, 8_ch, 8_np, 7_rot)

    # XOR with plaintext: plaintext_channels shape (n_probe, 8_ch)
    cand_xor = unrotated ^ plaintext_channels[:, :, np.newaxis, np.newaxis]  # (n_probe, 8_ch, 8_np, 7_rot)

    # Byte distribution per (noise_pos, rotation): aggregate over (n_probe, 8_ch)
    # We want byte_dist[np, rot, value_0_127] = count
    # Reshape: cand_xor has (n_probe, 8_ch) samples per (np, rot)
    # For each (np, rot), flatten to (n_probe × 8_ch,) and bincount
    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)
    for np_val in range(8):
        for rot in range(7):
            vals = cand_xor[:, :, np_val, rot].ravel()  # n_probe × 8
            counts = np.bincount(vals, minlength=128)
            byte_dist[np_val, rot] = counts

    # Chi² per candidate
    total_per_cand = byte_dist.sum(axis=-1, keepdims=True)  # (8, 7, 1)
    expected = total_per_cand / 128
    chi2 = ((byte_dist - expected) ** 2 / expected).sum(axis=-1)  # (8, 7)
    return float(chi2.mean())


def run_sample(hash_name: str, base: str, probe_pixels: int = 40) -> dict:
    """Run startPixel enumeration on one sample. Return rank statistics."""
    plain_path = PLAIN_DIR / f"{base}.txt"
    bin_path = ENCRYPTED / hash_name / f"{base}.bin"
    meta_path = SEEDS_DIR / hash_name / f"{base}.json"

    plaintext = plain_path.read_bytes()
    ciphertext = bin_path.read_bytes()
    meta = json.loads(meta_path.read_text())

    total_pixels = meta["total_pixels"]
    true_start_pixel = meta["start_pixel"]

    # Container as (total_pixels, 8_channels) uint8 array
    container = ciphertext[HEADER_SIZE:HEADER_SIZE + total_pixels * CHANNELS]
    container_arr = np.frombuffer(container, dtype=np.uint8).reshape(total_pixels, CHANNELS)

    plaintext_channels = get_plaintext_channels(plaintext, probe_pixels)

    chi2_per_guess = np.zeros(total_pixels, dtype=np.float64)
    for guess in range(total_pixels):
        chi2_per_guess[guess] = analyze_guess_fast(
            container_arr, plaintext_channels, guess, total_pixels
        )

    # Rank true startPixel (ascending: lower chi² = more uniform = rank 0)
    sort_idx = np.argsort(chi2_per_guess)
    true_rank = int(np.where(sort_idx == true_start_pixel)[0][0])

    true_chi2 = chi2_per_guess[true_start_pixel]
    mean_chi2 = chi2_per_guess.mean()
    std_chi2 = chi2_per_guess.std()
    z_score = (true_chi2 - mean_chi2) / std_chi2 if std_chi2 > 0 else 0.0

    return {
        "sample": base,
        "P": total_pixels,
        "true_sp": true_start_pixel,
        "true_rank": true_rank,
        "rank_fraction": true_rank / total_pixels,
        "true_chi2": float(true_chi2),
        "mean_chi2": float(mean_chi2),
        "std_chi2": float(std_chi2),
        "z_score": float(z_score),
        "narrowing_factor": total_pixels / (total_pixels - true_rank),  # P / (P - rank)
    }


def aggregate(hash_name: str, samples: list[str], probe_pixels: int = 40):
    print(f"\n{'='*70}")
    print(f"  HASH: {hash_name}   samples: {len(samples)}   probe_pixels: {probe_pixels}")
    print(f"{'='*70}")

    results = []
    for s in samples:
        r = run_sample(hash_name, s, probe_pixels)
        results.append(r)
        print(f"  {s}: P={r['P']}  true_sp={r['true_sp']:4d}  "
              f"rank={r['true_rank']:4d}/{r['P']}  "
              f"frac={r['rank_fraction']:.3f}  z={r['z_score']:+.3f}  "
              f"narrow=1/{r['narrowing_factor']:.1f}")

    # Aggregate statistics
    fractions = np.array([r["rank_fraction"] for r in results])
    z_scores = np.array([r["z_score"] for r in results])

    print(f"\n  --- aggregate ---")
    print(f"  Mean rank_fraction: {fractions.mean():.4f}  (expected under H0: 0.5)")
    print(f"  Std rank_fraction: {fractions.std():.4f}")
    print(f"  Mean z-score: {z_scores.mean():+.4f}  (expected under H0: 0)")
    print(f"  Std z-score: {z_scores.std():.4f}")

    # Sign test: how many samples have rank > P/2 (i.e., fraction > 0.5)?
    n_above = int((fractions > 0.5).sum())
    n = len(results)
    # Binomial one-sided p-value: P(X >= n_above | p=0.5)
    p_binom = 1 - stats.binom.cdf(n_above - 1, n, 0.5)
    print(f"  Samples with rank > P/2: {n_above} / {n}")
    print(f"  Binomial one-sided p-value (direction=high): {p_binom:.4f}")

    # t-test: is mean z significantly > 0?
    t_stat, p_t = stats.ttest_1samp(z_scores, 0.0)
    print(f"  T-test z_scores vs 0: t={t_stat:+.3f}  p={p_t:.4f}")

    return results


def list_samples(kind: str, hash_name: str) -> list[str]:
    """Enumerate all {kind}_NNN samples available for a hash variant."""
    import re
    pat = re.compile(rf"^{re.escape(kind)}_(\d{{3}})\.bin$")
    files = sorted((ENCRYPTED / hash_name).glob(f"{kind}_*.bin"))
    return [Path(f).stem for f in files if pat.match(Path(f).name)]


def probe_depth_for(plaintext_len: int) -> int:
    """Probe as many data pixels as available (capped at 200 to keep runtime bounded)."""
    total_bits = plaintext_len * 8
    data_pixels = (total_bits + DATA_BITS_PER_PIXEL - 1) // DATA_BITS_PER_PIXEL
    return max(5, min(data_pixels, 200))


def _worker_task(args):
    """Worker function for multiprocessing pool. Processes one sample."""
    hash_name, sample_base = args
    plain = (PLAIN_DIR / f"{sample_base}.txt").read_bytes()
    probe = probe_depth_for(len(plain))
    r = run_sample(hash_name, sample_base, probe_pixels=probe)
    r["probe"] = probe
    r["hash_name"] = hash_name
    # Extract kind from base like "http_large_007" -> "http_large"
    import re
    m = re.match(r"^(.+)_\d{3}$", sample_base)
    r["kind"] = m.group(1) if m else "unknown"
    return r


def aggregate_by_kind(hash_name: str, kind: str, precomputed_results: list | None = None):
    samples = list_samples(kind, hash_name)
    if not samples:
        return None

    if precomputed_results is not None:
        # Use pre-parallel-computed results
        results = precomputed_results
    else:
        results = []
        for s in samples:
            # Read plaintext length for adaptive probe
            plain = (PLAIN_DIR / f"{s}.txt").read_bytes()
            probe = probe_depth_for(len(plain))
            r = run_sample(hash_name, s, probe_pixels=probe)
            r["probe"] = probe
            results.append(r)

    fractions = np.array([r["rank_fraction"] for r in results])
    z_scores = np.array([r["z_score"] for r in results])
    n_above = int((fractions > 0.5).sum())
    p_binom = 1 - stats.binom.cdf(n_above - 1, len(results), 0.5)
    t_stat, p_t = stats.ttest_1samp(z_scores, 0.0) if len(results) > 1 else (0.0, 1.0)

    return {
        "kind": kind,
        "hash": hash_name,
        "n": len(results),
        "mean_probe": float(np.mean([r["probe"] for r in results])),
        "mean_frac": float(fractions.mean()),
        "std_frac": float(fractions.std()),
        "mean_z": float(z_scores.mean()),
        "std_z": float(z_scores.std()),
        "p_binom": float(p_binom),
        "p_t": float(p_t),
        "per_sample": results,
    }


if __name__ == "__main__":
    import multiprocessing as mp
    import time

    print("Phase 2c: multi-sample, multi-kind startPixel enumeration (parallel 8 workers)")

    # html_giant excluded: O(P²) startPixel enumeration is infeasible at ~4.8M pixels/container.
    kinds = KINDS_NO_GIANT
    hashes = HASH_DIRNAMES

    # Build full task list: one (hash, sample_base) per work unit
    tasks = []
    for h in hashes:
        for k in kinds:
            for s in list_samples(k, h):
                tasks.append((h, s))

    print(f"  Total tasks: {len(tasks)}  across {len(hashes)} hashes × {len(kinds)} kinds")
    print(f"  Spawning 8-worker pool...")

    t0 = time.time()
    # Use imap_unordered for streaming progress; chunksize small to balance load
    with mp.Pool(processes=8) as pool:
        all_sample_results = []
        for i, r in enumerate(pool.imap_unordered(_worker_task, tasks, chunksize=1), 1):
            all_sample_results.append(r)
            if i % 20 == 0 or i == len(tasks):
                elapsed = time.time() - t0
                print(f"    {i}/{len(tasks)} done  ({elapsed:.1f}s elapsed)")
    t1 = time.time()
    print(f"  Parallel pool done in {t1 - t0:.1f}s")

    # Group results by (hash, kind)
    grouped = {}
    for r in all_sample_results:
        key = (r["hash_name"], r["kind"])
        grouped.setdefault(key, []).append(r)

    # Compute per (hash, kind) aggregate and print
    summary = []
    for h in hashes:
        print(f"\n{'#'*70}")
        print(f"#  HASH: {h}")
        print(f"{'#'*70}")
        for k in kinds:
            key = (h, k)
            if key not in grouped:
                print(f"\n--- kind: {k} ---")
                print(f"  (no samples)")
                continue
            result = aggregate_by_kind(h, k, precomputed_results=grouped[key])
            if result is None:
                continue
            print(f"--- kind: {k} ---  "
                  f"n={result['n']}  probe≈{result['mean_probe']:.0f}  "
                  f"mean_frac={result['mean_frac']:.4f}  (±{result['std_frac']:.3f})  "
                  f"mean_z={result['mean_z']:+.3f}  (±{result['std_z']:.3f})  "
                  f"sign_p={result['p_binom']:.3f}  t_p={result['p_t']:.3f}")
            summary.append(result)

    print(f"\n{'='*85}")
    print(f"  CROSS-KIND / CROSS-HASH SUMMARY")
    print(f"{'='*85}")
    print(f"  {'hash':<5} {'kind':<12} {'n':>3} {'mean_frac':>10} {'mean_z':>8} "
          f"{'sign_p':>7} {'t_p':>7}  signal?")
    for r in summary:
        # Simple significance flag (purely heuristic)
        sig = ""
        if r["p_t"] < 0.05 or r["p_binom"] < 0.05:
            sig = " ⚠ possible"
        if r["p_t"] < 0.01 or r["p_binom"] < 0.01:
            sig = " ⚠⚠ likely"
        print(f"  {r['hash']:<5} {r['kind']:<12} {r['n']:>3} "
              f"{r['mean_frac']:>10.4f} {r['mean_z']:>+8.3f} "
              f"{r['p_binom']:>7.3f} {r['p_t']:>7.3f}{sig}")

    print(f"\n  Aggregating across kinds per hash:")
    print(f"  {'hash':<5} {'total_n':>7} {'overall_mean_frac':>17} {'overall_mean_z':>15}")
    for h in hashes:
        hash_results = [r for r in summary if r["hash"] == h]
        all_fractions = np.concatenate([
            np.array([s["rank_fraction"] for s in r["per_sample"]])
            for r in hash_results
        ])
        all_zs = np.concatenate([
            np.array([s["z_score"] for s in r["per_sample"]])
            for r in hash_results
        ])
        print(f"  {h:<5} {len(all_fractions):>7} "
              f"{all_fractions.mean():>17.4f} {all_zs.mean():>+15.3f}")

    print("\n  Interpretation:")
    print("    mean_frac ≈ 0.5 and sign_p, t_p > 0.05 → no distinguisher")
    print("    mean_frac systematically deviates from 0.5 → possible distinguisher")
    print("    Per-hash aggregation across kinds is the strongest test")
