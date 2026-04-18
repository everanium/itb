#!/usr/bin/env python3
"""Phase 2c: startPixel enumeration attack.

The attacker does NOT know startPixel. They try all P candidates and run
Phase 2b-style per-candidate analysis for each. Question: can the correct
startPixel be identified from statistical properties?

Theoretical prediction (Proof 4a obstacles 2 + 3 combined):
  - Under correct startPixel: 56 per-pixel candidates indistinguishable
    (one is "true" but not verifiable — KL pairs ~0.0003)
  - Under wrong startPixel: plaintext-to-ciphertext alignment is scrambled;
    all 56 candidates are garbage XOR masks
  - BOTH cases should produce statistically similar XOR mask distributions
    (since ciphertext bytes are uniform per Phase 1 validation, and plaintext
    is deterministic)
  - Attacker CANNOT identify correct startPixel from byte-level statistics

For efficiency: use one sample (http_large_000 for FNV), sample a subset of
data pixels per startPixel guess (first 50 pixels) to keep runtime tractable.

Output: for each startPixel guess, compute summary statistics:
  - mean chi² across 56 candidates (on XOR mask byte distribution)
  - max pairwise KL between candidates
Rank startPixel guesses by these statistics. Check where the TRUE startPixel
lands in the ranking.

If TRUE startPixel ranks in top 10 → possible distinguisher → concerning.
If TRUE startPixel ranks uniformly in the middle → obstacle (2) + (3) combine
  to give full signal/noise 1:1 at configuration-wide level.
"""

import glob
import json
from pathlib import Path

import numpy as np
from scipy import stats

PROJ = Path(__file__).resolve().parents[3]
ROOT = PROJ / "tmp"
PLAIN_DIR = ROOT / "plain"
ENCRYPTED = ROOT / "encrypted"
SEEDS_DIR = ROOT / "seeds"
HEADER_SIZE = 20
CHANNELS = 8
DATA_BITS_PER_CHANNEL = 7
DATA_BITS_PER_PIXEL = 56


def rotate7_right(v: int, n: int) -> int:
    n = n % 7
    mask = 0x7F
    return ((v >> n) | (v << (7 - n))) & mask


def extract_7bits(channel_byte: int, noise_pos: int) -> int:
    mask_low = (1 << noise_pos) - 1
    low = channel_byte & mask_low
    high = channel_byte >> (noise_pos + 1)
    return low | (high << noise_pos)


def get_plaintext_bits_for_pixel(plaintext: bytes, pixel_idx: int) -> list[int]:
    bit_index = pixel_idx * DATA_BITS_PER_PIXEL
    channels_bits = []
    total_bits = len(plaintext) * 8
    for ch in range(CHANNELS):
        if bit_index >= total_bits:
            channels_bits.append(0)
        else:
            byte_idx = bit_index // 8
            bit_off = bit_index % 8
            raw = plaintext[byte_idx]
            if byte_idx + 1 < len(plaintext):
                raw |= plaintext[byte_idx + 1] << 8
            data_bits = (raw >> bit_off) & 0x7F
            channels_bits.append(data_bits)
        bit_index += DATA_BITS_PER_CHANNEL
    return channels_bits


def load_one(hash_name: str, base: str):
    plain_path = PLAIN_DIR / f"{base}.txt"
    bin_path = ENCRYPTED / hash_name / f"{base}.bin"
    meta_path = SEEDS_DIR / hash_name / f"{base}.json"

    plaintext = plain_path.read_bytes()
    ciphertext = bin_path.read_bytes()
    meta = json.loads(meta_path.read_text())

    total_pixels = meta["total_pixels"]
    true_start_pixel = meta["start_pixel"]
    container = ciphertext[HEADER_SIZE:HEADER_SIZE + total_pixels * CHANNELS]
    return plaintext, container, true_start_pixel, total_pixels


def analyze_startpixel_guess(
    plaintext: bytes,
    container: bytes,
    startpixel_guess: int,
    total_pixels: int,
    data_pixels_to_test: int,
) -> dict:
    """For a given startPixel guess, enumerate 56 candidates across the first
    `data_pixels_to_test` plaintext pixels and compute summary stats."""
    # 56 candidates × data_pixels_to_test × 8 channels × 7-bit XOR mask
    # Accumulate byte distribution per candidate
    byte_dist = np.zeros((8, 7, 128), dtype=np.int64)

    # Hard cap on how many plaintext pixels we probe — we assume the plaintext
    # has at least data_pixels_to_test × 56 bits of actual content (else padded).
    total_bits = len(plaintext) * 8
    max_data_pixels = (total_bits + DATA_BITS_PER_PIXEL - 1) // DATA_BITS_PER_PIXEL
    n_probe = min(data_pixels_to_test, max_data_pixels)

    for p in range(n_probe):
        linear_idx = (startpixel_guess + p) % total_pixels
        pixel_offset = linear_idx * CHANNELS
        channel_bytes = container[pixel_offset:pixel_offset + CHANNELS]
        plaintext_channels = get_plaintext_bits_for_pixel(plaintext, p)

        for noise_pos in range(8):
            for rotation in range(7):
                for ch in range(CHANNELS):
                    extracted = extract_7bits(channel_bytes[ch], noise_pos)
                    unrotated = rotate7_right(extracted, rotation)
                    cand_xor = unrotated ^ plaintext_channels[ch]
                    byte_dist[noise_pos, rotation, cand_xor] += 1

    # Compute per-candidate chi² against uniform 128-bin
    chi2_vals = []
    for np_val in range(8):
        for rot in range(7):
            counts = byte_dist[np_val, rot]
            total = counts.sum()
            if total == 0:
                continue
            expected = total / 128
            chi2 = ((counts - expected) ** 2 / expected).sum()
            chi2_vals.append(chi2)
    chi2_arr = np.array(chi2_vals)

    # Pairwise KL between candidates (small — compute mean and max)
    flat = byte_dist.reshape(56, -1).astype(np.float64)
    probs = flat / flat.sum(axis=1, keepdims=True)
    probs = np.clip(probs, 1e-12, 1.0)  # avoid log(0)
    # KL(P||Q) for all pairs — vectorized
    log_probs = np.log(probs)
    # KL[i, j] = sum_k P_i[k] * (log P_i[k] - log P_j[k])
    kl_matrix = (probs[:, None, :] * (log_probs[:, None, :] - log_probs[None, :, :])).sum(axis=-1)
    np.fill_diagonal(kl_matrix, 0.0)
    non_diag = kl_matrix[~np.eye(56, dtype=bool)]

    return {
        "startpixel_guess": startpixel_guess,
        "chi2_mean": float(chi2_arr.mean()),
        "chi2_max": float(chi2_arr.max()),
        "chi2_min": float(chi2_arr.min()),
        "kl_mean": float(non_diag.mean()),
        "kl_max": float(non_diag.max()),
    }


def run_sample(hash_name: str, base: str, data_pixels_to_test: int = 40):
    """Iterate ALL P startPixel candidates for one sample and rank them."""
    plaintext, container, true_start_pixel, total_pixels = load_one(hash_name, base)

    print(f"\n{'='*70}")
    print(f"  Sample: {hash_name}/{base}")
    print(f"  Total pixels in container: {total_pixels}")
    print(f"  True startPixel (from seeds/, for verification only): {true_start_pixel}")
    print(f"  Plaintext length: {len(plaintext)} bytes")
    print(f"  Probe pixels per guess: {data_pixels_to_test}")
    print(f"  Total startPixel candidates to test: {total_pixels}")
    print(f"{'='*70}")

    results = []
    for guess in range(total_pixels):
        r = analyze_startpixel_guess(plaintext, container, guess, total_pixels, data_pixels_to_test)
        results.append(r)
        if guess % 500 == 0 and guess > 0:
            print(f"  ... processed {guess}/{total_pixels} candidates")

    # Sort by chi2_mean (ascending = closer to expected = more "uniform-looking")
    by_chi2 = sorted(results, key=lambda x: x["chi2_mean"])
    by_klmax = sorted(results, key=lambda x: x["kl_max"])

    # Find where true startPixel ranks
    true_rank_chi2 = next(i for i, r in enumerate(by_chi2) if r["startpixel_guess"] == true_start_pixel)
    true_rank_klmax = next(i for i, r in enumerate(by_klmax) if r["startpixel_guess"] == true_start_pixel)

    print(f"\n  TRUE startPixel rank by chi2_mean (ascending): {true_rank_chi2} / {total_pixels}")
    print(f"  TRUE startPixel rank by kl_max (ascending):    {true_rank_klmax} / {total_pixels}")

    # Pvalue of rank under H0 (uniform rank distribution)
    # If rank is uniformly distributed, 2*min(rank+1, P-rank) / P is a p-value
    p_rank_chi2 = 2 * min(true_rank_chi2 + 1, total_pixels - true_rank_chi2) / total_pixels
    p_rank_klmax = 2 * min(true_rank_klmax + 1, total_pixels - true_rank_klmax) / total_pixels
    print(f"  Two-sided p-value for chi2 rank under H0 (uniform): {p_rank_chi2:.4f}")
    print(f"  Two-sided p-value for kl_max rank under H0 (uniform): {p_rank_klmax:.4f}")

    # Show stats distribution
    chi2_arr = np.array([r["chi2_mean"] for r in results])
    kl_arr = np.array([r["kl_max"] for r in results])
    print(f"\n  chi2_mean distribution across all {total_pixels} startPixel candidates:")
    print(f"    min={chi2_arr.min():.3f}, mean={chi2_arr.mean():.3f}, max={chi2_arr.max():.3f}")
    print(f"    std={chi2_arr.std():.4f}")
    true_chi2 = next(r for r in results if r["startpixel_guess"] == true_start_pixel)["chi2_mean"]
    print(f"    TRUE startPixel chi2_mean: {true_chi2:.3f} "
          f"(z-score vs all: {(true_chi2 - chi2_arr.mean()) / chi2_arr.std():+.3f})")

    print(f"\n  kl_max distribution across all {total_pixels} startPixel candidates:")
    print(f"    min={kl_arr.min():.6f}, mean={kl_arr.mean():.6f}, max={kl_arr.max():.6f}")
    print(f"    std={kl_arr.std():.8f}")
    true_kl = next(r for r in results if r["startpixel_guess"] == true_start_pixel)["kl_max"]
    print(f"    TRUE startPixel kl_max: {true_kl:.6f} "
          f"(z-score vs all: {(true_kl - kl_arr.mean()) / kl_arr.std():+.3f})")

    # Show top 5 by chi2 and the true's neighbors
    print(f"\n  Top 5 startPixel candidates (lowest chi2_mean — closest to uniform):")
    for i in range(5):
        marker = " <-- TRUE" if by_chi2[i]["startpixel_guess"] == true_start_pixel else ""
        print(f"    rank {i}: sp={by_chi2[i]['startpixel_guess']:4d}  "
              f"chi2={by_chi2[i]['chi2_mean']:.3f}{marker}")

    return results, true_rank_chi2, true_rank_klmax


if __name__ == "__main__":
    print("Phase 2c: startPixel enumeration attack")
    print("Test: can attacker identify true startPixel from statistical fingerprint?")

    # Run on one sample per hash variant, using http_large_000 (data-dominated)
    for h in ["fnv", "md5", "md4"]:
        run_sample(h, "http_large_000", data_pixels_to_test=40)

    print("\n" + "="*70)
    print("  INTERPRETATION")
    print("="*70)
    print("  Under theory (obstacles 2 + 3 combined):")
    print("    - TRUE startPixel rank should be ~P/2 (uniform)")
    print("    - z-score of TRUE stats within ±2")
    print("    - p-value for rank > 0.05")
    print("  If TRUE startPixel stands out (top-5, z>3, p<0.01):")
    print("    - distinguisher exists at configuration level")
    print("    - obstacle (2) is weaker than claimed")
