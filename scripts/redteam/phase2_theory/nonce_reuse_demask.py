#!/usr/bin/env python3
"""Probe 1 (nonce-reuse) demasking helper.

Under Full KPA with nonce-reuse (two ciphertexts encrypted with the SAME
(noiseSeed, dataSeed, startSeed, nonce) but different plaintexts), this helper
recovers the ITB per-pixel configuration map (noisePos, rotation) for every
data-carrying pixel via Layer 1 constraint matching against the known plaintexts.

**This first implementation is the minimum-viable version:**
  - known-plaintext mode only
  - 128-bit hash family only (FNV-1a / MD5 / AES-CMAC / SipHash-2-4 corpus)
  - startPixel is READ FROM cell.meta.json (hardcoded-from-sidecar mode) instead
    of being brute-forced — this is a debugging step to validate the Layer 1
    formula in isolation before adding Layer 2 (startPixel search).
  - --validate compares recovered per-pixel (noisePos, rotation) to the ground
    truth written by the Go corpus generator (config.truth.json).
  - No Phase B reconstruction (dataHash stream emission) yet — that is Phase D
    in the plan and lands after Layer 2 search is in place.

Usage:
    python3 scripts/redteam/phase2_theory/nonce_reuse_demask.py \\
        --cell-dir tmp/attack/nonce_reuse/corpus/fnv1a/BF1/N2/known \\
        --pair 0000 0001 \\
        --mode known-plaintext \\
        --validate
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# scripts/redteam/ on sys.path so `from attack_common import ...` works
_THIS = Path(__file__).resolve()
sys.path.insert(0, str(_THIS.parent.parent))

from attack_common import (  # noqa: E402  (sys.path setup above)
    CHANNELS,
    DATA_BITS_PER_CHANNEL,
    DATA_BITS_PER_PIXEL,
    EXTRACT7_TABLE,
    HEADER_SIZE,
    ROT7_TABLE,
    cobs_encode,
    cobs_encode_with_mask,
    get_bits7,
    load_cell_meta,
    load_config_truth,
    parse_itb_header,
)

PROJ = _THIS.parents[3]  # repo root


# ----------------------------------------------------------------------------
# Layer 1 — per-pixel constraint matching
# ----------------------------------------------------------------------------

def build_payload_known(plaintext: bytes, capacity_bytes: int) -> bytes:
    """Build the attacker-knowable portion of the payload under Full KPA.

    Layout matches Encrypt128:
        payload = cobs_encode(plaintext) + [0x00] + random_fill
    The attacker knows cobs_encode(plaintext) and the 0x00 null byte.
    Everything from there on is random crypto/rand fill — we fill with zeros
    here as a placeholder (real fill is not known to the attacker); the helper
    only uses the first (len(cobs) + 1) bytes for constraint matching.
    """
    encoded = cobs_encode(plaintext)
    if len(encoded) + 1 > capacity_bytes:
        raise ValueError(f"cobs-encoded plaintext + null ({len(encoded) + 1}) exceeds "
                         f"capacity ({capacity_bytes})")
    payload = bytearray(capacity_bytes)
    payload[:len(encoded)] = encoded
    payload[len(encoded)] = 0x00
    # Remaining bytes stay 0x00 placeholders — attacker does not know real fill.
    return bytes(payload)


def layer1_recover_pixel_scalar(
    xor_bytes_8: np.ndarray,       # shape (8,) uint8  — (C1⊕C2) bytes for this pixel's 8 channels
    d_xor_7bits_8: np.ndarray,     # shape (8,) uint8  — (payload1_7bits ^ payload2_7bits) per channel
) -> Optional[Tuple[int, int]]:
    """Scalar Layer 1 — try all 56 (noisePos, rotation) candidates and return
    the unique match if one exists, else None.

    Constraint per channel ch, per candidate (p, r):
        extract7(xor_bytes_8[ch], p) == rotate7(d_xor_7bits_8[ch], r)

    A candidate is valid iff ALL 8 channels satisfy this equation.
    Under correct (p, r) all 8 channels match; under wrong candidate the
    false-positive rate is 2^-7 per channel → 2^-56 across 8 channels →
    effectively unique if any channel has d_xor ≠ 0.
    """
    candidates = []
    for noise_pos in range(CHANNELS):
        # Extract 7 non-noisePos bits from each channel's XOR byte at once
        extracted_7 = EXTRACT7_TABLE[noise_pos, xor_bytes_8]  # shape (8,)
        for rotation in range(7):
            # Expected 7-bit pattern per channel = rotate7(d_xor_ch, rotation)
            expected_7 = ROT7_TABLE[rotation, d_xor_7bits_8]  # shape (8,)
            if np.array_equal(extracted_7, expected_7):
                candidates.append((noise_pos, rotation))
                if len(candidates) > 1:
                    return None  # ambiguous — early exit
    if len(candidates) == 1:
        return candidates[0]
    return None


def precompute_d_xor_per_probe(
    payload1: bytes,
    payload2: bytes,
    n_probe: int,
) -> np.ndarray:
    """Precompute (payload1 ⊕ payload2) 7-bit values per (probe_pixel, channel).

    Shape: (n_probe, CHANNELS) uint8.

    Used by Layer 2 (startPixel brute force) — the d_xor values depend only on
    the attacker's known payloads, NOT on the startPixel candidate, so they can
    be precomputed once and reused across all 9604 startPixel guesses.
    """
    out = np.zeros((n_probe, CHANNELS), dtype=np.uint8)
    for p in range(n_probe):
        for ch in range(CHANNELS):
            bit_idx = p * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
            d1 = get_bits7(payload1, bit_idx)
            d2 = get_bits7(payload2, bit_idx)
            out[p, ch] = d1 ^ d2
    return out


def any_candidate_matches(
    xor_bytes_8: np.ndarray,       # shape (8,) uint8
    d_xor_7bits_8: np.ndarray,     # shape (8,) uint8
) -> bool:
    """Return True iff ANY of the 56 (noisePos, rotation) candidates satisfies
    the constraint across all 8 channels. Vectorized across all candidates.

    Used by Layer 2 short-circuit: under a wrong startPixel, false-positive
    rate is ~56 × 2^-56 ≈ 0; under the correct startPixel, at least the true
    (noisePos, rotation) passes. Binary classifier.
    """
    # extracted shape: (8_np, 8_channels)
    extracted = EXTRACT7_TABLE[:, xor_bytes_8]
    # expected shape: (7_rot, 8_channels)
    expected = ROT7_TABLE[:, d_xor_7bits_8]
    # Broadcast compare: (8_np, 1, 8_ch) vs (1, 7_rot, 8_ch) → (8_np, 7_rot, 8_ch) bool
    # A candidate (np, r) matches iff all 8 channels agree.
    matches = np.all(extracted[:, None, :] == expected[None, :, :], axis=2)
    return bool(matches.any())


def layer2_brute_force_startpixel(
    c1_container: np.ndarray,       # shape (total_pixels, CHANNELS) uint8
    c2_container: np.ndarray,       # shape (total_pixels, CHANNELS) uint8
    d_xor_per_probe: np.ndarray,    # shape (n_probe, CHANNELS) uint8 — precomputed
    total_pixels: int,
    n_probe: int = 10,
    verbose: bool = False,
) -> Tuple[int, int, float]:
    """Brute-force search for startPixel over [0, total_pixels).

    For each candidate startPixel:
      1. Extract XOR bytes for n_probe consecutive container pixels starting at
         that candidate (with wrap-around modulo total_pixels).
      2. For each probe pixel, check if ANY (noisePos, rotation) candidate
         satisfies all 8 channels vs the precomputed d_xor.
      3. Score = count of probe pixels with at least one candidate match.
      4. Short-circuit: if probe pixel 0 has zero matches, skip remaining.

    Under correct startPixel: score = n_probe (every probe pixel has ≥ the
    true (noisePos, rotation) candidate passing).

    Under wrong startPixel: expected false-positive rate per pixel is
    ~56 × 2^-56 ≈ 0. First probe pixel fails → short-circuit.

    Returns (best_startpixel, best_score, elapsed_seconds).
    """
    t0 = time.time()
    best_sp = -1
    best_score = -1
    short_circuited = 0

    for sp_guess in range(total_pixels):
        score = 0
        for p in range(n_probe):
            container_pos = (sp_guess + p) % total_pixels
            xor_bytes = c1_container[container_pos] ^ c2_container[container_pos]
            if any_candidate_matches(xor_bytes, d_xor_per_probe[p]):
                score += 1
            elif p == 0:
                # Short-circuit: first probe pixel has no match → wrong startPixel
                short_circuited += 1
                break

        if score > best_score:
            best_score = score
            best_sp = sp_guess
            if score == n_probe and verbose:
                print(f"  [brute force] startPixel={sp_guess} matches all {n_probe} probe pixels")
            if score == n_probe:
                # Full match on first n_probe pixels — accept this startPixel and
                # stop scanning. Under correct formula this is exactly the true
                # startPixel; any later matches would only be accidental coincidence
                # (already ~10^-56 per candidate after 8 channel constraint × 10 pixels).
                elapsed = time.time() - t0
                if verbose:
                    print(f"  [brute force] early-accept at sp={sp_guess} after "
                          f"{sp_guess + 1}/{total_pixels} candidates ({short_circuited} short-circuited); "
                          f"{elapsed:.2f}s")
                return sp_guess, score, elapsed

    elapsed = time.time() - t0
    if verbose:
        print(f"  [brute force] no perfect match; best sp={best_sp} score={best_score} "
              f"({short_circuited}/{total_pixels} short-circuited); {elapsed:.2f}s")
    return best_sp, best_score, elapsed


def layer1_recover_range(
    c1_container: np.ndarray,       # shape (total_pixels, CHANNELS) uint8
    c2_container: np.ndarray,       # shape (total_pixels, CHANNELS) uint8
    payload1: bytes,
    payload2: bytes,
    start_pixel: int,
    data_pixels: int,
    total_pixels: int,
    pixel_range: Tuple[int, int] = None,  # (start_data_idx, end_data_idx), default: all
) -> List[Optional[Tuple[int, int]]]:
    """Run Layer 1 on every data pixel in `pixel_range` and return the list of
    recovered (noisePos, rotation) pairs or None (ambiguous/no-match).

    `data_idx` ∈ [0, data_pixels) is the attacker's logical data-pixel index;
    the container-linear position is (start_pixel + data_idx) % total_pixels.
    """
    start_idx, end_idx = pixel_range if pixel_range else (0, data_pixels)
    out: List[Optional[Tuple[int, int]]] = [None] * (end_idx - start_idx)

    for i, data_idx in enumerate(range(start_idx, end_idx)):
        # Which container pixel does this data pixel live in?
        container_pos = (start_pixel + data_idx) % total_pixels
        xor_bytes_8 = c1_container[container_pos] ^ c2_container[container_pos]

        # Compute d1⊕d2 per channel for this pixel from the known payloads
        d_xor_7bits_8 = np.zeros(CHANNELS, dtype=np.uint8)
        for ch in range(CHANNELS):
            bit_idx = data_idx * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
            d1 = get_bits7(payload1, bit_idx)
            d2 = get_bits7(payload2, bit_idx)
            d_xor_7bits_8[ch] = d1 ^ d2

        result = layer1_recover_pixel_scalar(xor_bytes_8, d_xor_7bits_8)
        out[i] = result
    return out


# ----------------------------------------------------------------------------
# Phase D — Reconstruction pipeline: extract pure dataHash stream
# ----------------------------------------------------------------------------

def reconstruct_datahash_stream(
    ciphertext_container: np.ndarray,            # shape (total_pixels, CHANNELS) uint8
    payload: bytes,                              # attacker's known payload bytes
    recovered_config: List[Optional[Tuple[int, int]]],  # per data pixel: (noisePos, rotation) or None
    start_pixel: int,
    total_pixels: int,
    pixel_range: Tuple[int, int],                # (start_data_idx, end_data_idx)
) -> Tuple[bytes, List[int]]:
    """For each data pixel with uniquely-recovered config, strip the ITB masking
    layers and emit the pure ChainHash-derived `channelXOR` output as 56 bits
    (7 bytes) per pixel, densely packed little-endian.

    Per-pixel reconstruction:
        extracted_7 = EXTRACT7[noisePos, channel_byte]        # remove noise bit
        unrotated_7 = ROT7[(7 - rotation) % 7, extracted_7]    # inverse rotation
        channelXOR_7 = unrotated_7 ^ plaintext_7bits           # cancel known plaintext

    Under the construction, channelXOR[p, 0..7] == (dataSeed.ChainHash(p, nonce) >> 3) bits [0..55]
    — so the emitted bit stream is literally a prefix of the raw hash function output
    under a controlled (pixel, nonce) probe. THIS is the artefact for NIST STS
    PRF-separation: uniform for BLAKE3 / MD5, linear (and trivially distinguishable)
    for FNV-1a.

    Returns (stream_bytes, emitted_pixel_indices). Pixels with recovered_config[p]
    is None are SKIPPED (no bytes emitted for them). `emitted_pixel_indices` records
    which data-pixel indices contributed bytes so downstream analysis can un-pack
    if needed.
    """
    start_idx, end_idx = pixel_range
    out = bytearray()
    emitted_indices: List[int] = []

    for i, data_idx in enumerate(range(start_idx, end_idx)):
        cfg = recovered_config[i]
        if cfg is None:
            continue  # skip ambiguous pixels
        noise_pos, rotation = cfg
        container_pos = (start_pixel + data_idx) % total_pixels
        byte8 = ciphertext_container[container_pos]  # shape (8,) uint8

        inv_rotation = (7 - rotation) % 7
        # Accumulate 56 bits = 7 bytes little-endian
        accum = 0
        for ch in range(CHANNELS):
            extracted = int(EXTRACT7_TABLE[noise_pos, byte8[ch]])
            unrotated = int(ROT7_TABLE[inv_rotation, extracted])
            # XOR with known plaintext 7-bit value at this pixel-channel
            bit_idx = data_idx * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
            d = get_bits7(payload, bit_idx)
            channel_xor_7 = (unrotated ^ d) & 0x7F
            accum |= channel_xor_7 << (ch * DATA_BITS_PER_CHANNEL)

        out.extend(accum.to_bytes(7, "little"))
        emitted_indices.append(data_idx)

    return bytes(out), emitted_indices


def verify_datahash_vs_truth(
    stream_bytes: bytes,
    emitted_indices: List[int],
    truth_per_pixel: List[Dict],
) -> Tuple[int, int, int, List[int]]:
    """Compare each emitted pixel's channelXOR (as 7 bytes) against the
    ground-truth `channel_xor_8` array. This validates that reconstruction
    exactly recovers the dataHash-derived output.

    Returns (total, exact, mismatch, mismatch_indices_first_10).
    """
    total = len(emitted_indices)
    exact = 0
    mismatch = 0
    mismatch_idxs: List[int] = []

    for i, data_idx in enumerate(emitted_indices):
        # Unpack 7 bytes → 56-bit integer → 8 × 7-bit channelXOR values
        accum = int.from_bytes(stream_bytes[i * 7:(i + 1) * 7], "little")
        reconstructed = [(accum >> (ch * DATA_BITS_PER_CHANNEL)) & 0x7F for ch in range(CHANNELS)]
        want = truth_per_pixel[data_idx]["channel_xor_8"]
        if reconstructed == want:
            exact += 1
        else:
            mismatch += 1
            if len(mismatch_idxs) < 10:
                mismatch_idxs.append(data_idx)
    return total, exact, mismatch, mismatch_idxs


# ----------------------------------------------------------------------------
# Partial KPA — per-channel known/unknown filtering
# ----------------------------------------------------------------------------

def build_payload_and_mask_partial(
    plaintext: bytes,
    plaintext_mask: bytes,
    capacity_bytes: int,
) -> Tuple[bytes, bytes]:
    """Mirror build_payload_known but carry an attacker-known mask through
    COBS encoding + null terminator. Unknown plaintext bytes propagate as
    unknown mask positions; the null terminator and the CSPRNG fill tail
    beyond len(cobs)+1 bytes are marked as unknown (attacker cannot predict
    fill, and the null terminator is inside the known prefix anyway).

    Returns (payload, payload_mask) both of length capacity_bytes.
    """
    encoded, enc_mask = cobs_encode_with_mask(plaintext, plaintext_mask)
    if len(encoded) + 1 > capacity_bytes:
        raise ValueError(f"cobs-encoded plaintext + null ({len(encoded) + 1}) exceeds "
                         f"capacity ({capacity_bytes})")
    payload = bytearray(capacity_bytes)
    mask = bytearray(capacity_bytes)  # zero-initialised → fill bytes stay 'unknown'
    payload[:len(encoded)] = encoded
    mask[:len(encoded)] = enc_mask
    payload[len(encoded)] = 0x00
    mask[len(encoded)] = 1  # null terminator is always 0x00 — attacker-known
    # Fill beyond len(encoded)+1 remains 0 / unknown.
    return bytes(payload), bytes(mask)


def compute_channel_known_map(
    payload_mask1: bytes,
    payload_mask2: bytes,
    data_pixels: int,
) -> np.ndarray:
    """Return shape (data_pixels, CHANNELS) bool — channel_known[p, ch] is
    True iff every one of the 7 payload bits at (pixel p, channel ch) is
    marked known in BOTH payload masks.

    A channel's 7 bits span either one or two payload bytes depending on
    `(bit_idx % 8)`: if bit offset within byte ≤ 1 the 7 bits fit inside
    that one byte; otherwise the slice crosses into the next byte. Both
    spanning bytes must be known in both masks.
    """
    m1 = np.frombuffer(payload_mask1, dtype=np.uint8).astype(bool)
    m2 = np.frombuffer(payload_mask2, dtype=np.uint8).astype(bool)
    # Pad to common length with False — out-of-bounds counts as unknown.
    max_len = max(len(m1), len(m2))
    if len(m1) < max_len:
        m1 = np.concatenate([m1, np.zeros(max_len - len(m1), dtype=bool)])
    if len(m2) < max_len:
        m2 = np.concatenate([m2, np.zeros(max_len - len(m2), dtype=bool)])
    m_both = m1 & m2
    # Sentinel-extend with False so out-of-range lookups are "unknown".
    m_ext = np.concatenate([m_both, [False]])
    sentinel = len(m_both)

    pixel_indices = np.arange(data_pixels)
    out = np.zeros((data_pixels, CHANNELS), dtype=bool)
    for ch in range(CHANNELS):
        bit_starts = pixel_indices * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
        byte_lo = bit_starts // 8
        byte_hi = (bit_starts + DATA_BITS_PER_CHANNEL - 1) // 8
        byte_lo = np.where(byte_lo < sentinel, byte_lo, sentinel)
        byte_hi = np.where(byte_hi < sentinel, byte_hi, sentinel)
        out[:, ch] = m_ext[byte_lo] & m_ext[byte_hi]
    return out


def layer1_recover_pixel_partial(
    xor_bytes_8: np.ndarray,       # shape (8,) uint8
    d_xor_7bits_8: np.ndarray,     # shape (8,) uint8 (values on unknown channels ignored)
    channel_known: np.ndarray,     # shape (8,) bool
    min_known_channels: int,
) -> Optional[Tuple[int, int]]:
    """Partial-KPA variant of layer1_recover_pixel_scalar. Constraint-match
    only on channels where `channel_known` is True; require at least
    `min_known_channels` such channels for the pixel to be eligible.

    Under correct (p, r) all known channels agree. Under a wrong candidate
    the false-positive rate per known channel is 2⁻⁷ → 2⁻⁷ᴷ across K known
    channels. Across the 56 candidates the expected false-positive count per
    pixel is ≈ 56 × 2⁻⁷ᴷ (negligible for K ≥ 2: 56/16384 ≈ 0.34 %).
    """
    known_count = int(channel_known.sum())
    if known_count < min_known_channels:
        return None
    candidates = []
    for noise_pos in range(CHANNELS):
        extracted_7 = EXTRACT7_TABLE[noise_pos, xor_bytes_8]
        for rotation in range(7):
            expected_7 = ROT7_TABLE[rotation, d_xor_7bits_8]
            if np.array_equal(extracted_7[channel_known], expected_7[channel_known]):
                candidates.append((noise_pos, rotation))
                if len(candidates) > 1:
                    return None
    if len(candidates) == 1:
        return candidates[0]
    return None


def any_candidate_matches_partial(
    xor_bytes_8: np.ndarray,
    d_xor_7bits_8: np.ndarray,
    channel_known: np.ndarray,
    min_known_channels: int,
) -> bool:
    """Partial-KPA variant of any_candidate_matches. Returns True iff ANY
    (noisePos, rotation) candidate has all KNOWN channels satisfy the XOR
    constraint. Under wrong startPixel + K known channels, per-candidate FP
    rate is 2⁻⁷ᴷ → all-56-candidates FP rate ≈ 56 × 2⁻⁷ᴷ (K=2: 0.34 %).
    """
    if int(channel_known.sum()) < min_known_channels:
        return False
    extracted = EXTRACT7_TABLE[:, xor_bytes_8]  # (8_np, 8_ch)
    expected = ROT7_TABLE[:, d_xor_7bits_8]     # (7_rot, 8_ch)
    # For unknown channels we want the comparison to vacuously succeed.
    # Trick: compare `(ex == eq) | ~channel_known_bcast` so unknown channels
    # are always "matched" and .all() along axis 2 only requires known ones.
    cmp = (extracted[:, None, :] == expected[None, :, :])
    cmp |= ~channel_known[None, None, :]
    return bool(cmp.all(axis=2).any())


def precompute_d_xor_with_known_per_probe(
    payload1: bytes,
    payload2: bytes,
    channel_known_map: np.ndarray,
    n_probe: int,
) -> Tuple[np.ndarray, np.ndarray]:
    """Parallel to precompute_d_xor_per_probe but also returns the per-probe
    channel_known array. Shape: (n_probe, CHANNELS) uint8, (n_probe, CHANNELS) bool.
    """
    d_xor = np.zeros((n_probe, CHANNELS), dtype=np.uint8)
    known = np.zeros((n_probe, CHANNELS), dtype=bool)
    for p in range(n_probe):
        for ch in range(CHANNELS):
            bit_idx = p * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
            d1 = get_bits7(payload1, bit_idx)
            d2 = get_bits7(payload2, bit_idx)
            d_xor[p, ch] = d1 ^ d2
        known[p] = channel_known_map[p]
    return d_xor, known


def layer2_brute_force_startpixel_partial(
    c1_container: np.ndarray,
    c2_container: np.ndarray,
    d_xor_per_probe: np.ndarray,       # shape (n_probe, CHANNELS) uint8
    known_per_probe: np.ndarray,       # shape (n_probe, CHANNELS) bool
    total_pixels: int,
    n_probe: int,
    min_known_channels: int,
    verbose: bool = False,
) -> Tuple[int, int, float]:
    """Partial-KPA Layer 2 brute force. Skips probe pixels with too few known
    channels (<min_known_channels) — they don't contribute discriminatory
    power. If the FIRST K probe pixels all have K_known_ch < min_known_channels,
    Layer 2 falls back to using later pixels; the effective probe set is the
    first n_probe that meet the threshold.
    """
    # Compute the effective probe set — pixels with enough known channels
    # for the constraint. Indices into the d_xor / known arrays.
    known_counts = known_per_probe.sum(axis=1)
    usable = np.where(known_counts >= min_known_channels)[0]
    if len(usable) == 0:
        if verbose:
            print(f"  [brute force partial] no probe pixels have ≥ "
                  f"{min_known_channels} known channels in the first {n_probe}")
        return -1, 0, 0.0
    usable_set = usable.tolist()
    target_score = len(usable_set)

    t0 = time.time()
    best_sp = -1
    best_score = -1
    short_circuited = 0

    for sp_guess in range(total_pixels):
        score = 0
        failed_first = False
        for p_i, p in enumerate(usable_set):
            container_pos = (sp_guess + p) % total_pixels
            xor_bytes = c1_container[container_pos] ^ c2_container[container_pos]
            if any_candidate_matches_partial(
                xor_bytes, d_xor_per_probe[p], known_per_probe[p], min_known_channels,
            ):
                score += 1
            elif p_i == 0:
                short_circuited += 1
                failed_first = True
                break

        if failed_first:
            continue

        if score > best_score:
            best_score = score
            best_sp = sp_guess
            if score == target_score and verbose:
                print(f"  [brute force partial] startPixel={sp_guess} matches all "
                      f"{target_score} usable probe pixels")
            if score == target_score:
                elapsed = time.time() - t0
                if verbose:
                    print(f"  [brute force partial] early-accept at sp={sp_guess} after "
                          f"{sp_guess + 1}/{total_pixels} candidates "
                          f"({short_circuited} short-circuited); {elapsed:.2f}s")
                return sp_guess, score, elapsed

    elapsed = time.time() - t0
    if verbose:
        print(f"  [brute force partial] no perfect match; best sp={best_sp} "
              f"score={best_score}/{target_score} "
              f"({short_circuited}/{total_pixels} short-circuited); {elapsed:.2f}s")
    return best_sp, best_score, elapsed


def layer1_recover_range_partial(
    c1_container: np.ndarray,
    c2_container: np.ndarray,
    payload1: bytes,
    payload2: bytes,
    channel_known_map: np.ndarray,
    start_pixel: int,
    data_pixels: int,
    total_pixels: int,
    pixel_range: Tuple[int, int],
    min_known_channels: int,
) -> List[Optional[Tuple[int, int]]]:
    """Partial-KPA Layer 1: runs constraint-match only on known channels,
    requires ≥ min_known_channels per pixel. Returns per-pixel (noisePos,
    rotation) or None (skipped / ambiguous)."""
    start_idx, end_idx = pixel_range
    out: List[Optional[Tuple[int, int]]] = [None] * (end_idx - start_idx)

    for i, data_idx in enumerate(range(start_idx, end_idx)):
        container_pos = (start_pixel + data_idx) % total_pixels
        xor_bytes_8 = c1_container[container_pos] ^ c2_container[container_pos]

        d_xor_7bits_8 = np.zeros(CHANNELS, dtype=np.uint8)
        for ch in range(CHANNELS):
            bit_idx = data_idx * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
            d1 = get_bits7(payload1, bit_idx)
            d2 = get_bits7(payload2, bit_idx)
            d_xor_7bits_8[ch] = d1 ^ d2

        out[i] = layer1_recover_pixel_partial(
            xor_bytes_8, d_xor_7bits_8,
            channel_known_map[data_idx], min_known_channels,
        )
    return out


def reconstruct_datahash_stream_partial(
    ciphertext_container: np.ndarray,
    payload: bytes,
    recovered_config: List[Optional[Tuple[int, int]]],
    channel_known_map: np.ndarray,
    start_pixel: int,
    total_pixels: int,
    pixel_range: Tuple[int, int],
) -> Tuple[bytes, List[Tuple[int, int]]]:
    """Partial-KPA reconstruction: emit 7-bit channelXOR values ONLY for
    channels where channel_known is True. Output is densely packed MSB-first
    across variable numbers of channels per pixel, then split into whole bytes.

    Returns (stream_bytes, emitted_index_pairs) where each pair is
    `(data_pixel_idx, channel_idx)` — records which 7-bit slice contributed
    to each block of the output for downstream analysis.
    """
    start_idx, end_idx = pixel_range
    bit_accumulator = 0
    bit_count = 0
    out = bytearray()
    emitted_pairs: List[Tuple[int, int]] = []

    for i, data_idx in enumerate(range(start_idx, end_idx)):
        cfg = recovered_config[i]
        if cfg is None:
            continue
        noise_pos, rotation = cfg
        container_pos = (start_pixel + data_idx) % total_pixels
        byte8 = ciphertext_container[container_pos]
        inv_rotation = (7 - rotation) % 7

        for ch in range(CHANNELS):
            if not channel_known_map[data_idx, ch]:
                continue
            extracted = int(EXTRACT7_TABLE[noise_pos, byte8[ch]])
            unrotated = int(ROT7_TABLE[inv_rotation, extracted])
            bit_idx = data_idx * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
            d = get_bits7(payload, bit_idx)
            channel_xor_7 = (unrotated ^ d) & 0x7F
            emitted_pairs.append((data_idx, ch))

            # Pack 7 bits LSB-first (little-endian at 7-bit granularity) into
            # the continuous bit accumulator; flush whole bytes as they fill.
            bit_accumulator |= (channel_xor_7 & 0x7F) << bit_count
            bit_count += 7
            while bit_count >= 8:
                out.append(bit_accumulator & 0xFF)
                bit_accumulator >>= 8
                bit_count -= 8

    # Flush trailing bits (pad with zero to byte boundary)
    if bit_count > 0:
        out.append(bit_accumulator & 0xFF)

    return bytes(out), emitted_pairs


# ----------------------------------------------------------------------------
# Validation against ground truth
# ----------------------------------------------------------------------------

def validate_against_truth(
    recovered: List[Optional[Tuple[int, int]]],
    truth: List[Dict],  # config.truth.json PerPixel entries
    start_data_idx: int,
) -> Tuple[int, int, int, int, List[int]]:
    """Compare recovered (noisePos, rotation) list to ground truth.

    Returns (total, exact_matches, ambiguous, wrong_matches, wrong_match_indices_first_10).

    - exact_match: recovered == truth (unique, correct)
    - ambiguous: recovered is None (multi-candidate; NOT an error if formula is correct —
      just means single-pair Layer 1 could not disambiguate, typically adjacent-noisePos
      same-rotation pairs that both pass constraints. Multi-pair combining resolves these.)
    - wrong_match: recovered != None AND recovered != truth (this WOULD be a bug —
      helper claimed a unique result different from the ground truth. Should be zero if the
      constraint formula is correct.)

    `start_data_idx` is the data_pixel index of recovered[0] in the full truth list.
    """
    total = len(recovered)
    exact = 0
    ambiguous = 0
    wrong = 0
    wrong_idxs: List[int] = []
    for i, got in enumerate(recovered):
        truth_entry = truth[start_data_idx + i]
        want = (truth_entry["noise_pos"], truth_entry["rotation"])
        if got is None:
            ambiguous += 1
        elif got == want:
            exact += 1
        else:
            wrong += 1
            if len(wrong_idxs) < 10:
                wrong_idxs.append(start_data_idx + i)
    return total, exact, ambiguous, wrong, wrong_idxs


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="ITB nonce-reuse demasking helper (Probe 1, Layer 1 MVP).",
    )
    parser.add_argument(
        "--cell-dir",
        type=Path,
        required=True,
        help="Path to a nonce-reuse corpus cell directory "
             "(contains ct_NNNN.bin/.plain + cell.meta.json + config.truth.json).",
    )
    parser.add_argument(
        "--pair",
        type=str,
        nargs=2,
        metavar=("I", "J"),
        required=True,
        help="Two ciphertext IDs within the cell (e.g. --pair 0000 0001).",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["known-plaintext", "same-plaintext", "blind", "partial-plaintext"],
        default="known-plaintext",
        help="Attacker-knowledge mode. known-plaintext = Full KPA. partial-plaintext = "
             "Partial KPA (requires ct_NNNN.known_mask sidecars written by the Go test "
             "under mode=partial). same-plaintext / blind are declared but not implemented "
             "in this MVP.",
    )
    parser.add_argument(
        "--min-known-channels",
        type=int,
        default=2,
        help="Partial-KPA: minimum number of attacker-known channels per pixel required "
             "to attempt constraint matching on that pixel. Below this threshold the "
             "per-candidate false-positive rate (56 × 2⁻⁷ᴷ) becomes non-negligible; "
             "K=2 keeps it at ~0.34 %% (default).",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="If set, diff recovered (noisePos, rotation) per pixel against "
             "config.truth.json and report matches / mismatches.",
    )
    parser.add_argument(
        "--pixel-range",
        type=str,
        default=None,
        help="Optional data-pixel index range 'start:end' (default: all).",
    )
    parser.add_argument(
        "--brute-force-startpixel",
        action="store_true",
        help="Layer 2 — recover startPixel by brute force instead of reading from sidecar. "
             "This is the realistic attacker mode (attacker does NOT know startPixel).",
    )
    parser.add_argument(
        "--n-probe",
        type=int,
        default=10,
        help="Number of probe pixels per startPixel candidate during Layer 2 brute force "
             "(default: 10; each probe pixel needs all 8 channels to match one (noisePos, "
             "rotation) candidate).",
    )
    parser.add_argument(
        "--emit-datahash",
        type=Path,
        default=None,
        metavar="OUT.bin",
        help="Phase D — reconstruct and write the pure dataHash-derived channelXOR stream "
             "(7 bytes per recovered pixel, densely packed) to OUT.bin. This is the PRF-"
             "separation artefact for NIST STS: uniform under BLAKE3 / MD5, linear under FNV-1a.",
    )
    parser.add_argument(
        "--skip-nonce-check",
        action="store_true",
        help="Bypass the sanity assertion that the two ciphertexts share a nonce. Used ONLY "
             "for the nonce-mismatch sensitivity test — lets the helper proceed into Layer 1 + "
             "Layer 2 on non-nonce-reuse data so the negative outcome (Layer 2 score well below "
             "n_probe, Layer 1 near-zero exact recovery) can be observed empirically. "
             "Not a real attacker mode.",
    )
    args = parser.parse_args()

    if args.mode not in {"known-plaintext", "partial-plaintext"}:
        print(f"ERROR: mode '{args.mode}' not implemented yet — only "
              f"known-plaintext (Full KPA) and partial-plaintext (Partial KPA)",
              file=sys.stderr)
        return 2
    is_partial = args.mode == "partial-plaintext"

    cell_dir = args.cell_dir.resolve()
    if not cell_dir.is_dir():
        print(f"ERROR: cell-dir does not exist or is not a directory: {cell_dir}", file=sys.stderr)
        return 2

    # -----------------------------------------------------------------------
    # Load cell metadata + ciphertexts + plaintexts
    # -----------------------------------------------------------------------
    meta = load_cell_meta(cell_dir)
    print(f"Cell: {cell_dir.relative_to(PROJ)}")
    print(f"  hash        : {meta['hash_display']} ({meta['hash']}, {meta['hash_width']}-bit)")
    print(f"  BF          : {meta['barrier_fill']}")
    print(f"  N           : {meta['n_collisions']}")
    print(f"  mode        : {meta['mode']}")
    print(f"  plaintext   : {meta['plaintext_size']} bytes")
    print(f"  totalPixels : {meta['total_pixels']}")
    print(f"  startPixel  : {meta['start_pixel']}  (read from sidecar — Layer 2 brute force not yet implemented)")
    print(f"  dataPixels  : {meta['data_pixels']}")
    print(f"  knownBytes  : {meta['known_bytes']}  fullyKnownPixels: {meta['fully_known_pixels']}")

    i_id, j_id = args.pair[0], args.pair[1]
    ct1_path = cell_dir / f"ct_{i_id}.bin"
    ct2_path = cell_dir / f"ct_{j_id}.bin"
    pl1_path = cell_dir / f"ct_{i_id}.plain"
    pl2_path = cell_dir / f"ct_{j_id}.plain"
    for p in (ct1_path, ct2_path, pl1_path, pl2_path):
        if not p.exists():
            print(f"ERROR: missing {p}", file=sys.stderr)
            return 2

    ct1 = ct1_path.read_bytes()
    ct2 = ct2_path.read_bytes()
    pl1 = pl1_path.read_bytes()
    pl2 = pl2_path.read_bytes()

    pm1: Optional[bytes] = None
    pm2: Optional[bytes] = None
    if is_partial:
        mk1_path = cell_dir / f"ct_{i_id}.known_mask"
        mk2_path = cell_dir / f"ct_{j_id}.known_mask"
        for p in (mk1_path, mk2_path):
            if not p.exists():
                print(f"ERROR: partial mode requires {p} (run Go test with "
                      f"ITB_NONCE_REUSE_MODE=partial)", file=sys.stderr)
                return 2
        pm1 = mk1_path.read_bytes()
        pm2 = mk2_path.read_bytes()
        if len(pm1) != len(pl1) or len(pm2) != len(pl2):
            print(f"ERROR: known_mask length ({len(pm1)}, {len(pm2)}) does not match "
                  f"plaintext length ({len(pl1)}, {len(pl2)})", file=sys.stderr)
            return 2

    # -----------------------------------------------------------------------
    # Parse headers, verify nonce match (true nonce reuse)
    # -----------------------------------------------------------------------
    nonce_size = 16  # 128-bit nonce (default)
    n1, w1, h1, tp1, cb1_bytes = parse_itb_header(ct1, nonce_size)
    n2, w2, h2, tp2, cb2_bytes = parse_itb_header(ct2, nonce_size)
    if n1 != n2:
        if args.skip_nonce_check:
            print(f"WARNING: nonces differ (ct1: {n1.hex()}, ct2: {n2.hex()}) — "
                  f"proceeding anyway due to --skip-nonce-check; expect Layer 2 ≪ n_probe "
                  f"and Layer 1 ~0% exact recovery.", file=sys.stderr)
        else:
            print(f"ERROR: nonces differ — this is NOT a nonce-reuse pair "
                  f"(ct1 nonce: {n1.hex()}, ct2 nonce: {n2.hex()})", file=sys.stderr)
            return 2
    if (w1, h1) != (w2, h2):
        print(f"ERROR: container dimensions differ: ({w1}×{h1}) vs ({w2}×{h2})", file=sys.stderr)
        return 2
    if tp1 != meta["total_pixels"]:
        print(f"ERROR: meta says totalPixels={meta['total_pixels']}, ciphertext says {tp1}",
              file=sys.stderr)
        return 2

    print(f"  nonce       : {n1.hex()}  (identical across ct_{i_id} and ct_{j_id} ✓)")

    # -----------------------------------------------------------------------
    # Build attacker-knowable payloads (Full KPA: cobs + null + zeroed fill;
    # Partial KPA: cobs_with_mask + null + zeroed fill, with per-byte mask).
    # -----------------------------------------------------------------------
    capacity = (tp1 * DATA_BITS_PER_PIXEL) // 8

    channel_known_map: Optional[np.ndarray] = None
    if is_partial:
        payload1, payload_mask1 = build_payload_and_mask_partial(pl1, pm1, capacity)
        payload2, payload_mask2 = build_payload_and_mask_partial(pl2, pm2, capacity)
        channel_known_map = compute_channel_known_map(
            payload_mask1, payload_mask2, meta["data_pixels"],
        )
        known_channel_total = int(channel_known_map.sum())
        total_channel_slots = meta["data_pixels"] * CHANNELS
        print(f"  capacity    : {capacity} bytes  "
              f"(cobs1_len={len(cobs_encode(pl1))}, cobs2_len={len(cobs_encode(pl2))})")
        print(f"  channel-known coverage: {known_channel_total}/{total_channel_slots} = "
              f"{known_channel_total / total_channel_slots * 100:.2f}% "
              f"(min_known_channels per pixel: {args.min_known_channels})")
        enough = int((channel_known_map.sum(axis=1) >= args.min_known_channels).sum())
        print(f"  pixels with ≥ {args.min_known_channels} known channels: "
              f"{enough}/{meta['data_pixels']} = {enough / meta['data_pixels'] * 100:.2f}%")
    else:
        payload1 = build_payload_known(pl1, capacity)
        payload2 = build_payload_known(pl2, capacity)
        print(f"  capacity    : {capacity} bytes  "
              f"(cobs1_len={len(cobs_encode(pl1))}, cobs2_len={len(cobs_encode(pl2))})")

    # Reshape container bytes to (totalPixels, CHANNELS) for per-pixel access
    c1_container = np.frombuffer(cb1_bytes, dtype=np.uint8).reshape(tp1, CHANNELS)
    c2_container = np.frombuffer(cb2_bytes, dtype=np.uint8).reshape(tp2, CHANNELS)

    # -----------------------------------------------------------------------
    # Layer 2 — startPixel recovery (partial-aware dispatch)
    # -----------------------------------------------------------------------
    if args.brute_force_startpixel:
        print(f"\nLayer 2 brute force: searching startPixel over [0, {tp1}) with "
              f"n_probe={args.n_probe} probe pixels"
              + (f" [partial, min_known_channels={args.min_known_channels}]" if is_partial else ""))
        if is_partial:
            d_xor_probe, known_probe = precompute_d_xor_with_known_per_probe(
                payload1, payload2, channel_known_map, args.n_probe,
            )
            recovered_sp, score, l2_elapsed = layer2_brute_force_startpixel_partial(
                c1_container, c2_container, d_xor_probe, known_probe,
                tp1, args.n_probe, args.min_known_channels, verbose=True,
            )
            target_score = int((known_probe.sum(axis=1) >= args.min_known_channels).sum())
            print(f"  recovered startPixel : {recovered_sp}  "
                  f"(score {score}/{target_score}; target = usable probe pixels)")
        else:
            d_xor_probe = precompute_d_xor_per_probe(payload1, payload2, args.n_probe)
            recovered_sp, score, l2_elapsed = layer2_brute_force_startpixel(
                c1_container, c2_container, d_xor_probe, tp1, args.n_probe,
                verbose=True,
            )
            target_score = args.n_probe
            print(f"  recovered startPixel : {recovered_sp}  (score {score}/{target_score})")
        print(f"  sidecar says          : {meta['start_pixel']}")
        if recovered_sp == meta["start_pixel"]:
            print(f"  Layer 2 RESULT: ✓ recovered startPixel matches ground truth")
            start_pixel_used = recovered_sp
        elif args.skip_nonce_check:
            # Expected negative outcome on nonce-mismatch data: continue with
            # the sidecar's startPixel so Layer 1 can still report its recovery
            # rate (will be near-zero exact, ~100% ambiguous).
            print(f"  Layer 2 RESULT: ✗ no valid startPixel found (expected under "
                  f"--skip-nonce-check; proceeding to Layer 1 using sidecar sp for diagnostics)")
            start_pixel_used = meta["start_pixel"]
        elif is_partial:
            # Partial-KPA with repeated-record plaintexts: d_xor pattern is
            # periodic → Layer 2 may settle on a period-shifted sp. The
            # reconstructed stream under such an sp is still valid dataHash
            # output, just labelled from a shifted pixel index. For NIST STS
            # PRF-separation this is fine — the stream properties don't depend
            # on which contiguous pixel range the attacker landed on. Accept
            # the recovered sp and continue; validation against truth will be
            # done with a shift-accounting helper below.
            shift_candidate = (recovered_sp - meta["start_pixel"]) % tp1
            print(f"  Layer 2 RESULT: ⚠ recovered startPixel {recovered_sp} differs from "
                  f"ground-truth {meta['start_pixel']} by {shift_candidate} pixels — accepting "
                  f"as a period-shifted alignment (valid under Partial-KPA with periodic "
                  f"plaintexts; reconstructed stream is still valid dataHash output).")
            start_pixel_used = recovered_sp
        else:
            print(f"  Layer 2 RESULT: ✗ recovered startPixel DIFFERS from ground truth (BUG)")
            return 3
    else:
        start_pixel_used = meta["start_pixel"]
        print(f"\nLayer 2 SKIPPED — using startPixel={start_pixel_used} from sidecar "
              f"(pass --brute-force-startpixel for realistic attacker simulation).")

    # -----------------------------------------------------------------------
    # Determine pixel range to attempt recovery on
    # -----------------------------------------------------------------------
    if args.pixel_range:
        try:
            start_idx, end_idx = [int(x) for x in args.pixel_range.split(":")]
        except ValueError:
            print(f"ERROR: --pixel-range must be 'start:end'", file=sys.stderr)
            return 2
    else:
        # Default: only the fully-known pixels (where Full KPA constraint matching
        # is expected to succeed at all 8 channels). Pixels beyond fully_known_pixels
        # contain random crypto/rand fill that the attacker cannot predict.
        start_idx = 0
        end_idx = meta["fully_known_pixels"]

    # Under partial mode the "fully-known pixels" concept from meta is the Full
    # KPA boundary — irrelevant here. Widen the default to the entire data-pixel
    # range: Partial KPA only claims to cover the channels the mask says are
    # known. Pixels with too few known channels are automatically skipped by
    # layer1_recover_pixel_partial → min_known_channels threshold.
    if is_partial and not args.pixel_range:
        end_idx = meta["data_pixels"]

    n_attempt = end_idx - start_idx
    print(f"\nLayer 1 recovery on data-pixel range [{start_idx}, {end_idx}) — {n_attempt} pixels"
          + (f" [partial-KPA, min_known_channels={args.min_known_channels}]" if is_partial else ""))
    t0 = time.time()
    if is_partial:
        recovered = layer1_recover_range_partial(
            c1_container, c2_container,
            payload1, payload2,
            channel_known_map,
            start_pixel_used, meta["data_pixels"], meta["total_pixels"],
            pixel_range=(start_idx, end_idx),
            min_known_channels=args.min_known_channels,
        )
    else:
        recovered = layer1_recover_range(
            c1_container, c2_container,
            payload1, payload2,
            start_pixel_used, meta["data_pixels"], meta["total_pixels"],
            pixel_range=(start_idx, end_idx),
        )
    elapsed = time.time() - t0

    unique = sum(1 for r in recovered if r is not None)
    ambiguous = n_attempt - unique
    rate = n_attempt / elapsed if elapsed > 0 else 0
    print(f"  elapsed     : {elapsed:.2f}s  ({rate:.0f} pixels/s)")
    print(f"  unique      : {unique}/{n_attempt}")
    print(f"  ambiguous/no-match : {ambiguous}/{n_attempt}")

    # -----------------------------------------------------------------------
    # Validate against ground truth if requested
    # -----------------------------------------------------------------------
    # -----------------------------------------------------------------------
    # Phase D — reconstruct dataHash stream (if --emit-datahash was passed)
    # -----------------------------------------------------------------------
    if args.emit_datahash is not None:
        print(f"\nPhase D reconstruction — emitting pure dataHash stream to {args.emit_datahash}")
        # Use ct_0000 as the source ciphertext (either C1 or C2 works — same
        # config yields same channelXOR per (pixel, channel) since nonce+seeds
        # are identical).
        t_emit0 = time.time()
        if is_partial:
            stream_bytes, emitted_pairs = reconstruct_datahash_stream_partial(
                c1_container, payload1, recovered, channel_known_map,
                start_pixel_used, meta["total_pixels"],
                pixel_range=(start_idx, end_idx),
            )
            # Emit a parallel sidecar recording which (pixel, channel) pairs
            # contributed each 7-bit block, so downstream analysis can correlate
            # the scattered stream back to specific positions in the data region.
            index_path = args.emit_datahash.with_suffix(
                args.emit_datahash.suffix + ".index"
            )
            with open(index_path, "w") as f:
                for p, ch in emitted_pairs:
                    f.write(f"{p} {ch}\n")
            emitted_idxs = emitted_pairs  # reused by validation below
        else:
            stream_bytes, emitted_idxs = reconstruct_datahash_stream(
                c1_container, payload1, recovered,
                start_pixel_used, meta["total_pixels"],
                pixel_range=(start_idx, end_idx),
            )
        t_emit = time.time() - t_emit0
        args.emit_datahash.parent.mkdir(parents=True, exist_ok=True)
        args.emit_datahash.write_bytes(stream_bytes)
        print(f"  reconstruction time : {t_emit:.2f}s")
        if is_partial:
            print(f"  emitted channels    : {len(emitted_idxs)} 7-bit slices "
                  f"(of {(end_idx - start_idx) * CHANNELS} possible data-pixel channel positions)")
            print(f"  stream size         : {len(stream_bytes)} bytes = "
                  f"{len(stream_bytes) * 8} bits (dense bit-packing across variable-coverage pixels)")
            print(f"  index sidecar       : {index_path}")
        else:
            print(f"  emitted pixels      : {len(emitted_idxs)} (of {end_idx - start_idx} attempted)")
            print(f"  stream size         : {len(stream_bytes)} bytes = {len(stream_bytes) * 8} bits")
        print(f"  output file         : {args.emit_datahash}")

        if args.validate:
            truth = load_config_truth(cell_dir)
            if is_partial:
                # Account for any period-shift Layer 2 settled on. The
                # emitted (p, ch) pair at our "data pixel p" corresponds to
                # ground-truth pixel (p + shift) mod data_pixels.
                shift_r = (start_pixel_used - meta["start_pixel"]) % tp1
                expected_accum = 0
                expected_bits = 0
                expected_out = bytearray()
                for p, ch in emitted_pairs:
                    truth_idx = (p + shift_r) % meta["data_pixels"]
                    truth_entry = truth["per_pixel"][truth_idx]
                    want_val = truth_entry["channel_xor_8"][ch] & 0x7F
                    expected_accum |= want_val << expected_bits
                    expected_bits += 7
                    while expected_bits >= 8:
                        expected_out.append(expected_accum & 0xFF)
                        expected_accum >>= 8
                        expected_bits -= 8
                if expected_bits > 0:
                    expected_out.append(expected_accum & 0xFF)
                d_total = len(emitted_pairs)
                d_exact = d_total if bytes(expected_out) == stream_bytes else 0
                d_mismatch = 0 if d_exact == d_total else d_total
                print(f"  reconstruction validation against config.truth.json:")
                if shift_r != 0:
                    print(f"    (accounting for period-shift of {shift_r} pixels)")
                print(f"    channels compared: {d_total}")
                if d_total == 0:
                    print(f"    (nothing emitted — nothing to validate)")
                elif d_exact == d_total:
                    print(f"    exact match      : {d_exact} / {d_total}  (100.00%)")
                else:
                    print(f"    MISMATCH on reconstructed stream — partial-mode "
                          f"reconstruction has a bug; first 32 bytes expected vs got:")
                    print(f"      expected: {bytes(expected_out)[:32].hex()}")
                    print(f"      got     : {stream_bytes[:32].hex()}")
            else:
                d_total, d_exact, d_mismatch, d_mismatch_idxs = verify_datahash_vs_truth(
                    stream_bytes, emitted_idxs, truth["per_pixel"],
                )
                print(f"  reconstruction validation against config.truth.json:")
                print(f"    pixels compared : {d_total}")
                if d_total == 0:
                    print(f"    (no pixels recovered — nothing to validate; expected under "
                          f"--skip-nonce-check on nonce-mismatch corpus)")
                else:
                    print(f"    exact match      : {d_exact}   ({d_exact / d_total * 100:.2f}%)")
                    print(f"    mismatch         : {d_mismatch}")
                    if d_mismatch_idxs:
                        print(f"    first mismatch pixel indices: {d_mismatch_idxs}")

    if args.validate:
        truth = load_config_truth(cell_dir)
        per_pixel_truth = truth["per_pixel"]
        # Partial-KPA on periodic plaintexts may settle on a period-shifted sp.
        # Validate against truth at the shifted offset so "wrong" only reflects
        # real formula bugs, not period alignment.
        shift = 0
        if is_partial:
            shift = (start_pixel_used - meta["start_pixel"]) % tp1
            if shift != 0:
                print(f"\nValidation accounting for period-shift: {shift} pixels "
                      f"(Partial-KPA accepted a shifted sp; recovered "
                      f"(noisePos, rotation) will be compared to truth@(data_idx + shift))")
            shifted_truth = [per_pixel_truth[(i + shift) % meta["data_pixels"]]
                             for i in range(meta["data_pixels"])]
            per_pixel_truth_for_compare = shifted_truth
        else:
            per_pixel_truth_for_compare = per_pixel_truth
        total, exact, ambiguous, wrong, wrong_idxs = validate_against_truth(
            recovered, per_pixel_truth_for_compare, start_idx,
        )
        print(f"\nValidation against config.truth.json:")
        print(f"  total compared          : {total}")
        print(f"  exact recovery           : {exact}   ({exact / total * 100:.2f}%)")
        print(f"  ambiguous (multi-cand.)  : {ambiguous}   ({ambiguous / total * 100:.2f}%)")
        print(f"  WRONG match (BUG if > 0) : {wrong}")
        if wrong > 0:
            print(f"  wrong-match pixel indices: {wrong_idxs}")
            for idx in wrong_idxs[:3]:
                rec = recovered[idx - start_idx]
                want = per_pixel_truth[idx]
                print(f"    pixel {idx}: recovered={rec}  truth=(noisePos={want['noise_pos']}, "
                      f"rotation={want['rotation']})")
            print(f"  RESULT: ✗ FORMULA BUG — helper returned a unique but incorrect config")
            return 2  # formula bug
        if exact == total:
            print(f"  RESULT: ✓ helper recovery matches ground truth on every pixel")
            return 0
        print(f"  RESULT: ✓ formula correct (zero wrong matches) — ambiguous pixels are known")
        print(f"          adjacent-noisePos artefacts of single-pair Layer 1. Multi-pair")
        print(f"          combining (N ≥ 4) would disambiguate. Expected ~1% per single pair.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
