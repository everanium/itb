#!/usr/bin/env python3
"""Phase 2f — CRIB-KPA algebraic K recovery against ChainHash<CRC128>.

Goal B: recover K (CRC128 compound key) from a raw ITB ciphertext
*without* nonce-reuse, *without* demasker. Attacker knows:

  * ITB public algorithm + primitive = CRC128 (public inference).
  * Nonce + W × H from the 20-byte header of the ciphertext.
  * Format = JSON (Content-Type / TLS SNI / API docs).
  * Schema field name: public API docs state that every record begins
    `"identifier_of_record_in_system":"..."`, so the first 36 bytes of
    the plaintext are `[{"identifier_of_record_in_system":"` — a fixed
    template prefix that covers 5 full pixels.

The attack:

  Step 1 (pixel 0, 56 per-pixel-guesses):
      For each (noise_pos, rotation) ∈ 8 × 7 combinations:
          - Extract 8 × 7-bit unrotated values from container bytes.
          - Known plaintext 7 bytes → unpack to 8 × 7-bit slots pt[ch].
          - channelXOR[ch] = unrotated[ch] XOR pt[ch]    (per channel)
          - K[3..58] = channelXOR[0..7] XOR const(0)[3..58]  (56 bits)
      Result: 56 K candidates per shift.

  Step 2 (verify on pixel 1, 56 per-pixel-guesses):
      For each K candidate from Step 1:
          For each (noise_pos', rotation') at pixel 1:
              decrypt pixel 1's 7 bytes under this K + guess
              if result equals known `ifier_o` exactly → WINNER

  Step 3 (optional triple-verify on pixel 2..4): same check, filters
      any remaining false positives to near-zero.

Search size: |plateau| × 56² verifier pairs = trivial (a few thousand
candidate pairs for a handful of plateau shifts). Alternatively,
brute-force across all 9604 shifts for 64 KB corpus.

False-positive probability for wrong (shift, K, guess0, guess1): each
of the 56 pixel 1 candidates has 1/128^7 ≈ 10⁻¹⁵ chance of matching a
7-byte random crib. Across 9604 × 56² = 30M pair tests, expected false
positives ≈ 3 × 10⁻⁸. Effectively zero.

Usage:
    python3 crib_crc128_kpa.py \\
        --cell-dir <corpus> \\
        --brute-force-shifts \\
        --verify-pixels 3

Lab audit compares recovered K to cell.meta.json seed-derived K.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import importlib

from raw_mode_common import (
    parse_raw_ciphertext,
    precompute_const_all as _precompute_const_all,
    recover_compound_key_cached,
)

# Pluggable hash module — parametrized at runtime to test different
# primitives. CRC128 is the baseline (GF(2)-linear, attack works);
# other primitives should fail.
_HASH_MODULE = None


def _load_hash_module(name: str):
    global _HASH_MODULE
    _HASH_MODULE = importlib.import_module(f"chainhashes.{name}")
    return _HASH_MODULE

MASK64 = (1 << 64) - 1

# Full format-derived plaintext prefix the attacker reconstructs from
# public API docs. First pixel = bytes 0..6, pixel 1 = bytes 7..13, etc.
# ITB encodes data through COBS (Consistent Overhead Byte Stuffing) before
# the rotation + channelXOR + noisePos layers. Our JSON plaintext never
# contains 0x00 bytes, so COBS always starts with 0xFF (maximum overhead
# header = 255 bytes follow without a 0x00), then the raw bytes. The
# attacker reads ITB source (open source) to know the COBS wrapping, and
# the JSON schema (API docs) to know what follows.
JSON_PREFIX_37 = b'\xff[{"identifier_of_record_in_system":"'


def precompute_const_all(total_pixels: int, nonce: bytes) -> np.ndarray:
    if _HASH_MODULE is None:
        raise RuntimeError("hash module not loaded — call _load_hash_module first")
    return _precompute_const_all(
        total_pixels, nonce, _HASH_MODULE.chainhash_lo,
        _HASH_MODULE.N_SEED_COMPONENTS,
    )


def rotate7_left(v: int, r: int) -> int:
    r = r % 7
    return ((v << r) | (v >> (7 - r))) & 0x7F


def rotate7_right(v: int, r: int) -> int:
    r = r % 7
    return ((v >> r) | (v << (7 - r))) & 0x7F


def extract_drop_bit(byte: int, drop_pos: int) -> int:
    low = byte & ((1 << drop_pos) - 1)
    high = byte >> (drop_pos + 1)
    return (low | (high << drop_pos)) & 0x7F


def insert_drop_bit(seven_bit: int, drop_pos: int, inserted_bit: int) -> int:
    low = seven_bit & ((1 << drop_pos) - 1)
    high = seven_bit >> drop_pos
    return low | ((inserted_bit & 1) << drop_pos) | (high << (drop_pos + 1))


def unpack_7bytes_to_channels(chunk: bytes) -> List[int]:
    """Given a 7-byte plaintext chunk, unpack into 8 × 7-bit channel
    values via the ITB LE convention (slab = Σ pt[ch] << 7*ch)."""
    assert len(chunk) == 7
    slab = int.from_bytes(chunk, "little")
    return [(slab >> (ch * 7)) & 0x7F for ch in range(8)]


def derive_K_from_pixel(
    container_bytes: bytes,
    plaintext_chunk: bytes,
    pixel_idx: int,
    const_all: np.ndarray,
    noise_pos: int,
    rotation: int,
) -> int:
    """Given one data-pixel's container bytes, known 7-byte plaintext,
    and a (noise_pos, rotation) guess, derive the 56 K-bits at positions
    3..58. Returns K with those bits set (bits 0..2 and 59..63 remain 0).
    """
    pt_ch = unpack_7bytes_to_channels(plaintext_chunk)
    const_val = int(const_all[pixel_idx])
    K = 0
    for ch in range(8):
        extracted = extract_drop_bit(container_bytes[ch], noise_pos)
        unrotated = rotate7_right(extracted, rotation)
        channel_xor = unrotated ^ pt_ch[ch]
        # Place into K at bits 3 + 7*ch .. 9 + 7*ch
        const_slot = (const_val >> (3 + 7 * ch)) & 0x7F
        k_slot = channel_xor ^ const_slot
        K |= (k_slot & 0x7F) << (3 + 7 * ch)
    return K & MASK64


def decrypt_pixel(
    K: int,
    container_bytes: bytes,
    pixel_idx: int,
    const_all: np.ndarray,
    noise_pos: int,
    rotation: int,
) -> bytes:
    """Given K + (noise_pos, rotation) guess at pixel_idx, return the
    decrypted 7-byte plaintext chunk."""
    const_val = int(const_all[pixel_idx])
    h_seeded = K ^ const_val
    pt_ch = []
    for ch in range(8):
        channel_xor = (h_seeded >> (3 + 7 * ch)) & 0x7F
        extracted = extract_drop_bit(container_bytes[ch], noise_pos)
        unrotated = rotate7_right(extracted, rotation)
        pt_ch.append(unrotated ^ channel_xor)
    slab = 0
    for ch in range(8):
        slab |= (pt_ch[ch] & 0x7F) << (ch * 7)
    return slab.to_bytes(7, "little")


def try_shift_algebraic(
    shift: int,
    body: bytes,
    total_pixels: int,
    const_all: np.ndarray,
    known_prefix: bytes,
    verify_pixels: int,
) -> Optional[int]:
    """Try algebraic K-recovery for a given shift. Returns recovered K
    on success or None on failure."""
    start_pixel = (-shift) % total_pixels
    # Pixel 0 known plaintext
    p0_chunk = known_prefix[0:7]
    cp0 = start_pixel % total_pixels
    cb0 = body[cp0 * 8: cp0 * 8 + 8]
    # Candidates from pixel 0 guesses
    candidates: List[Tuple[int, int, int]] = []  # (K, noise_pos, rotation)
    for noise_pos in range(8):
        for rotation in range(7):
            K = derive_K_from_pixel(cb0, p0_chunk, 0, const_all, noise_pos, rotation)
            candidates.append((K, noise_pos, rotation))
    # Verify on pixels 1..verify_pixels-1
    for K_cand, np0, r0 in candidates:
        ok = True
        for verify_p in range(1, verify_pixels):
            expected_chunk = known_prefix[verify_p * 7: verify_p * 7 + 7]
            if len(expected_chunk) < 7:
                # Not enough known plaintext for this verify pixel; skip.
                continue
            cp = (start_pixel + verify_p) % total_pixels
            cb = body[cp * 8: cp * 8 + 8]
            found_match = False
            for np_v in range(8):
                for r_v in range(7):
                    got = decrypt_pixel(K_cand, cb, verify_p, const_all, np_v, r_v)
                    if got == expected_chunk:
                        found_match = True
                        break
                if found_match:
                    break
            if not found_match:
                ok = False
                break
        if ok:
            return K_cand
    return None


def try_shift_algebraic_vectorized(
    shift: int,
    body: bytes,
    total_pixels: int,
    const_all: np.ndarray,
    known_prefix: bytes,
    verify_pixels: int,
) -> Optional[int]:
    """Numpy-vectorized variant of try_shift_algebraic — same search,
    much faster on the verifier loop (the 56 inner (noise, rotation)
    enumerations per pixel per candidate)."""
    start_pixel = (-shift) % total_pixels
    p0_chunk = known_prefix[0:7]
    cp0 = start_pixel % total_pixels
    cb0 = body[cp0 * 8: cp0 * 8 + 8]

    candidates_K = np.zeros(56, dtype=np.uint64)
    idx = 0
    for noise_pos in range(8):
        for rotation in range(7):
            candidates_K[idx] = np.uint64(
                derive_K_from_pixel(cb0, p0_chunk, 0, const_all,
                                    noise_pos, rotation)
            )
            idx += 1

    # Verify: for each K candidate, try all 56 combos at pixel v
    # and check if any yields the known chunk.
    for verify_p in range(1, verify_pixels):
        expected_chunk = known_prefix[verify_p * 7: verify_p * 7 + 7]
        if len(expected_chunk) < 7:
            continue
        expected_arr = np.frombuffer(expected_chunk, dtype=np.uint8)
        cp = (start_pixel + verify_p) % total_pixels
        cb = np.frombuffer(body, dtype=np.uint8,
                           count=8, offset=cp * 8)
        # For each candidate: compute all 56 decrypted chunks, check equality.
        M = len(candidates_K)
        const_val = np.uint64(int(const_all[verify_p]))
        h_seeded = candidates_K ^ const_val  # (M,)
        shifts_arr = np.uint64(3) + np.uint64(7) * np.arange(8, dtype=np.uint64)
        ch_slots = np.empty((M, 8), dtype=np.uint8)
        for ch in range(8):
            ch_slots[:, ch] = ((h_seeded >> shifts_arr[ch]) & np.uint64(0x7F)).astype(np.uint8)

        # 56 combos precomputed
        survives = np.zeros(M, dtype=bool)
        for noise_pos in range(8):
            for rotation in range(7):
                # Extract 7-bit values
                extracted = np.empty(8, dtype=np.uint8)
                for ch in range(8):
                    b = int(cb[ch])
                    low = b & ((1 << noise_pos) - 1)
                    high = b >> (noise_pos + 1)
                    extracted[ch] = (low | (high << noise_pos)) & 0x7F
                unrotated = np.empty(8, dtype=np.uint8)
                for ch in range(8):
                    v = int(extracted[ch])
                    unrotated[ch] = ((v >> rotation) | (v << (7 - rotation))) & 0x7F
                # pt_ch[M, ch] = unrotated XOR ch_slots
                pt_ch = unrotated[None, :] ^ ch_slots  # (M, 8)
                # Pack to 7 bytes
                slab = np.zeros(M, dtype=np.uint64)
                for ch in range(8):
                    slab |= pt_ch[:, ch].astype(np.uint64) << np.uint64(7 * ch)
                chunk_bytes = np.empty((M, 7), dtype=np.uint8)
                for b in range(7):
                    chunk_bytes[:, b] = ((slab >> np.uint64(8 * b)) &
                                         np.uint64(0xFF)).astype(np.uint8)
                match = (chunk_bytes == expected_arr[None, :]).all(axis=1)
                survives = survives | match
        # Only keep candidates that survived this verify pixel
        survivors = np.where(survives)[0]
        if len(survivors) == 0:
            return None  # no K candidate matches all constraints
        candidates_K = candidates_K[survivors]
        if len(candidates_K) == 1 and verify_p >= 2:
            # Unique survivor after at least 2 verify pixels → winner
            return int(candidates_K[0])
    if len(candidates_K) == 1:
        return int(candidates_K[0])
    if len(candidates_K) > 1:
        # Multiple survivors — return first (rare, likely false matches)
        return int(candidates_K[0])
    return None


def disambiguate_unobserved_bits(
    K_observable: int,
    body: bytes,
    total_pixels: int,
    const_all: np.ndarray,
    known_prefix: bytes,
    start_pixel: int,
) -> Optional[int]:
    """Return the list of 64-bit K candidates consistent with the crib.

    channelXOR exposes only bits 3..58 of hLo, so the initial algebraic
    recovery leaves 8 bits (3 low + 5 high) unconstrained. Those bits DO
    affect `rotation = hLo mod 7`. Here we enumerate all 256 placements
    of the unknown bits, keep only K_trial values where every pixel in
    the short-crib passes under some noise_pos (8-way brute force) with
    deterministic rotation, and return the first survivor.

    Cryptographically, more than one K_trial can survive a short crib
    when const(p) bit 60/63 patterns happen to cancel the bit-60/bit-63
    flips in K_trial (mod 7). The caller must treat the returned K as
    belonging to a small equivalence class and disambiguate fully by
    running the downstream full-plaintext decrypt over all 256 variants
    — see `crib_crc128_decrypt.py` — not by over-constraining this step
    with knowledge an attacker would not have.
    """
    OBSERVABLE_MASK = 0x07FFFFFFFFFFFFF8  # bits 3..58 (56 bits)
    K_base = K_observable & OBSERVABLE_MASK
    max_pixels_in_crib = len(known_prefix) // 7

    for unknown_8 in range(256):
        low_3 = unknown_8 & 0x07
        high_5 = (unknown_8 >> 3) & 0x1F
        K_trial = K_base | low_3 | (high_5 << 59)

        all_match = True
        for p_idx in range(max_pixels_in_crib):
            cp = (start_pixel + p_idx) % total_pixels
            const_p = int(const_all[p_idx])
            h_lo = (K_trial ^ const_p) & 0xFFFFFFFFFFFFFFFF
            rotation = h_lo % 7
            expected = known_prefix[p_idx * 7: p_idx * 7 + 7]
            cb = body[cp * 8: cp * 8 + 8]

            found = False
            for noise_pos in range(8):
                got = decrypt_pixel(K_trial, cb, p_idx, const_all, noise_pos, rotation)
                if got == expected:
                    found = True
                    break
            if not found:
                all_match = False
                break

        if all_match:
            return K_trial

    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cell-dir", type=Path, required=True)
    ap.add_argument("--hash-module", type=str, default="crc128",
                    help="Hash primitive mirror (chainhashes/<name>.py). "
                         "Default: crc128 (baseline GF(2)-linear attack). "
                         "For FNV-1a / BLAKE3 / etc. pass corresponding name — "
                         "attack is expected to FAIL (no pixel-independent K).")
    ap.add_argument("--ciphertext", type=Path, default=None)
    ap.add_argument("--crib-prefix-hex", type=str,
                    default=JSON_PREFIX_37.hex(),
                    help="Known plaintext prefix in hex (COBS-wrapped "
                         "JSON schema; default: 0xff + '[{\"identifier_of_record_in_system\":\"').")
    ap.add_argument("--verify-pixels", type=int, default=4,
                    help="How many pixels to use for K-verification "
                         "(pixel 0 for derivation, 1..N-1 for verify).")
    ap.add_argument("--brute-force-shifts", action="store_true",
                    help="Try every shift in [0, total_pixels) instead of "
                         "only the bias-probe plateau.")
    ap.add_argument("--probe-size", type=int, default=16000,
                    help="Only used when --brute-force-shifts not set.")
    ap.add_argument("--plateau-tolerance", type=float, default=0.005)
    args = ap.parse_args()

    meta = json.loads((args.cell_dir / "cell.meta.json").read_text())
    total_pixels = int(meta["total_pixels"])
    nonce = bytes.fromhex(meta["nonce_hex"])
    ct_path = args.ciphertext or (args.cell_dir / "ct_0000.bin")
    raw = ct_path.read_bytes()
    HEADER = 20
    body = raw[HEADER:HEADER + total_pixels * 8]
    hmod = _load_hash_module(args.hash_module)
    if hasattr(hmod, "init_from_meta"):
        hmod.init_from_meta(meta)
    K_expected = (hmod.compute_expected_K(meta, nonce)
                  if hasattr(hmod, "compute_expected_K") else 0)
    known_prefix = bytes.fromhex(args.crib_prefix_hex)

    print(f"{'=' * 72}")
    print(f"Phase 2f — crib-KPA (algebraic K recovery against ChainHash<CRC128>)")
    print(f"{'=' * 72}")
    print(f"Cell:              {args.cell_dir}")
    print(f"Ciphertext:        {ct_path.name} ({ct_path.stat().st_size} bytes)")
    print(f"total_pixels:      {total_pixels}")
    print(f"Known prefix:      {known_prefix!r}  ({len(known_prefix)} bytes)")
    print(f"Verify pixels:     {args.verify_pixels}")
    print(f"Brute-force shifts: {args.brute_force_shifts}")
    print(f"Expected K (lab):  0x{K_expected:016x}  [audit only]")
    print()

    t0 = time.time()
    print(f"Precomputing const(p) for {total_pixels} pixels ...")
    const_all = precompute_const_all(total_pixels, nonce)
    print(f"  done in {time.time() - t0:.1f}s")

    if args.brute_force_shifts:
        shifts_to_try = list(range(total_pixels))
    else:
        observations = parse_raw_ciphertext(ct_path, total_pixels)
        t0 = time.time()
        probe = observations[:args.probe_size]
        pins_max = sum(
            1 for _, ch, _ in probe for k in range(7) if (ch * 7 + 3 + k) < 64
        )
        results = []
        for s in range(total_pixels):
            _, _, _, conflicts = recover_compound_key_cached(
                probe, total_pixels, const_all, pixel_shift=s,
            )
            results.append((s, conflicts))
        min_conf = min(c for _, c in results)
        tolerance = int(pins_max * args.plateau_tolerance)
        shifts_to_try = [s for s, c in results if c <= min_conf + tolerance]
        shifts_to_try.sort(key=lambda s: [c for ss, c in results if ss == s][0])
        print(f"Bias plateau: {len(shifts_to_try)} shifts ({time.time() - t0:.1f}s)")

    t0 = time.time()
    winner = None
    winning_shift = None
    for i, s in enumerate(shifts_to_try):
        K = try_shift_algebraic_vectorized(
            s, body, total_pixels, const_all, known_prefix, args.verify_pixels,
        )
        if K is not None:
            winner = K
            winning_shift = s
            print(f"  [shift {s}] ★ MATCH  K=0x{K:016x}")
            break
        if (i + 1) % 500 == 0 or i == len(shifts_to_try) - 1:
            print(f"  [{i+1}/{len(shifts_to_try)}] scanned (elapsed {time.time() - t0:.1f}s)")
    elapsed = time.time() - t0

    print(f"\n{'=' * 72}")
    print(f"RESULT")
    print(f"{'=' * 72}")
    print(f"  Scan time:         {elapsed:.1f}s")
    if winner is None:
        print(f"  Winner:            NOT FOUND")
        print(f"  Expected K (lab):  0x{K_expected:016x}")
        return 2
    else:
        print(f"  Winner K (56-observable): 0x{winner:016x}")
        print(f"  Winning shift:     {winning_shift}")

        # Step 4: Disambiguate the 8 unobservable bits (0..2, 59..63)
        # using deterministic rotation derived from candidate K + crib.
        start_pixel_winning = (-winning_shift) % total_pixels
        t_dis = time.time()
        full_K = disambiguate_unobserved_bits(
            winner, body, total_pixels, const_all, known_prefix, start_pixel_winning,
        )
        print(f"  Disambiguation:    {time.time() - t_dis:.2f}s over 256 high/low-bit combos")
        if full_K is not None:
            winner = full_K
            print(f"  Full 64-bit K:     0x{winner:016x}")

        print(f"  Expected K (lab):  0x{K_expected:016x}")
        match = winner == K_expected
        print(f"  Matches GT:        {'✓ SEED INVERTED' if match else '✗ MISMATCH'}")
        if not match:
            xor_diff = (winner ^ K_expected) & MASK64
            popcount = bin(xor_diff).count("1")
            print(f"  Hamming distance:  {popcount} / 64 bits")
        # Print decrypted prefix as sanity
        start_pixel = (-winning_shift) % total_pixels
        prefix_bytes = bytearray()
        for p in range(10):
            cp = (start_pixel + p) % total_pixels
            cb = body[cp * 8: cp * 8 + 8]
            # Find (noise, rotation) that matches for this pixel
            expected = known_prefix[p * 7: p * 7 + 7] if (p + 1) * 7 <= len(known_prefix) else None
            best_chunk = None
            for noise_pos in range(8):
                for rotation in range(7):
                    c = decrypt_pixel(winner, cb, p, const_all, noise_pos, rotation)
                    if expected is not None and c == expected:
                        best_chunk = c
                        break
                    if best_chunk is None:
                        best_chunk = c
                if best_chunk and expected and best_chunk == expected:
                    break
            prefix_bytes.extend(best_chunk or b'.' * 7)
        print(f"  Decrypt preview:   {bytes(prefix_bytes)!r}")
        return 0 if match else 2


if __name__ == "__main__":
    sys.exit(main())
