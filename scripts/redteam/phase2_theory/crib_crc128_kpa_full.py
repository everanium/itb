#!/usr/bin/env python3
"""Phase 2f — Crib KPA full K recovery (K_data + K_noise_bits_0_2).

Recovers both the 64-bit compound key K_data and the 3 low bits of
noiseSeed's compound key K_noise as a joint side effect of the
56-hypothesis filter on a known-plaintext crib. Under CRC128 GF(2)-
linearity, this pair is sufficient for 100 % byte-level decryption of
any future ciphertext under the same dataSeed/noiseSeed/startSeed
triple — any nonce, any plaintext format (printable text, HTML, JSON,
binary, compressed, or encrypted streams).

Algebraic insight:

  noisePos(p, nonce) = noiseSeed.ChainHash(pixel||nonce).lo & 7
                     = (K_noise ⊕ c_public(p, nonce)) & 7
                     = (K_noise & 7) ⊕ (c_public(p, nonce) & 7)
                     = K_noise_bits_0_2 ⊕ (c_public(p, nonce) & 7)

Both noiseSeed and dataSeed wrap the same CRC128 primitive through the
same 8-round ChainHash on the same 20-byte (pixel_u32le || nonce) input;
the seed-independent compound `c_public` is therefore identical for both
lanes and is the same `const_all[p]` array already computed by the base
crib_crc128_kpa.py script.

During the 56-hypothesis filter that recovers K_data, the correct
(noise_pos, rotation) pair per crib pixel reveals the observed noisePos
for that pixel. Per pixel:

  K_noise_bits_0_2_candidate = observed_noise_pos ⊕ (const_all[p] & 7)

Consistency across all crib pixels confirms the 3-bit value and, as a
bonus, disambiguates among the 256 K_data variants (the observable bits
of K_data are fixed at 56 out of 64; the 8 unobservable bits are
enumerated) — only the correct K_data variant yields a consistent
K_noise_bits_0_2 across all crib pixels.

Usage:
    python3 crib_crc128_kpa_full.py \\
        --cell-dir <corpus> \\
        --brute-force-shifts \\
        --verify-pixels 4

Output: K_data (64-bit hex) + K_noise_bits_0_2 (3-bit int) + start_pixel.
Feed these into crib_crc128_decrypt_full.py for 100 % decryption of any
ciphertext under the same seeds.

Lab audit: compares recovered values to cell.meta.json seed-derived
values when available (using crc128 hash module's compute_expected_K).
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

from crib_crc128_kpa import (
    MASK64,
    _load_hash_module,
    precompute_const_all,
    decrypt_pixel,
    try_shift_algebraic_vectorized,
)

# Default 21-byte (3-pixel) JSON crib covering the publicly-known
# COBS 0xFF prefix + JSON array start + the first portion of the first-
# field schema: `[{"identifier_of_rec`. 3 pixels is the minimum-viable
# crib for Stage 2's (K_data variant, K_noise_bits_0_2) enumeration:
# at this length mod-7 aliasing on the 8 unobservable K_data bits
# typically leaves multiple structural-shadow survivors, which the
# downstream crib_crc128_decrypt_full.py disambiguates via COBS-decode
# validity on a second ciphertext (attacker-realistic cross-check —
# COBS is part of the public ITB spec). A longer crib (e.g. up to 77
# bytes / 11 pixels covering `:"00000","the_timestamp_of_the_event_iso":`)
# narrows Stage 2's survivor count and shortens decrypt_full's wall
# clock, but is not required for correctness.
JSON_PREFIX_21 = b'\xff[{"identifier_of_rec'
from raw_mode_common import (
    parse_raw_ciphertext,
    recover_compound_key_cached,
)


OBSERVABLE_MASK = 0x07FFFFFFFFFFFFF8  # K_data bits 3..58


def recover_k_full(
    K_observable: int,
    body: bytes,
    total_pixels: int,
    const_all: np.ndarray,
    known_prefix: bytes,
    start_pixel: int,
) -> List[Tuple[int, int, List[Tuple[int, int]]]]:
    """Enumerate all 256 × 8 = 2048 (K_data variant, K_noise_bits_0_2) pairs
    and return every one that decrypts every crib pixel EXACTLY — using the
    pair's derived rotation (from K_data) AND its derived noise_pos (from
    K_noise_bits_0_2) per pixel, with no brute-force on any channel.

    Returns a list of surviving pairs as (K_data_full, K_noise_bits_0_2,
    per_pixel_noisepos_list). In the common case the list has one entry;
    when structural mod-7 aliasing on the 8 unobservable K_data bits lets
    a shadow pair pass the crib filter, multiple entries are returned
    and the caller is expected to disambiguate via attacker-realistic
    cross-validation (e.g. COBS-decode validity on a second ciphertext).
    An empty list indicates an error in K_observable or start_pixel.
    """
    K_base = K_observable & OBSERVABLE_MASK
    max_pixels_in_crib = len(known_prefix) // 7
    if max_pixels_in_crib < 2:
        raise ValueError(
            "need at least 2 crib pixels for reliable (K_data, K_noise_bits_0_2) recovery"
        )

    survivors: List[Tuple[int, int, List[Tuple[int, int]]]] = []

    for unknown_8 in range(256):
        low_3 = unknown_8 & 0x07
        high_5 = (unknown_8 >> 3) & 0x1F
        K_trial = K_base | low_3 | (high_5 << 59)

        for k_noise_bits_0_2 in range(8):
            observed_noise_positions: List[Tuple[int, int]] = []
            all_pixels_matched = True

            for p_idx in range(max_pixels_in_crib):
                cp = (start_pixel + p_idx) % total_pixels
                const_p = int(const_all[p_idx])
                h_lo = (K_trial ^ const_p) & MASK64
                rotation = h_lo % 7
                noise_pos = k_noise_bits_0_2 ^ (const_p & 7)
                expected = known_prefix[p_idx * 7: p_idx * 7 + 7]
                cb = body[cp * 8: cp * 8 + 8]

                got = decrypt_pixel(
                    K_trial, cb, p_idx, const_all, noise_pos, rotation
                )
                if got != expected:
                    all_pixels_matched = False
                    break
                observed_noise_positions.append((p_idx, noise_pos))

            if all_pixels_matched:
                survivors.append((K_trial, k_noise_bits_0_2, observed_noise_positions))

    # Return every survivor. Normal-case single survivor; when structural
    # mod-7 aliasing on the 8 unobservable K_data bits lets a shadow pair
    # pass the crib filter (see Phase 2f architectural finding 3), multiple
    # survivors appear — downstream decrypt_full disambiguates them via
    # COBS-validity cross-check on the target ciphertext.
    return survivors


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cell-dir", type=Path, required=True)
    ap.add_argument("--hash-module", type=str, default="crc128",
                    help="Hash primitive mirror (default: crc128).")
    ap.add_argument("--ciphertext", type=Path, default=None)
    ap.add_argument("--crib-prefix-hex", type=str,
                    default=JSON_PREFIX_21.hex(),
                    help="Known plaintext prefix in hex (COBS-wrapped JSON "
                         "schema + first-field name prefix; default = 21 "
                         "bytes / 3 pixels — minimum safe crib for Stage 2 "
                         "enumeration. Stage 2 returns every pair that survives; "
                         "downstream decrypt_full disambiguates via COBS "
                         "validity, so uniqueness is not required here.)")
    ap.add_argument("--verify-pixels", type=int, default=3,
                    help="How many pixels to use for Stage 1 K_data verification "
                         "(default 3 matches default crib length).")
    ap.add_argument("--brute-force-shifts", action="store_true",
                    help="Scan all shifts (disables default bias-probe plateau).")
    ap.add_argument("--probe-size", type=int, default=16000,
                    help="Bias-probe observation count (default path only).")
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
    K_data_expected = (hmod.compute_expected_K(meta, nonce)
                       if hasattr(hmod, "compute_expected_K") else 0)
    K_noise_expected = 0
    if hasattr(hmod, "compute_expected_K_noise"):
        K_noise_expected = hmod.compute_expected_K_noise(meta, nonce)

    known_prefix = bytes.fromhex(args.crib_prefix_hex)

    print(f"{'=' * 72}")
    print(f"Phase 2f — Crib KPA full K recovery (K_data + K_noise_bits_0_2)")
    print(f"{'=' * 72}")
    print(f"Cell:              {args.cell_dir}")
    print(f"Ciphertext:        {ct_path.name} ({ct_path.stat().st_size} bytes)")
    print(f"total_pixels:      {total_pixels}")
    print(f"Known prefix:      {known_prefix!r}  ({len(known_prefix)} bytes)")
    print(f"Verify pixels:     {args.verify_pixels}")
    print(f"Brute-force shifts: {args.brute_force_shifts}")
    print(f"Expected K_data:   0x{K_data_expected:016x}  [audit only]")
    if K_noise_expected:
        print(f"Expected K_noise & 7: 0x{K_noise_expected & 7}  [audit only]")
    print()

    t0 = time.time()
    print(f"Precomputing const(p) for {total_pixels} pixels ...")
    const_all = precompute_const_all(total_pixels, nonce)
    print(f"  done in {time.time() - t0:.1f}s")

    # Stage 1 — find K_data_observable + winning shift via existing filter.
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
    K_observable: Optional[int] = None
    winning_shift: Optional[int] = None
    for i, s in enumerate(shifts_to_try):
        K = try_shift_algebraic_vectorized(
            s, body, total_pixels, const_all, known_prefix, args.verify_pixels,
        )
        if K is not None:
            K_observable = K
            winning_shift = s
            print(f"  [shift {s}] ★ MATCH  K_observable=0x{K:016x}")
            break
        if (i + 1) % 500 == 0 or i == len(shifts_to_try) - 1:
            print(f"  [{i+1}/{len(shifts_to_try)}] scanned "
                  f"(elapsed {time.time() - t0:.1f}s)")
    print(f"Stage 1 scan time: {time.time() - t0:.1f}s")

    if K_observable is None or winning_shift is None:
        print("\nNO MATCH — crib did not anchor any shift with any K_data candidate")
        return 2

    # Stage 2 — disambiguate K_data's 8 unobservable bits AND extract
    # K_noise_bits_0_2 in one pass via cross-pixel consistency. Returns
    # every pair that survives the crib filter; shadow pairs arising
    # from mod-7 aliasing on unobservable bits 59..63 and 0..2 require
    # downstream cross-validation (COBS-decode on a second ciphertext).
    start_pixel = (-winning_shift) % total_pixels
    t0 = time.time()
    survivors = recover_k_full(
        K_observable, body, total_pixels, const_all, known_prefix, start_pixel,
    )
    print(f"Stage 2 (full K recovery): {time.time() - t0:.2f}s")

    print(f"\n{'=' * 72}")
    print(f"RESULT")
    print(f"{'=' * 72}")

    if not survivors:
        print(f"  K_data_observable: 0x{K_observable:016x}  (partial recovery)")
        print(f"  K_noise_bits_0_2: NOT RECOVERED (no K_data variant yielded")
        print(f"                    consistent K_noise across crib pixels —")
        print(f"                    crib may be too short or hash module mismatch)")
        return 2

    print(f"  Winning shift:      {winning_shift}")
    print(f"  startPixel:         {start_pixel}")
    print(f"  K_data_observable:  0x{K_observable:016x}  (bits 3..58)")
    print(f"  Survivor count:     {len(survivors)}")
    print()
    for idx, (K_data_full, K_noise_bits_0_2, per_pixel_np) in enumerate(survivors):
        print(f"  Candidate {idx}:")
        print(f"    K_data (64-bit):    0x{K_data_full:016x}")
        print(f"    K_noise_bits_0_2:   0x{K_noise_bits_0_2:x}  ({K_noise_bits_0_2:03b})")

    # Audit — compare each candidate to lab ground truth. Printout-only;
    # the attacker-side selection happens downstream via COBS cross-check.
    print()
    print(f"  --- Audit comparison with lab ground truth (cell.meta.json) ---")
    print(f"  Expected K_data:        0x{K_data_expected:016x}")
    any_match_data = False
    for idx, (K_data_full, K_noise_bits_0_2, _) in enumerate(survivors):
        match_data = K_data_full == K_data_expected
        any_match_data = any_match_data or match_data
        xor_diff = (K_data_full ^ K_data_expected) & MASK64
        popcount = bin(xor_diff).count("1")
        print(f"    Candidate {idx}: K_data=0x{K_data_full:016x}  "
              f"{'✓ matches GT' if match_data else f'✗ Hamming={popcount}/64'}")
    if K_noise_expected:
        expected_bits_0_2 = K_noise_expected & 7
        print(f"  Expected K_noise & 7:   0x{expected_bits_0_2}")
        for idx, (_, K_noise_bits_0_2, _) in enumerate(survivors):
            match_noise = K_noise_bits_0_2 == expected_bits_0_2
            print(f"    Candidate {idx}: K_noise_bits_0_2=0x{K_noise_bits_0_2}  "
                  f"{'✓ matches GT' if match_noise else '✗ MISMATCH'}")
    else:
        print(f"  K_noise ground truth:   not available from this hash module")

    # Machine-readable output for piping into decrypt_full.
    print()
    print(f"{'=' * 72}")
    print(f"PIPE INTO crib_crc128_decrypt_full.py:")
    print(f"{'=' * 72}")
    if len(survivors) == 1:
        K_data_full, K_noise_bits_0_2, _ = survivors[0]
        print(f"  --k-data 0x{K_data_full:016x}")
        print(f"  --k-noise-bits-0-2 {K_noise_bits_0_2}")
        print(f"  (Single survivor — safe to use single-candidate flags.)")
    else:
        print(f"  {len(survivors)} candidates survived — use --candidates-json:")
        print(f"  --candidates-json {(args.cell_dir / 'recovered_k_full.json').resolve()}")
        print(f"  (decrypt_full will try each in turn and accept the one whose")
        print(f"   full-ciphertext decrypt produces a valid COBS stream.)")

    # JSON sidecar for programmatic consumption (all survivors).
    sidecar = {
        "k_data_observable_hex": f"0x{K_observable:016x}",
        "winning_shift": winning_shift,
        "start_pixel": start_pixel,
        "candidates": [
            {
                "k_data_hex": f"0x{K_data_full:016x}",
                "k_noise_bits_0_2": K_noise_bits_0_2,
                "per_pixel_noise_pos": [
                    {"pixel": p, "noise_pos": np_obs} for p, np_obs in per_pixel_np
                ],
            }
            for (K_data_full, K_noise_bits_0_2, per_pixel_np) in survivors
        ],
        "lab_audit": {
            "k_data_expected_hex": f"0x{K_data_expected:016x}",
            "any_candidate_matches_k_data": any_match_data,
            "k_noise_bits_0_2_expected": (K_noise_expected & 7) if K_noise_expected else None,
        },
    }
    sidecar_path = args.cell_dir / "recovered_k_full.json"
    sidecar_path.write_text(json.dumps(sidecar, indent=2))
    print(f"\nWrote machine-readable sidecar: {sidecar_path}")

    return 0 if any_match_data else 1


if __name__ == "__main__":
    sys.exit(main())
