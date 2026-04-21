#!/usr/bin/env python3
"""Phase 2f — Crib KPA full-plaintext decrypt via (K_data + K_noise_bits_0_2).

Second stage of the Crib KPA attack chain. Consumes the output of
`crib_crc128_kpa_full.py` (K_data 64-bit + K_noise_bits_0_2 3-bit)
recovered from a first ciphertext under some dataSeed / noiseSeed /
startSeed triple, and decrypts a SECOND ciphertext encrypted under the
same seeds (any nonce, any plaintext format) to **100 % byte accuracy**.

The script uses the 3-bit `K_noise_bits_0_2` to compute the EXACT
noise_pos per pixel:

    noise_pos(p, nonce) = K_noise_bits_0_2 ⊕ (c_public(p, nonce) & 7)

No 8-way brute force on noise_pos, no printable-ASCII heuristic. Every
pixel decrypted with the exact rotation (from K_data % 7) and exact
noise_pos (from K_noise_bits_0_2). Works on any plaintext class:
printable ASCII, binary (ZIP / PDF / MP4 / compressed streams), random
bytes — the 60-82 % / 12.5 % partial-recovery bound of the base
decrypt script is lifted to 100 %.

Attacker knowledge needed:
  * K_data (64-bit, from crib_crc128_kpa_full.py)
  * K_noise_bits_0_2 (3-bit, from crib_crc128_kpa_full.py)
  * One short known-plaintext crib (7-byte minimum) to anchor startPixel
    against the target ciphertext
  * Nonce + W × H from the 20-byte ITB ciphertext header (public)

NOT required:
  * No demasker, no nonce reuse, no bias probe
  * No printable-ASCII filter
  * No ground-truth peek (only for optional post-hoc validation reporting)

Usage:
    python3 crib_crc128_decrypt_full.py \\
        --cell-dir tmp/attack/crib_cross/corpus_B_html \\
        --k-data 0xf4f2320a561fd405 \\
        --k-noise-bits-0-2 7 \\
        --crib-hex ff3c6964656e7469666965722d6f662d7265636f72642d696e2d7379 \\
        --expected-plaintext tmp/attack/crib_cross/corpus_B_html/ct_0000.plain

Lab audit: compares reconstructed plaintext byte-for-byte to the ground
truth file (attacker would validate via format parse — HTML tag balance,
JSON structure, ZIP signature, etc.).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from crib_crc128_kpa import (
    MASK64,
    _load_hash_module,
    precompute_const_all,
    decrypt_pixel,
)
sys.path.insert(0, str(HERE.parent))
from attack_common import cobs_encode as _cobs_encode


def cobs_decode(buf: bytes) -> Optional[tuple[bytes, int]]:
    """Decode an ITB-style COBS stream (0xFF block markers, terminated by a
    single 0x00). Returns (plaintext, terminator_position) on success, or
    None on format error. `terminator_position` is the index of the 0x00
    that terminated the chain — the decrypted stream length minus this
    number is the trailing random-fill region ITB appends after COBS
    framing.

    A correctly-recovered plaintext byte stream must COBS-decode cleanly
    AND the terminator position must sit near the end of the decrypted
    stream (ITB at BF=1 pads to the pixel boundary, so random fill is
    small — typically < 7 bytes, never more than the pixel width).
    A wrong K_data pair decrypt corrupts ~50 % of bytes past the short
    crib anchor, so either (a) the block-length chain fails (None), or
    (b) a stray 0x00 in garbage terminates the chain early at a position
    well before the true terminator — the caller rejects both cases."""
    i = 0
    out = bytearray()
    while i < len(buf):
        code = buf[i]
        if code == 0:
            return bytes(out), i
        block = buf[i + 1: i + code]
        if len(block) != code - 1:
            return None
        out.extend(block)
        i += code
        # Inter-block 0x00 represents a literal 0x00 in the source plaintext.
        # Suppress it immediately before the terminator: the trailing empty
        # block (code=0x01 with no bytes) emitted by cobs_encode after a
        # completed 0xFF run is a framing marker, not a source-byte position.
        if code < 0xFF and i < len(buf) and buf[i] != 0:
            out.append(0x00)
    return None  # no terminator found


def find_start_pixel(
    k_data: int,
    k_noise_bits_0_2: int,
    body: bytes,
    total_pixels: int,
    const_all: np.ndarray,
    crib: bytes,
) -> Optional[int]:
    """Find the startPixel in target ciphertext by anchoring to the crib
    prefix, decrypting each candidate shift with EXACT (rotation, noise_pos)
    from (K_data, K_noise_bits_0_2), and picking the shift whose first few
    pixels match the crib."""
    crib_pixels = len(crib) // 7
    for sp in range(total_pixels):
        all_match = True
        for p_idx in range(crib_pixels):
            cp = (sp + p_idx) % total_pixels
            const_p = int(const_all[p_idx])
            h_lo = (k_data ^ const_p) & MASK64
            rotation = h_lo % 7
            noise_pos = k_noise_bits_0_2 ^ (const_p & 7)
            expected = crib[p_idx * 7: p_idx * 7 + 7]
            cb = body[cp * 8: cp * 8 + 8]
            got = decrypt_pixel(k_data, cb, p_idx, const_all, noise_pos, rotation)
            if got != expected:
                all_match = False
                break
        if all_match:
            return sp
    return None


def decrypt_full(
    k_data: int,
    k_noise_bits_0_2: int,
    body: bytes,
    total_pixels: int,
    const_all: np.ndarray,
    start_pixel: int,
    data_pixels: int,
) -> bytes:
    """Decrypt `data_pixels` pixels starting at `start_pixel` with EXACT
    rotation (from K_data) and EXACT noise_pos (from K_noise_bits_0_2).
    No brute force, no printable-ASCII filter — every pixel recovered
    deterministically."""
    out = bytearray()
    for p_idx in range(data_pixels):
        cp = (start_pixel + p_idx) % total_pixels
        const_p = int(const_all[p_idx])
        h_lo = (k_data ^ const_p) & MASK64
        rotation = h_lo % 7
        noise_pos = k_noise_bits_0_2 ^ (const_p & 7)
        cb = body[cp * 8: cp * 8 + 8]
        chunk = decrypt_pixel(k_data, cb, p_idx, const_all, noise_pos, rotation)
        out.extend(chunk)
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cell-dir", type=Path, required=True,
                    help="Directory with ct_0000.bin + cell.meta.json")
    ap.add_argument("--k-data", type=str, default=None,
                    help="Full 64-bit K_data from crib_crc128_kpa_full.py (hex). "
                         "Use together with --k-noise-bits-0-2 for single-"
                         "candidate decrypt. Mutually exclusive with "
                         "--candidates-json.")
    ap.add_argument("--k-noise-bits-0-2", type=int, default=None,
                    help="3-bit K_noise_bits_0_2 from crib_crc128_kpa_full.py "
                         "(integer 0..7). Required if --k-data is set.")
    ap.add_argument("--candidates-json", type=Path, default=None,
                    help="Path to the `recovered_k_full.json` sidecar written "
                         "by crib_crc128_kpa_full.py. When multiple survivors "
                         "exist, each is tried in turn and the one producing a "
                         "valid COBS-decoded plaintext is accepted.")
    ap.add_argument("--crib-hex", type=str,
                    default="ff3c6964656e7469666965722d6f662d7265636f72",
                    help="Crib (hex) to anchor startPixel on target ciphertext "
                         "(default: 21 bytes / 3 pixels of HTML schema — "
                         "\\xFF<identifier-of-recor; 7-byte minimum, multiple "
                         "of 7). Short cribs may anchor multiple startPixels "
                         "per candidate; the COBS-decode step rejects non-true "
                         "candidates regardless.")
    ap.add_argument("--expected-plaintext", type=Path, default=None,
                    help="Path to ground-truth plaintext for lab validation "
                         "(optional; attacker doesn't have this; used only "
                         "for the terminal-stage byte/pixel accuracy report "
                         "and NOT for any candidate-selection decision).")
    args = ap.parse_args()

    # Resolve candidate list from --candidates-json OR (--k-data + --k-noise-bits-0-2).
    candidates: list[tuple[int, int]] = []
    if args.candidates_json is not None:
        if args.k_data is not None or args.k_noise_bits_0_2 is not None:
            print("ERROR: --candidates-json is mutually exclusive with "
                  "--k-data/--k-noise-bits-0-2", file=sys.stderr)
            return 2
        sidecar = json.loads(args.candidates_json.read_text())
        if "candidates" not in sidecar or not sidecar["candidates"]:
            print(f"ERROR: {args.candidates_json} has no 'candidates' array",
                  file=sys.stderr)
            return 2
        for entry in sidecar["candidates"]:
            k_data = int(entry["k_data_hex"], 16)
            k_nb = int(entry["k_noise_bits_0_2"])
            candidates.append((k_data, k_nb))
    else:
        if args.k_data is None or args.k_noise_bits_0_2 is None:
            print("ERROR: supply --k-data AND --k-noise-bits-0-2, OR "
                  "--candidates-json", file=sys.stderr)
            return 2
        if not (0 <= args.k_noise_bits_0_2 <= 7):
            print(f"ERROR: --k-noise-bits-0-2 must be 0..7, got "
                  f"{args.k_noise_bits_0_2}", file=sys.stderr)
            return 2
        candidates.append((int(args.k_data, 16), args.k_noise_bits_0_2))

    _load_hash_module("crc128")

    meta = json.loads((args.cell_dir / "cell.meta.json").read_text())
    nonce = bytes.fromhex(meta["nonce_hex"])
    total_pixels = int(meta["total_pixels"])
    ct_path = args.cell_dir / "ct_0000.bin"
    raw = ct_path.read_bytes()
    body = raw[20:]
    crib = bytes.fromhex(args.crib_hex)
    if len(crib) < 7 or len(crib) % 7 != 0:
        print(f"ERROR: --crib-hex must be a multiple of 7 bytes (≥7), got {len(crib)}",
              file=sys.stderr)
        return 2

    print(f"{'=' * 72}")
    print(f"Phase 2f — full-plaintext decrypt via (K_data + K_noise_bits_0_2)")
    print(f"{'=' * 72}")
    print(f"Cell:               {args.cell_dir}")
    print(f"Ciphertext:         {ct_path.name} ({ct_path.stat().st_size} bytes)")
    print(f"total_pixels:       {total_pixels}")
    print(f"Candidates to try:  {len(candidates)}")
    for idx, (k_data, k_nb) in enumerate(candidates):
        print(f"  [{idx}] K_data=0x{k_data:016x}  K_noise_bits_0_2={k_nb}")
    print(f"Crib:               {crib!r}  ({len(crib)} bytes = {len(crib)//7} pixels)")
    print()

    t0 = time.time()
    print(f"Precomputing const(p) for {total_pixels} pixels ...")
    const_all = precompute_const_all(total_pixels, nonce)
    print(f"  done in {time.time() - t0:.1f}s")

    # Per-candidate: anchor via short HTML crib → full decrypt → COBS decode.
    # A wrong K_data survivor from the KPA filter carries the same channelXOR
    # bits 3..58 as the true K_data but potentially a wrong rotation pattern;
    # the short crib may still anchor (shadow survivors match rotation on
    # a fraction of pixels), and on longer corpora some shadow decrypts can
    # complete a COBS block-length chain by chance. To disambiguate, iterate
    # every candidate through the full decrypt and COBS-decode, then select
    # the one whose terminator position sits closest to the end of the
    # decrypted stream — the true K_data always wins because its entire
    # COBS-encoded plaintext is consistent with the stream while a shadow's
    # ~50 % corrupted tail pushes any valid terminator earlier. Both metrics
    # (COBS block-length chain validity and terminator position) are
    # computable by the attacker from public ITB spec alone.
    data_pixels = total_pixels  # BF=1: every container pixel carries data
    results: list[dict] = []
    for idx, (k_data, k_nb) in enumerate(candidates):
        print()
        print(f"--- Trying candidate [{idx}]: K_data=0x{k_data:016x}  "
              f"K_noise_bits_0_2={k_nb} ---")

        # Stage 1 — anchor startPixel via short crib.
        t0 = time.time()
        start_pixel = find_start_pixel(
            k_data, k_nb, body, total_pixels, const_all, crib,
        )
        elapsed = time.time() - t0
        if start_pixel is None:
            print(f"  crib did NOT anchor any startPixel ({elapsed:.2f}s) — "
                  f"candidate rejected.")
            continue
        print(f"  crib anchored at startPixel={start_pixel} ({elapsed:.2f}s)")

        # Stage 2 — full-ciphertext decrypt.
        t0 = time.time()
        decrypted = decrypt_full(
            k_data, k_nb, body, total_pixels, const_all,
            start_pixel, data_pixels,
        )
        print(f"  full decrypt: {len(decrypted)} bytes ({time.time() - t0:.2f}s)")

        # Stage 3 — COBS-decode validity. The true K_data always produces a
        # cleanly-decodable stream. Some wrong K_data pairs also complete a
        # COBS chain by chance (block-length bytes happen to align with the
        # corrupted decrypt), but their terminator position sits strictly
        # below the true one. Collect every COBS-valid candidate; final
        # selection is the one with the highest terminator ratio.
        cobs_result = cobs_decode(decrypted)
        if cobs_result is None:
            print(f"  COBS decode FAILED (block-length chain broken) — "
                  f"candidate rejected.")
            continue
        cobs_plain, term_pos = cobs_result
        term_ratio = term_pos / len(decrypted) if decrypted else 0
        print(f"  COBS decode OK — terminator at byte {term_pos}/"
              f"{len(decrypted)} ({term_ratio * 100:.2f} %), "
              f"{len(cobs_plain)} plaintext bytes recovered.")
        results.append({
            "idx": idx,
            "k_data": k_data,
            "k_nb": k_nb,
            "start_pixel": start_pixel,
            "decrypted": decrypted,
            "cobs_plain": cobs_plain,
            "term_pos": term_pos,
            "term_ratio": term_ratio,
        })

    # Select the COBS-valid candidate with the highest terminator ratio.
    # Ties (practically never occur) are broken by earliest candidate index.
    if not results:
        accepted_idx = None
        accepted_decrypt = None
        accepted_cobs_plaintext = None
        accepted_start_pixel = None
    else:
        results.sort(key=lambda r: (-r["term_ratio"], r["idx"]))
        best = results[0]
        accepted_idx = best["idx"]
        accepted_decrypt = best["decrypted"]
        accepted_cobs_plaintext = best["cobs_plain"]
        accepted_start_pixel = best["start_pixel"]
        print()
        print(f"COBS-valid candidates ranked by terminator position:")
        for r in results:
            marker = "  ← SELECTED" if r["idx"] == accepted_idx else ""
            print(f"  candidate [{r['idx']}]: terminator "
                  f"{r['term_pos']}/{len(r['decrypted'])} "
                  f"({r['term_ratio'] * 100:.2f} %){marker}")

    print()
    print(f"{'=' * 72}")
    print(f"RESULT")
    print(f"{'=' * 72}")
    if accepted_idx is None:
        print(f"✗ No candidate produced a valid COBS-decoded plaintext. Either the")
        print(f"  Stage-2 survivor list is incomplete or the target ciphertext was")
        print(f"  not encrypted under the same (dataSeed, noiseSeed) as corpus A.")
        return 2

    k_data, k_nb = candidates[accepted_idx]
    print(f"✓ Accepted candidate [{accepted_idx}]:")
    print(f"    K_data:            0x{k_data:016x}")
    print(f"    K_noise_bits_0_2:  {k_nb}")
    print(f"    startPixel:        {accepted_start_pixel}")
    print(f"    decrypted stream:  {len(accepted_decrypt)} bytes")
    print(f"    COBS plaintext:    {len(accepted_cobs_plaintext)} bytes")

    # Save artefacts.
    stream_path = args.cell_dir / "recovered_stream_full.bin"
    stream_path.write_bytes(accepted_decrypt)
    plain_path = args.cell_dir / "recovered_plaintext_cobs.bin"
    plain_path.write_bytes(accepted_cobs_plaintext)
    print(f"    wrote: {stream_path}")
    print(f"    wrote: {plain_path}")

    # Terminal-stage lab validation (optional, attacker does not have this).
    # Used only for reporting accuracy — does NOT feed back into any
    # selection logic (that happened via COBS validity above).
    if args.expected_plaintext is not None and args.expected_plaintext.exists():
        expected_plain = args.expected_plaintext.read_bytes()
        expected_cobs = _cobs_encode(expected_plain) + b"\x00"
        min_len = min(len(expected_cobs), len(accepted_decrypt))
        matches = sum(1 for i in range(min_len)
                      if expected_cobs[i] == accepted_decrypt[i])
        pct = 100.0 * matches / min_len if min_len else 0

        print()
        print(f"{'=' * 72}")
        print(f"LAB VALIDATION vs ground-truth COBS-encoded plaintext")
        print(f"{'=' * 72}")
        print(f"Expected COBS-encoded length:  {len(expected_cobs)} bytes")
        print(f"Recovered stream length:       {len(accepted_decrypt)} bytes")
        print(f"Byte match over min length:    {matches} / {min_len} = {pct:.2f} %")

        pixels_full_match = 0
        pixels_checked = min_len // 7
        for p in range(pixels_checked):
            if expected_cobs[p * 7: (p + 1) * 7] == accepted_decrypt[p * 7: (p + 1) * 7]:
                pixels_full_match += 1
        if pixels_checked:
            print(f"Full-pixel match:              {pixels_full_match} / "
                  f"{pixels_checked} = "
                  f"{100.0 * pixels_full_match / pixels_checked:.2f} %")

        # Plaintext match after COBS decode — the end-user-visible metric.
        exp_plain_match = (accepted_cobs_plaintext == expected_plain)
        print(f"COBS-decoded plaintext match:  "
              f"{'✓ EXACT' if exp_plain_match else '✗ DIFFERS'}  "
              f"(expected {len(expected_plain)} B, recovered "
              f"{len(accepted_cobs_plaintext)} B)")

        if not exp_plain_match:
            # Diagnostic: show first mismatch.
            min_p = min(len(expected_plain), len(accepted_cobs_plaintext))
            first = next((i for i in range(min_p)
                          if expected_plain[i] != accepted_cobs_plaintext[i]), None)
            if first is not None:
                lo, hi = max(0, first - 8), min(min_p, first + 24)
                print(f"  First plaintext mismatch at offset {first}:")
                print(f"    expected: {expected_plain[lo:hi].hex()}")
                print(f"    got:      {accepted_cobs_plaintext[lo:hi].hex()}")
        else:
            print(f"✓ FULL PLAINTEXT MATCH — 100 % recovery")

        return 0 if (pct >= 99.99 and exp_plain_match) else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
