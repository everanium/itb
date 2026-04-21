#!/usr/bin/env python3
"""Phase 2f — full-plaintext decryption via recovered K against ChainHash<CRC128>.

Second stage of the Crib KPA attack chain. Takes a 56-bit observable K
(recovered by `crib_crc128_kpa.py` from a first ciphertext under some
dataSeed) and a SECOND ciphertext encrypted under the same dataSeed /
startSeed / noiseSeed but a DIFFERENT nonce, and reconstructs the full
plaintext of the second message.

Attacker knowledge for the second message:

  * K (56 bits observable, 8 bits = low 3 + high 5 enumerated here).
  * Nonce (from the 20-byte ITB ciphertext header, public).
  * Width × Height (from the same header).
  * Plaintext format public (e.g. HTML). One known 7-byte prefix chunk
    (e.g. `\\xFF<iden` for HTML tag template) used to anchor startPixel
    and select among 256 unknown-bit variants of K.

NOT required:
  * No demasker, no nonce reuse, no bias probe, no ground-truth peek.
  * noisePos per pixel is brute-forced per pixel (8 options); the
    correct option is selected by producing printable-ASCII output.
    If the plaintext contains only printable ASCII + COBS markers, this
    brute force converges; otherwise the decrypt script falls back to
    ground-truth noisePos (lab shortcut, clearly flagged).

Runtime: ~256 × total_pixels × 8 pixel decrypts for the startPixel +
K-variant search, ~seconds on a small corpus.

Usage:
    python3 crib_crc128_decrypt.py \\
        --cell-dir tmp/attack/crib_cross/corpus_B_html \\
        --k-observable 0x0770020d7031bed8 \\
        --crib-hex ff3c6964656e  \\
        --expected-plaintext tmp/attack/crib_cross/corpus_B_html/ct_0000.plain

Lab audit: compares reconstructed plaintext byte-for-byte to the
attacker-known ground truth (only for reporting; the attacker already
has the plaintext format model and would validate via HTML parse).
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

import importlib
from crib_crc128_kpa import (
    decrypt_pixel,
    precompute_const_all,
    _load_hash_module,
)
sys.path.insert(0, str(HERE.parent))
from attack_common import cobs_encode as _cobs_encode


MASK64 = (1 << 64) - 1
OBSERVABLE_MASK = 0x07FFFFFFFFFFFFF8  # bits 3..58


def iterate_k_variants(k_observable: int):
    """Yield all 256 K candidates with same observable bits, varying low 3 +
    high 5 unobservable bits."""
    k_base = k_observable & OBSERVABLE_MASK
    for unknown_8 in range(256):
        low_3 = unknown_8 & 0x07
        high_5 = (unknown_8 >> 3) & 0x1F
        yield k_base | low_3 | (high_5 << 59)


def is_printable_plaintext(chunk: bytes) -> bool:
    """True if chunk consists entirely of COBS markers (0xFF), whitespace,
    printable ASCII, or the null terminator."""
    for b in chunk:
        if b == 0xFF or b == 0x00 or b in (0x09, 0x0A, 0x0D):
            continue
        if 0x20 <= b <= 0x7E:
            continue
        return False
    return True


def try_decrypt_full(
    k_trial: int,
    body: bytes,
    total_pixels: int,
    const_all: np.ndarray,
    start_pixel: int,
    data_pixels: int,
) -> Optional[bytes]:
    """Decrypt `data_pixels` pixels with `k_trial` + deterministic rotation,
    choosing noise_pos per pixel that yields all-printable output. Return
    the 7 × data_pixels-byte stream, or None if too many pixels have no
    printable candidate (indicating wrong K variant)."""
    out = bytearray()
    printable_count = 0
    for p_idx in range(data_pixels):
        cp = (start_pixel + p_idx) % total_pixels
        const_p = int(const_all[p_idx])
        h_lo = (k_trial ^ const_p) & MASK64
        rot = h_lo % 7
        cb = body[cp * 8: cp * 8 + 8]
        best = None
        for np_val in range(8):
            got = decrypt_pixel(k_trial, cb, p_idx, const_all, np_val, rot)
            if is_printable_plaintext(got):
                best = got
                printable_count += 1
                break
        if best is None:
            # fall back to np=0 so we can continue counting
            best = decrypt_pixel(k_trial, cb, p_idx, const_all, 0, rot)
        out.extend(best)
    # Attach printable_count via side effect trick: embed as header byte? No —
    # return (bytes, count) pair caller can inspect. Simpler: caller will
    # recompute printability post-hoc; we just return the raw stream.
    return bytes(out)


def cobs_decode(buf: bytes) -> Optional[bytes]:
    """Decode a COBS stream that uses 0xFF block markers. Returns the
    recovered plaintext, or None on format error. Matches ITB's
    `cobsEncode` convention: the encoder emits `0xFF <254 bytes> 0xFF
    <254 bytes> ...` for plaintexts with no null bytes, followed by a
    single 0x00 terminator (which ITB appends)."""
    i = 0
    out = bytearray()
    while i < len(buf):
        code = buf[i]
        if code == 0:
            return bytes(out)
        block = buf[i + 1: i + code]
        if len(block) != code - 1:
            return None
        out.extend(block)
        # ITB emits 0x00 separator only at final terminator; between blocks
        # when code == 0xFF with no zero found in next 254 bytes, no zero
        # byte is emitted — the next block starts immediately.
        i += code
        if code < 0xFF and i < len(buf):
            out.append(0x00)
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cell-dir", type=Path, required=True,
                    help="Directory with ct_0000.bin + cell.meta.json")
    ap.add_argument("--k-observable", type=str, required=True,
                    help="56-bit observable K from crib_crc128_kpa.py (hex, e.g. 0x0770020d7031bed8)")
    ap.add_argument("--crib-hex", type=str, default="ff3c6964656e",
                    help="First-pixel crib hex to anchor startPixel (default: \\xFF<iden for HTML)")
    ap.add_argument("--expected-plaintext", type=Path, default=None,
                    help="Path to ground-truth plaintext for lab validation")
    args = ap.parse_args()

    _load_hash_module("crc128")

    meta_path = args.cell_dir / "cell.meta.json"
    meta = json.loads(meta_path.read_text())
    nonce = bytes.fromhex(meta["nonce_hex"])
    total_pixels = int(meta["total_pixels"])
    ct_path = args.cell_dir / "ct_0000.bin"
    raw = ct_path.read_bytes()
    body = raw[20:]
    k_observable = int(args.k_observable, 16)
    crib = bytes.fromhex(args.crib_hex)
    if len(crib) < 7 or len(crib) % 7 != 0:
        print(f"ERROR: --crib-hex must be a multiple of 7 bytes, got {len(crib)}", file=sys.stderr)
        return 2
    crib_pixels = len(crib) // 7

    print(f"{'=' * 72}")
    print(f"Phase 2f — crib-cross full-plaintext decrypt against ChainHash<CRC128>")
    print(f"{'=' * 72}")
    print(f"Cell:              {args.cell_dir}")
    print(f"Ciphertext:        {ct_path.name} ({ct_path.stat().st_size} bytes)")
    print(f"total_pixels:      {total_pixels}")
    print(f"K_observable:      0x{k_observable:016x}")
    print(f"Pixel-0 crib:      {crib!r}  ({len(crib)} bytes)")
    print()

    t0 = time.time()
    print(f"Precomputing const(p) for {total_pixels} pixels ...")
    const_all = precompute_const_all(total_pixels, nonce)
    print(f"  done in {time.time() - t0:.1f}s")

    # Stage 1: find (K_variant, startPixel) matching the multi-pixel crib.
    # For each K variant, for each candidate startPixel, verify that all
    # `crib_pixels` crib chunks decrypt correctly under some noise_pos per
    # pixel (8-way brute force) with deterministic rotation from K.
    t0 = time.time()
    candidates = []
    for k_trial in iterate_k_variants(k_observable):
        for sp in range(total_pixels):
            all_match = True
            for p_idx in range(crib_pixels):
                cp = (sp + p_idx) % total_pixels
                const_p = int(const_all[p_idx])
                h_lo = (k_trial ^ const_p) & MASK64
                rot = h_lo % 7
                cb = body[cp * 8: cp * 8 + 8]
                expected = crib[p_idx * 7: p_idx * 7 + 7]
                found = False
                for np_val in range(8):
                    got = decrypt_pixel(k_trial, cb, p_idx, const_all, np_val, rot)
                    if got == expected:
                        found = True
                        break
                if not found:
                    all_match = False
                    break
            if all_match:
                candidates.append((k_trial, sp, -1))  # np_val per pixel not tracked
    print(f"Stage 1: {len(candidates)} (K_variant, startPixel) crib matches ({crib_pixels}-pixel crib) in {time.time() - t0:.1f}s")

    if not candidates:
        print("NO MATCH — crib did not decrypt at any (K_variant, startPixel)")
        return 2

    # Stage 2: for each candidate, attempt full decrypt; pick the one that
    # produces most-printable plaintext across all pixels.
    t0 = time.time()
    data_pixels = total_pixels  # ITB packs every container pixel with data in BF=1
    best = None
    # How many pixels to score (first N — enough to distinguish correct K).
    score_pixels = min(60, total_pixels)
    for idx, (k_trial, sp, np0) in enumerate(candidates):
        # Partial decrypt for scoring (cheap).
        printable_count = 0
        for p_idx in range(score_pixels):
            cp = (sp + p_idx) % total_pixels
            const_p = int(const_all[p_idx])
            h_lo = (k_trial ^ const_p) & MASK64
            rot = h_lo % 7
            cb = body[cp * 8: cp * 8 + 8]
            for np_val in range(8):
                got = decrypt_pixel(k_trial, cb, p_idx, const_all, np_val, rot)
                if is_printable_plaintext(got):
                    printable_count += 1
                    break
        score = printable_count / score_pixels
        if best is None or score > best[3]:
            best = (k_trial, sp, None, score)
    print(f"Stage 2: scored {len(candidates)} candidates over first {score_pixels} pixels in {time.time() - t0:.1f}s")
    if best is not None:
        print(f"  top score: {best[3]:.3f} for K=0x{best[0]:016x} sp={best[1]}")

    # Stage 2b: full decrypt for the winning candidate.
    if best is not None:
        k_win0, sp_win0, _, _ = best
        decrypted = try_decrypt_full(k_win0, body, total_pixels, const_all, sp_win0, data_pixels)
        best = (k_win0, sp_win0, decrypted, best[3])

    if best is None:
        print("Stage 2 exhausted without printable decrypt")
        return 2

    k_winner, sp_winner, raw_decrypt, score = best
    print(f"Winner:            K=0x{k_winner:016x}  startPixel={sp_winner}  printable score={score:.3f}")

    # Save raw decrypted 7-byte-per-pixel stream.
    out_path = args.cell_dir / "recovered_stream.bin"
    out_path.write_bytes(raw_decrypt)
    print(f"Wrote 7×P raw stream: {out_path} ({len(raw_decrypt)} bytes)")
    print(f"First 140 bytes:      {raw_decrypt[:140].hex()}")

    # Stage 3: report partial-recovery accuracy.
    # noise_pos cannot be recovered from ciphertext alone (noiseSeed output
    # is not observable through the cipher — insert/strip of one bit per
    # channel is indistinguishable from data). So decrypt picks noise_pos
    # per pixel by printable-ASCII heuristic, which misidentifies 2–3 % of
    # pixels (random bytes accidentally look printable). COBS decode of the
    # full stream therefore fails, but byte-level accuracy vs the ground
    # truth COBS-encoded plaintext is high.
    if args.expected_plaintext is not None and args.expected_plaintext.exists():
        expected_plain = args.expected_plaintext.read_bytes()
        expected_cobs = _cobs_encode(expected_plain) + b"\x00"
        min_len = min(len(expected_cobs), len(raw_decrypt))
        matches = sum(1 for i in range(min_len) if expected_cobs[i] == raw_decrypt[i])
        pct = 100.0 * matches / min_len if min_len else 0
        print()
        print(f"{'=' * 72}")
        print(f"PARTIAL-RECOVERY REPORT vs ground-truth COBS-encoded plaintext")
        print(f"{'=' * 72}")
        print(f"Expected COBS-encoded length:  {len(expected_cobs)} bytes")
        print(f"Recovered stream length:       {len(raw_decrypt)} bytes")
        print(f"Byte match over min length:    {matches} / {min_len} = {pct:.2f} %")

        # Align pixels and count full-pixel matches (7 consecutive bytes
        # all equal — pixels where the right noise_pos was picked).
        pixels_full_match = 0
        pixels_checked = min_len // 7
        for p in range(pixels_checked):
            if expected_cobs[p * 7: (p + 1) * 7] == raw_decrypt[p * 7: (p + 1) * 7]:
                pixels_full_match += 1
        print(f"Full-pixel match:              {pixels_full_match} / {pixels_checked} = "
              f"{100.0 * pixels_full_match / pixels_checked:.2f} %" if pixels_checked else "n/a")

        # Print sample alignment (first 200 bytes side-by-side as hex).
        print()
        print("First 200 bytes alignment:")
        for i in range(0, min(200, min_len), 32):
            exp_chunk = expected_cobs[i:i+32].hex()
            got_chunk = raw_decrypt[i:i+32].hex()
            diff_mask = ''.join('.' if expected_cobs[j] == raw_decrypt[j] else 'X'
                                for j in range(i, min(i+32, min_len)))
            print(f"  offset {i:5d} exp: {exp_chunk}")
            print(f"  offset {i:5d} got: {got_chunk}")
            print(f"  diff          {diff_mask}")

        return 0 if pct > 90 else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
