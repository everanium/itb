#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 4 — full plaintext decrypt under recovered K (.FNVSTRESS).

Given a recovered dataSeed lo-lane compound state `K_lo` from the Phase 3b
SAT harness and a fresh target ciphertext under the same seeds, this
script brute-forces `startPixel` (~total_pixels candidates) and, per
startPixel candidate, brute-forces `noise_pos` per pixel (8 candidates)
constrained by COBS framing structure of the encoded stream:

  - Byte 0 of the encoded stream MUST be `0xFF` (COBS overhead for the
    first 254-byte run; holds for our structured JSON/HTML plaintext
    which contains no `0x00` bytes).
  - Byte 255, 510, 765, ... MUST also be `0xFF` (subsequent COBS code
    bytes for contiguous non-zero runs).
  - A single `0x00` byte MUST appear as the terminator AFTER the last
    real code + data group. Anything following is attacker-unknown
    CSPRNG fill (`Encrypt128` tail-fills the capacity).
  - `cobs_decode(stream_prefix_before_0x00)` MUST round-trip to a
    valid, non-empty plaintext.

Correct `(sp, noise_pos_0, noise_pos_1, ...)` tuple is the one whose
final decoded stream passes every check; wrong guesses almost always
fail at one of the `0xFF` code positions or the terminator check.

This is the FNV-1a analogue of `crib_crc128_decrypt_full.py`. Attacker-
realistic: only uses public ITB spec (COBS framing, byte→channel map)
plus the recovered `K_lo`. `cell.meta.json` / ground-truth plaintext
read only for the terminal-stage audit line (byte-match %).

Usage:
    python3 decrypt_full_fnv1a.py --target-cell-dir DIR --k-json FILE
                                   [--rounds 4]
                                   [--expected-plaintext ct_0000.plain]
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from fnv_chain_lo_concrete import MASK64, fnv_chain_lo_concrete  # type: ignore
from itb_channel_mirror import (  # type: ignore
    CHANNELS,
    DATA_BITS_PER_CHANNEL,
    DATA_BITS_PER_PIXEL,
    DATA_ROTATION_BITS,
    cobs_decode,
    decode_channel_to_plaintext_bits,
)


def _decode_pixel_56bits(
    container: bytes, linear_pixel: int, noise_pos: int,
    rotation: int, data_hash_lo: int,
) -> int:
    """Return 56 plaintext bits of one pixel packed as one int
    (bit 0..6 = channel 0, bit 7..13 = channel 1, ..., bit 49..55 =
    channel 7)."""
    bits = 0
    for ch in range(CHANNELS):
        ch_byte = container[linear_pixel * CHANNELS + ch]
        channel_xor = (data_hash_lo >> (DATA_ROTATION_BITS + DATA_BITS_PER_CHANNEL * ch)) & 0x7F
        data_bits = decode_channel_to_plaintext_bits(
            ch_byte, noise_pos, rotation, channel_xor
        )
        bits |= data_bits << (ch * DATA_BITS_PER_CHANNEL)
    return bits


def _pixel_bytes(bits_56: int) -> bytes:
    """Extract the 7 stream bytes that one pixel's 56 plaintext bits cover."""
    return bytes((bits_56 >> (i * 8)) & 0xFF for i in range(7))


class _COBSStreamState:
    """Running COBS-decoder state machine used to validate candidate
    pixel decodes during the per-pixel noise_pos beam search.

    For a plaintext that itself contains no 0x00 bytes (the .FNVSTRESS
    JSON/HTML corpora satisfy this), the COBS-encoded stream has a
    single structural signature: byte 0 = 0xFF, every 255-stepped code
    position = 0xFF until the final short tail, every non-code byte is
    non-zero, and exactly one 0x00 terminator marks the boundary with
    the CSPRNG-fill tail. The state machine enforces the non-zero-data
    and implicit-next-code invariants directly; the anchor (byte 0 =
    0xFF) is treated as a hard gate. A byte that violates any invariant
    means the current noise_pos guess is wrong for this pixel.

    A running `quality` score tracks evidence that the path is on the
    true plaintext — incremented for 0xFF at 255-stepped code positions
    (a very strong structural signal) and for printable-ASCII data
    bytes (a weaker signal, but persistent across thousands of bytes).
    Used only as a beam-pruning tiebreaker; never gates acceptance.
    """

    __slots__ = (
        "awaiting_code", "remaining", "terminated", "term_pos", "quality",
        "relaxed_anchor",
    )

    def __init__(self, relaxed_anchor: bool = False) -> None:
        self.awaiting_code = True
        self.remaining = 0
        self.terminated = False
        self.term_pos = -1
        self.quality = 0
        # relaxed_anchor = True → accept any 1..254 at byte 0 (plaintext may
        # contain 0x00 bytes, so the COBS first-code byte varies with the
        # position of the first 0x00 in source; no 0xFF anchor invariant).
        # Used for binary plaintext formats (ZIP, PDF, compressed streams).
        self.relaxed_anchor = relaxed_anchor

    def feed(self, byte: int, abs_pos: int) -> bool:
        """Advance the state by one byte at stream position `abs_pos`.
        Return True if the byte is consistent with COBS framing, False
        otherwise. After the terminator has been observed, subsequent
        bytes (CSPRNG fill) are accepted unconditionally and do not
        change state or quality."""
        if self.terminated:
            return True
        if self.awaiting_code:
            if byte == 0:
                if abs_pos == 0:
                    return False
                self.terminated = True
                self.term_pos = abs_pos
                return True
            if abs_pos == 0 and byte != 0xFF and not self.relaxed_anchor:
                return False
            self.remaining = byte - 1
            self.awaiting_code = self.remaining == 0
            # 0xFF-at-255-stepped-position bonus is a structural signal that
            # only holds for no-0x00 plaintexts (JSON/HTML). Suppress for
            # relaxed anchor mode — binary plaintexts have code bytes at
            # varying offsets driven by the 0x00 distribution in source.
            if byte == 0xFF and abs_pos % 255 == 0 and not self.relaxed_anchor:
                self.quality += 100
            return True
        if byte == 0:
            return False
        self.remaining -= 1
        if self.remaining == 0:
            self.awaiting_code = True
        if 0x20 <= byte <= 0x7E:
            self.quality += 1
        return True

    def clone(self) -> "_COBSStreamState":
        s = _COBSStreamState.__new__(_COBSStreamState)
        s.awaiting_code = self.awaiting_code
        s.remaining = self.remaining
        s.terminated = self.terminated
        s.term_pos = self.term_pos
        s.quality = self.quality
        s.relaxed_anchor = self.relaxed_anchor
        return s


_BEAM_WIDTH_DEFAULT = 32


def _try_decode_sp_np0(
    sp: int,
    np_0: int,
    K_lo: List[int],
    nonce: bytes,
    container: bytes,
    total_pixels: int,
    rounds: int,
    beam_width: int = _BEAM_WIDTH_DEFAULT,
    relaxed_anchor: bool = False,
) -> Optional[Tuple[bytes, int, List[int]]]:
    """Decode the full container at `(sp, np_0)` via beam search over
    per-pixel noise_pos with COBS-state-machine rejection.

    At each pixel 8 candidate noise_pos values are enumerated (fixed to
    np_0 for pixel 0). A candidate survives only if its 7 decoded bytes
    extend the running COBS state without violating framing invariants
    (non-zero data bytes, code-byte anchor at position 0, etc.). Beam
    width caps how many surviving paths propagate forward. When a
    candidate's byte lands a valid terminator (0x00 at an awaiting-code
    position AND the prefix cobs_decodes cleanly to non-empty plaintext),
    it is recorded. The final returned answer is the recorded terminator
    at the highest stream position — same rationale as the CRC128 Phase
    2f decrypt: the true noise_pos path always survives to the latest
    terminator, while chance-lucky wrong paths terminate earlier.
    """
    # Beam entries: (COBS state, full stream bytes so far, np_list so far).
    beam: List[Tuple[_COBSStreamState, bytearray, List[int]]] = [
        (_COBSStreamState(relaxed_anchor=relaxed_anchor), bytearray(), [])
    ]
    terminator_hits: List[Tuple[int, bytes, List[int]]] = []  # (term_pos, stream, np_list)

    for p in range(total_pixels):
        linear_pixel = (sp + p) % total_pixels
        data = struct.pack("<I", p) + nonce
        dh_lo = fnv_chain_lo_concrete(K_lo, data, rounds)
        rotation = dh_lo % 7

        try_order = [np_0] if p == 0 else range(8)

        new_beam: List[Tuple[_COBSStreamState, bytearray, List[int]]] = []
        for state, stream, np_list in beam:
            if state.terminated:
                # Terminated paths already scored; do not extend further
                # (their cobs prefix is already recorded in terminator_hits).
                continue
            for np_try in try_order:
                bits = _decode_pixel_56bits(
                    container, linear_pixel, np_try, rotation, dh_lo,
                )
                pb = _pixel_bytes(bits)
                cand_state = state.clone()
                stream_len_before = len(stream)
                valid = True
                for i, b in enumerate(pb):
                    if not cand_state.feed(b, stream_len_before + i):
                        valid = False
                        break
                if not valid:
                    continue
                cand_stream = bytearray(stream) + bytearray(pb)
                cand_np_list = np_list + [np_try]
                new_beam.append((cand_state, cand_stream, cand_np_list))
                if cand_state.terminated:
                    prefix = bytes(cand_stream[: cand_state.term_pos])
                    pt = cobs_decode(prefix)
                    if pt:
                        terminator_hits.append(
                            (cand_state.term_pos, bytes(cand_stream), cand_np_list)
                        )

        if not new_beam:
            break

        # Prune beam: prefer still-active (non-terminated) paths, then
        # highest quality score (0xFF-at-code-position + printable-ASCII
        # accumulation), then longer streams as final tiebreaker.
        new_beam.sort(
            key=lambda e: (
                0 if e[0].terminated else 1,
                e[0].quality,
                len(e[1]),
            ),
            reverse=True,
        )
        beam = new_beam[:beam_width]

    if not terminator_hits:
        return None
    terminator_hits.sort(key=lambda h: -h[0])
    term_pos, stream_bytes, np_list = terminator_hits[0]
    return stream_bytes, term_pos, np_list


def decrypt_full(
    ciphertext: bytes,
    K_lo: List[int],
    nonce: bytes,
    total_pixels: int,
    rounds: int = 4,
    header_size: int = 20,
    progress_every: int = 16,
    plaintext_format: str = "ascii",
    start_pixel_override: Optional[int] = None,
) -> Optional[dict]:
    """Attempt full decrypt. Enumerate every (sp, np_0) combination,
    collect all candidates that produce a COBS-valid stream, pick the
    one whose terminator position is highest — mirrors the CRC128 Phase
    2f selection rule. A wrong (sp, np_0) can occasionally produce a
    valid but premature terminator on a chance-aligned short COBS
    chain; the true (sp, np_0) always places its terminator at the
    architectural `COBS(plaintext) + 0x00` boundary, which sits strictly
    beyond any accidental shorter chain under attacker-realistic
    structured plaintext.

    `plaintext_format` selects COBS anchor / ranker behaviour:
      * "ascii" (default) — plaintext assumed 0x00-free (JSON, HTML,
        printable text); COBS anchor at byte 0 must equal 0xFF, cobs-
        valid survivors ranked by printable-ASCII ratio.
      * "binary-zip" — plaintext may contain 0x00 at arbitrary offsets
        (ZIP, PDF, compressed streams); COBS anchor relaxed to any
        1..254 value, cobs-valid survivors ranked by ZIP-signature
        count (PK\\x03\\x04 local file headers, PK\\x01\\x02 central
        directory entries, PK\\x05\\x06 end-of-central-directory). The
        format hint represents attacker side-channel knowledge — e.g.
        partial decrypt reveals ZIP structure, or protocol context
        announces a ZIP payload.

    `start_pixel_override` optionally restricts the outer loop to a
    single startPixel candidate (lab convenience or distributed-worker
    single-candidate assignment). If None, the loop brute-forces every
    startPixel 0..total_pixels-1 as before.
    """
    container = ciphertext[header_size:]
    t0 = time.perf_counter()
    tried = 0
    results: List[dict] = []
    relaxed_anchor = plaintext_format == "binary-zip"
    sp_range = (
        [start_pixel_override % total_pixels]
        if start_pixel_override is not None
        else range(total_pixels)
    )
    for sp in sp_range:
        for np_0 in range(8):
            tried += 1
            r = _try_decode_sp_np0(
                sp=sp, np_0=np_0, K_lo=K_lo, nonce=nonce,
                container=container, total_pixels=total_pixels, rounds=rounds,
                relaxed_anchor=relaxed_anchor,
            )
            if r is None:
                continue
            stream, term_idx, np_list = r
            pt = cobs_decode(stream[:term_idx])
            if not pt:
                continue
            results.append({
                "sp": sp,
                "np_0": np_0,
                "np_per_pixel": np_list,
                "terminator_idx": term_idx,
                "stream_hex": stream.hex(),
                "plaintext": pt,
                "tried_candidates": tried,
            })
        if sp % progress_every == 0 and sp > 0:
            wall = time.perf_counter() - t0
            print(
                f"  [progress] scanned sp=0..{sp}, {tried} candidates, "
                f"{wall:.1f}s elapsed, {len(results)} valid so far",
                file=sys.stderr,
            )

    if not results:
        return None

    # Rank cobs-valid candidates by a format-aware discriminator. The
    # true path always scores highest; ghost terminators (valid COBS
    # chains that happen to land inside the CSPRNG-fill region past
    # the real terminator) score near-zero because their recovered
    # "plaintext" is random bytes that fail format-specific checks.
    def _printable_ratio(pt: bytes) -> float:
        if not pt:
            return 0.0
        return sum(1 for b in pt if 0x20 <= b <= 0x7E) / len(pt)

    def _zip_signature_count(pt: bytes) -> int:
        """Count PK\\x03\\x04, PK\\x01\\x02, PK\\x05\\x06 signatures in
        candidate plaintext. True ZIP plaintext has N local file headers
        + N central directory entries + 1 EOCD = 2N+1 signatures; random
        garbage has near-zero signatures (probability `3 / 2^32` per
        aligned 4-byte window)."""
        sig_local = b"PK\x03\x04"
        sig_central = b"PK\x01\x02"
        sig_eocd = b"PK\x05\x06"
        return (
            pt.count(sig_local)
            + pt.count(sig_central)
            + pt.count(sig_eocd)
        )

    for r in results:
        r["printable_ratio"] = _printable_ratio(r["plaintext"])
        r["zip_signature_count"] = _zip_signature_count(r["plaintext"])

    if plaintext_format == "binary-zip":
        # ZIP primary key: total PK-signature count (architectural: true
        # path holds 2N+1 signatures for an N-file archive, ghost
        # candidates have ≤ a handful by pure chance). Fallback to
        # terminator position for ties (rare).
        results.sort(
            key=lambda r: (-r["zip_signature_count"], -r["terminator_idx"])
        )
    else:
        # ASCII / JSON / HTML primary key: printable-ASCII ratio
        # (≥ 99 % for true, ~35 % for ghost). Fallback to terminator.
        results.sort(
            key=lambda r: (-r["printable_ratio"], -r["terminator_idx"])
        )

    best = results[0]
    best["wall_clock_sec"] = time.perf_counter() - t0
    best["tried_candidates"] = tried
    best["alt_candidates"] = len(results) - 1
    return best


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--target-cell-dir", type=Path, required=True,
        help="Path to ct_0000.bin + cell.meta.json (for nonce / total_pixels)",
    )
    ap.add_argument(
        "--k-json", type=Path, default=None,
        help="JSON report from sat_harness_4round.py with recovered_seed_lo_hex. "
             "Mutually exclusive with --lab-k-from-summary.",
    )
    ap.add_argument(
        "--lab-k-from-summary", type=Path, default=None,
        help="LAB-ONLY: read K_lo from the fnvstress summary.json "
             "data_lo_lane_hex field. For testing decrypt machinery against "
             "the ground-truth seed; never used in attacker-realistic runs.",
    )
    ap.add_argument(
        "--rounds", type=int, default=4,
        help="ChainHash rounds (default 4 for keyBits=512)",
    )
    ap.add_argument(
        "--expected-plaintext", type=Path, default=None,
        help="ct_0000.plain for terminal-stage audit only (byte-match percent)",
    )
    ap.add_argument(
        "--plaintext-format",
        choices=["ascii", "binary-zip"],
        default="ascii",
        help="Plaintext format hint for decrypt-side candidate ranking. "
             "ascii (default): JSON / HTML / printable text, 0x00-free, "
             "COBS anchor 0xFF at byte 0 enforced, ranker = printable-"
             "ASCII ratio. binary-zip: ZIP archive, 0x00 bytes at "
             "arbitrary offsets, relaxed COBS anchor (byte 0 any 1..254), "
             "ranker = PK-signature count (0x03\\x04 / 0x01\\x02 / "
             "0x05\\x06 headers). Represents attacker side-channel "
             "knowledge of the plaintext format.",
    )
    ap.add_argument(
        "--start-pixel", type=int, default=None,
        help="Optional override: restrict the outer startPixel loop to "
             "this specific integer (modulo total_pixels) and decrypt a "
             "single candidate. Used either as a lab convenience (skip "
             "brute force when truth startPixel is known from "
             "cell.meta.json) OR in distributed attacker scenarios where "
             "each worker is assigned one startPixel candidate and only "
             "one returns a structurally-valid decrypt. When unset the "
             "outer loop brute-forces every startPixel 0..total_pixels-1 "
             "as before — full attacker-realistic behaviour unchanged.",
    )
    args = ap.parse_args()

    meta = json.loads((args.target_cell_dir / "cell.meta.json").read_text())
    ciphertext = (args.target_cell_dir / "ct_0000.bin").read_bytes()
    nonce = bytes.fromhex(meta["nonce_hex"])
    total_pixels = int(meta["total_pixels"])

    if args.lab_k_from_summary is not None:
        summary = json.loads(args.lab_k_from_summary.read_text())
        K_lo = [int(h, 16) for h in summary["data_lo_lane_hex"]]
        print(
            f"[LAB] K_lo sourced from {args.lab_k_from_summary} "
            "(ground truth — testing mode, not attacker-realistic)"
        )
        result = decrypt_full(
            ciphertext=ciphertext, K_lo=K_lo, nonce=nonce,
            total_pixels=total_pixels, rounds=args.rounds,
            plaintext_format=args.plaintext_format,
            start_pixel_override=args.start_pixel,
        )
        if result is None:
            print("[FAIL] decrypt machinery broken — ground-truth K failed")
            return 1
        print(f"[OK] LAB decrypt: sp={result['sp']} np_0={result['np_0']} "
              f"wall={result['wall_clock_sec']:.2f}s tried={result['tried_candidates']}")
        print(f"  plaintext: {len(result['plaintext'])} bytes")
        if args.expected_plaintext is not None and args.expected_plaintext.is_file():
            expected = args.expected_plaintext.read_bytes()
            match = sum(a == b for a, b in zip(result["plaintext"], expected))
            total = min(len(result["plaintext"]), len(expected))
            pct = 100.0 * match / total if total > 0 else 0.0
            print(f"  [audit] byte match: {match}/{total} = {pct:.2f}% "
                  f"{'✓' if match == len(expected) else '✗'}")
        return 0 if (
            args.expected_plaintext is None or
            result["plaintext"] == args.expected_plaintext.read_bytes()
        ) else 1

    if args.k_json is None:
        print("[FATAL] one of --k-json or --lab-k-from-summary required", file=sys.stderr)
        return 2
    k_report = json.loads(args.k_json.read_text())
    if "recovered_seed_lo_hex" in k_report:
        K_lo = [int(h, 16) for h in k_report["recovered_seed_lo_hex"] if h]
    elif "results" in k_report:
        # brute-force report — pick first holdout-equivalent hit
        hits = [r for r in k_report["results"]
                if r.get("status") == "sat"
                and r.get("holdout_functionally_equivalent")]
        if not hits:
            hits = [r for r in k_report["results"] if r.get("status") == "sat"]
        if not hits:
            print(f"[FATAL] no sat hits in {args.k_json}", file=sys.stderr)
            return 2
        K_lo = [int(h, 16) for h in hits[0]["recovered_seed_lo_hex"] if h]
    else:
        print(f"[FATAL] unknown K json format: {args.k_json}", file=sys.stderr)
        return 2

    if not K_lo:
        print(f"[FATAL] empty K_lo in {args.k_json}", file=sys.stderr)
        return 2

    print(
        f"decrypt_full_fnv1a: target={args.target_cell_dir} "
        f"total_pixels={total_pixels} rounds={args.rounds} "
        f"K_lo={' '.join(f'{v:016x}' for v in K_lo)}"
    )
    result = decrypt_full(
        ciphertext=ciphertext, K_lo=K_lo, nonce=nonce,
        total_pixels=total_pixels, rounds=args.rounds,
        plaintext_format=args.plaintext_format,
        start_pixel_override=args.start_pixel,
    )
    if result is None:
        print("[FAIL] no (sp, np_0) candidate decoded to a COBS-valid stream")
        return 1

    print(f"[WIN] sp={result['sp']}  np_0={result['np_0']}  "
          f"wall={result['wall_clock_sec']:.2f}s  "
          f"tried={result['tried_candidates']} candidates")
    print(f"  terminator at stream byte {result['terminator_idx']}")
    print(f"  plaintext: {len(result['plaintext'])} bytes")

    # Terminal-stage audit (not in decision path).
    if args.expected_plaintext is not None and args.expected_plaintext.is_file():
        expected = args.expected_plaintext.read_bytes()
        match = sum(a == b for a, b in zip(result["plaintext"], expected))
        total = min(len(result["plaintext"]), len(expected))
        pct = 100.0 * match / total if total > 0 else 0.0
        print(
            f"  [audit] byte match vs ground truth: {match}/{total} = {pct:.2f}% "
            f"{'✓' if match == len(expected) else '✗'}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
