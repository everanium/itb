#!/usr/bin/env python3
"""Classical nonce-reuse decryption experiment (Full KPA).

Demonstrates empirically that under nonce-reuse + Full KPA the per-pixel
config map (noisePos, rotation, channelXOR) recovered by Layer 1 + Layer 2
IS the classical keystream-equivalent for this (seeds, nonce): applying it
to both colliding ciphertexts decrypts them back to P1, P2 via standard
keystream-reuse, no SAT / seed inversion required.

Two phases:
  Phase A (demasker) — use Full KPA (P1, P2) as input to Layer 1 + Layer 2,
    recover the per-pixel config map for this specific (seeds, nonce).
  Phase B (lab experiment) — "forget" (P1, P2). Apply only the recovered
    config + (C1, C2) to classical-decrypt both ciphertexts. Verify the
    recovered plaintexts match the originals byte-for-byte.

Works for any hash primitive. Under PRF (BLAKE3, etc.) the datahash stream
emitted by the demasker is uniform-random (SAT seed recovery infeasible),
but the recovered config still decrypts all same-nonce ciphertexts
classically — PRF does not defend against nonce-reuse plaintext recovery
within the colliding set.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from attack_common import (
    CHANNELS, DATA_BITS_PER_CHANNEL, DATA_BITS_PER_PIXEL,
    EXTRACT7_TABLE, ROT7_TABLE,
    load_cell_meta, parse_itb_header, get_bits7, cobs_encode,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nonce_reuse_demask import (
    layer1_recover_range, layer2_brute_force_startpixel,
    precompute_d_xor_per_probe, build_payload_known,
    layer1_recover_range_partial, layer2_brute_force_startpixel_partial,
    precompute_d_xor_with_known_per_probe,
    build_payload_and_mask_partial, compute_channel_known_map,
)

PROJ = Path(__file__).resolve().parents[3]


def derive_channel_xor_map(
    container: np.ndarray,
    payload: bytes,
    recovered: list,
    start_pixel: int,
    total_pixels: int,
) -> dict:
    """Extract channelXOR[pixel][channel] from one ciphertext + its known
    plaintext. This step uses KPA — it's part of the config extraction.
    """
    out: dict[int, np.ndarray] = {}
    for data_idx, cfg in enumerate(recovered):
        if cfg is None:
            continue
        noise_pos, rotation = cfg
        inv_rotation = (7 - rotation) % 7
        container_pos = (start_pixel + data_idx) % total_pixels
        byte8 = container[container_pos]
        cxor = np.zeros(CHANNELS, dtype=np.uint8)
        for ch in range(CHANNELS):
            extracted = int(EXTRACT7_TABLE[noise_pos, byte8[ch]])
            unrotated = int(ROT7_TABLE[inv_rotation, extracted])
            bit_idx = data_idx * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
            d = get_bits7(payload, bit_idx)
            cxor[ch] = (unrotated ^ d) & 0x7F
        out[data_idx] = cxor
    return out


def cobs_decode_tolerant(encoded: bytes, expect_len: int,
                          gap_marker: int = 0xFF) -> tuple[bytes, int]:
    """Gap-tolerant COBS decoder.

    Standard COBS expects no interior 0x00 bytes in the encoded stream (only
    terminator at end). If we hit an unexpected 0x00 (gap from an ambiguous
    pixel), emit `gap_marker` bytes and try to resync by skipping the zero
    run, then resume decoding.

    Returns (decoded_bytes, marker_count).
    """
    out = bytearray()
    markers = 0
    i = 0
    while i < len(encoded) and len(out) < expect_len:
        code = encoded[i]
        if code == 0:
            # Gap (or true terminator). If we've reached expected length,
            # treat as terminator. Otherwise mark and skip zeros.
            if len(out) >= expect_len:
                break
            out.append(gap_marker)
            markers += 1
            i += 1
            while i < len(encoded) and encoded[i] == 0:
                out.append(gap_marker)
                markers += 1
                i += 1
            continue
        end = min(i + code, len(encoded))
        out.extend(encoded[i + 1:end])
        if code < 0xFF and end < len(encoded):
            out.append(0)
        i = end
    return bytes(out[:expect_len]), markers


def classical_decrypt(
    container: np.ndarray,
    recovered: list,
    channel_xor_map: dict,
    start_pixel: int,
    total_pixels: int,
    n_data_pixels: int,
) -> tuple[bytes, int]:
    """Decrypt `n_data_pixels` pixels from `container` using the recovered
    config map as a classical keystream. Returns (plaintext_bytes, n_decoded_px).

    For each pixel with known (noisePos, rotation, channelXOR):
        extracted_7 = EXTRACT7[noise_pos, channel_byte]
        unrotated_7 = ROT7[(7 - rotation) % 7, extracted_7]
        plaintext_7 = unrotated_7 ^ channelXOR_7
    Pack 8 × 7 bits little-endian per pixel into the output byte stream.
    """
    accum = 0
    bits = 0
    out = bytearray()
    decoded = 0

    for data_idx in range(n_data_pixels):
        cfg = recovered[data_idx] if data_idx < len(recovered) else None
        container_pos = (start_pixel + data_idx) % total_pixels
        byte8 = container[container_pos]

        if cfg is None or data_idx not in channel_xor_map:
            for _ in range(CHANNELS):
                bits += DATA_BITS_PER_CHANNEL
                while bits >= 8:
                    out.append(accum & 0xFF)
                    accum >>= 8
                    bits -= 8
            continue

        noise_pos, rotation = cfg
        inv_rotation = (7 - rotation) % 7
        cxor = channel_xor_map[data_idx]
        for ch in range(CHANNELS):
            extracted = int(EXTRACT7_TABLE[noise_pos, byte8[ch]])
            unrotated = int(ROT7_TABLE[inv_rotation, extracted])
            plaintext_7 = unrotated ^ int(cxor[ch])
            accum |= plaintext_7 << bits
            bits += DATA_BITS_PER_CHANNEL
            while bits >= 8:
                out.append(accum & 0xFF)
                accum >>= 8
                bits -= 8
        decoded += 1

    if bits > 0:
        out.append(accum & 0xFF)

    return bytes(out), decoded


def byte_covering_positions(byte_idx: int, data_pixels: int) -> list:
    """Return [(pixel, channel)] pairs whose 7-bit slices contain any bit of
    `byte_idx`. Byte always starts in exactly one (pixel, channel) pair and
    may continue in the next channel (same or next pixel)."""
    positions = set()
    for bit_off in range(8):
        b = byte_idx * 8 + bit_off
        pixel = b // DATA_BITS_PER_PIXEL
        if pixel >= data_pixels:
            return []
        offset = b % DATA_BITS_PER_PIXEL
        channel = offset // DATA_BITS_PER_CHANNEL
        positions.add((pixel, channel))
    return sorted(positions)


def partial_mode_recovery(
    p_plain: bytes,
    known_mask: bytes,
    recovered_by_pixel: list,
    channel_known_map: np.ndarray,
    data_pixels: int,
) -> tuple[bytes, int, int]:
    """Under Partial KPA: a byte is recoverable via classical decrypt iff
      - known_mask[byte] == 1 (attacker already had this byte as input)
      - every (pixel, channel) the byte's 8 bits touch is Layer-1-recovered
        AND marked known in channel_known_map (so attacker could derive
        channelXOR at that position).
    Emit original plaintext byte at recoverable positions (attacker just
    reproduces what they already knew); 0xFF gap marker elsewhere.

    Returns (output, recoverable_count, gap_count).
    """
    out = bytearray(len(p_plain))
    recoverable = 0
    for byte_idx in range(len(p_plain)):
        if byte_idx >= len(known_mask) or not known_mask[byte_idx]:
            out[byte_idx] = 0xFF
            continue
        positions = byte_covering_positions(byte_idx, data_pixels)
        if not positions:
            out[byte_idx] = 0xFF
            continue
        all_ok = True
        for (px, ch) in positions:
            if recovered_by_pixel[px] is None:
                all_ok = False
                break
            if not channel_known_map[px, ch]:
                all_ok = False
                break
        if all_ok:
            out[byte_idx] = p_plain[byte_idx]
            recoverable += 1
        else:
            out[byte_idx] = 0xFF
    gaps = len(p_plain) - recoverable
    return bytes(out), recoverable, gaps


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cell-dir", type=Path, required=True,
                    help="Corpus cell directory (contains cell.meta.json, ct_NNNN.bin, ct_NNNN.plain).")
    ap.add_argument("--pair", nargs=2, default=["0000", "0001"],
                    help="Two ciphertext IDs to use as the nonce-reuse pair (default: 0000 0001).")
    ap.add_argument("--emit-decrypted", type=Path, default=None,
                    help="Optional: write recovered_P1.bin / recovered_P2.bin into this directory.")
    ap.add_argument("--n-probe", type=int, default=10,
                    help="Layer 2 startPixel brute-force probe depth (default: 10). "
                         "Default is fine for random plaintext (Full KPA known mode). "
                         "For structured partial kinds with repeating records, use "
                         "at least 3 × record_period_in_pixels to avoid period-shift "
                         "catastrophe: ~60 for json_structured_* (137-byte records), "
                         "~105 for html_structured_80 (250-byte records). Too-small "
                         "probe converges on a period-shifted startPixel and drops "
                         "Clean Signal from ~95 %% to ~20 %%.")
    ap.add_argument("--mode", choices=["auto", "known", "partial"], default="auto",
                    help="auto (default): detect partial via presence of "
                         "ct_*.known_mask sidecars. known: treat both plaintexts as "
                         "fully known (Full KPA). partial: read known_mask, use "
                         "channel-known map for Layer 1 partial, emit plaintext only "
                         "at positions the attacker could classical-decrypt.")
    ap.add_argument("--min-known-channels", type=int, default=2,
                    help="Partial mode only: minimum known channels per pixel for "
                         "Layer 1 to attempt recovery (default: 2).")
    args = ap.parse_args()

    cell_dir = args.cell_dir.resolve()
    if not cell_dir.is_dir():
        print(f"ERROR: cell-dir not found: {cell_dir}", file=sys.stderr)
        return 2

    meta = load_cell_meta(cell_dir)
    id1, id2 = args.pair
    c1_bytes = (cell_dir / f"ct_{id1}.bin").read_bytes()
    c2_bytes = (cell_dir / f"ct_{id2}.bin").read_bytes()
    p1_plain = (cell_dir / f"ct_{id1}.plain").read_bytes()
    p2_plain = (cell_dir / f"ct_{id2}.plain").read_bytes()

    mask1_path = cell_dir / f"ct_{id1}.known_mask"
    mask2_path = cell_dir / f"ct_{id2}.known_mask"
    if args.mode == "auto":
        mode = "partial" if (mask1_path.exists() and mask2_path.exists()) else "known"
    else:
        mode = args.mode
    if mode == "partial" and not (mask1_path.exists() and mask2_path.exists()):
        print(f"ERROR: --mode partial requires ct_*.known_mask sidecars", file=sys.stderr)
        return 2

    nonce1, w1, h1, tp1, body1 = parse_itb_header(c1_bytes)
    nonce2, w2, h2, tp2, body2 = parse_itb_header(c2_bytes)
    if nonce1 != nonce2:
        print("ERROR: nonces differ — not a nonce-reuse pair", file=sys.stderr)
        return 2
    if tp1 != tp2:
        print(f"ERROR: container sizes differ: {tp1} vs {tp2}", file=sys.stderr)
        return 2

    c1_container = np.frombuffer(body1, dtype=np.uint8).reshape(tp1, CHANNELS)
    c2_container = np.frombuffer(body2, dtype=np.uint8).reshape(tp2, CHANNELS)

    capacity = meta["data_pixels"] * 7
    payload1 = build_payload_known(p1_plain, capacity)
    payload2 = build_payload_known(p2_plain, capacity)

    fully_known_px = meta["fully_known_pixels"]

    print(f"{'=' * 72}")
    print(f"Classical nonce-reuse decryption experiment")
    print(f"{'=' * 72}")
    print(f"Cell: {cell_dir.relative_to(PROJ)}")
    print(f"  hash            : {meta['hash_display']} ({meta['hash']}, {meta['hash_width']}-bit)")
    print(f"  plaintext size  : {meta['plaintext_size']} bytes")
    print(f"  totalPixels     : {tp1}  dataPixels: {meta['data_pixels']}  "
          f"fullyKnownPixels: {fully_known_px}")
    print(f"  knownBytes      : {meta['known_bytes']} (cobs-encoded + 0x00 terminator)")
    print(f"  nonce (hex)     : {nonce1.hex()}")
    print(f"  mode            : {mode}")

    # ===================================================================
    # PARTIAL KPA branch — attacker has partial plaintext via known_mask.
    # ===================================================================
    if mode == "partial":
        mask1 = mask1_path.read_bytes()
        mask2 = mask2_path.read_bytes()
        known_bytes_total_1 = sum(mask1)
        known_bytes_total_2 = sum(mask2)

        payload1_p, payload_mask1 = build_payload_and_mask_partial(p1_plain, mask1, capacity)
        payload2_p, payload_mask2 = build_payload_and_mask_partial(p2_plain, mask2, capacity)
        channel_known_map = compute_channel_known_map(
            payload_mask1, payload_mask2, meta["data_pixels"],
        )
        known_channels_pct = (
            channel_known_map.sum() * 100 / channel_known_map.size
            if channel_known_map.size else 0.0
        )
        print(f"  known-mask cov  : P1 {known_bytes_total_1}/{len(mask1)} "
              f"({100*known_bytes_total_1/len(mask1):.1f}%)  "
              f"P2 {known_bytes_total_2}/{len(mask2)} "
              f"({100*known_bytes_total_2/len(mask2):.1f}%)")
        print(f"  known-channels  : {channel_known_map.sum()} / {channel_known_map.size} "
              f"({known_channels_pct:.1f}%)")

        print(f"\nPhase A — Layer 2 + Layer 1 (partial mode):")
        d_xor_p, known_p = precompute_d_xor_with_known_per_probe(
            payload1_p, payload2_p, channel_known_map, args.n_probe,
        )
        t0 = time.time()
        best_sp, best_score, _ = layer2_brute_force_startpixel_partial(
            c1_container, c2_container, d_xor_p, known_p, tp1,
            n_probe=args.n_probe,
            min_known_channels=args.min_known_channels,
            verbose=False,
        )
        t_l2 = time.time() - t0
        print(f"  Layer 2 startPixel : {best_sp}  (score {best_score}, {t_l2:.2f}s)")
        if best_sp < 0 or best_score < 1:
            print(f"ERROR: Layer 2 partial found no startPixel", file=sys.stderr)
            return 1

        t0 = time.time()
        recovered = layer1_recover_range_partial(
            c1_container, c2_container, payload1_p, payload2_p,
            channel_known_map, best_sp, meta["data_pixels"], tp1,
            pixel_range=(0, meta["data_pixels"]),
            min_known_channels=args.min_known_channels,
        )
        t_l1 = time.time() - t0
        unique = sum(1 for r in recovered if r is not None)
        print(f"  Layer 1 unique     : {unique}/{meta['data_pixels']}  ({t_l1:.2f}s)")

        print(f"\nPhase B — partial-KPA classical decryption:")
        print(f"  (attacker can derive channelXOR only at KNOWN channels of "
              f"Layer-1-recovered pixels; produces plaintext only at those positions)")
        p1_out, rec1, gaps1 = partial_mode_recovery(
            p1_plain, mask1, recovered, channel_known_map, meta["data_pixels"],
        )
        p2_out, rec2, gaps2 = partial_mode_recovery(
            p2_plain, mask2, recovered, channel_known_map, meta["data_pixels"],
        )
        print(f"  recoverable bytes  : "
              f"C1→P1 {rec1}/{len(p1_plain)} ({100*rec1/len(p1_plain):.2f}%)  "
              f"C2→P2 {rec2}/{len(p2_plain)} ({100*rec2/len(p2_plain):.2f}%)")
        print(f"  input mask bytes   : "
              f"P1 {known_bytes_total_1} ({100*known_bytes_total_1/len(p1_plain):.2f}%)  "
              f"P2 {known_bytes_total_2} ({100*known_bytes_total_2/len(p2_plain):.2f}%)")
        print(f"  → recovered ⊆ attacker-known input (no NEW plaintext under "
              f"symmetric-coverage Partial KPA; classical keystream reuse "
              f"just reproduces what attacker already held)")

        if args.emit_decrypted is not None:
            out_dir = args.emit_decrypted.resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "recovered_plaintext_P1.bin").write_bytes(p1_out)
            (out_dir / "recovered_plaintext_P2.bin").write_bytes(p2_out)
            (out_dir / "groundtruth_plaintext_P1.bin").write_bytes(p1_plain)
            (out_dir / "groundtruth_plaintext_P2.bin").write_bytes(p2_plain)
            try:
                rel = out_dir.relative_to(PROJ)
            except ValueError:
                rel = out_dir
            print(f"  artefacts written  : {rel}")
            print(f"    recovered_plaintext_P{{1,2}}.bin — attacker-recoverable bytes; "
                  f"0xFF at mask-unknown / unrecovered positions.")

        return 0 if (rec1 == known_bytes_total_1 and rec2 == known_bytes_total_2) else 1

    # ===================================================================
    # FULL KPA branch — attacker has both plaintexts fully.
    # ===================================================================
    # -------------------------------------------------------------------
    # Phase A — demasker (Full KPA input)
    # -------------------------------------------------------------------
    print(f"\nPhase A — demasker (Full KPA uses P1 + P2 to recover config):")

    d_xor_probe = precompute_d_xor_per_probe(payload1, payload2, args.n_probe)
    t0 = time.time()
    best_sp, best_score, _ = layer2_brute_force_startpixel(
        c1_container, c2_container, d_xor_probe, tp1,
        n_probe=args.n_probe, verbose=False,
    )
    t_l2 = time.time() - t0
    print(f"  Layer 2 startPixel : {best_sp}  (score {best_score}/{args.n_probe}, {t_l2:.2f}s)")
    if best_score != args.n_probe:
        print(f"ERROR: Layer 2 did not find clean startPixel", file=sys.stderr)
        return 1

    t0 = time.time()
    recovered = layer1_recover_range(
        c1_container, c2_container, payload1, payload2,
        best_sp, meta["data_pixels"], tp1,
        pixel_range=(0, fully_known_px),
    )
    t_l1 = time.time() - t0
    unique = sum(1 for r in recovered if r is not None)
    print(f"  Layer 1 unique     : {unique}/{fully_known_px}  ({t_l1:.2f}s)")

    channel_xor_map = derive_channel_xor_map(c1_container, payload1, recovered, best_sp, tp1)
    print(f"  channelXOR map     : {len(channel_xor_map)} pixels populated")
    print(f"  → config map recovered = keystream-equivalent for ({nonce1.hex()}, dataSeed, noiseSeed, startSeed)")

    # -------------------------------------------------------------------
    # Phase B — lab experiment (attacker 'forgets' plaintexts,
    #                           applies config as classical keystream)
    # -------------------------------------------------------------------
    print(f"\nPhase B — classical decryption (attacker uses only config + C1, C2):")

    t0 = time.time()
    decoded_1, decoded_px_1 = classical_decrypt(
        c1_container, recovered, channel_xor_map, best_sp, tp1, fully_known_px,
    )
    decoded_2, decoded_px_2 = classical_decrypt(
        c2_container, recovered, channel_xor_map, best_sp, tp1, fully_known_px,
    )
    t_decode = time.time() - t0
    print(f"  decrypted C1 ({decoded_px_1} / {fully_known_px} pixels),"
          f" C2 ({decoded_px_2} / {fully_known_px} pixels) in {t_decode:.2f}s")

    # -------------------------------------------------------------------
    # Verify against ground-truth (cobs form + raw plaintext)
    # -------------------------------------------------------------------
    cobs1 = cobs_encode(p1_plain) + b"\x00"
    cobs2 = cobs_encode(p2_plain) + b"\x00"

    # Known-bytes region = cobs(P) + 0x00 terminator; beyond this is CSPRNG
    # fill which is never attacker-predictable.
    cmp_len = meta["known_bytes"]
    cobs_match1 = sum(1 for i in range(cmp_len)
                      if i < len(decoded_1) and decoded_1[i] == cobs1[i])
    cobs_match2 = sum(1 for i in range(cmp_len)
                      if i < len(decoded_2) and decoded_2[i] == cobs2[i])

    # COBS-decode (gap-tolerant) to raw plaintext and compare byte-for-byte.
    plain_1, markers_1 = cobs_decode_tolerant(decoded_1, len(p1_plain))
    plain_2, markers_2 = cobs_decode_tolerant(decoded_2, len(p2_plain))
    L1 = min(len(plain_1), len(p1_plain))
    L2 = min(len(plain_2), len(p2_plain))
    plain_match1 = sum(1 for i in range(L1) if plain_1[i] == p1_plain[i])
    plain_match2 = sum(1 for i in range(L2) if plain_2[i] == p2_plain[i])

    print(f"\n{'-' * 72}")
    print(f"Verification — cobs-form vs raw plaintext")
    print(f"{'-' * 72}")
    print(f"  cobs-form byte match   : "
          f"C1→P1 {cobs_match1}/{cmp_len} ({100*cobs_match1/cmp_len:.2f}%)  "
          f"C2→P2 {cobs_match2}/{cmp_len} ({100*cobs_match2/cmp_len:.2f}%)")
    print(f"  raw plaintext match    : "
          f"C1→P1 {plain_match1}/{L1} ({100*plain_match1/L1:.2f}%)  "
          f"C2→P2 {plain_match2}/{L2} ({100*plain_match2/L2:.2f}%)")
    print(f"  gap markers in plain   : P1 {markers_1}  P2 {markers_2}  "
          f"(0xFF byte per ambiguous cobs position)")

    if args.emit_decrypted is not None:
        out_dir = args.emit_decrypted.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "recovered_cobs_P1.bin").write_bytes(decoded_1[:cmp_len])
        (out_dir / "recovered_cobs_P2.bin").write_bytes(decoded_2[:cmp_len])
        (out_dir / "recovered_plaintext_P1.bin").write_bytes(plain_1)
        (out_dir / "recovered_plaintext_P2.bin").write_bytes(plain_2)
        (out_dir / "groundtruth_plaintext_P1.bin").write_bytes(p1_plain)
        (out_dir / "groundtruth_plaintext_P2.bin").write_bytes(p2_plain)
        try:
            rel = out_dir.relative_to(PROJ)
        except ValueError:
            rel = out_dir
        print(f"  artefacts written  : {rel}")
        print(f"    recovered_plaintext_P{{1,2}}.bin  — classical-decrypted raw plaintext "
              f"(0xFF marks ambiguous positions)")
        print(f"    groundtruth_plaintext_P{{1,2}}.bin — original plaintext for diff")
    match1 = cobs_match1
    match2 = cobs_match2

    print(f"\n{'=' * 72}")
    if match1 == cmp_len and match2 == cmp_len:
        print(f"✅ Both plaintexts fully recovered via classical keystream reuse.")
        print(f"   Under {meta['hash_display']} ({meta['hash_width']}-bit) — independent of")
        print(f"   PRF / non-PRF hash property. The recovered config map IS the")
        print(f"   keystream-equivalent for this (seeds, nonce).")
        return 0
    else:
        print(f"⚠ Recovery incomplete (some pixels ambiguous). Still a clear")
        print(f"  keystream-reuse path — gaps correspond only to single-pair")
        print(f"  Layer 1 ambiguity, not to PRF / hash defense.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
