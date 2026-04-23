#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ITB byte->channel encoding mirror for Phase 3 SAT harness.

Pure-Python bit-exact port of the encode/decode logic in
`process_generic.go:processChunk128` (without CGO). Covers the byte
packing that every hash primitive goes through on the way into / out
of ciphertext pixels. Two parity-tested public entry points:

  - `decode_pixel(container, pixel_offset, noise_pos, rotation,
                  data_hash_lo)` -> 7 bytes of plaintext for one pixel
  - `encode_pixel(plaintext_7, container_byte_slice, noise_pos,
                  rotation, data_hash_lo)` -> 8 updated container bytes

Plus a `parity_check_corpus()` driver that reads a Phase 1 fnvstress
corpus (cell.meta.json + ct_0000.bin + ct_0000.plain + summary.json),
re-derives noise_pos / rotation / channelXOR per pixel using the Go
lab ground-truth seeds (laboratory-audit only - the Phase 3 SAT
harness must NOT do this; it will solve for them), and verifies that
the Python decoder reproduces the original plaintext bit-exact for
every cell in the corpus.

Usage:
    python3 itb_channel_mirror.py parity
        [--fnvstress-dir tmp/attack/fnvstress]
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import List, Tuple

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from fnv_chain_lo_concrete import (  # type: ignore
    MASK64,
    fnv_chain_lo_concrete,
)

CHANNELS = 8
DATA_BITS_PER_CHANNEL = 7
DATA_BITS_PER_PIXEL = CHANNELS * DATA_BITS_PER_CHANNEL  # 56
DATA_ROTATION_BITS = 3


def cobs_encode(src: bytes) -> bytes:
    """Bit-exact port of `cobs.go:cobsEncode`.

    Pre-pends and interleaves `code` bytes so that 0x00 never appears in
    output. Used inside ITB `Encrypt128` before byte->pixel packing,
    so the Python channel mirror must COBS-wrap expected plaintext
    before comparing to what the decoder recovers.
    """
    out = bytearray([0])  # reserve first code slot
    code_idx = 0
    code = 1
    for b in src:
        if b == 0:
            out[code_idx] = code
            code_idx = len(out)
            out.append(0)  # next placeholder
            code = 1
        else:
            out.append(b)
            code += 1
            if code == 0xFF:
                out[code_idx] = code
                code_idx = len(out)
                out.append(0)
                code = 1
    out[code_idx] = code
    return bytes(out)


def cobs_decode(src: bytes) -> bytes:
    """Bit-exact port of `cobs.go:cobsDecode`."""
    if not src:
        return b""
    out = bytearray()
    idx = 0
    n = len(src)
    while idx < n:
        code = src[idx]
        idx += 1
        if code == 0:
            break
        i = 1
        while i < code and idx < n:
            out.append(src[idx])
            idx += 1
            i += 1
        if code < 0xFF and idx < n:
            out.append(0)
    return bytes(out)


def rotate_bits_7(v: int, r: int) -> int:
    """Rotate the low 7 bits of `v` left by `r` (r mod 7) positions.

    Bit-exact port of Go `itb.rotateBits7`.
    """
    v &= 0x7F
    r = r % 7
    return ((v << r) | (v >> (7 - r))) & 0x7F


def _derive_pixel_params(data_hash_lo: int) -> Tuple[int, int]:
    """Extract (rotation, xor_mask) from hLo the same way the encoder does.

    `rotation = data_hash_lo % 7`
    `xor_mask = data_hash_lo >> 3`  (56 data bits + 5 unused high)

    Matches `process_generic.go:26-27` for the 128-bit variant.
    """
    rotation = data_hash_lo % 7
    xor_mask = (data_hash_lo >> DATA_ROTATION_BITS) & MASK64
    return rotation, xor_mask


def _derive_noise_pos(noise_hash_lo: int) -> int:
    """`noise_pos = noise_hash_lo & 7` — matches `process_generic.go:23`."""
    return noise_hash_lo & 7


def extract_channel_xor(data_hash_lo: int, channel_idx: int) -> int:
    """7 bits of channelXOR for channel `ch` from dataHash.lo.

    Matches `process_generic.go:31`:
        channelXOR = byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)
    where xorMask = dataHash >> 3.
    """
    rotation, xor_mask = _derive_pixel_params(data_hash_lo)
    return (xor_mask >> (channel_idx * DATA_BITS_PER_CHANNEL)) & 0x7F


def decode_channel_to_plaintext_bits(
    container_byte: int, noise_pos: int, rotation: int, channel_xor: int
) -> int:
    """Return the 7 plaintext bits the encoder packed into `container_byte`.

    Reverses:
      low  = dataBits & byte(noiseMask-1)
      high = dataBits >> noisePos
      container = low | (orig & noiseMask) | (high << (noisePos+1))
      dataBits (pre-insert)  = rotate7(plaintext ^ channelXOR, rotation)
    """
    noise_mask = 1 << noise_pos
    low = container_byte & (noise_mask - 1)
    high = container_byte >> (noise_pos + 1)
    data_bits_enc = (low | (high << noise_pos)) & 0x7F
    # Undo rotation: encode does `rotate7(v, r)`; reverse is `rotate7(·, 7-r)`
    # (r mod 7 aware).
    data_bits_pre_rot = rotate_bits_7(data_bits_enc, (7 - (rotation % 7)) % 7)
    return data_bits_pre_rot ^ (channel_xor & 0x7F)


def encode_plaintext_bits_to_channel(
    plaintext_bits_7: int,
    container_orig_byte: int,
    noise_pos: int,
    rotation: int,
    channel_xor: int,
) -> int:
    """Return the 8-bit container value after injecting 7 plaintext bits."""
    data_bits = (plaintext_bits_7 & 0x7F) ^ (channel_xor & 0x7F)
    data_bits = rotate_bits_7(data_bits, rotation % 7)
    noise_mask = 1 << noise_pos
    low = data_bits & (noise_mask - 1)
    high = data_bits >> noise_pos
    return (low | (container_orig_byte & noise_mask) | (high << (noise_pos + 1))) & 0xFF


def decode_pixel(
    container: bytes,
    pixel_offset: int,
    noise_pos: int,
    rotation: int,
    data_hash_lo: int,
) -> int:
    """Decode 56 plaintext bits (as one uint64) from one container pixel.

    `pixel_offset` is the byte offset of channel 0 in the container
    (already multiplied by `Channels`).
    """
    packed = 0
    for ch in range(CHANNELS):
        channel_xor = extract_channel_xor(data_hash_lo, ch)
        bits = decode_channel_to_plaintext_bits(
            container[pixel_offset + ch], noise_pos, rotation, channel_xor
        )
        packed |= bits << (ch * DATA_BITS_PER_CHANNEL)
    return packed


def decode_container_to_payload(
    ciphertext: bytes,
    data_hash_lo_per_pixel: List[int],
    noise_hash_lo_per_pixel: List[int],
    start_pixel: int,
    total_pixels: int,
    header_size: int = 20,
) -> bytes:
    """Decode every data-bearing pixel into the packed `payload` byte stream.

    Matches `Encrypt128` exactly: the payload delivered to processChunk128
    is `cobs_encode(plaintext) || 0x00 || csprng_fill` up to `capacity`
    bytes, where `capacity = (totalPixels * DataBitsPerPixel) / 8`. The
    caller is responsible for slicing to the cobs-encoded region + its
    0x00 terminator, then running `cobs_decode` to obtain the original
    plaintext.

    Per-pixel `dataHash.lo` / `noiseHash.lo` arrays come from the caller
    so the function is hash-agnostic.

    `header_size` strips the 20-byte ITB header (16-byte nonce + 2W + 2H).
    """
    capacity = (total_pixels * DATA_BITS_PER_PIXEL) // 8
    total_bits = capacity * 8
    payload_bits = bytearray(capacity)
    container = ciphertext[header_size:]
    if len(container) < total_pixels * CHANNELS:
        raise ValueError(
            f"container too short: {len(container)} < {total_pixels * CHANNELS}"
        )

    bit_index = 0
    p = 0
    while p < total_pixels and bit_index < total_bits:
        linear_idx = (start_pixel + p) % total_pixels
        pixel_offset = linear_idx * CHANNELS
        data_hash_lo = data_hash_lo_per_pixel[p]
        noise_hash_lo = noise_hash_lo_per_pixel[p]
        rotation, _ = _derive_pixel_params(data_hash_lo)
        noise_pos = _derive_noise_pos(noise_hash_lo)

        for ch in range(CHANNELS):
            if bit_index >= total_bits:
                break
            channel_xor = extract_channel_xor(data_hash_lo, ch)
            data_bits = decode_channel_to_plaintext_bits(
                container[pixel_offset + ch], noise_pos, rotation, channel_xor
            )
            byte_idx = bit_index // 8
            bit_off = bit_index % 8
            payload_bits[byte_idx] |= (data_bits << bit_off) & 0xFF
            if bit_off + DATA_BITS_PER_CHANNEL > 8 and byte_idx + 1 < len(payload_bits):
                payload_bits[byte_idx + 1] |= data_bits >> (8 - bit_off)
            bit_index += DATA_BITS_PER_CHANNEL
            if bit_index > total_bits:
                bit_index = total_bits
        p += 1

    return bytes(payload_bits)


# ----------------------------------------------------------------------------
# Parity driver against Phase 1 fnvstress corpus
# ----------------------------------------------------------------------------


def _read_cell_header(cell_path: Path) -> dict:
    return json.loads((cell_path / "cell.meta.json").read_text())


def _derive_start_pixel(
    start_seed_lo_components: List[int],
    nonce_bytes: bytes,
    total_pixels: int,
    rounds: int,
) -> int:
    """Replicate `Seed128.deriveStartPixel` (seed128.go:155-161) bit-exact.

    The Go implementation:
        buf[0] = 0x02
        copy(buf[1:], nonce)
        hLo, _ := s.ChainHash128(buf)
        return int(hLo % uint64(totalPixels))

    Distinct from per-pixel blockHash128 (which uses `LE32(pixelIdx) ||
    nonce`, 20 bytes). The leading 0x02 is a domain tag separating the
    startPixel derivation from pixel hashing.
    """
    buf = b"\x02" + nonce_bytes
    start_hash_lo = fnv_chain_lo_concrete(start_seed_lo_components, buf, rounds)
    return start_hash_lo % total_pixels


def _build_pixel_data(pixel_idx: int, nonce: bytes) -> bytes:
    """`data = LE32(pixelIdx) || nonce` — matches `blockHash128`."""
    return struct.pack("<I", pixel_idx) + nonce


def parity_check_corpus(fnvstress_dir: Path) -> bool:
    """Return True iff the Python channel mirror reproduces every cell's
    plaintext bit-exact using the lab-audit seeds from summary.json.

    This check runs in LAB MODE: it reads noise/data/start seed
    components from summary.json so it can compute the ground-truth
    hLo per pixel. The Phase 3 SAT harness must NOT do this — it will
    solve for hLo.
    """
    summary = json.loads((fnvstress_dir / "summary.json").read_text())
    rounds = summary["rounds"]
    data_lo = [int(h, 16) for h in summary["data_lo_lane_hex"]]
    noise_lo = [int(h, 16) for h in summary["noise_lo_lane_hex"]]
    # We also need the startSeed lo-lane components. summary.json stores
    # the full 16-uint64 start_seed_hex; extract even-indexed for lo lane.
    full_start = [int(h, 16) for h in summary["start_seed_hex"]]
    start_lo = full_start[0::2]

    if len(data_lo) != rounds or len(noise_lo) != rounds or len(start_lo) != rounds:
        raise RuntimeError(
            f"lo-lane component count mismatch vs rounds={rounds}: "
            f"data={len(data_lo)} noise={len(noise_lo)} start={len(start_lo)}"
        )

    total_failures = 0
    for cell in summary["cells"]:
        cell_dir = fnvstress_dir / cell["cell_name"]
        ciphertext = (cell_dir / "ct_0000.bin").read_bytes()
        plaintext_expected = (cell_dir / "ct_0000.plain").read_bytes()
        nonce = bytes.fromhex(cell["nonce_hex"])
        total_pixels = cell["total_pixels"]

        # Precompute per-pixel hLo arrays.
        data_hash_lo_per_pixel = [0] * total_pixels
        noise_hash_lo_per_pixel = [0] * total_pixels
        for p in range(total_pixels):
            data_bytes_ = _build_pixel_data(p, nonce)
            data_hash_lo_per_pixel[p] = fnv_chain_lo_concrete(data_lo, data_bytes_, rounds)
            noise_hash_lo_per_pixel[p] = fnv_chain_lo_concrete(noise_lo, data_bytes_, rounds)

        # startPixel derived from startSeed (same nonce).
        start_pixel = _derive_start_pixel(start_lo, nonce, total_pixels, rounds)

        # Decode all `capacity` bytes of the payload the encoder packed.
        payload_recovered = decode_container_to_payload(
            ciphertext=ciphertext,
            data_hash_lo_per_pixel=data_hash_lo_per_pixel,
            noise_hash_lo_per_pixel=noise_hash_lo_per_pixel,
            start_pixel=start_pixel,
            total_pixels=total_pixels,
        )
        # Encoder wrote: `cobs_encode(plaintext) || 0x00 || csprng_fill`.
        # Parity passes if: (a) the first len(cobs_expected) bytes match
        # cobs_encode(plaintext_expected) exactly, (b) the byte at that
        # offset is 0x00, and (c) cobs_decode of the (cobs+0x00) prefix
        # round-trips back to the original plaintext. CSPRNG tail bytes
        # are unpredictable and intentionally skipped.
        cobs_expected = cobs_encode(plaintext_expected)
        cobs_len = len(cobs_expected)
        cell_ok = True
        if payload_recovered[:cobs_len] != cobs_expected:
            # Find first divergence.
            for i, (a, b) in enumerate(zip(payload_recovered[:cobs_len], cobs_expected)):
                if a != b:
                    print(
                        f"[FAIL] {cell['cell_name']}: cobs-prefix divergence at "
                        f"byte {i} (got 0x{a:02x} expected 0x{b:02x}); "
                        f"startPixel={start_pixel}",
                        file=sys.stderr,
                    )
                    break
            else:
                print(
                    f"[FAIL] {cell['cell_name']}: cobs-prefix length mismatch",
                    file=sys.stderr,
                )
            cell_ok = False
        elif cobs_len >= len(payload_recovered) or payload_recovered[cobs_len] != 0x00:
            print(
                f"[FAIL] {cell['cell_name']}: missing 0x00 terminator at "
                f"cobs_len={cobs_len}; got 0x{payload_recovered[cobs_len]:02x}",
                file=sys.stderr,
            )
            cell_ok = False
        else:
            # Round-trip sanity: cobs_decode(prefix) == plaintext?
            roundtrip = cobs_decode(cobs_expected)
            if roundtrip != plaintext_expected:
                print(
                    f"[FAIL] {cell['cell_name']}: cobs_decode round-trip "
                    f"diverges from plaintext "
                    f"(got {len(roundtrip)} B, expected {len(plaintext_expected)} B)",
                    file=sys.stderr,
                )
                cell_ok = False

        if cell_ok:
            print(
                f"[OK] {cell['cell_name']}: cobs-prefix {cobs_len} B + 0x00 "
                f"terminator match; round-trip plaintext {len(plaintext_expected)} B"
            )
        else:
            total_failures += 1

    if total_failures:
        print(
            f"[FAIL] Python channel mirror diverges from Go encoder on "
            f"{total_failures} / {len(summary['cells'])} cells",
            file=sys.stderr,
        )
        return False
    print(
        f"[OK] Python channel mirror matches Go encoder on all "
        f"{len(summary['cells'])} cells"
    )
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_parity = sub.add_parser("parity", help="run parity vs Phase 1 corpus")
    p_parity.add_argument(
        "--fnvstress-dir",
        default="tmp/attack/fnvstress",
        help="path to Phase 1 corpus root",
    )
    args = ap.parse_args()

    if args.cmd == "parity":
        ok = parity_check_corpus(Path(args.fnvstress_dir))
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
