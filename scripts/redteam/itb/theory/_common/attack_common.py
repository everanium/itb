"""Shared utilities for ITB attack simulations (Probe 1+).

Separate from `common.py` (which holds constants for the existing validation
suite) because attack orchestrators have a different safety discipline —
particularly around disk cleanup — that should not leak into the validation
tooling.

Responsibilities:
    - safe_rmtree — validated deletion helper (mandatory safety discipline)
    - cobs_encode — Python port of cobsEncode from cobs.go
    - parse_itb_header — extract main nonce + W + H + container from a
      Single Message wire `[prefix 32][main nonce N][W][H][container]`
    - SM_PREFIX_LEN / prefix_size_from_meta / header_size_from_meta /
      container_offset_from_meta — wire-offset helpers shared by every
      corpus reader
    - rotate7 / extract7 — 7-bit bit-manipulation helpers matching processChunk128
    - load_cell_meta / load_config_truth — JSON sidecar loaders
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# ----------------------------------------------------------------------------
# Constants (must match itb.go)
# ----------------------------------------------------------------------------

CHANNELS = 8
DATA_BITS_PER_CHANNEL = 7
DATA_BITS_PER_PIXEL = 56
DATA_ROTATION_BITS = 3

# Single Message wire prefix: 32 bytes ahead of the chunk header on every
# ITB wire (a CSPRNG dummy on the No MAC arm, the MAC-bound streamID on the
# MAC arm). Attacker-visible public bytes; derived from no seed. Corpus
# metadata carries it as `prefix_size`; a reader without metadata (a file
# from `itb3`, an in-memory wire) uses this constant.
SM_PREFIX_LEN = 32

# ----------------------------------------------------------------------------
# Deletion safety (mandatory for every attack orchestrator).
# ----------------------------------------------------------------------------

def safe_rmtree(target: Path, expected_parent: Path) -> None:
    """Delete target if and only if it resolves inside expected_parent.

    Enforces the deletion-safety discipline:
      1. target must be absolute after resolve()
      2. target must be inside expected_parent (raises ValueError on escape)
      3. skips silently if target does not exist (first-run convenience)
      4. logs the deletion before performing it

    Raises:
        ValueError: if target.resolve() is not inside expected_parent.resolve().
        OSError: if the rmtree itself fails (not caught silently).
    """
    target = target.resolve()
    expected_parent = expected_parent.resolve()
    # relative_to raises ValueError on escape — propagate, don't catch
    target.relative_to(expected_parent)
    if not target.exists():
        print(f"[cleanup] (skipped — does not exist) {target}")
        return
    print(f"[cleanup] shutil.rmtree({target})")
    shutil.rmtree(target, ignore_errors=False)


# ----------------------------------------------------------------------------
# COBS encoding (Python port of cobs.go:cobsEncode)
# ----------------------------------------------------------------------------

def cobs_encode(src: bytes) -> bytes:
    """Port of cobsEncode from cobs.go. Deterministic — no key/seed needed.

    The ITB Encrypt* pipeline wraps plaintext through cobsEncode before feeding
    it to process{128,256,512} as the encode-target "data". The attacker, under
    Full or Partial KPA, knows the public plaintext and can run cobs_encode
    locally — the result is a deterministic function of plaintext bytes.
    """
    out = bytearray()
    out.append(0)  # placeholder for first group code
    code_idx = 0
    code = 1
    for b in src:
        if b == 0:
            out[code_idx] = code
            code_idx = len(out)
            out.append(0)  # placeholder for next group code
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


def cobs_encode_with_mask(src: bytes, src_mask: bytes) -> Tuple[bytes, bytes]:
    """Parallel COBS encoding — emits (encoded, cobs_mask) where cobs_mask[i]
    is 1 iff output byte i is derived from known input (data byte inherited
    from src_mask) or is a structural code byte (always attacker-known, since
    COBS group lengths depend only on where 0x00 bytes fall in src — and under
    Partial KPA with the json_structured kind the attacker knows 0x00 positions
    never appear).

    Strictly: a structural code byte depends on where the NEXT 0x00 falls in
    src OR on 0xFF-reset boundaries (every 254 non-zero bytes). Both of those
    are visible to the attacker only if they know the positions of 0x00s in
    src. For the json_structured kind src contains NO 0x00 bytes (the
    generator excludes them by construction), so every code byte is either
    the fixed 0xFF (mid-stream reset at 254-byte boundaries) or the final
    group's length = 1 + (len(src) % 254) — both fully attacker-derivable
    from the public plaintext length. Hence every code byte is marked known.

    For plaintexts that contain 0x00 bytes (not applicable to Partial KPA) the
    code values still depend only on 0x00 positions in src; those positions
    are KNOWN only if every byte up to the next 0x00 is known. The logic
    here is slightly conservative — marks the code byte known iff EVERY src
    byte in the block was known. Safe for the json_structured use case.
    """
    if len(src) != len(src_mask):
        raise ValueError(f"cobs_encode_with_mask: src ({len(src)}) and src_mask "
                         f"({len(src_mask)}) length mismatch")
    out = bytearray()
    mask_out = bytearray()

    def append_code_placeholder():
        out.append(0)
        mask_out.append(1)  # provisionally mark known; updated if block has unknowns

    append_code_placeholder()
    code_idx = 0
    code = 1
    block_all_known = True

    def finalize_code_byte(block_known: bool):
        # out[code_idx] is already set by the caller; adjust its mask_out to
        # reflect whether EVERY byte in the block was known.
        if not block_known:
            mask_out[code_idx] = 0

    for i, b in enumerate(src):
        m = 1 if src_mask[i] else 0
        if b == 0:
            out[code_idx] = code
            finalize_code_byte(block_all_known)
            append_code_placeholder()
            code_idx = len(out) - 1
            code = 1
            block_all_known = True
        else:
            out.append(b)
            mask_out.append(m)
            if m == 0:
                block_all_known = False
            code += 1
            if code == 0xFF:
                out[code_idx] = code
                finalize_code_byte(block_all_known)
                append_code_placeholder()
                code_idx = len(out) - 1
                code = 1
                block_all_known = True
    out[code_idx] = code
    finalize_code_byte(block_all_known)
    return bytes(out), bytes(mask_out)


# ----------------------------------------------------------------------------
# ITB wire offsets + header parser — the Single Message wire emitted by Encrypt*
# ----------------------------------------------------------------------------

def prefix_size_from_meta(meta: Dict[str, Any]) -> int:
    """Bytes ahead of the main nonce: `meta["prefix_size"]`, else SM_PREFIX_LEN.

    Accepts the JSON `cell.meta.json` dict and the KEY=VALUE `.pixel`
    sidecar dict alike (values may be strings)."""
    return int(meta.get("prefix_size", SM_PREFIX_LEN))


def header_size_from_meta(meta: Dict[str, Any]) -> int:
    """Chunk header length (main nonce + W + H = N + 4), excluding the prefix.

    Reads `meta["header_size"]`; falls back to `len(main_nonce) + 4` from
    `main_nonce_hex` / `nonce_hex`. Raises ValueError when the metadata
    carries none of the three — guessing a header length misparses the
    container silently, so no literal default exists here."""
    if "header_size" in meta:
        return int(meta["header_size"])
    nonce_hex = meta.get("main_nonce_hex") or meta.get("nonce_hex")
    if nonce_hex:
        return len(nonce_hex) // 2 + 4
    raise ValueError(
        "metadata has no header_size / main_nonce_hex / nonce_hex field — "
        "cannot locate the container; regenerate the corpus"
    )


def container_offset_from_meta(meta: Dict[str, Any]) -> int:
    """Byte offset of the container in a corpus file: prefix_size + header_size."""
    return prefix_size_from_meta(meta) + header_size_from_meta(meta)


def parse_itb_header(
    ciphertext: bytes, nonce_size: int = 16, prefix_size: int = SM_PREFIX_LEN,
) -> Tuple[bytes, int, int, int, bytes]:
    """Parse a Single Message wire and return (nonce, W, H, totalPixels, container_body).

    Layout (P = prefix_size, N = nonce_size):
        [0 : P]                             prefix (public bytes, skipped)
        [P : P+N]                           main nonce
        [P+N : P+N+2]                       width  (uint16 BE)
        [P+N+2 : P+N+4]                     height (uint16 BE)
        [P+N+4 :]                           container_body = totalPixels × 8 bytes

    `nonce_size` is the chunk-header nonce width only; the prefix is passed
    separately (from `prefix_size_from_meta(meta)` when metadata is at hand)
    and is never folded into `nonce_size`.
    """
    header_size = nonce_size + 4
    offset = prefix_size + header_size
    if len(ciphertext) < offset:
        raise ValueError(
            f"ciphertext too short for prefix + header (got {len(ciphertext)}, "
            f"need ≥ {offset} = prefix {prefix_size} + header {header_size})"
        )
    nonce = ciphertext[prefix_size:prefix_size + nonce_size]
    w = int.from_bytes(ciphertext[prefix_size + nonce_size:prefix_size + nonce_size + 2], "big")
    h = int.from_bytes(ciphertext[prefix_size + nonce_size + 2:offset], "big")
    total_pixels = w * h
    container = ciphertext[offset:]
    expected_container = total_pixels * CHANNELS
    if len(container) != expected_container:
        raise ValueError(
            f"container size mismatch: got {len(container)}, expected {expected_container} "
            f"(W={w} × H={h} × {CHANNELS} channels; prefix {prefix_size}, header {header_size})"
        )
    return nonce, w, h, total_pixels, container


# ----------------------------------------------------------------------------
# 7-bit bit-manipulation helpers (matching itb.go:rotateBits7 + processChunk128 packing)
# ----------------------------------------------------------------------------

def rotate7_scalar(v: int, r: int) -> int:
    """Left-rotate a 7-bit value by r positions. Matches rotateBits7 in itb.go."""
    r %= 7
    return ((v << r) | (v >> (7 - r))) & 0x7F


def extract7_scalar(byte_val: int, noise_pos: int) -> int:
    """Inverse of the processChunk128 packing: given a container channel byte
    and the noisePos that was used during encoding, recover the 7 data bits by
    removing the noise bit and concatenating the remaining 7 bits in order.
    """
    low_mask = (1 << noise_pos) - 1
    low = byte_val & low_mask
    high = byte_val >> (noise_pos + 1)
    return (low | (high << noise_pos)) & 0x7F


# Precomputed lookup tables for vectorised Layer 1 constraint matching.
# ROT7_TABLE[r, v] = rotate7_scalar(v, r) for r ∈ 0..6, v ∈ 0..127
# EXTRACT7_TABLE[np, byte_val] = extract7_scalar(byte_val, np) for np ∈ 0..7, byte_val ∈ 0..255

ROT7_TABLE = np.zeros((7, 128), dtype=np.uint8)
for _r in range(7):
    for _v in range(128):
        ROT7_TABLE[_r, _v] = rotate7_scalar(_v, _r)

EXTRACT7_TABLE = np.zeros((8, 256), dtype=np.uint8)
for _np in range(8):
    for _b in range(256):
        EXTRACT7_TABLE[_np, _b] = extract7_scalar(_b, _np)


def get_bits7(payload: bytes, bit_idx: int) -> int:
    """Extract 7 data bits from payload starting at bit_idx. Matches the
    byte-crossing extraction in processChunk128."""
    byte_idx = bit_idx // 8
    bit_off = bit_idx % 8
    if byte_idx >= len(payload):
        return 0
    raw = payload[byte_idx]
    if byte_idx + 1 < len(payload):
        raw |= payload[byte_idx + 1] << 8
    return (raw >> bit_off) & 0x7F


# ----------------------------------------------------------------------------
# Cell metadata / ground-truth sidecar loaders
# ----------------------------------------------------------------------------

def load_cell_meta(cell_dir: Path) -> Dict[str, Any]:
    """Read cell.meta.json from a corpus cell directory."""
    meta_path = cell_dir / "cell.meta.json"
    with open(meta_path, "r") as f:
        return json.load(f)


def load_config_truth(cell_dir: Path) -> Dict[str, Any]:
    """Read config.truth.json (ground-truth per-pixel config; validation only)."""
    truth_path = cell_dir / "config.truth.json"
    with open(truth_path, "r") as f:
        return json.load(f)
