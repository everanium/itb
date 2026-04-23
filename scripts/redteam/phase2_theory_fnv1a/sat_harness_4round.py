#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 3b — ITB FNV-1a ChainHash128 SAT harness (keyBits=512, 4 rounds).

Consumes the Phase 1 fnvstress corpus (`tmp/attack/fnvstress/`) and
builds one global Z3 bitvector SAT instance over:

  - `rounds` × 64-bit unknown lo-lane seed components (256 unknowns
    total at keyBits=512).
  - Per crib pixel: 3-bit `noise_pos` + 3-bit `rotation` symbolic
    unknowns (6 bits per pixel). `rotation` is pinned by the solver
    via `dataHash % 7 == rotation` constraint; `noise_pos` is free.

Concessions (logged at startup, see `.FNVSTRESS.md` § 4.5):

  1. `startPixel` per cell is disclosed from the lab summary.json.
     Unknown-startPixel case is analytically extrapolated in the
     final report (multiply wall-clock by ~total_pixels/2).
  2. Multi-cell corpus stacking is over fresh nonces with shared
     (noiseSeed, dataSeed, startSeed) — strictly weaker than nonce
     reuse.

Strictly attacker-realistic inputs in the decision path:

  - Ciphertexts (`ct_0000.bin`) from every cell.
  - `startPixel` per cell (concession).
  - Per-cell crib list: (byte_start_in_plaintext, expected plaintext
    bytes). All expected plaintext bytes come from the public JSON /
    HTML schema the corpus was built with — PREDICTABLE without any
    access to the defender's data.
  - Nonces (attacker-visible in ciphertext header).

NOT used in decision path (forbidden by CLAUDE.md attacker-realism):

  - `noise_seed` / `data_seed` / `start_seed` components from
    summary.json / cell.meta.json. These are read ONLY for the
    final terminal-stage "did recovered seed match ground truth"
    audit line, after solve completes.

Usage:
    python3 sat_harness_4round.py [--fnvstress-dir DIR]
                                  [--max-cells N]
                                  [--max-cribs-per-cell N]
                                  [--timeout-sec 1800]
                                  [--json-report PATH]
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import resource
import struct
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed, FIRST_COMPLETED, wait
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Tuple

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from fnv_chain_lo_concrete import (  # type: ignore
    MASK64,
    fnv_chain_lo_concrete,
    fnv_chain_lo_z3,
)
from itb_channel_mirror import (  # type: ignore
    CHANNELS,
    DATA_BITS_PER_CHANNEL,
    DATA_BITS_PER_PIXEL,
    DATA_ROTATION_BITS,
    rotate_bits_7,
    cobs_encode,
    cobs_decode,
)


# ============================================================================
# Observation gathering
# ============================================================================


@dataclass
class ChannelObservation:
    """One per channel with known plaintext bits — an attacker constraint."""

    cell_idx: int
    linear_pixel: int        # container-space pixel index (== (startPixel + p) mod totalPixels)
    p: int                   # encoded-stream pixel index (0 = startPixel)
    channel: int             # 0..7
    observed_byte: int       # concrete container byte at (linear_pixel*8 + channel)
    plaintext_bits: int      # 7-bit known plaintext value for this channel
    data_bytes_hex: str      # LE32(p) || nonce — fed into ChainHash


@dataclass
class CellContext:
    """Per-cell data needed by the SAT encoder."""

    cell_idx: int
    cell_name: str
    nonce: bytes
    total_pixels: int
    start_pixel: int
    container: bytes         # ciphertext minus 20-byte header
    plaintext_expected: bytes  # lab-only, for terminal-stage audit
    cobs_encoded: bytes      # cobs_encode(plaintext_expected) — public-schema predictable
    observations: List[ChannelObservation] = field(default_factory=list)


def _pixel_data_bytes(pixel_idx: int, nonce: bytes) -> bytes:
    return struct.pack("<I", pixel_idx) + nonce


def _extract_7bit_window_from_plaintext(
    plaintext_bytes: bytes, bit_index: int
) -> Optional[int]:
    """Return the 7 bit plaintext window at `bit_index` from `plaintext_bytes`.

    Matches `processChunk128`'s `raw = data[byteIdx] | data[byteIdx+1]<<8;
    dataBits = (raw >> bitOff) & 0x7F`. Returns None if either of the
    two plaintext bytes needed is outside `plaintext_bytes`.
    """
    byte_idx = bit_index // 8
    bit_off = bit_index % 8
    if byte_idx >= len(plaintext_bytes):
        return None
    lo = plaintext_bytes[byte_idx]
    hi = plaintext_bytes[byte_idx + 1] if byte_idx + 1 < len(plaintext_bytes) else None
    # Need hi if bit_off + 7 > 8 i.e. bit_off > 1.
    if bit_off > 1 and hi is None:
        return None
    raw = lo | ((hi or 0) << 8)
    return (raw >> bit_off) & 0x7F


def _build_cell_context(
    fnvstress_dir: Path,
    cell_info: dict,
    cell_idx: int,
    max_cribs: Optional[int],
    start_pixel_override: Optional[int] = None,
) -> CellContext:
    cell_dir = fnvstress_dir / cell_info["cell_name"]
    meta = json.loads((cell_dir / "cell.meta.json").read_text())
    ciphertext = (cell_dir / "ct_0000.bin").read_bytes()
    plaintext_expected = (cell_dir / "ct_0000.plain").read_bytes()
    nonce = bytes.fromhex(cell_info["nonce_hex"])
    total_pixels = cell_info["total_pixels"]

    if start_pixel_override is not None:
        # Brute-force candidate path: do NOT consult lab-audit startSeed.
        # The caller is enumerating 0..total_pixels-1 and will accept
        # whichever candidate produces a sat model.
        start_pixel = start_pixel_override % total_pixels
    else:
        # startPixel concession (disclosed, see `.FNVSTRESS.md` § 4.5):
        # compute from the lab-audit startSeed components.
        summary = json.loads((fnvstress_dir / "summary.json").read_text())
        full_start = [int(h, 16) for h in summary["start_seed_hex"]]
        start_lo = full_start[0::2]
        rounds = summary["rounds"]
        # Replicate Seed128.deriveStartPixel: [0x02] || nonce, then hLo % totalPixels.
        start_hash_lo = fnv_chain_lo_concrete(start_lo, b"\x02" + nonce, rounds)
        start_pixel = start_hash_lo % total_pixels

    container = ciphertext[20:]  # strip nonce (16) + W/H (4)
    cobs_encoded = cobs_encode(plaintext_expected)

    # Attacker-visible crib material: the public-schema byte ranges.
    # meta["cribs"] is a list of {record_index, byte_start_in_plaintext,
    # byte_len, expected_hex, anchor_kind?}. The byte_start is relative
    # to raw plaintext (pre-COBS). After COBS framing they shift by the
    # overhead bytes; we re-derive the encoded-stream offsets below.
    cribs_meta: List[dict] = meta["cribs"]

    # Build record cribs (anchor_kind == "") first; anchor handled separately.
    record_cribs = [c for c in cribs_meta if not c.get("anchor_kind")]
    anchor_cribs = [c for c in cribs_meta if c.get("anchor_kind") == "cobs_ff_overhead"]
    if max_cribs is not None:
        record_cribs = record_cribs[:max_cribs]

    ctx = CellContext(
        cell_idx=cell_idx,
        cell_name=cell_info["cell_name"],
        nonce=nonce,
        total_pixels=total_pixels,
        start_pixel=start_pixel,
        container=container,
        plaintext_expected=plaintext_expected,
        cobs_encoded=cobs_encoded,
    )

    # --- Anchor: the COBS overhead byte at encoded-stream offset 0. ---
    # For plaintexts containing no 0x00, cobs_encode output starts with
    # byte 0xFF when the first run length > 254 (always true here at
    # keyBits=512 / ~1641 B JSON and ~1845 B HTML). We verify and expose
    # the anchor as 7 consecutive plaintext bytes (0xFF plus the first
    # 6 bytes of record 0 — all public-schema).
    if anchor_cribs and cobs_encoded[0] == 0xFF:
        # Encoded-stream byte 0 is 0xFF. The next 6 bytes of the encoded
        # stream are record-0 schema bytes (which are at plaintext[0..5]
        # in the original — COBS just prepends one overhead byte since
        # no 0x00 in first 254 bytes). cobs_encoded[1..6] = plaintext[0..5].
        # But the encoder writes the entire `cobs_encoded || 0x00 || fill`
        # stream starting at encoded_byte 0 → which maps to bitIndex 0 →
        # pixel 0 (i.e. linear_idx = start_pixel).
        # Build 8 channel observations for the anchor pixel.
        anchor_pixel = 0  # p-coordinate (startPixel-local)
        for ch in range(CHANNELS):
            bit_index = anchor_pixel * DATA_BITS_PER_PIXEL + ch * DATA_BITS_PER_CHANNEL
            plaintext_bits = _extract_7bit_window_from_plaintext(
                cobs_encoded, bit_index
            )
            if plaintext_bits is None:
                break
            linear_pixel = (start_pixel + anchor_pixel) % total_pixels
            observed = container[linear_pixel * CHANNELS + ch]
            ctx.observations.append(ChannelObservation(
                cell_idx=cell_idx,
                linear_pixel=linear_pixel,
                p=anchor_pixel,
                channel=ch,
                observed_byte=observed,
                plaintext_bits=plaintext_bits,
                data_bytes_hex=_pixel_data_bytes(anchor_pixel, nonce).hex(),
            ))

    # --- Record cribs: 21 known bytes per crib, split across 3-4 pixels. ---
    # Each record crib's public prefix sits in the RAW plaintext at
    # byte_start_in_plaintext. After COBS framing it shifts by 1 (the
    # initial 0xFF overhead) plus 1 extra for every 254-byte group
    # boundary it has crossed. We re-derive per-crib encoded offset by
    # searching cobs_encoded for the known byte sequence — unambiguous
    # when the sequence contains the record's 8-digit hex index (unique
    # per record).
    for crib in record_cribs:
        expected = bytes.fromhex(crib["expected_hex"])
        pt_offset = crib["byte_start_in_plaintext"]
        # Encoded offset: plaintext byte N at index N in original plaintext
        # becomes cobs_encoded[N + 1 + (N // 254)] — because each 254-byte
        # group of non-zero bytes starts with one overhead byte.
        # (Our structured plaintext has no 0x00, so groups are exactly
        # 254 non-zero runs.)
        encoded_offset = pt_offset + 1 + (pt_offset // 254)
        # Sanity: verify that cobs_encoded[encoded_offset : encoded_offset +
        # byte_len] == expected; skip the crib otherwise (a group boundary
        # might split it — we don't handle that edge case in the first pass).
        if encoded_offset + len(expected) > len(cobs_encoded):
            continue
        if cobs_encoded[encoded_offset:encoded_offset + len(expected)] != expected:
            # Group boundary split the crib — the expected bytes are no
            # longer contiguous in encoded form. Skip (rare; can be
            # recovered by reading cobs_encoded[offset:offset+len+2] and
            # accounting for group boundary, but deferred).
            continue

        # For each byte of the crib, determine which (pixel, channel)
        # window covers its bits. A 7-bit ITB window spans bits
        # [bit_index, bit_index+7). plaintext byte M spans bits
        # [8M, 8M+8). Overlap is non-trivial because 7 and 8 don't align.
        bit_start = encoded_offset * 8
        bit_end = (encoded_offset + len(expected)) * 8

        # Enumerate every 7-bit ITB window that lies ENTIRELY within
        # the crib-byte-range. A window at bit_index i spans i..i+7; we
        # need all 7 bits of its plaintext to come from known bytes,
        # which means both cobs_encoded[i//8] and cobs_encoded[(i+7)//8]
        # are inside [encoded_offset, encoded_offset+len(expected)).
        first_window = (bit_start + DATA_BITS_PER_CHANNEL - 1) // DATA_BITS_PER_CHANNEL * DATA_BITS_PER_CHANNEL
        window_idx = first_window
        while window_idx + DATA_BITS_PER_CHANNEL <= bit_end:
            last_byte_needed = (window_idx + DATA_BITS_PER_CHANNEL - 1) // 8
            if last_byte_needed >= encoded_offset + len(expected):
                break
            p_idx = window_idx // DATA_BITS_PER_PIXEL
            ch = (window_idx // DATA_BITS_PER_CHANNEL) % CHANNELS
            plaintext_bits = _extract_7bit_window_from_plaintext(
                cobs_encoded, window_idx
            )
            if plaintext_bits is None:
                break
            linear_pixel = (start_pixel + p_idx) % total_pixels
            observed = container[linear_pixel * CHANNELS + ch]
            ctx.observations.append(ChannelObservation(
                cell_idx=cell_idx,
                linear_pixel=linear_pixel,
                p=p_idx,
                channel=ch,
                observed_byte=observed,
                plaintext_bits=plaintext_bits,
                data_bytes_hex=_pixel_data_bytes(p_idx, nonce).hex(),
            ))
            window_idx += DATA_BITS_PER_CHANNEL

    return ctx


# ============================================================================
# Python-side sanity: do the observations we collected satisfy the plaintext
# when we plug in the lab-audit ground-truth seeds? Without this the SAT is
# on sand. This check is LAB ONLY — never runs in the SAT logic.
# ============================================================================


def _sanity_observations(
    ctx: CellContext,
    data_lo: List[int],
    noise_lo: List[int],
    rounds: int,
) -> int:
    """Return number of observations where the lab ground-truth reproduces
    the observed byte (via the concrete Python mirror). MUST equal
    len(ctx.observations) — else the observation-building code is buggy."""
    from itb_channel_mirror import (
        _derive_pixel_params, _derive_noise_pos,
        extract_channel_xor, rotate_bits_7,
    )
    ok = 0
    for o in ctx.observations:
        data_bytes_ = bytes.fromhex(o.data_bytes_hex)
        dh = fnv_chain_lo_concrete(data_lo, data_bytes_, rounds)
        nh = fnv_chain_lo_concrete(noise_lo, data_bytes_, rounds)
        rotation, _ = _derive_pixel_params(dh)
        noise_pos = _derive_noise_pos(nh)
        channel_xor = extract_channel_xor(dh, o.channel)
        # Re-encode plaintext bits the way the encoder does:
        data_bits = (o.plaintext_bits & 0x7F) ^ channel_xor
        data_bits = rotate_bits_7(data_bits, rotation)
        noise_mask = 1 << noise_pos
        low = data_bits & (noise_mask - 1)
        high = data_bits >> noise_pos
        expected = (
            low | (o.observed_byte & noise_mask) | (high << (noise_pos + 1))
        ) & 0xFF
        if expected == o.observed_byte:
            ok += 1
    return ok


# ============================================================================
# Z3 SAT encoding
# ============================================================================


def _z3_mod7_of_64bit(z3, bv64):
    """Compute `bv64 % 7` as a BitVec(3), bit-blasting much cheaper than
    the direct `URem(bv64, 7)` subcircuit.

    Identity: 2³ ≡ 1 (mod 7) ⇒ `x mod 7 ≡ (Σ 3-bit chunks of x) (mod 7)`.
    A 64-bit value splits into 21 chunks of 3 bits covering bits 0..62,
    with bit 63 remaining (which is 2⁶³ ≡ 1 (mod 7) since 63 = 3·21, so
    bit 63 contributes +1 if set). The chunk sum fits in a few 8-bit
    values (max 21·7 + 1 = 148), so a final small 8-bit `URem` is
    ~150 gates — vs ~8 k gates for the 64-bit URem with divisor 7.

    Expected ~50× reduction on the rotation constraint alone, applied
    to every crib pixel (§ 8.6 optimisation #1).
    """
    BitVecVal = z3.BitVecVal
    ZeroExt = z3.ZeroExt
    Extract = z3.Extract

    # 21 chunks of 3 bits from positions [0,2], [3,5], ..., [60,62].
    # Plus bit 63 as a 1-bit value contributing +1 if set.
    chunks = []
    for i in range(0, 63, 3):
        chunks.append(ZeroExt(5, Extract(i + 2, i, bv64)))  # BV(8)
    # Bit 63 contribution (value 1 if set).
    chunks.append(ZeroExt(7, Extract(63, 63, bv64)))  # BV(8)

    total8 = chunks[0]
    for c in chunks[1:]:
        total8 = total8 + c  # sums stay ≤ 148 < 256, no overflow

    rem8 = z3.URem(total8, BitVecVal(7, 8))  # small 8-bit URem
    return Extract(2, 0, rem8)


def _z3_rotate7(z3, v, r_sym):
    """Rotate a Z3 BitVec(8) (low 7 bits hold the value) left by r_sym (BitVec(3)).

    NOTE: Optimisation #3 (symbolic-shift barrel rotation) was tried
    and REGRESSED on Bitwuzla from 130 s to 464 s on the tiny baseline
    — BV(8) shift-by-BV(8) bit-blasts as a full 3-level barrel shifter
    ×2 (one for left, one for right), which generates more gates than
    the 7-way If-cascade below. Reverted. If-cascade confirmed as
    the best tested form on Bitwuzla 0.9.0 for this rotation.
    """
    If = z3.If
    # Produce each of 7 candidates and select via If cascade.
    def rot(k):
        if k == 0:
            return v
        mask = z3.BitVecVal(0x7F, 8)
        left = (v << k) & mask
        right = (v >> (7 - k)) & mask
        return left | right
    out = rot(6)
    for k in range(5, -1, -1):
        out = If(r_sym == k, rot(k), out)
    return out


def _extract_7bits_around_noise_pos(z3, byte_sym, np_sym):
    """Given an 8-bit container byte and a 3-bit noise_pos, return the 7
    plaintext bits (low..high excluding the bit at noise_pos) packed
    into a BitVec(8) (bit 7 is always 0).

    Optimisation #2 (§ 8.6): symbolic shift-mask-or — one unified
    bit-level formula instead of an 8-way If-cascade. Per case the
    prior form emitted ~50 gates × 8 branches = ~400 per channel.
    This form uses symbolic shift-by-3-bit, which Z3 / Bitwuzla
    bit-blast as a 3-level mux — ~70 gates total. ~6× gate reduction
    per channel × 8 channels × 13 crib pixels ≈ 36 k gates saved.
    """
    BitVecVal = z3.BitVecVal
    LShR = z3.LShR
    ZeroExt = z3.ZeroExt

    # Promote np_sym (3-bit) to 8-bit shift amount.
    np8 = ZeroExt(5, np_sym)
    # Low mask: (1 << np) - 1. Implemented as LShR of 0xFF by (8 - np).
    # When np = 0: mask = 0; when np = 7: mask = 0x7F.
    # Use (0x01 << np) - 1, but shift-by-symbolic with BV(8) is
    # native in both solvers.
    one_shifted = (BitVecVal(1, 8) << np8)
    mask_lo = one_shifted - BitVecVal(1, 8)  # 0 for np=0 ... 0x7F for np=7
    low = byte_sym & mask_lo
    # High bits: byte_sym >> (np + 1), shifted back up by np.
    np1 = np8 + BitVecVal(1, 8)
    high = LShR(byte_sym, np1)
    return (low | (high << np8)) & BitVecVal(0x7F, 8)


@dataclass
class SolveResult:
    cells: int
    total_observations: int
    unknowns_seed_bits: int
    unknowns_ambiguity_bits: int
    status: str
    wall_clock_sec: float
    memory_rss_kb: int
    recovered_seed_lo_hex: List[str]
    matches_ground_truth: bool  # bit-exact component match — expected False by CRC128 paradigm
    training_forward_ok: int    # # of training observations where recovered seed reproduces observed_byte
    training_forward_total: int
    holdout_forward_ok: int     # # of held-out observations (different cell) that recovered seed reproduces
    holdout_forward_total: int
    holdout_functionally_equivalent: bool  # holdout_forward_ok == holdout_forward_total AND > 0
    sanity_observations_ok: int
    sanity_observations_total: int
    note: str = ""


def _forward_check_one(
    observation: ChannelObservation,
    recovered_data_lo: List[int],
    rounds: int,
) -> bool:
    """Check: does the recovered data-seed, combined with SOME noise_pos
    in 0..7 (brute-forced), reproduce this observation's observed_byte?

    Attacker-realistic. A real attacker recovers only the data-seed
    compound state via SAT; for each new pixel they enumerate all 8
    noise_pos values trivially (3 bits) and accept whichever one
    reproduces the observed byte. If ANY noise_pos makes the concrete
    encoder match the ciphertext, the data-seed recovery succeeded for
    this channel — the specific noise_pos value is a per-pixel detail,
    not a seed-level secret. This is the same reduction as Phase 2f
    (where K_noise_bits_0_2 was recovered separately from K_data).
    """
    from itb_channel_mirror import (
        _derive_pixel_params,
        extract_channel_xor, rotate_bits_7,
    )

    data_bytes_ = bytes.fromhex(observation.data_bytes_hex)
    dh = fnv_chain_lo_concrete(recovered_data_lo, data_bytes_, rounds)
    rotation, _ = _derive_pixel_params(dh)
    channel_xor = extract_channel_xor(dh, observation.channel)
    data_bits = (observation.plaintext_bits & 0x7F) ^ channel_xor
    data_bits = rotate_bits_7(data_bits, rotation)
    for noise_pos in range(8):
        noise_mask = 1 << noise_pos
        low = data_bits & (noise_mask - 1)
        high = data_bits >> noise_pos
        expected = (
            low | (observation.observed_byte & noise_mask) | (high << (noise_pos + 1))
        ) & 0xFF
        if expected == observation.observed_byte:
            return True
    return False


def _solve_via_bitwuzla(
    smt2_text: str,
    seed_var_names: List[str],
    timeout_sec: int,
    quiet: bool = False,
) -> Tuple[str, List[int]]:
    """Pipe the SMT-LIB2 dump through the Bitwuzla CLI, parse `sat`/
    `unsat`/`unknown` + per-variable model values for `seed_var_names`.

    Subprocess call is wrapped with `subprocess.run(timeout=...)` which
    is the HARD wall-clock cap Bitwuzla honors across every phase
    (parse + preprocess + bit-blast + SAT loop). That guarantee is what
    distinguishes this path from Z3's `solver.set('timeout', ms)` which
    applies only to CDCL. Attacker-realism unaffected — Bitwuzla is
    public, `yay -S bitwuzla` is the single-command install.

    Returns ("sat"|"unsat"|"timeout"|"unknown", [model_value_per_name]).
    """
    import subprocess
    import tempfile
    import re

    # Z3's `to_smt2()` already appends `(check-sat)`. We append only
    # `(get-value ...)` queries after it (and optional `(exit)`).
    # Double `(check-sat)` caused Bitwuzla to evaluate get-value
    # against a stale model state, which surfaced as wrong seed bytes
    # in early testing (training_forward 15/31 instead of 31/31).
    value_queries = "\n".join(f"(get-value ({name}))" for name in seed_var_names)
    smt2_full = smt2_text.rstrip() + "\n" + value_queries + "\n(exit)\n"

    with tempfile.NamedTemporaryFile("w", suffix=".smt2", delete=False) as fh:
        fh.write(smt2_full)
        smt2_path = fh.name

    try:
        proc = subprocess.run(
            ["bitwuzla",
             "--produce-models",
             "--print-model",
             "--time-limit", str(timeout_sec * 1000),
             smt2_path],
            capture_output=True, text=True,
            timeout=timeout_sec + 60,  # outer safety margin
        )
        # NOTE: Tried `--sat-solver=kissat --abstraction-inc-bitblast`
        # for an extra speedup — REGRESSION from 130 s (CaDiCaL default)
        # to 281 s on the tiny baseline. Kissat beats CaDiCaL on many
        # QF_BV benchmarks but not this FNV-chain formula; the
        # incremental bvmul bit-blast apparently fights Bitwuzla's
        # default abstraction heuristic. Reverted to CaDiCaL default.
    except subprocess.TimeoutExpired:
        return ("timeout", [])
    finally:
        try:
            import os as _os
            _os.unlink(smt2_path)
        except Exception:
            pass

    out = proc.stdout
    if not quiet and proc.returncode not in (0, 10, 20):
        # 10 = sat, 20 = unsat per SMT-LIB convention
        print(
            f"[bitwuzla] exit={proc.returncode} stderr={proc.stderr[:200]!r}",
            file=sys.stderr,
        )
    first_line = (out.splitlines() or [""])[0].strip()
    if first_line == "sat":
        status = "sat"
    elif first_line == "unsat":
        status = "unsat"
    elif first_line in ("timeout", "unknown"):
        status = first_line
    else:
        status = "unknown"

    model_values: List[int] = []
    if status == "sat":
        for name in seed_var_names:
            # Bitwuzla output for (get-value (s_lo_0)) is
            # `((s_lo_0 #x...hexdigits..))` with 64 hex chars, OR
            # `((s_lo_0 #b...bits...))`.
            m = re.search(
                rf"\({re.escape(name)}\s+(#x[0-9a-fA-F]+|#b[01]+)\s*\)", out
            )
            if not m:
                model_values.append(0)
                continue
            tok = m.group(1)
            if tok.startswith("#x"):
                model_values.append(int(tok[2:], 16) & MASK64)
            else:
                model_values.append(int(tok[2:], 2) & MASK64)
    return (status, model_values)


def solve(
    cells: List[CellContext],
    rounds: int,
    data_lo_truth: List[int],
    noise_lo_truth: List[int],
    timeout_sec: int,
    holdout_cells: Optional[List[CellContext]] = None,
    skip_sanity: bool = False,
    quiet: bool = False,
    solver_backend: str = "z3",
    np_anchor_pin: Optional[int] = None,
) -> SolveResult:
    import z3
    from z3 import BitVec, BitVecVal, And, Or, Solver, sat, unsat, unknown

    total_obs = sum(len(c.observations) for c in cells)
    if total_obs == 0:
        raise RuntimeError("no observations gathered; nothing to solve")

    # ----- Sanity: lab ground truth must satisfy every observation. -----
    # Skipped when caller is enumerating wrong startPixel candidates — for
    # those, observations map the container to wrong pixels by design
    # and the ground-truth check would trivially fail.
    total_sanity_ok = 0
    if not skip_sanity:
        for c in cells:
            total_sanity_ok += _sanity_observations(
                c, data_lo_truth, noise_lo_truth, rounds
            )
        if total_sanity_ok != total_obs:
            raise RuntimeError(
                f"observation sanity check FAILED: {total_sanity_ok} / "
                f"{total_obs} observations reproduce under lab ground truth — "
                "SAT is on sand, aborting before solver invocation."
            )
        if not quiet:
            print(
                f"[sanity] lab ground truth reproduces all {total_obs} "
                "observations ✓"
            )

    # ----- Build the SAT instance. -----
    # Symbolic unknowns.
    seed_lo_syms = [BitVec(f"s_lo_{i}", 64) for i in range(rounds)]

    # For each unique (cell_idx, p) encountered, one (noise_pos, rotation)
    # pair + one cached symbolic dataHash.
    pixel_cache: dict[Tuple[int, int], Tuple[object, object, object]] = {}

    def pixel_symbols(cell_idx: int, p: int, data_bytes_hex: str):
        key = (cell_idx, p)
        if key in pixel_cache:
            return pixel_cache[key]
        np_sym = BitVec(f"np_c{cell_idx}_p{p}", 3)
        rot_sym = BitVec(f"rot_c{cell_idx}_p{p}", 3)
        data_bytes_ = bytes.fromhex(data_bytes_hex)
        data_hash_sym = fnv_chain_lo_z3(z3, seed_lo_syms, data_bytes_, rounds)
        pixel_cache[key] = (np_sym, rot_sym, data_hash_sym)
        return pixel_cache[key]

    solver = Solver()
    # Wall-clock timeout only. `rlimit` was tried briefly but it fires
    # even on cases that would legitimately succeed under wall-clock —
    # it cuts Z3 off mid-preprocess when the instance needs more than
    # ~10M instructions, which is short of true-sp solves that did
    # succeed in earlier tiny runs at ~443 s. For brute-force sweeps
    # the cost is that wrong-sp candidates can hang longer than
    # wall-clock in bit-blast phase; accept that as the price of
    # giving true candidates a real chance to complete.
    solver.set("timeout", int(timeout_sec * 1000))

    def eight(x):
        return z3.ZeroExt(8 - x.size(), x) if x.size() < 8 else x

    for c in cells:
        for o in c.observations:
            np_sym, rot_sym, data_hash_sym = pixel_symbols(
                c.cell_idx, o.p, o.data_bytes_hex
            )
            # rotation < 7 constraint (rotation ∈ {0..6}).
            solver.add(z3.ULT(rot_sym, BitVecVal(7, 3)))
            # rotation == dataHash % 7 — NECESSARY (see comment below),
            # encoded via optimisation #1 from `.FNVSTRESS.md` § 8.6:
            # sum-of-3-bit-chunks trick based on `2^3 ≡ 1 (mod 7)`.
            # ~50× fewer gates than naive `URem(BV(64), 7)`. Parity
            # with native `x % 7` verified on 10 000 random uint64
            # samples before enabling. Earlier removal of this tie-
            # down broke correctness: surfaced as training_forward
            # 15-18/31 instead of the required 31/31 invariant.
            solver.add(rot_sym == _z3_mod7_of_64bit(z3, data_hash_sym))

            # channelXOR for this channel: (data_hash >> (3 + 7*ch)) & 0x7F
            shift_amount = DATA_ROTATION_BITS + DATA_BITS_PER_CHANNEL * o.channel
            channel_xor = z3.Extract(
                shift_amount + 6, shift_amount, data_hash_sym
            )  # 7-bit

            # Encoded data bits: rotate7(plaintext ^ channelXOR, rotation)
            pt_bits = BitVecVal(o.plaintext_bits, 7)
            xor_bits = channel_xor  # BitVec(7)
            xored = pt_bits ^ xor_bits
            # Extend to 8 bits (high bit 0) for rotate helper.
            xored8 = z3.ZeroExt(1, xored)
            encoded_dataBits = _z3_rotate7(z3, xored8, rot_sym)  # BitVec(8), top bit == 0

            # Observed 7 data bits (with noise bit stripped).
            observed_sym = BitVecVal(o.observed_byte, 8)
            obs_7 = _extract_7bits_around_noise_pos(z3, observed_sym, np_sym)
            solver.add(encoded_dataBits == obs_7)

    # ----- Cube-and-conquer anchor-np pin (optional). -----
    # When `np_anchor_pin` is set, add one concrete assertion forcing
    # the first crib pixel's noise_pos to that 3-bit value. Cube-worker
    # dispatch enumerates 0..7 externally and runs 8 cubes in parallel.
    if np_anchor_pin is not None:
        if not cells or not cells[0].observations:
            raise RuntimeError(
                "np_anchor_pin set but no training observations to pin"
            )
        anchor_p = cells[0].observations[0].p  # first observation = anchor pixel
        anchor_key = (cells[0].cell_idx, anchor_p)
        if anchor_key not in pixel_cache:
            raise RuntimeError(
                f"anchor pixel {anchor_key} not in pixel_cache — cannot pin np"
            )
        np_sym_anchor, _rot_sym, _dh_sym = pixel_cache[anchor_key]
        solver.add(np_sym_anchor == BitVecVal(np_anchor_pin & 7, 3))
        if not quiet:
            print(
                f"[C&C] pinned anchor pixel (cell 0, p={anchor_p}) "
                f"noise_pos = {np_anchor_pin}"
            )

    # ----- Report SAT instance size. -----
    ambig_bits = 6 * len(pixel_cache)
    seed_bits = 64 * rounds
    if not quiet:
        print(
            f"[sat] built instance: {len(cells)} cells, {total_obs} observations, "
            f"{len(pixel_cache)} distinct crib pixels, "
            f"{seed_bits} seed bits + {ambig_bits} ambiguity bits = "
            f"{seed_bits + ambig_bits} unknowns"
        )

    # ----- Solve. -----
    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    t0 = time.perf_counter()
    recovered: List[int] = []
    matches = False
    training_ok = 0
    holdout_ok = 0
    holdout_total = 0

    if solver_backend == "bitwuzla":
        # Dump the Z3-built formula as SMT-LIB2, ship it to the
        # `bitwuzla` CLI via subprocess. This gives us Bitwuzla's
        # faster QF_BV bit-blaster + CaDiCaL / Kissat / CryptoMiniSat
        # SAT backends and — crucially — a hard subprocess timeout that
        # is honored across every solver phase (unlike Z3's `timeout`
        # parameter which applies to CDCL only). See `.FNVSTRESS.md`
        # § 8.5 "bit-blasting bottleneck" for the Z3 failure mode that
        # drove this decision.
        smt2_text = solver.to_smt2()
        seed_names = [f"s_lo_{i}" for i in range(rounds)]
        bw_status, bw_values = _solve_via_bitwuzla(
            smt2_text, seed_names, timeout_sec, quiet=quiet,
        )
        status = bw_status
        if status == "sat":
            recovered = bw_values[: rounds] + [0] * max(0, rounds - len(bw_values))
    else:
        # Z3 path (default).
        check = solver.check()
        status = str(check)
        if check == sat:
            model = solver.model()
            for sym in seed_lo_syms:
                v = model.eval(sym, model_completion=True)
                recovered.append(int(v.as_long()) & MASK64)
        elif check == unknown:
            reason = solver.reason_unknown()
            if "timeout" in reason.lower() or "canceled" in reason.lower():
                status = "timeout"
            else:
                status = f"unknown ({reason})"

    wall = time.perf_counter() - t0
    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    mem_kb = max(rusage_after.ru_maxrss, rusage_before.ru_maxrss)

    if status == "sat" and recovered:
        matches = all(recovered[i] == data_lo_truth[i] for i in range(rounds))

        # Training-forward check: recovered seed re-encodes every
        # training observation correctly under SOME noise_pos in 0..7?
        # Must be True by SAT construction; any miss signals an
        # encoding bug.
        for c in cells:
            for o in c.observations:
                if _forward_check_one(o, recovered, rounds):
                    training_ok += 1

        # Holdout: observations from held-out cells (different nonce,
        # same seeds). If recovered data-seed is functionally equivalent
        # to ground truth, every observation must be reproducible under
        # some noise_pos (brute-forced per pixel).
        if holdout_cells:
            for c in holdout_cells:
                for o in c.observations:
                    holdout_total += 1
                    if _forward_check_one(o, recovered, rounds):
                        holdout_ok += 1

    return SolveResult(
        cells=len(cells),
        total_observations=total_obs,
        unknowns_seed_bits=seed_bits,
        unknowns_ambiguity_bits=ambig_bits,
        status=status,
        wall_clock_sec=wall,
        memory_rss_kb=mem_kb,
        recovered_seed_lo_hex=[f"{v:016x}" for v in recovered],
        matches_ground_truth=matches,
        training_forward_ok=training_ok,
        training_forward_total=total_obs,
        holdout_forward_ok=holdout_ok,
        holdout_forward_total=holdout_total,
        holdout_functionally_equivalent=(
            holdout_total > 0 and holdout_ok == holdout_total
        ),
        sanity_observations_ok=total_sanity_ok,
        sanity_observations_total=total_obs,
    )


# ============================================================================
# Cube-and-conquer — split a single SAT instance into cubes by external
# enumeration of the anchor pixel's noise_pos (8 values), run cubes in
# parallel, first-sat-wins short-circuit. Helps when a single SAT
# instance does not converge in wall-clock but a smaller subproblem
# (with one 3-bit ambiguity pinned) does.
# ============================================================================


def _cc_worker(worker_args: dict) -> dict:
    """Top-level worker for cube-and-conquer ProcessPoolExecutor.

    Rebuilds the training cells from the supplied info dicts, forces a
    concrete value for the anchor pixel's `noise_pos` SAT unknown (cube
    split), runs Bitwuzla, returns status + recovered seed + training/
    holdout forward-check stats. RLIMIT_AS installed before heavy work.
    """
    memory_limit_mb = worker_args.get("memory_limit_mb", 5120)
    try:
        limit_bytes = memory_limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
    except (ValueError, OSError) as exc:
        print(f"[cc-worker-warn] could not install RLIMIT_AS={memory_limit_mb}MB: {exc}",
              file=sys.stderr)

    np_anchor_value = worker_args["np_anchor_value"]
    fnvstress_dir = Path(worker_args["fnvstress_dir_str"])
    training_infos = worker_args["training_infos"]
    training_max_cribs = worker_args["training_max_cribs"]
    holdout_infos = worker_args["holdout_infos"]
    holdout_max_cribs = worker_args["holdout_max_cribs"]
    rounds = worker_args["rounds"]
    data_lo_truth = worker_args["data_lo_truth"]
    noise_lo_truth = worker_args["noise_lo_truth"]
    per_cube_timeout_sec = worker_args["per_cube_timeout_sec"]
    solver_backend = worker_args.get("solver_backend", "bitwuzla")

    training: List[CellContext] = []
    for idx, ci in enumerate(training_infos):
        training.append(_build_cell_context(
            fnvstress_dir, ci, idx, training_max_cribs,
        ))
    holdout: List[CellContext] = []
    for idx, ci in enumerate(holdout_infos):
        holdout.append(_build_cell_context(
            fnvstress_dir, ci, len(training_infos) + idx, holdout_max_cribs,
        ))

    try:
        result = _solve_with_anchor_np_pinned(
            cells=training,
            rounds=rounds,
            data_lo_truth=data_lo_truth,
            noise_lo_truth=noise_lo_truth,
            timeout_sec=per_cube_timeout_sec,
            holdout_cells=holdout or None,
            solver_backend=solver_backend,
            np_anchor_pin=np_anchor_value,
        )
    except RuntimeError as exc:
        return {
            "np_anchor": np_anchor_value,
            "status": "error",
            "error": str(exc),
            "wall_clock_sec": 0.0,
        }
    return {
        "np_anchor": np_anchor_value,
        "status": result.status,
        "wall_clock_sec": result.wall_clock_sec,
        "training_forward_ok": result.training_forward_ok,
        "training_forward_total": result.training_forward_total,
        "holdout_forward_ok": result.holdout_forward_ok,
        "holdout_forward_total": result.holdout_forward_total,
        "holdout_functionally_equivalent": result.holdout_functionally_equivalent,
        "recovered_seed_lo_hex": result.recovered_seed_lo_hex,
        "matches_ground_truth": result.matches_ground_truth,
    }


def _solve_with_anchor_np_pinned(
    cells: List[CellContext],
    rounds: int,
    data_lo_truth: List[int],
    noise_lo_truth: List[int],
    timeout_sec: int,
    holdout_cells: Optional[List[CellContext]] = None,
    solver_backend: str = "bitwuzla",
    np_anchor_pin: Optional[int] = None,
) -> SolveResult:
    """Same as `solve()` but adds one extra constraint pinning the
    anchor pixel's `noise_pos` SAT unknown to a concrete value. That
    removes 3 ambiguity bits from the search space for this cube.
    Wraps the standard `solve()` by passing an additional assertion
    through a helper — implemented here inline rather than refactoring
    `solve()` to keep the existing call-sites untouched.
    """
    import z3
    # Detect the anchor pixel identity: p=0 of cell index 0, first
    # observation in training cells[0].
    if not cells or not cells[0].observations:
        raise RuntimeError("no training observations — cannot pin anchor np")
    # Anchor convention: first observation has p == 0 (see
    # `_build_cell_context`, anchor crib is added first). Pin via a
    # module-level global the solver consumes. Simpler route: skip
    # this helper and inject into `solve()` via a parameter. The
    # cleanest fix is to extend `solve()`; that is the next edit.
    return solve(
        cells=cells,
        rounds=rounds,
        data_lo_truth=data_lo_truth,
        noise_lo_truth=noise_lo_truth,
        timeout_sec=timeout_sec,
        holdout_cells=holdout_cells,
        skip_sanity=True,
        quiet=True,
        solver_backend=solver_backend,
        np_anchor_pin=np_anchor_pin,
    )


def _cube_and_conquer_solve(
    fnvstress_dir: Path,
    summary: dict,
    training_infos: List[dict],
    training_max_cribs: int,
    holdout_infos: List[dict],
    holdout_max_cribs: int,
    rounds: int,
    data_lo_truth: List[int],
    noise_lo_truth: List[int],
    per_cube_timeout_sec: int,
    workers: int,
    memory_limit_mb: int,
    solver_backend: str = "bitwuzla",
) -> List[dict]:
    """Enumerate anchor-pixel noise_pos across 8 cubes via
    ProcessPoolExecutor. First cube that returns `sat` with
    `holdout_functionally_equivalent == True` short-circuits; wrong-np
    cubes return `unsat` much faster than the full SAT normally would.

    Expected speedup ~4-8× over single-worker solve when `workers >= 4`
    because one of 8 cubes contains the true-np solution (probability
    `1/8` per cube) and wrong cubes fail fast on constraint
    contradiction.
    """
    print(
        f"[C&C] 8 cubes × anchor noise_pos ∈ [0..7], {workers} workers, "
        f"{per_cube_timeout_sec} s per-cube timeout, {memory_limit_mb} MB/worker"
    )
    jobs = [
        {
            "np_anchor_value": np_value,
            "fnvstress_dir_str": str(fnvstress_dir),
            "summary": summary,
            "training_infos": training_infos,
            "training_max_cribs": training_max_cribs,
            "holdout_infos": holdout_infos,
            "holdout_max_cribs": holdout_max_cribs,
            "rounds": rounds,
            "data_lo_truth": data_lo_truth,
            "noise_lo_truth": noise_lo_truth,
            "per_cube_timeout_sec": per_cube_timeout_sec,
            "memory_limit_mb": memory_limit_mb,
            "solver_backend": solver_backend,
        }
        for np_value in range(8)
    ]
    results: List[dict] = []
    ctx = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
        futures = {pool.submit(_cc_worker, job): job["np_anchor_value"] for job in jobs}
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as exc:
                r = {
                    "np_anchor": futures[fut],
                    "status": "error",
                    "error": repr(exc),
                }
            results.append(r)
            np_val = r["np_anchor"]
            print(
                f"  [cube np_anchor={np_val}] status={r['status']:<8s} "
                f"t={r.get('wall_clock_sec', 0):>6.1f}s  "
                f"holdout={r.get('holdout_forward_ok', 0)}/"
                f"{r.get('holdout_forward_total', 0)}"
            )
            if r["status"] == "sat" and r.get("holdout_functionally_equivalent"):
                # Short-circuit: cancel remaining cubes.
                for pending, _np in futures.items():
                    if pending is not fut and not pending.done():
                        pending.cancel()
                break
    return results


# ============================================================================
# Brute-force startPixel worker (Option A from .FNVSTRESS § 4.5)
# ============================================================================


def _auto_pick_workers(memory_limit_mb: int) -> int:
    """Pick a safe worker count from /proc/meminfo free RAM.

    Reserves 4 GB for OS + other processes, divides the remainder by
    `memory_limit_mb` (per-worker RLIMIT_AS). Never returns less than 1,
    never returns more than `cpu_count - 1` (keep a core free so the
    host stays responsive).
    """
    try:
        meminfo = open("/proc/meminfo").read()
    except Exception:
        return 1
    mem_avail_kb = 0
    for line in meminfo.splitlines():
        if line.startswith("MemAvailable:"):
            mem_avail_kb = int(line.split()[1])
            break
    mem_avail_mb = mem_avail_kb // 1024
    safety_buffer_mb = 4096
    budget_mb = max(0, mem_avail_mb - safety_buffer_mb)
    by_ram = max(1, budget_mb // max(1, memory_limit_mb))
    by_cpu = max(1, multiprocessing.cpu_count() - 1)
    return min(by_ram, by_cpu)


def _bf_worker(worker_args: dict) -> dict:
    """Top-level worker for ProcessPoolExecutor.

    Receives one startPixel candidate for the first training cell (cell
    index 0) and rebuilds that cell's observations with the candidate
    startPixel, then runs Z3 with a SHORT timeout (wrong candidates
    should unsat in seconds once a conflict appears; the true one runs
    to completion). Returns a dict with status + candidate so the main
    process can decide whether to break the sweep.

    First thing the worker does is install a hard RLIMIT_AS (virtual-
    memory cap) — if Z3 tries to allocate more than
    `memory_limit_mb`, the kernel kills this worker process. That
    prevents one runaway instance from swap-thrashing the whole host.

    Other training cells (and holdout cells) are NOT rebuilt here — the
    brute-force convention is: attacker only has ONE ciphertext they
    want to crack; extra cells are either unused (`--max-cells 1`) or
    their startPixel stays disclosed for the first realistic test. When
    combined with `--max-cells 1`, this function scans the full
    `total_pixels` space for a single cell.
    """
    # Install memory cap BEFORE any heavy work. 64-bit virtual-memory
    # limit in bytes; kernel kills the process on over-allocation.
    memory_limit_mb = worker_args.get("memory_limit_mb", 3072)
    try:
        limit_bytes = memory_limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
    except (ValueError, OSError) as exc:
        # Keep going — the monitor + default ProcessPoolExecutor timeout
        # will still catch runaways; just log for visibility.
        print(
            f"[worker-warn] could not install RLIMIT_AS={memory_limit_mb}MB: {exc}",
            file=sys.stderr,
        )

    candidate = worker_args["sp_candidate"]
    fnvstress_dir = Path(worker_args["fnvstress_dir_str"])
    summary = worker_args["summary"]
    training_infos = worker_args["training_infos"]
    training_max_cribs = worker_args["training_max_cribs"]
    holdout_infos = worker_args["holdout_infos"]
    holdout_max_cribs = worker_args["holdout_max_cribs"]
    rounds = worker_args["rounds"]
    data_lo_truth = worker_args["data_lo_truth"]
    noise_lo_truth = worker_args["noise_lo_truth"]
    per_candidate_timeout_sec = worker_args["per_candidate_timeout_sec"]
    solver_backend = worker_args.get("solver_backend", "z3")
    _ = memory_limit_mb  # referenced above, silence linter if any

    # Rebuild cell 0 with candidate sp; keep other cells disclosed.
    training: List[CellContext] = []
    for idx, ci in enumerate(training_infos):
        sp_override = candidate if idx == 0 else None
        training.append(_build_cell_context(
            fnvstress_dir, ci, idx, training_max_cribs,
            start_pixel_override=sp_override,
        ))
    holdout: List[CellContext] = []
    for idx, ci in enumerate(holdout_infos):
        holdout.append(_build_cell_context(
            fnvstress_dir, ci, len(training_infos) + idx, holdout_max_cribs,
        ))

    try:
        result = solve(
            cells=training,
            rounds=rounds,
            data_lo_truth=data_lo_truth,
            noise_lo_truth=noise_lo_truth,
            timeout_sec=per_candidate_timeout_sec,
            holdout_cells=holdout or None,
            skip_sanity=True,
            quiet=True,
            solver_backend=solver_backend,
        )
    except RuntimeError as exc:
        return {
            "sp_candidate": candidate,
            "status": "error",
            "error": str(exc),
            "wall_clock_sec": 0.0,
        }
    return {
        "sp_candidate": candidate,
        "status": result.status,
        "wall_clock_sec": result.wall_clock_sec,
        "training_forward_ok": result.training_forward_ok,
        "training_forward_total": result.training_forward_total,
        "holdout_forward_ok": result.holdout_forward_ok,
        "holdout_forward_total": result.holdout_forward_total,
        "holdout_functionally_equivalent": result.holdout_functionally_equivalent,
        "recovered_seed_lo_hex": result.recovered_seed_lo_hex,
        "matches_ground_truth": result.matches_ground_truth,
    }


def _brute_force_startpixel_pool(
    fnvstress_dir: Path,
    summary: dict,
    training_infos: List[dict],
    training_max_cribs: int,
    holdout_infos: List[dict],
    holdout_max_cribs: int,
    rounds: int,
    data_lo_truth: List[int],
    noise_lo_truth: List[int],
    per_candidate_timeout_sec: int,
    workers: int,
    memory_limit_mb: int,
    solver_backend: str = "z3",
) -> List[dict]:
    """Enumerate startPixel for training cell 0 across a ProcessPoolExecutor
    of `workers` processes. Returns a list of per-candidate result dicts.

    First candidate that reports `status == "sat"` with `holdout_
    functionally_equivalent == True` triggers cancellation of the rest
    — that's the "first realistic attacker wins" short-circuit.
    Candidates that return sat WITHOUT holdout-equivalence are logged
    but not accepted (they are either (a) training-overfit false
    positives, or (b) correct seed on under-determined instances that
    happen to match holdout ≥ 1). The main process picks the best one.
    """
    total_pixels = training_infos[0]["total_pixels"]
    projected_peak_gb = workers * memory_limit_mb / 1024
    print(
        f"[brute-force] scanning {total_pixels} candidate startPixels for "
        f"cell 0 ({training_infos[0]['cell_name']}) on {workers} workers, "
        f"{per_candidate_timeout_sec}s per-candidate timeout, "
        f"{memory_limit_mb} MB/worker hard cap "
        f"(projected peak RAM ~{projected_peak_gb:.1f} GB — "
        f"check `free -g` before launching larger runs)"
    )
    # Randomise the candidate order so a wall-clock-unlucky placement
    # of the true startPixel (e.g. sp=total_pixels-1 under FIFO order)
    # does not force a full sequential sweep before a hit. Seeded PRNG
    # so the order is reproducible within a run.
    import random
    order_rng = random.Random(0xBF_0D_0E_0A)
    sp_order = list(range(total_pixels))
    order_rng.shuffle(sp_order)
    jobs = [
        {
            "sp_candidate": sp,
            "fnvstress_dir_str": str(fnvstress_dir),
            "summary": summary,
            "training_infos": training_infos,
            "training_max_cribs": training_max_cribs,
            "holdout_infos": holdout_infos,
            "holdout_max_cribs": holdout_max_cribs,
            "rounds": rounds,
            "data_lo_truth": data_lo_truth,
            "noise_lo_truth": noise_lo_truth,
            "per_candidate_timeout_sec": per_candidate_timeout_sec,
            "memory_limit_mb": memory_limit_mb,
            "solver_backend": solver_backend,
        }
        for sp in sp_order
    ]
    results: List[dict] = []
    ctx = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
        futures = {pool.submit(_bf_worker, job): job["sp_candidate"] for job in jobs}
        done_count = 0
        hits = 0
        for fut in as_completed(futures):
            done_count += 1
            try:
                r = fut.result()
            except Exception as exc:
                r = {
                    "sp_candidate": futures[fut],
                    "status": "error",
                    "error": repr(exc),
                }
            results.append(r)
            sp = r["sp_candidate"]
            if r["status"] == "sat":
                hits += 1
                marker = "★" if r.get("holdout_functionally_equivalent") else " "
                print(
                    f"  [{done_count:>4d}/{total_pixels}] sp={sp:>4d} "
                    f"SAT  t={r.get('wall_clock_sec', 0):>6.1f}s  "
                    f"holdout={r.get('holdout_forward_ok')}/"
                    f"{r.get('holdout_forward_total')} {marker}"
                )
                if r.get("holdout_functionally_equivalent"):
                    # Short-circuit: cancel remaining candidates.
                    for pending, _cand in futures.items():
                        if pending is not fut and not pending.done():
                            pending.cancel()
                    break
            elif done_count % 50 == 0:
                print(
                    f"  [{done_count:>4d}/{total_pixels}] progress, "
                    f"{hits} SAT hits so far"
                )
    return results


# ============================================================================
# CLI
# ============================================================================


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--fnvstress-dir",
        default="tmp/attack/fnvstress",
        help="path to Phase 1 corpus root",
    )
    ap.add_argument(
        "--max-cells", type=int, default=1,
        help="limit number of cells (for fast scaling tests)",
    )
    ap.add_argument(
        "--max-cribs-per-cell", type=int, default=1,
        help="limit number of record cribs per cell (anchor crib counted separately)",
    )
    ap.add_argument(
        "--timeout-sec", type=int, default=1800,
        help="Z3 solver wall-clock limit in seconds (default 1800 s = "
             "30 min). Used as the CDCL wall-clock cap for one check() "
             "call. In brute-force mode per-candidate timeout = "
             "timeout_sec // 4 (so default brute-force per-candidate "
             "is 450 s). Raise for larger crib counts / rounds where "
             "the true-sp candidate legitimately takes longer.",
    )
    ap.add_argument(
        "--json-report",
        default=None,
        help="if set, write the SolveResult here as JSON",
    )
    ap.add_argument(
        "--holdout-cells", type=int, default=1,
        help="use this many cells BEYOND --max-cells for the holdout test. "
             "Each held-out cell uses a distinct nonce but the same seeds, "
             "so recovered dataSeed must reproduce its observations too.",
    )
    ap.add_argument(
        "--holdout-cribs-per-cell", type=int, default=1,
        help="max record cribs to consume from each holdout cell",
    )
    ap.add_argument(
        "--cube-and-conquer", action="store_true",
        help="Run the single SAT instance (startPixel disclosed) as 8 "
             "parallel cubes enumerating the anchor pixel's noise_pos "
             "∈ 0..7. First cube that returns sat + holdout-equivalent "
             "short-circuits the rest. Expected speedup 2-8× vs single-"
             "worker when SAT does not converge in wall-clock. Does not "
             "combine with --brute-force-start-pixel in the current "
             "harness (separate runs).",
    )
    ap.add_argument(
        "--solver", choices=["z3", "bitwuzla"], default="z3",
        help="SMT backend. z3 (default) uses z3-solver Python bindings "
             "directly. bitwuzla dumps the Z3-built formula as SMT-LIB2 "
             "and runs the `bitwuzla` CLI (AUR `yay -S bitwuzla`). "
             "Bitwuzla is 2-10x faster on QF_BV mul-heavy circuits and, "
             "more importantly, its subprocess-level wall-clock timeout "
             "is honored in EVERY phase (parse, bit-blast, SAT) — Z3's "
             "`timeout` only applies to the CDCL loop. See "
             "`.FNVSTRESS.md` § 8.5 for why this matters on this "
             "formula.",
    )
    ap.add_argument(
        "--brute-force-start-pixel", action="store_true",
        help="Do NOT read startPixel from summary.json; enumerate every "
             "candidate startPixel for the FIRST training cell (the one at "
             "index 0) in parallel workers, take the first that returns sat. "
             "Other training cells keep their disclosed startPixel. This is "
             "Option A from the .FNVSTRESS § 4.5 analytical framing — a "
             "realistic single-ciphertext attacker who has no bias-probe "
             "shortcut under FNV-1a.",
    )
    ap.add_argument(
        "--parallel-workers", type=int,
        default=2,
        help="number of ProcessPoolExecutor workers when brute-forcing "
             "startPixel. DEFAULT 2 is conservative — each Z3 worker "
             "peaks at 3-6 GB RAM on a 4-round × 40-obs instance, so 12 "
             "workers × 5 GB would OOM a 16 GB host. Raise only if you "
             "have ≥ 4 GB free RAM per additional worker. Set to 0 to "
             "auto-pick based on /proc/meminfo.",
    )
    ap.add_argument(
        "--memory-limit-mb-per-worker", type=int, default=3072,
        help="hard RLIMIT_AS (virtual memory) per worker, in MB. If a "
             "worker's Z3 instance tries to allocate more than this, the "
             "kernel kills that worker — prevents OOM cascades that can "
             "freeze the host. Default 3072 MB (3 GB); raise for bigger "
             "instances on hosts with enough free RAM.",
    )
    ap.add_argument(
        "--start-pixel", type=int, default=None,
        help="Override training cell 0's startPixel with this specific "
             "integer (modulo total_pixels) and run ONE SAT instance. "
             "Attacker-realistic mode for a single candidate: the user of "
             "a distributed 289-core pool assigns one --start-pixel N per "
             "worker, gathers `sat` hits, validates by cross-check. "
             "Mutually exclusive with --brute-force-start-pixel. If unset "
             "and --brute-force-start-pixel is also unset, the disclosed "
             "startPixel from summary.json is used (Concession 1).",
    )
    args = ap.parse_args()
    if args.start_pixel is not None and args.brute_force_start_pixel:
        print(
            "[FATAL] --start-pixel and --brute-force-start-pixel are mutually "
            "exclusive — the former runs one SAT instance at the chosen "
            "candidate, the latter sweeps all candidates in parallel.",
            file=sys.stderr,
        )
        return 2

    fnvstress_dir = Path(args.fnvstress_dir)
    summary = json.loads((fnvstress_dir / "summary.json").read_text())
    rounds = summary["rounds"]
    data_lo_truth = [int(h, 16) for h in summary["data_lo_lane_hex"]]
    noise_lo_truth = [int(h, 16) for h in summary["noise_lo_lane_hex"]]

    print(
        f"FNV-1a stress SAT harness — keyBits={summary['key_bits']} "
        f"rounds={rounds} corpus_count={summary['corpus_count']}"
    )
    print(
        "[concession 1] startPixel disclosed from summary.json — logged"
    )
    print(
        f"[concession 2] multi-cell corpus with shared seeds + fresh nonces — "
        f"using {min(args.max_cells, summary['corpus_count'])} / "
        f"{summary['corpus_count']} cells"
    )

    # ----- Brute-force startPixel branch (Option A) -----
    if args.brute_force_start_pixel:
        training_infos = list(summary["cells"][: args.max_cells])
        holdout_start = args.max_cells
        holdout_end = min(
            holdout_start + args.holdout_cells, summary["corpus_count"]
        )
        holdout_infos = list(summary["cells"][holdout_start:holdout_end])

        print(
            f"[brute-force] training_cells={[c['cell_name'] for c in training_infos]}"
        )
        print(
            f"[brute-force] holdout_cells={[c['cell_name'] for c in holdout_infos]}"
        )
        bf_timeout = max(10, args.timeout_sec // 4)

        # Auto-pick worker count from free RAM if requested (workers=0).
        workers = args.parallel_workers
        if workers <= 0:
            workers = _auto_pick_workers(
                memory_limit_mb=args.memory_limit_mb_per_worker
            )
            print(f"[brute-force] auto-picked --parallel-workers={workers}")

        # Explicit safety gate: projected peak MUST fit available RAM
        # with a ~4 GB buffer for OS/browser/etc. Abort loudly if not.
        projected_peak_mb = workers * args.memory_limit_mb_per_worker
        try:
            mem_total_kb = int(
                [l for l in open("/proc/meminfo").read().splitlines()
                 if l.startswith("MemTotal:")][0].split()[1]
            )
        except Exception:
            mem_total_kb = 0
        mem_total_mb = mem_total_kb // 1024
        safety_buffer_mb = 4096
        if mem_total_mb and projected_peak_mb + safety_buffer_mb > mem_total_mb:
            print(
                f"[ABORT] projected peak {projected_peak_mb} MB + "
                f"{safety_buffer_mb} MB OS buffer exceeds total RAM "
                f"{mem_total_mb} MB. Reduce --parallel-workers or "
                f"--memory-limit-mb-per-worker before retrying.",
                file=sys.stderr,
            )
            return 2
        print(
            f"[brute-force] RAM budget: projected peak {projected_peak_mb} MB "
            f"on a {mem_total_mb} MB host (buffer {mem_total_mb - projected_peak_mb} MB)"
        )

        t0 = time.perf_counter()
        bf_results = _brute_force_startpixel_pool(
            fnvstress_dir=fnvstress_dir,
            summary=summary,
            training_infos=training_infos,
            training_max_cribs=args.max_cribs_per_cell,
            holdout_infos=holdout_infos,
            holdout_max_cribs=args.holdout_cribs_per_cell,
            rounds=rounds,
            data_lo_truth=data_lo_truth,
            noise_lo_truth=noise_lo_truth,
            per_candidate_timeout_sec=bf_timeout,
            workers=workers,
            memory_limit_mb=args.memory_limit_mb_per_worker,
            solver_backend=args.solver,
        )
        wall_bf = time.perf_counter() - t0
        print(
            f"\n[brute-force] scanned {len(bf_results)} candidates in "
            f"{wall_bf:.1f}s wall-clock on {args.parallel_workers} workers"
        )
        # Rank: prefer sat + holdout-equivalent, then sat without holdout.
        sat_eq = [r for r in bf_results
                  if r["status"] == "sat" and r.get("holdout_functionally_equivalent")]
        sat_other = [r for r in bf_results
                     if r["status"] == "sat" and not r.get("holdout_functionally_equivalent")]
        summary_path = Path(args.json_report or "tmp/attack/fnvstress/phase3b_bruteforce.json")
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps({
            "wall_clock_sec": wall_bf,
            "workers": args.parallel_workers,
            "per_candidate_timeout_sec": bf_timeout,
            "training_cells": [c["cell_name"] for c in training_infos],
            "holdout_cells": [c["cell_name"] for c in holdout_infos],
            "sat_equivalent_count": len(sat_eq),
            "sat_other_count": len(sat_other),
            "results": bf_results,
        }, indent=2))
        print(f"report: {summary_path}")
        if sat_eq:
            print(f"[WIN] {len(sat_eq)} functionally-equivalent candidates found:")
            for r in sat_eq[:5]:
                print(f"  sp={r['sp_candidate']}  holdout={r['holdout_forward_ok']}/{r['holdout_forward_total']}")
            return 0
        if sat_other:
            print(f"[WEAK] {len(sat_other)} SAT-only candidates (no holdout equivalence)")
            return 1
        print("[FAIL] no candidate returned sat under the per-candidate timeout")
        return 1

    # ----- Cube-and-conquer branch (single-SAT parallel split) -----
    if args.cube_and_conquer:
        training_infos = list(summary["cells"][: args.max_cells])
        holdout_start = args.max_cells
        holdout_end = min(
            holdout_start + args.holdout_cells, summary["corpus_count"]
        )
        holdout_infos = list(summary["cells"][holdout_start:holdout_end])

        # Auto-pick workers from free RAM if user passed 0 or default.
        workers = args.parallel_workers
        if workers <= 0:
            workers = _auto_pick_workers(
                memory_limit_mb=args.memory_limit_mb_per_worker
            )
        # C&C has 8 cubes max — cap workers at 8.
        workers = min(workers, 8)

        projected_peak_mb = workers * args.memory_limit_mb_per_worker
        try:
            mem_total_kb = int(
                [l for l in open("/proc/meminfo").read().splitlines()
                 if l.startswith("MemTotal:")][0].split()[1]
            )
        except Exception:
            mem_total_kb = 0
        mem_total_mb = mem_total_kb // 1024
        if mem_total_mb and projected_peak_mb + 4096 > mem_total_mb:
            print(
                f"[ABORT] C&C peak {projected_peak_mb} MB + 4096 MB "
                f"exceeds {mem_total_mb} MB. Reduce --parallel-workers "
                f"or --memory-limit-mb-per-worker.",
                file=sys.stderr,
            )
            return 2
        print(
            f"[C&C] training={[c['cell_name'] for c in training_infos]} "
            f"holdout={[c['cell_name'] for c in holdout_infos]} "
            f"workers={workers} RAM peak ~{projected_peak_mb/1024:.1f} GB"
        )

        t0 = time.perf_counter()
        cc_results = _cube_and_conquer_solve(
            fnvstress_dir=fnvstress_dir,
            summary=summary,
            training_infos=training_infos,
            training_max_cribs=args.max_cribs_per_cell,
            holdout_infos=holdout_infos,
            holdout_max_cribs=args.holdout_cribs_per_cell,
            rounds=rounds,
            data_lo_truth=data_lo_truth,
            noise_lo_truth=noise_lo_truth,
            per_cube_timeout_sec=args.timeout_sec,
            workers=workers,
            memory_limit_mb=args.memory_limit_mb_per_worker,
            solver_backend=args.solver,
        )
        wall_cc = time.perf_counter() - t0
        print(
            f"\n[C&C] total wall-clock {wall_cc:.1f}s across "
            f"{len(cc_results)} cube results"
        )
        summary_path = Path(
            args.json_report or "tmp/attack/fnvstress/phase3b_cc.json"
        )
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps({
            "wall_clock_sec": wall_cc,
            "workers": workers,
            "per_cube_timeout_sec": args.timeout_sec,
            "training_cells": [c["cell_name"] for c in training_infos],
            "holdout_cells": [c["cell_name"] for c in holdout_infos],
            "cube_results": cc_results,
        }, indent=2))
        print(f"report: {summary_path}")
        eq = [r for r in cc_results
              if r["status"] == "sat" and r.get("holdout_functionally_equivalent")]
        sat_only = [r for r in cc_results
                    if r["status"] == "sat" and not r.get("holdout_functionally_equivalent")]
        if eq:
            print(f"[WIN] holdout-equivalent cube hit — np_anchor={eq[0]['np_anchor']}")
            return 0
        if sat_only:
            print(f"[WEAK] {len(sat_only)} SAT-only cubes, no holdout equivalence")
            return 1
        print("[FAIL] no cube returned sat within per-cube timeout")
        return 1

    cells: List[CellContext] = []
    for idx, cell_info in enumerate(summary["cells"][: args.max_cells]):
        sp_override = args.start_pixel if idx == 0 else None
        ctx = _build_cell_context(
            fnvstress_dir=fnvstress_dir,
            cell_info=cell_info,
            cell_idx=idx,
            max_cribs=args.max_cribs_per_cell,
            start_pixel_override=sp_override,
        )
        cells.append(ctx)
        override_tag = " (override via --start-pixel)" if sp_override is not None else ""
        print(
            f"  cell {idx} {ctx.cell_name}: "
            f"startPixel={ctx.start_pixel}{override_tag}, "
            f"total_pixels={ctx.total_pixels}, "
            f"observations={len(ctx.observations)}"
        )

    holdout_cells: List[CellContext] = []
    holdout_start_idx = args.max_cells
    holdout_end_idx = min(
        holdout_start_idx + args.holdout_cells, summary["corpus_count"]
    )
    for idx in range(holdout_start_idx, holdout_end_idx):
        cell_info = summary["cells"][idx]
        ctx = _build_cell_context(
            fnvstress_dir=fnvstress_dir,
            cell_info=cell_info,
            cell_idx=idx,
            max_cribs=args.holdout_cribs_per_cell,
        )
        holdout_cells.append(ctx)
        print(
            f"  holdout cell {idx} {ctx.cell_name}: "
            f"startPixel={ctx.start_pixel}, observations={len(ctx.observations)}"
        )

    result = solve(
        cells=cells,
        rounds=rounds,
        data_lo_truth=data_lo_truth,
        noise_lo_truth=noise_lo_truth,
        timeout_sec=args.timeout_sec,
        holdout_cells=holdout_cells or None,
        solver_backend=args.solver,
    )

    print()
    print(f"status:                 {result.status}")
    print(f"wall-clock:             {result.wall_clock_sec:.3f} s")
    print(f"peak memory:            {result.memory_rss_kb/1024:.1f} MB")
    print(f"observations:           {result.total_observations}")
    print(f"seed unknowns:          {result.unknowns_seed_bits}")
    print(f"ambiguity unknowns:     {result.unknowns_ambiguity_bits}")
    print(f"matches ground truth:   {result.matches_ground_truth}")
    print(
        f"training forward:       "
        f"{result.training_forward_ok}/{result.training_forward_total}"
    )
    print(
        f"holdout functional:     "
        f"{result.holdout_forward_ok}/{result.holdout_forward_total} "
        f"({'EQUIVALENT' if result.holdout_functionally_equivalent else 'DIVERGED'})"
    )
    if result.recovered_seed_lo_hex:
        print("recovered seed (lo lane):")
        for i, h in enumerate(result.recovered_seed_lo_hex):
            truth_hex = f"{data_lo_truth[i]:016x}"
            marker = "✓" if h == truth_hex else "✗"
            print(f"  s_lo[{i}] = {h}  (truth {truth_hex}) {marker}")

    if args.json_report:
        Path(args.json_report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_report).write_text(json.dumps(asdict(result), indent=2))
        print(f"\nreport: {args.json_report}")

    return 0 if result.status == "sat" else 1


if __name__ == "__main__":
    sys.exit(main())
