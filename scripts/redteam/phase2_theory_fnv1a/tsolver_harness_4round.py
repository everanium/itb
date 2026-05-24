#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 3b — ITB FNV-1a Level-2 seed recovery via the structure-aware
T-function solver (t_solver_fnv.solve_via_tsolver_masked), the fast
alternative to the Bitwuzla SAT harness (sat_harness_4round.py).

This script does NOT touch sat_harness_4round.py — the working Bitwuzla path
is left intact. It reuses that harness's attacker-realistic crib / channel /
COBS machinery (`_build_cell_context`, `ChannelObservation`) and the channel
barrier math in itb_channel_mirror.py, then replaces the global Bitwuzla SAT
solve with the two-layer hybrid:

  1. BARRIER LAYER (per crib pixel). Each known channel byte, with the pixel's
     (noise_pos, rotation), decodes to a 7-bit channelXOR slice of dataHash:
         channelXOR_ch = rotate7(extract(container, noise_pos), 7-rotation)
                         ^ plaintext_bits
     and channelXOR_ch occupies dataHash bits [3 + 7*ch .. +6]. A fully-covered
     pixel (8 channels) yields dataHash bits 3..58 (56 bits). The result is a
     masked hLo observation (data = LE32(p)||nonce, dataHash bits, known_mask).

  2. CHAINHASH LAYER. The masked observations feed solve_via_tsolver_masked,
     which recovers the 4-round lo-lane seed by the LSB->MSB T-function DFS.

WHY A SCAFFOLD RIGHT NOW
------------------------
The per-pixel (noise_pos, rotation) pair is needed to decode channelXOR.
noise_pos = noiseHash & 7 comes from the SEPARATE (unknown) noiseSeed chain,
and rotation = dataHash % 7 from the (unknown) dataSeed chain, so for an
attacker both are unknown and per-pixel ambiguous (8 x 7 = 56 combinations,
with no per-pixel filter — the rotation == dataHash%7 self-consistency is
always satisfiable through the unobserved low bits). Resolving them is the
barrier-dominated search the final tool must do (noise_pos beam-search +
COBS-rejection, as in decrypt_full_fnv1a.py).

For now `--noise-source gt` derives (noise_pos, rotation) from the lab
ground-truth seeds (summary.json) — a DEVELOPMENT SCAFFOLD that proves the
barrier-decode + masked tsolver recover the real seed on the real corpus. It
is a CLAUDE.md attacker-realism violation and MUST be replaced by
`--noise-source search` (not yet implemented) before any reported result.
The ground-truth seeds are also read for the terminal audit line only.

Usage:
    python3 tsolver_harness_4round.py [--fnvstress-dir DIR] [--cell 0]
                                      [--max-cribs 4] [--noise-source gt]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from fnv_chain_lo_concrete import fnv_chain_lo_concrete  # type: ignore
from itb_channel_mirror import (  # type: ignore
    DATA_BITS_PER_CHANNEL,
    DATA_ROTATION_BITS,
    rotate_bits_7,
)
import sat_harness_4round as bw  # reuse _build_cell_context / ChannelObservation
from t_solver_fnv import solve_via_tsolver_masked  # type: ignore

MASK64 = (1 << 64) - 1


class MaskedObs:
    """Per-pixel masked hLo observation for solve_via_tsolver_masked."""

    __slots__ = ("data_bytes", "target_hlo", "known_mask")

    def __init__(self, data_bytes: bytes, target_hlo: int, known_mask: int):
        self.data_bytes = data_bytes
        self.target_hlo = target_hlo & MASK64
        self.known_mask = known_mask & MASK64


def _channel_xor_from_observation(obs, noise_pos: int, rotation: int) -> int:
    """Recover the 7-bit channelXOR slice of dataHash from one channel.

    Inverse of itb_channel_mirror.encode_plaintext_bits_to_channel: strip the
    noise bit at noise_pos, undo the rotation, XOR the known plaintext bits.
    """
    nm = 1 << noise_pos
    low = obs.observed_byte & (nm - 1)
    high = obs.observed_byte >> (noise_pos + 1)
    data_bits_enc = (low | (high << noise_pos)) & 0x7F
    pre_rot = rotate_bits_7(data_bits_enc, (7 - (rotation % 7)) % 7)
    return pre_rot ^ (obs.plaintext_bits & 0x7F)


def _decode_pixel(channel_obs: List, noise_pos: int, rotation: int) -> Tuple[int, int]:
    """Assemble (dataHash bits, known_mask) for one pixel from its channels."""
    hbits = 0
    mask = 0
    for obs in channel_obs:
        cx = _channel_xor_from_observation(obs, noise_pos, rotation)
        shift = DATA_ROTATION_BITS + DATA_BITS_PER_CHANNEL * obs.channel
        hbits |= (cx & 0x7F) << shift
        mask |= 0x7F << shift
    return hbits & MASK64, mask & MASK64


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ITB FNV-1a Level-2 seed recovery via masked T-solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--fnvstress-dir", default="tmp/attack/fnvstress")
    ap.add_argument("--cell", type=int, default=0)
    ap.add_argument("--max-cribs", type=int, default=4)
    ap.add_argument(
        "--noise-source", choices=["gt"], default="gt",
        help="gt = derive (noise_pos, rotation) from lab seeds (DEV SCAFFOLD, "
             "not attacker-realistic; the 'search' source is the TODO).",
    )
    args = ap.parse_args()

    fdir = Path(args.fnvstress_dir)
    summary = json.loads((fdir / "summary.json").read_text())
    rounds = int(summary["rounds"])
    cell_info = summary["cells"][args.cell]

    ctx = bw._build_cell_context(fdir, cell_info, args.cell, args.max_cribs,
                                 start_pixel_override=None)
    nonce = ctx.nonce

    # --- DEV SCAFFOLD: ground-truth seeds for (noise_pos, rotation) ---------
    # CLAUDE.md attacker-realism violation; replace with a noise_pos search.
    data_lo = [int(h, 16) for h in summary["data_lo_lane_hex"]]
    noise_lo = [int(h, 16) for h in summary["noise_lo_lane_hex"]]

    # Group channel observations by encoded-stream pixel index p.
    by_pixel: Dict[int, List] = defaultdict(list)
    for o in ctx.observations:
        by_pixel[o.p].append(o)

    masked: List[MaskedObs] = []
    rot_constraints: List[Tuple[bytes, int]] = []
    full_pixels = 0
    for p, chans in sorted(by_pixel.items()):
        data = bw._pixel_data_bytes(p, nonce)
        if args.noise_source == "gt":
            data_hash = fnv_chain_lo_concrete(data_lo, data, rounds)
            noise_hash = fnv_chain_lo_concrete(noise_lo, data, rounds)
            noise_pos = noise_hash & 7
            rotation = data_hash % 7
        else:  # pragma: no cover (search not yet implemented)
            raise NotImplementedError("noise_pos search not implemented yet")
        hbits, mask = _decode_pixel(chans, noise_pos, rotation)
        masked.append(MaskedObs(data, hbits, mask))
        rot_constraints.append((data, rotation))
        if len(chans) == 8:
            full_pixels += 1

    # rotation = dataHash % 7 pins the low bits the channelXOR projection
    # (dataHash bits 3..58) leaves unobserved; folding it into the leaf check
    # makes the recovered lo-lane match bitwuzla's bits 0..62.
    def _leaf_check(seed: List[int]) -> bool:
        return all(
            fnv_chain_lo_concrete(seed, d, rounds) % 7 == r
            for d, r in rot_constraints
        )

    print(f"cell={ctx.cell_name} start_pixel={ctx.start_pixel} "
          f"cribs={args.max_cribs} pixels={len(masked)} full(8ch)={full_pixels} "
          f"noise_source={args.noise_source}")

    t0 = time.perf_counter()
    status, recovered = solve_via_tsolver_masked(rounds, masked, leaf_check=_leaf_check)
    dt = time.perf_counter() - t0
    print(f"tsolver: {status} in {dt:.3f}s")
    if status != "sat":
        print("FAIL: no consistent seed found")
        return 1

    # --- Functional-equivalence check on the recovered seed -----------------
    # Reproduce each observation's KNOWN dataHash bits.
    ok = sum(
        1 for m in masked
        if (fnv_chain_lo_concrete(recovered, m.data_bytes, rounds) ^ m.target_hlo) & m.known_mask == 0
    )
    print(f"training known-bit reproduce: {ok}/{len(masked)}")

    # --- Terminal-stage ground-truth audit (NOT in decision path) -----------
    gt_match_bits = [
        bin((recovered[j] ^ data_lo[j]) & ((1 << 63) - 1)).count("1")
        for j in range(rounds)
    ]
    print(f"GT audit (bits 0..62 mismatch count per lane): {gt_match_bits}")
    print(f"recovered lo-lane: {[f'{v:016x}' for v in recovered]}")
    print(f"ground-truth lane: {[f'{v:016x}' for v in data_lo]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
