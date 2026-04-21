#!/usr/bin/env python3
"""Phase 2a — empirical compound-key recovery against ChainHash<CRC128>.

## The finding this script demonstrates

When ITB's ChainHash is instantiated with a GF(2)-linear primitive (here:
`CRC128(data, seed0, seed1) = (CRC64-ECMA(data, seed0), CRC64-ISO(data, seed1))`
concatenated to 128 bits), the entire 8-round chain at 1024-bit key collapses
to an affine function of the seed:

    hLo(p) = K  XOR  const(data(p))

where:
  * `K` is a pixel-INDEPENDENT 64-bit "compound key" derived by GF(2)-linear
    projection `K = [M_L^1, M_L^2, ..., M_L^8] · [s_14, s_12, s_10, ..., s_0]`
    (`M_L` = the length-L CRC64 state-transfer matrix; ECMA-side only).
  * `const(data(p)) = ChainHash(data(p), seed=0)` — the attacker can compute
    this trivially for any pixel.

Because `data(p) = pixel_le_u32 || nonce` has constant length (20 bytes) for
every pixel, `M_L` does not vary between pixels. Every observation gives
equations only on the 64 output bits of the compound image. **No number of
pixels can push the rank above 64.**

ITB exposes 56 of these 64 bits through `xorMask = hLo >> 3` (channel 0
starts at bit 3, channel 7 ends at bit 58). Bits 0..2 and 59..63 of hLo are
never used for `channelXOR` and are unobservable via this path (`noisePos`
comes from a separate `noiseSeed` — a different ChainHash evaluation with
its own compound key).

## Why this is a dramatic empirical result

Recovering 56 of 64 bits of K is sufficient for the attacker to **predict
channelXOR exactly at every container pixel** of every ciphertext encrypted
under the same `(dataSeed, nonce)`:

    channelXOR(p, ch) = ( (K ^ const(data(p))) >> (3 + 7*ch) ) & 0x7F

Mapping to ITB's 1024-bit flagship key: the 16-uint64 dataSeed splits into
an ECMA-side half (s[0], s[2], ..., s[14] = 8 × 64 = 512 bits) that feeds
hLo and an ISO-side half (s[1], s[3], ..., s[15] = 512 bits) that feeds
hHi. ITB's encoding reads hLo only (`xorMask = hLo >> 3`), so the ISO-side
half is structurally unobservable through any ciphertext probe. The
observable ECMA-side 512 bits collapse to the 64-bit compound key K —
of which 56 bits are pinned by channelXOR.

## Contrast with FNV-1a

FNV-1a's round operation is `h = (h XOR byte) * FNV_PRIME`. Integer
multiplication modulo 2^64 by a constant is **NOT GF(2)-linear** (carry
propagation creates AND-combinations between bit positions). ChainHash's
inter-round XOR adds GF(2) structure, but it cannot "straighten out" the
nonlinear multiplication accumulated over 8 rounds. `K` as defined here
does not exist for FNV-1a; the analogous "compound observation" involves
genuine carries through 8 Z/2^64 multiplications stacked by GF(2) XOR.

That mixed algebra is precisely the defense the Phase 2a cost tables rely
on. This empirical probe demonstrates that the defense is load-bearing:
once the primitive is GF(2)-linear throughout (as CRC128 is), the cost
collapses from research-lab SAT to a handful of XORs. CRC128 is a test-
only primitive, never used in shipped ITB.

## Pipeline

1. Read the demasked `.datahash.bin` stream + its `.index` sidecar.
2. For each observation `(data_pixel_idx, channel, observed_7bit)`:
    * Compute `const_p = ChainHash(pixel_le(data_pixel_idx + shift) || nonce,
      seed=0)` using our Python mirror of Go's CRC64 (`chainhashes/crc128.py`).
    * `K_bits_at_(3+7*ch..3+7*ch+6) = observed_7bit XOR (const_p >> (3+7*ch)) & 0x7F`
    * Majority-vote per K bit across all observations.
3. After aggregating, the attacker has the full observable slice of K.
4. Validation (red-team side only): recover true K from `cell.meta.json`'s
   ground-truth seed and confirm byte-for-byte match; then predict
   `channel_xor_8` at HELD-OUT pixels via `K XOR const_p` and check
   against `config.truth.json`.

Shared hash-agnostic machinery lives in `raw_mode_common.py`; this script
is strictly the CRC128-specific attack chain (brute-force pixel_shift +
ground-truth shadow-K filter + prediction audit).
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from pathlib import Path

from raw_mode_common import (
    chainhash_const_at_pixel,
    observations_to_numpy,
    parse_full_stream,
    parse_partial_stream,
    parse_raw_ciphertext,
    precompute_const_all,
    recover_compound_key_cached,
    recover_compound_key_cached_np,
)
from chainhashes import crc128 as crc128_mod
from chainhashes.crc128 import chainhash_lo as chainhash_crc128_lo
from chainhashes.crc128 import compute_expected_K

PROJ = Path(__file__).resolve().parents[3]
N_SEED_COMPONENTS = crc128_mod.N_SEED_COMPONENTS  # = 16


def predict_channel_xor(K: int, pixel_idx: int, nonce: bytes) -> list[int]:
    """Attacker predicts the 8 × 7-bit channelXOR values at `pixel_idx` given
    a recovered compound key K. All 8 channels are fully predictable from
    the 56 observable bits of K (positions 3..58 cover `ch * 7 + 3..9` for
    every ch in 0..7)."""
    const_p = chainhash_const_at_pixel(pixel_idx, nonce, chainhash_crc128_lo,
                                       N_SEED_COMPONENTS)
    h_lo = K ^ const_p
    x_mask = h_lo >> 3  # ITB's DataRotationBits = 3
    return [(x_mask >> (ch * 7)) & 0x7F for ch in range(8)]


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cell-dir", type=Path, required=True,
                    help="Corpus cell directory (contains cell.meta.json, "
                         "seed.truth.json, config.truth.json).")
    ap.add_argument("--datahash-stream", type=Path, required=True,
                    help="Demasked `.datahash.bin` emitted by nonce_reuse_demask.py "
                         "(or raw ct_NNNN.bin under --raw-ciphertext-mode).")
    ap.add_argument("--index-sidecar", type=Path, default=None,
                    help="Partial-mode `.index` sidecar (auto-detected if absent).")
    ap.add_argument("--pixel-shift", type=int, default=0,
                    help="Offset added to every data_pixel_idx when feeding "
                         "ChainHash(seed=0). Full KPA + clean Layer 2: use 0. "
                         "Partial KPA period-shift: attacker brute-forces. "
                         "This is NOT the ground-truth startPixel.")
    ap.add_argument("--brute-force-shift", type=int, default=0,
                    help="If non-zero, try candidate shifts in [0, value) and "
                         "accept the first conflict-free shift. 0 = disable.")
    ap.add_argument("--probe-size", type=str, default="auto",
                    help="Observations used in the brute-force probe batch. "
                         "`auto` scales with corpus size (~1/8 of observations, "
                         "capped at 16000) so per-bit binomial noise stays "
                         "≈ 0.6%% across cell sizes; explicit integer overrides.")
    ap.add_argument("--raw-ciphertext-mode", action="store_true",
                    help="Treat --datahash-stream as raw ITB ciphertext "
                         "(ct_NNNN.bin) — 8 bytes per pixel, 20-byte header skip. "
                         "Attacker skips demasking entirely.")
    ap.add_argument("--n-verify-pixels", type=int, default=64,
                    help="Predict channelXOR for N random pixels and diff "
                         "against config.truth.json (red-team validation).")
    args = ap.parse_args()

    cell_dir = args.cell_dir.resolve()
    meta = json.loads((cell_dir / "cell.meta.json").read_text())
    hash_name = meta["hash"]
    if hash_name != "crc128":
        print(f"WARNING: this solver is CRC128-specific; got hash={hash_name}. "
              f"Python ChainHash<CRC128> mirror will produce garbage for a "
              f"different primitive. Abort.", file=sys.stderr)
        return 2
    if meta["hash_width"] != 128 or meta["key_bits"] != 1024:
        print(f"ERROR: solver assumes hash_width=128 + key_bits=1024. Got "
              f"hash_width={meta['hash_width']}, key_bits={meta['key_bits']}.",
              file=sys.stderr)
        return 2

    nonce = bytes.fromhex(meta["nonce_hex"])

    print(f"{'=' * 72}")
    print(f"Phase 2a — empirical compound-key recovery against ChainHash<CRC128>")
    print(f"{'=' * 72}")
    print(f"Cell: {cell_dir.relative_to(PROJ)}")
    print(f"  hash              : {meta['hash_display']}")
    print(f"  key_bits          : {meta['key_bits']} (8 ECMA rounds × 64-bit CRC64 state)")
    print(f"  nonce             : {nonce.hex()}")
    print(f"  data_pixels       : {meta['data_pixels']}")
    print(f"  total_pixels      : {meta['total_pixels']}")

    # Parse observations.
    stream_path = args.datahash_stream.resolve()
    demask_meta_path = stream_path.with_suffix(stream_path.suffix + ".meta.json")
    demask_meta: dict = {}
    if demask_meta_path.exists():
        demask_meta = json.loads(demask_meta_path.read_text())
    stream_mode_hint = demask_meta.get("stream_mode")

    auto_index = args.index_sidecar.resolve() if args.index_sidecar else \
                 stream_path.with_suffix(stream_path.suffix + ".index")

    total_pixels = int(meta["total_pixels"])
    if args.raw_ciphertext_mode:
        observations = parse_raw_ciphertext(stream_path, total_pixels)
        stream_mode = ("raw-ciphertext (NEGATIVE CONTROL: 8-byte-per-pixel, "
                       "20-byte header skipped)")
    elif stream_mode_hint == "partial":
        observations = parse_partial_stream(stream_path, auto_index)
        stream_mode = "partial-mode"
    elif stream_mode_hint == "full":
        idx_path = auto_index if auto_index.exists() else None
        observations = parse_full_stream(stream_path, idx_path)
        stream_mode = f"Full KPA ({'w/ index' if idx_path else 'legacy, no index'})"
    elif auto_index.exists():
        first = auto_index.read_text().splitlines()[0].split()
        if len(first) == 2:
            observations = parse_partial_stream(stream_path, auto_index)
            stream_mode = "partial-mode (inferred from index format)"
        else:
            observations = parse_full_stream(stream_path, auto_index)
            stream_mode = "Full KPA (inferred from index format)"
    else:
        observations = parse_full_stream(stream_path, None)
        stream_mode = "Full KPA (legacy, contiguous indexing)"
    print(f"  stream            : {stream_path.name}")
    print(f"  mode              : {stream_mode}")
    if demask_meta:
        rsp = demask_meta.get("recovered_start_pixel")
        print(f"  demasker recovered_sp : {rsp}  "
              f"(attacker-visible from demasker Layer 2 output)")
    print(f"  observations      : {len(observations)} (pixel, channel, 7-bit) triples")

    if len(observations) < 16:
        print(f"ERROR: too few observations ({len(observations)}); need ≥ 16.",
              file=sys.stderr)
        return 1

    # Recover compound key — with optional shift brute-force.
    t0 = time.time()
    chosen_shift = args.pixel_shift
    const_all = None
    obs_np = None

    if args.brute_force_shift > 0:
        brute_max = min(args.brute_force_shift, total_pixels)
        probe_skip = min(10, len(observations))
        # Auto-scale probe size: ~12.5% of observations capped at 16000.
        # Larger corpora need more pins per K bit to robustly separate
        # plateau aliases from noise; smaller corpora can afford to use
        # most of what they have. Floor at 2000 so small cells still get
        # a meaningful scan.
        if args.probe_size == "auto":
            target = min(16000, max(2000, len(observations) // 8))
            probe_size = min(target, max(0, len(observations) - probe_skip))
        else:
            probe_size = int(args.probe_size)
        probe_obs = observations[probe_skip:probe_skip + probe_size]
        probe_pins_max = sum(
            1 for _, ch, _ in probe_obs for k in range(7)
            if (ch * 7 + 3 + k) < 64
        )
        candidate_threshold = max(1, probe_pins_max // 20)  # 5% pins
        print(f"  probe size        : {len(probe_obs)} observations "
              f"({probe_pins_max} bit-pins, threshold < {candidate_threshold})")

        print(f"\nPrecomputing const(p) for p in [0, {total_pixels}) "
              f"(one-time; enables fast brute-force)...")
        t_pre = time.time()
        const_all = precompute_const_all(total_pixels, nonce, chainhash_crc128_lo,
                                          N_SEED_COMPONENTS)
        print(f"  precompute elapsed: {time.time() - t_pre:.2f}s")

        # Convert probe observations to numpy arrays once for the fast-path.
        probe_px, probe_ch, probe_val = observations_to_numpy(probe_obs)
        print(f"\nBrute-forcing pixel_shift in [0, {brute_max}) against "
              f"{len(probe_obs)} observations ({probe_pins_max} bit-pins; "
              f"collecting shifts with < {candidate_threshold} conflicts)...")
        candidates: list[tuple[int, int, int, int]] = []
        t_brute = time.time()
        for s in range(brute_max):
            K_c, mask_c, _, conflicts = recover_compound_key_cached_np(
                probe_px, probe_ch, probe_val, total_pixels, const_all,
                pixel_shift=s,
            )
            if conflicts < candidate_threshold:
                candidates.append((s, conflicts, K_c, mask_c))
        print(f"  brute-force elapsed: {time.time() - t_brute:.2f}s")
        candidates.sort(key=lambda t: t[1])
        print(f"  found {len(candidates)} candidate shift(s) below threshold")
        if candidates:
            print(f"  lowest-conflict shift: {candidates[0][0]} "
                  f"({candidates[0][1]} conflicts / {probe_pins_max} pins)")
        chosen_shift = candidates[0][0] if candidates else args.pixel_shift
        print(f"  tentative pixel_shift: {chosen_shift}")
        setattr(args, "_candidates", candidates)
        setattr(args, "_const_all", const_all)

    print(f"\nRecovering 64-bit compound key K at shift={chosen_shift} ...")
    if const_all is None:
        const_all = precompute_const_all(total_pixels, nonce,
                                          chainhash_crc128_lo, N_SEED_COMPONENTS)
    full_px, full_ch, full_val = observations_to_numpy(observations)
    K, known_mask, n_used, n_conflicts = recover_compound_key_cached_np(
        full_px, full_ch, full_val, total_pixels, const_all,
        pixel_shift=chosen_shift,
    )
    elapsed = time.time() - t0
    known_bits = bin(known_mask).count("1")
    total_pins = max(1, n_used * 7)
    conflict_rate = n_conflicts / total_pins if total_pins else 0.0
    shift_verdict = "likely correct" if conflict_rate < 0.02 else (
        "likely wrong" if conflict_rate > 0.3 else "ambiguous"
    )
    print(f"  observations used : {n_used}")
    print(f"  K bits recovered  : {known_bits} / 64 "
          f"(56 observable via channelXOR; 8 always unobservable)")
    print(f"  conflicts         : {n_conflicts} / {total_pins} pins "
          f"({100.0 * conflict_rate:.2f}%) — shift verdict: {shift_verdict}")
    print(f"  recovered K       : 0x{K:016x}  (known mask 0x{known_mask:016x})")
    print(f"  elapsed           : {elapsed:.3f}s")

    if conflict_rate > 0.3 and not getattr(args, "_candidates", None):
        print(f"\n  ⚠ {100.0 * conflict_rate:.1f}% conflict rate — shift is wrong "
              f"(random-shift expectation is ~50%). Try --brute-force-shift or "
              f"supply a different --pixel-shift.")
        return 1

    # Lab-only ground-truth filter.
    try:
        K_expected = compute_expected_K(meta, nonce)
    except KeyError:
        print("  [warn] cell.meta.json missing `data_seed` ground-truth field.")
        K_expected = None

    print(f"\n{'-' * 72}")
    print(f"Red-team oracle filtering (lab-only: cell.meta.json ground truth")
    print(f"used to identify which brute-force candidate is correct; attacker")
    print(f"would filter shadow K via plaintext-consistency on companion ct)")
    print(f"{'-' * 72}")
    candidates = getattr(args, "_candidates", None)
    if candidates and K_expected is not None:
        n_correct = 0
        n_shadow = 0
        correct_shifts: list[int] = []
        for s, _conf, K_cand, mask_cand in candidates:
            if (K_cand & mask_cand) == (K_expected & mask_cand):
                n_correct += 1
                correct_shifts.append(s)
                if chosen_shift != s:
                    chosen_shift = s
                    K = K_cand
                    known_mask = mask_cand
            else:
                n_shadow += 1
        print(f"  brute-force candidates : {len(candidates)}")
        print(f"  CORRECT dataSeed match : {n_correct}  (shift(s): {correct_shifts})")
        print(f"  shadow / wrong K       : {n_shadow}  (CRC64 linear-alias false positives)")
        print(f"  selected chosen_shift  : {chosen_shift}")
        if n_correct == 0:
            print(f"\n  ⚠ none of the brute-force candidates matched ground truth.")
            return 1
    if K_expected is not None:
        K_match = (K & known_mask) == (K_expected & known_mask)
        print(f"  expected K        : 0x{K_expected:016x}")
        print(f"  recovered K       : 0x{K:016x}")
        print(f"  match on known    : {'✓' if K_match else '✗ MISMATCH'}")
        diff_on_known = (K ^ K_expected) & known_mask
        if diff_on_known:
            print(f"  mismatched bits   : {bin(diff_on_known).count('1')} of "
                  f"{known_bits} known")
    else:
        K_match = None

    # Prediction test on held-out pixels.
    try:
        config_truth = json.loads((cell_dir / "config.truth.json").read_text())
        truth_pixels = config_truth["per_pixel"] if "per_pixel" in config_truth else config_truth
        if isinstance(truth_pixels, dict) and "pixels" in truth_pixels:
            truth_pixels = truth_pixels["pixels"]
    except Exception as e:
        print(f"  [warn] could not load config.truth.json: {e}")
        truth_pixels = None

    prediction_ok = None
    if truth_pixels is not None:
        total_px = min(len(truth_pixels), meta["data_pixels"])
        import random
        rng = random.Random(0xC0DEBEE1)
        test_idxs = rng.sample(range(total_px), min(args.n_verify_pixels, total_px))
        n_pixels_match = 0
        n_channels_match = 0
        n_channels_total = 0
        for idx in test_idxs:
            truth_entry = truth_pixels[idx]
            truth_ch = truth_entry["channel_xor_8"] if isinstance(truth_entry, dict) else truth_entry
            predicted = predict_channel_xor(K, idx, nonce)
            chs_ok = sum(1 for a, b in zip(predicted, truth_ch) if a == b)
            n_channels_match += chs_ok
            n_channels_total += 8
            if chs_ok == 8:
                n_pixels_match += 1
        print(f"\n  Predicted channelXOR at {len(test_idxs)} held-out data pixels:")
        print(f"    pixels fully matching : {n_pixels_match} / {len(test_idxs)}")
        print(f"    channels matching     : {n_channels_match} / {n_channels_total}  "
              f"({100.0 * n_channels_match / n_channels_total:.2f}%)")
        prediction_ok = (n_channels_match == n_channels_total)

    print(f"\n{'=' * 72}")
    if K_match is True and (prediction_ok is True or prediction_ok is None):
        print(f"  ✅ COMPOUND KEY RECOVERED.  ChainHash<CRC128> at 1024-bit key")
        print(f"     effectively reduces to 64-bit security (56 observable via")
        print(f"     channelXOR); attacker predicts every channelXOR at every")
        print(f"     pixel of every ciphertext sharing (dataSeed, nonce).")
        return 0
    elif K_match is False or prediction_ok is False:
        print(f"  ⚠ Inversion appears inconsistent. Possible causes: wrong shift,")
        print(f"     demasker-stream corruption, or bug in Python chainhash mirror.")
        return 1
    else:
        print(f"  (validation artefacts missing)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
