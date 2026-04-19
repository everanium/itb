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
of which 56 bits are pinned by channelXOR. Attacker never needs to
recover individual `s[i]` components; K alone lets them predict every
channelXOR across every pixel sharing `(dataSeed, nonce)`.

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
      seed=0)` using our Python mirror of Go's CRC64.
    * `K_bits_at_(3+7*ch..3+7*ch+6) = observed_7bit XOR (const_p >> (3+7*ch)) & 0x7F`
    * Write those 7 bits into a known-mask over the 64-bit K.
    * If the same bit has been set before, verify consistency — inconsistency
      indicates wrong `pixel_shift` (period-shift) or a bug.
3. After aggregating across ≥ 8 observations (≥ 8 channels × 7 bits = 56
   bits covered), the attacker has the full observable slice of K.
4. Validation (red-team side only): recover true K from `cell.meta.json`'s
   ground-truth seed and confirm byte-for-byte match; then predict
   `channel_xor_8` at HELD-OUT pixels via `K XOR const_p` and check
   against `config.truth.json`. A successful solver predicts every
   unobserved pixel's channelXOR bits exactly.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from pathlib import Path

PROJ = Path(__file__).resolve().parents[3]


# --------------------------------------------------------------------------
# CRC64 tables — polynomial constants match Go stdlib `hash/crc64` (ECMA + ISO).
# The corpus generator in `redteam_nonce_reuse_test.go` uses a CUSTOM
# `crc64Keyed` (not `crc64.Update`) that runs the raw Sarwate table loop with
# NO entry/exit complementation:
#     crc := seed
#     for _, b := range data { crc = (*table)[byte(crc)^b] ^ (crc >> 8) }
#     return crc
# Our Python mirror must match that — NOT stdlib `crc64.Update`. (Go's
# `crc64.Update` does `crc = ^crc` at both entry and exit, which would
# introduce an affine offset our probe machinery would cancel but fixed-
# reference comparisons would not.)
# --------------------------------------------------------------------------

CRC64_ECMA_POLY = 0xC96C5795D7870F42
CRC64_ISO_POLY = 0xD800000000000000
MASK64 = (1 << 64) - 1


def build_crc64_table(poly: int) -> list[int]:
    """Mirror of Go's `crc64.MakeTable(poly)` — 256-entry reflected table."""
    table = [0] * 256
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        table[i] = crc
    return table


CRC64_TABLE_ECMA = build_crc64_table(CRC64_ECMA_POLY)
CRC64_TABLE_ISO = build_crc64_table(CRC64_ISO_POLY)


def crc64_keyed(table: list[int], data: bytes, seed: int) -> int:
    """Mirror of the corpus generator's custom `crc64Keyed` — no entry/exit
    complement. This is PURELY GF(2)-linear in seed, which is precisely why
    CRC128 collapses under ChainHash (see module docstring)."""
    crc = seed & MASK64
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc & MASK64


def chainhash_crc128_lo(data: bytes, seed_components: list[int]) -> int:
    """Low 64 bits of ChainHash<CRC128>(data) under the given 16-component seed.

    Mirrors `Seed128.ChainHash128` exactly:
        (hLo, hHi) = CRC128(data, s[0],            s[1])
        (hLo, hHi) = CRC128(data, s[2]  XOR hLo,   s[3]  XOR hHi)
        ...
        (hLo, hHi) = CRC128(data, s[14] XOR hLo,   s[15] XOR hHi)
    Only hLo is returned — that is all ITB's encoding exposes.
    """
    assert len(seed_components) % 2 == 0
    h_lo = crc64_keyed(CRC64_TABLE_ECMA, data, seed_components[0] & MASK64)
    h_hi = crc64_keyed(CRC64_TABLE_ISO,  data, seed_components[1] & MASK64)
    for i in range(2, len(seed_components), 2):
        k_lo = (seed_components[i]     ^ h_lo) & MASK64
        k_hi = (seed_components[i + 1] ^ h_hi) & MASK64
        h_lo = crc64_keyed(CRC64_TABLE_ECMA, data, k_lo)
        h_hi = crc64_keyed(CRC64_TABLE_ISO,  data, k_hi)
    return h_lo


# --------------------------------------------------------------------------
# Partial-mode stream parsing — LSB-first 7-bit blocks, matching the demasker
# in nonce_reuse_demask.py → reconstruct_datahash_stream_partial (which packs
# `acc |= val << bit_count`, flushes whole bytes from the low end).
# --------------------------------------------------------------------------

def parse_partial_stream(
    stream_path: Path, index_path: Path
) -> list[tuple[int, int, int]]:
    """Parse the demasker's `.datahash.bin` + `.index` sidecar.

    Returns a list of `(data_pixel_idx, channel_idx, observed_7bits)` triples.
    """
    data = stream_path.read_bytes()
    with open(index_path) as f:
        pairs: list[tuple[int, int]] = []
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                pairs.append((int(parts[0]), int(parts[1])))

    observations: list[tuple[int, int, int]] = []
    bit_buf = 0
    bit_count = 0
    byte_idx = 0
    for (px, ch) in pairs:
        while bit_count < 7 and byte_idx < len(data):
            bit_buf |= data[byte_idx] << bit_count
            bit_count += 8
            byte_idx += 1
        if bit_count < 7:
            break  # stream truncated
        val7 = bit_buf & 0x7F
        bit_buf >>= 7
        bit_count -= 7
        observations.append((px, ch, val7))
    return observations


def parse_full_stream(
    stream_path: Path, index_path: Path | None = None
) -> list[tuple[int, int, int]]:
    """Parse a Full-KPA stream — 7 bytes per successfully-demasked data pixel.

    Full-KPA reconstruction in `nonce_reuse_demask.py` SKIPS data pixels
    where Layer 1 returned ambiguous (`recovered_config[i] is None`), so a
    naive `stream[i*7:(i+1)*7] = pixel i` walk is incorrect. The demasker
    now emits an `.index` sidecar listing the data_pixel_idx of each
    emitted 7-byte block in order; this parser honors it.

    If `index_path` is None, assumes contiguous 0..(N-1) indexing (legacy
    streams without the sidecar — will misattribute pixels if any were
    skipped).
    """
    data = stream_path.read_bytes()
    n_blocks = len(data) // 7
    if index_path is not None and index_path.exists():
        with open(index_path) as f:
            indices = [int(line.strip()) for line in f if line.strip()]
        if len(indices) != n_blocks:
            raise RuntimeError(
                f"full-mode stream has {n_blocks} blocks but index sidecar "
                f"has {len(indices)} entries — mismatch; file is corrupt."
            )
    else:
        indices = list(range(n_blocks))

    observations: list[tuple[int, int, int]] = []
    for b, data_idx in enumerate(indices):
        chunk = data[b * 7:(b + 1) * 7]
        acc = int.from_bytes(chunk, "little")
        for ch in range(8):
            val7 = (acc >> (ch * 7)) & 0x7F
            observations.append((data_idx, ch, val7))
    return observations


# --------------------------------------------------------------------------
# Compound-key recovery — the inversion itself.
# --------------------------------------------------------------------------

# ECMA + ISO components = 16 (8 rounds × 2 components per round at 1024-bit
# key + 128-bit hash width).
N_SEED_COMPONENTS = 16


def chainhash_const_at_pixel(pixel_idx: int, nonce: bytes) -> int:
    """Compute `const(pixel_idx) = ChainHash(pixel_le || nonce, seed=0)`.

    Entirely attacker-computable — depends on public info only (pixel_idx,
    nonce). No seed involved.
    """
    pixel_le = struct.pack("<I", pixel_idx)
    data = pixel_le + nonce
    return chainhash_crc128_lo(data, [0] * N_SEED_COMPONENTS)


def precompute_const_all(total_pixels: int, nonce: bytes) -> list[int]:
    """Precompute `const(p) = ChainHash(p_le || nonce, seed=0)` for every
    pixel p ∈ [0, total_pixels). One-time cost (~60s at 150k pixels in
    pure Python). Enables O(1) lookup during brute-force shift search —
    without this, each candidate shift re-computes ~2000 ChainHash
    evaluations, making large-corpus brute force infeasible.
    """
    out = [0] * total_pixels
    for p in range(total_pixels):
        pixel_le = struct.pack("<I", p)
        data = pixel_le + nonce
        out[p] = chainhash_crc128_lo(data, [0] * N_SEED_COMPONENTS)
    return out


def recover_compound_key_cached(
    observations: list[tuple[int, int, int]],
    total_pixels: int,
    const_all: list[int],
    pixel_shift: int = 0,
) -> tuple[int, int, int, int]:
    """Majority-vote K recovery using precomputed const_all lookup —
    same output semantics as `recover_compound_key` but O(1) per
    observation instead of O(ChainHash)."""
    counts = [[0, 0] for _ in range(64)]
    n_used = 0
    for (px, ch, observed_val) in observations:
        hash_pixel = (px + pixel_shift) % total_pixels
        const_p = const_all[hash_pixel]
        for k in range(7):
            bit_pos = ch * 7 + 3 + k
            if bit_pos >= 64:
                continue
            observed_bit = (observed_val >> k) & 1
            const_bit = (const_p >> bit_pos) & 1
            counts[bit_pos][observed_bit ^ const_bit] += 1
        n_used += 1
    K = 0
    known_mask = 0
    n_conflicts = 0
    for bit_pos in range(64):
        n_zero, n_one = counts[bit_pos]
        if n_zero == 0 and n_one == 0:
            continue
        majority = 1 if n_one > n_zero else 0
        K |= majority << bit_pos
        known_mask |= 1 << bit_pos
        n_conflicts += min(n_zero, n_one)
    return K, known_mask, n_used, n_conflicts


def recover_compound_key(
    observations: list[tuple[int, int, int]],
    nonce: bytes,
    total_pixels: int,
    pixel_shift: int = 0,
) -> tuple[int, int, int, int]:
    """Recover bits of the 64-bit compound key `K` from observations via
    per-bit majority voting.

    For each observation `(data_pixel_idx, ch, observed_7bit)`:
      1. hash_pixel = (data_pixel_idx + pixel_shift) mod total_pixels
      2. const_p = ChainHash(hash_pixel_le || nonce, seed = all-zero)
      3. Seven bits of K at positions `3 + 7*ch + k` (k in 0..6, < 64) are
         candidate-pinned by `observed_bit XOR const_p_bit`.
      4. Each K-bit is decided by majority across all observations that
         pinned it. `n_conflicts` counts observations outvoted by the
         majority — an indicator of stream seam artefacts (e.g., the
         1-bit period-shift seam) or wrong `pixel_shift`.

    Majority voting makes the solver tolerant of small imperfections in
    the demasker output (like the partial-mode period-shift seam) without
    deferring to hand-tuning. If a large fraction of observations conflict
    with the majority, `pixel_shift` is wrong.

    Returns `(K, known_mask, n_observations_used, n_conflicts)`.
    """
    # Per-bit tally: counts[bit_pos] = [zeros, ones]
    counts = [[0, 0] for _ in range(64)]
    n_used = 0
    const_cache: dict[int, int] = {}
    for (px, ch, observed_val) in observations:
        hash_pixel = (px + pixel_shift) % total_pixels
        const_p = const_cache.get(hash_pixel)
        if const_p is None:
            const_p = chainhash_const_at_pixel(hash_pixel, nonce)
            const_cache[hash_pixel] = const_p
        for k in range(7):
            bit_pos = ch * 7 + 3 + k
            if bit_pos >= 64:
                continue
            observed_bit = (observed_val >> k) & 1
            const_bit = (const_p >> bit_pos) & 1
            K_bit = observed_bit ^ const_bit
            counts[bit_pos][K_bit] += 1
        n_used += 1

    K = 0
    known_mask = 0
    n_conflicts = 0
    for bit_pos in range(64):
        n_zero, n_one = counts[bit_pos]
        total = n_zero + n_one
        if total == 0:
            continue  # bit never pinned
        majority = 1 if n_one > n_zero else 0
        K |= majority << bit_pos
        known_mask |= 1 << bit_pos
        n_conflicts += min(n_zero, n_one)

    return K, known_mask, n_used, n_conflicts


def compute_expected_K(meta: dict, nonce: bytes) -> int:
    """Red-team validation only: what `K` *should* be given ground-truth
    seed. Use any pixel — K is pixel-independent by construction. Reads
    `meta['data_seed']` (ground truth, NOT attacker-visible)."""
    true_ds = list(meta["data_seed"])
    pixel_le = struct.pack("<I", 0)
    data = pixel_le + nonce
    h_true = chainhash_crc128_lo(data, true_ds)
    h_zero = chainhash_crc128_lo(data, [0] * N_SEED_COMPONENTS)
    return h_true ^ h_zero


def predict_channel_xor(K: int, pixel_idx: int, nonce: bytes) -> list[int]:
    """Attacker predicts the 8 × 7-bit channelXOR values at `pixel_idx`.

    Under the 56 observable bits of K (positions 3..58), all 8 channels are
    fully predictable because channel i uses bits `3 + 7*i .. 3 + 7*i + 6`,
    all within 3..58 for i in 0..7.
    """
    const_p = chainhash_const_at_pixel(pixel_idx, nonce)
    h_lo = K ^ const_p
    x_mask = h_lo >> 3  # ITB's DataRotationBits = 3
    return [(x_mask >> (ch * 7)) & 0x7F for ch in range(8)]


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cell-dir", type=Path, required=True,
                    help="Corpus cell directory (contains cell.meta.json, "
                         "seed.truth.json, config.truth.json).")
    ap.add_argument("--datahash-stream", type=Path, required=True,
                    help="Demasked `.datahash.bin` emitted by nonce_reuse_demask.py.")
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
    ap.add_argument("--n-verify-pixels", type=int, default=64,
                    help="Predict channelXOR for N random pixels and diff "
                         "against config.truth.json (red-team validation).")
    args = ap.parse_args()

    cell_dir = args.cell_dir.resolve()
    meta = json.loads((cell_dir / "cell.meta.json").read_text())
    hash_name = meta["hash"]
    if hash_name != "crc128":
        print(f"WARNING: solver is written for crc128; got hash={hash_name}. "
              f"Python ChainHash<CRC128> mirror will produce garbage for "
              f"a different primitive. Abort.", file=sys.stderr)
        return 2
    if meta["hash_width"] != 128 or meta["key_bits"] != 1024:
        print(f"ERROR: solver assumes hash_width=128 + key_bits=1024 "
              f"(8 rounds ChainHash, 16 seed components). Got hash_width="
              f"{meta['hash_width']}, key_bits={meta['key_bits']}.",
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

    # Parse observations. Determine stream_mode from the demasker-emitted
    # `.meta.json` sidecar when available (attacker-visible metadata — no
    # ground truth). Falls back to heuristic for legacy streams.
    stream_path = args.datahash_stream.resolve()
    demask_meta_path = stream_path.with_suffix(stream_path.suffix + ".meta.json")
    demask_meta: dict = {}
    if demask_meta_path.exists():
        demask_meta = json.loads(demask_meta_path.read_text())
    stream_mode_hint = demask_meta.get("stream_mode")

    auto_index = args.index_sidecar.resolve() if args.index_sidecar else \
                 stream_path.with_suffix(stream_path.suffix + ".index")

    if stream_mode_hint == "partial":
        observations = parse_partial_stream(stream_path, auto_index)
        stream_mode = "partial-mode"
    elif stream_mode_hint == "full":
        idx_path = auto_index if auto_index.exists() else None
        observations = parse_full_stream(stream_path, idx_path)
        stream_mode = f"full-KPA ({'w/ index' if idx_path else 'legacy, no index'})"
    elif auto_index.exists():
        # No .meta.json — guess from index format (partial: "p ch" per line;
        # full: "p" per line).
        first = auto_index.read_text().splitlines()[0].split()
        if len(first) == 2:
            observations = parse_partial_stream(stream_path, auto_index)
            stream_mode = "partial-mode (inferred from index format)"
        else:
            observations = parse_full_stream(stream_path, auto_index)
            stream_mode = "full-KPA (inferred from index format)"
    else:
        observations = parse_full_stream(stream_path, None)
        stream_mode = "full-KPA (legacy, contiguous indexing)"
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
    #
    # Under majority-voting `recover_compound_key`, a correct `pixel_shift`
    # produces near-zero conflicts per bit-pin (seam artefacts only); a
    # wrong shift produces ~50% conflicts (random K-bit values across
    # pins). We accept the first shift whose conflict-rate per pin falls
    # well below the random-shift expectation of ~0.5.
    total_pixels = int(meta["total_pixels"])
    t0 = time.time()
    chosen_shift = args.pixel_shift
    const_all: list[int] | None = None
    if args.brute_force_shift > 0:
        brute_max = min(args.brute_force_shift, total_pixels)
        probe_skip = min(10, len(observations))
        probe_obs = observations[probe_skip:probe_skip + min(2000, len(observations) - probe_skip)]
        probe_pins_max = sum(
            1 for _, ch, _ in probe_obs for k in range(7)
            if (ch * 7 + 3 + k) < 64
        )
        candidate_threshold = max(1, probe_pins_max // 20)  # 5% pins
        # Precompute `const(p)` for every p in range ONCE so each brute-force
        # iteration becomes a cheap array lookup. Otherwise each shift would
        # re-compute ~2000 ChainHash evaluations → infeasible at 1MB+.
        max_p_needed = min(total_pixels, brute_max + max(px for px, _, _ in probe_obs) + 1)
        print(f"\nPrecomputing const(p) for p in [0, {total_pixels}) "
              f"(one-time ~{total_pixels // 2500}s; enables fast brute-force)...")
        t_pre = time.time()
        const_all = precompute_const_all(total_pixels, nonce)
        print(f"  precompute elapsed: {time.time() - t_pre:.2f}s")

        print(f"\nBrute-forcing pixel_shift in [0, {brute_max}) against "
              f"{len(probe_obs)} observations ({probe_pins_max} bit-pins; "
              f"collecting shifts with < {candidate_threshold} conflicts)...")
        # Store K + mask alongside each candidate so the lab-filter phase
        # doesn't re-solve expensive full-observation passes (O(candidates
        # × obs) blow-up otherwise).
        candidates: list[tuple[int, int, int, int]] = []  # (shift, conf, K, mask)
        t_brute = time.time()
        for s in range(brute_max):
            K_c, mask_c, _, conflicts = recover_compound_key_cached(
                probe_obs, total_pixels, const_all, pixel_shift=s,
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

    print(f"\nRecovering 64-bit compound key K = "
          f"[M_L^1, M_L^2, ..., M_L^8] · [s_14, s_12, ..., s_0] ...")
    K, known_mask, n_used, n_conflicts = recover_compound_key(
        observations, nonce, total_pixels, pixel_shift=chosen_shift,
    )
    elapsed = time.time() - t0
    known_bits = bin(known_mask).count("1")
    # Total bit-pins attempted = sum_ch,k ∈ observable of 1 per obs
    pins_per_obs = sum(1 for ch in range(8) for k in range(7) if (ch * 7 + 3 + k) < 64)
    total_pins = n_used * pins_per_obs // 8  # rough: only observable channels contribute
    total_pins = max(1, n_used * 7)  # per-observation pins (ch-restricted to observable)
    conflict_rate = n_conflicts / total_pins if total_pins else 0.0
    # Correct shift: < 1% conflicts (stream-seam noise only).
    # Wrong shift: ≈ 50% (random K-bit values across pins).
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

    # When brute-force gathered candidates, the lab-filter phase below picks
    # the correct one even if the tentative `chosen_shift` on the probe batch
    # turns out to have high conflicts on the full observation set (the probe
    # batch's first 2000 observations don't capture all shadow-K aliases,
    # so a probe-clean shift may go dirty on full data — this is fine, the
    # TRUE shift will still appear in the candidate list).
    if conflict_rate > 0.3 and not getattr(args, "_candidates", None):
        print(f"\n  ⚠ {100.0 * conflict_rate:.1f}% conflict rate — shift is wrong "
              f"(random-shift expectation is ~50%). Try --brute-force-shift or "
              f"supply a different --pixel-shift.")
        return 1

    # Red-team / laboratory validation: compare against ground truth.
    # The solver is a laboratory tool — it reads ground-truth data_seed
    # from cell.meta.json PURELY to tell the operator WHICH of the
    # brute-force candidates is the correct one. It does NOT use ground
    # truth for the solve itself (no --start-pixel from truth, no
    # --pixel-shift from truth). In production an attacker would filter
    # shadow Ks via a plaintext-consistency check on the companion
    # ciphertext — the same information-theoretic outcome without the
    # lab shortcut.
    try:
        K_expected = compute_expected_K(meta, nonce)
    except KeyError:
        print("  [warn] cell.meta.json missing `data_seed` ground-truth field; "
              "skipping oracle K comparison.")
        K_expected = None

    # If brute force collected multiple candidates, re-evaluate each against
    # ground truth and report the population.
    print(f"\n{'-' * 72}")
    print(f"Red-team oracle filtering (lab-only: uses cell.meta.json ground")
    print(f"truth to identify which of the brute-force candidates is correct")
    print(f"— attacker would filter via plaintext-consistency on companion ct)")
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
            print(f"  Likely causes: (a) correct shift was outside --brute-force-shift range,")
            print(f"  (b) probe batch too small, (c) demasker stream has broader corruption.")
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

    # Prediction test: predict channelXOR for a held-out set of pixels.
    # The attacker, having recovered K, predicts channelXOR at ANY go-pixel
    # index directly (indep of period-shift since K is pixel-independent).
    # Red-team validation: compare predictions against config.truth.json.
    try:
        config_truth = json.loads((cell_dir / "config.truth.json").read_text())
        truth_pixels = config_truth["per_pixel"] if "per_pixel" in config_truth \
                       else config_truth
        if isinstance(truth_pixels, dict) and "pixels" in truth_pixels:
            truth_pixels = truth_pixels["pixels"]
    except Exception as e:
        print(f"  [warn] could not load config.truth.json: {e}")
        truth_pixels = None

    if truth_pixels is not None:
        total_px = min(len(truth_pixels), meta["data_pixels"])
        import random
        rng = random.Random(0xC0DEBEE1)
        test_idxs = rng.sample(range(total_px), min(args.n_verify_pixels, total_px))
        n_pixels_match = 0
        n_channels_match = 0
        n_channels_total = 0
        # truth_pixels is indexed by Go's data-pixel index `p` (0..data_pixels-1).
        # For each idx, predict using hash_pixel = idx (Go feeds p directly).
        for idx in test_idxs:
            truth_entry = truth_pixels[idx]
            truth_ch = truth_entry["channel_xor_8"] if isinstance(truth_entry, dict) \
                       else truth_entry
            predicted = predict_channel_xor(K, idx, nonce)
            chs_ok = sum(1 for a, b in zip(predicted, truth_ch) if a == b)
            n_channels_match += chs_ok
            n_channels_total += 8
            if chs_ok == 8:
                n_pixels_match += 1
        print(f"\n  Predicted channelXOR at {len(test_idxs)} held-out data pixels "
              f"(not in observations):")
        print(f"    pixels fully matching : {n_pixels_match} / {len(test_idxs)}")
        print(f"    channels matching     : {n_channels_match} / {n_channels_total}  "
              f"({100.0 * n_channels_match / n_channels_total:.2f}%)")
        prediction_ok = (n_channels_match == n_channels_total)
    else:
        prediction_ok = None

    # Final verdict.
    print(f"\n{'=' * 72}")
    if K_match is True and (prediction_ok is True or prediction_ok is None):
        print(f"  ✅ COMPOUND KEY RECOVERED.  ChainHash<CRC128> at 1024-bit key")
        print(f"     effectively reduces to 64-bit security (56 observable via")
        print(f"     channelXOR); attacker predicts every channelXOR at every")
        print(f"     pixel of every ciphertext sharing (dataSeed, nonce).")
        print(f"  (FNV-1a at the same chain depth resists this attack because")
        print(f"   its Z/2^64 multiplication is not GF(2)-linear — see Phase 2a.)")
        return 0
    elif K_match is False or prediction_ok is False:
        print(f"  ⚠ Inversion appears inconsistent. Possible causes:")
        print(f"     - wrong --pixel-shift (period-shift catastrophe; try")
        print(f"       --brute-force-shift N for small N first)")
        print(f"     - demasker produced corrupted stream (check its validation)")
        print(f"     - bug in Python ChainHash<CRC128> mirror vs Go stdlib crc64")
        return 1
    else:
        print(f"  (validation artefacts missing — see warnings above)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
