"""Shared hash-agnostic machinery for raw-ciphertext bias analysis and
compound-key recovery against ITB nonce-reuse streams.

Every function here operates on opaque observation triples `(pixel_idx,
channel_idx, observed_7bits)` and a pluggable `chainhash_lo` function
that returns the low 64 bits of a ChainHash-wrapped hash primitive. The
module does not care which primitive is used — it only cares that the
ChainHash-output is pixel-independent + nonce-dependent through the
standard ITB encoding (`xorMask = hLo >> 3`, 8 × 7-bit channelXOR slots).

Use `chainhashes/*.py` modules as pluggable implementations.

The `*_np` variants are numpy-vectorized and 10-50× faster than the
pure-Python reference variants on large observation sets — prefer them
for any brute-force scan over many pixel-shifts.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

import numpy as np

HEADER_SIZE = 20          # ITB ciphertext header: 16-byte nonce + 2 × uint16
CHANNELS = 8              # RGBWYOPA
DATA_BITS_PER_CHANNEL = 7
DATA_BITS_PER_PIXEL = 56  # 8 × 7
MASK64 = (1 << 64) - 1


# --------------------------------------------------------------------------
# Stream / ciphertext parsing
# --------------------------------------------------------------------------

def parse_raw_ciphertext(
    ciphertext_path: Path, total_pixels: int,
) -> List[Tuple[int, int, int]]:
    """Parse raw ITB ciphertext directly (no demasking).

    Reads the 20-byte header, then `total_pixels × 8` channel bytes.
    For each container position `cp` and each channel `ch`, emits a
    triple `(cp, ch, byte & 0x7F)` — raw byte masked to low 7 bits.

    The raw byte contains `rotate7(plaintext_bits XOR channelXOR,
    rotation)` with one noise bit inserted at `noisePos`; without
    demasking the solver's majority-vote sees a mix of those components
    across many pixels and statistically extracts any residual bias.
    """
    raw = ciphertext_path.read_bytes()
    need = HEADER_SIZE + total_pixels * CHANNELS
    if len(raw) < need:
        raise RuntimeError(
            f"raw ciphertext too short for total_pixels={total_pixels}: "
            f"{len(raw)} bytes, need {need}."
        )
    body = raw[HEADER_SIZE:need]
    observations: List[Tuple[int, int, int]] = []
    for cp in range(total_pixels):
        base = cp * CHANNELS
        for ch in range(CHANNELS):
            observations.append((cp, ch, body[base + ch] & 0x7F))
    return observations


def parse_partial_stream(
    stream_path: Path, index_path: Path,
) -> List[Tuple[int, int, int]]:
    """Parse a partial-mode demasked stream + its `.index` sidecar.

    The demasker packs 7-bit blocks LSB-first (accumulator fills at low
    bit-count, whole bytes flush from the low end). Returns triples
    `(data_pixel_idx, channel_idx, observed_7bits)` in emission order.
    """
    data = stream_path.read_bytes()
    with open(index_path) as f:
        pairs: List[Tuple[int, int]] = []
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                pairs.append((int(parts[0]), int(parts[1])))

    out: List[Tuple[int, int, int]] = []
    bit_buf = 0
    bit_count = 0
    byte_idx = 0
    for (px, ch) in pairs:
        while bit_count < 7 and byte_idx < len(data):
            bit_buf |= data[byte_idx] << bit_count
            bit_count += 8
            byte_idx += 1
        if bit_count < 7:
            break
        val7 = bit_buf & 0x7F
        bit_buf >>= 7
        bit_count -= 7
        out.append((px, ch, val7))
    return out


def parse_full_stream(
    stream_path: Path, index_path: Optional[Path] = None,
) -> List[Tuple[int, int, int]]:
    """Parse a Full-KPA demasked stream (7 bytes per successfully-recovered
    data pixel, packed little-endian across 8 × 7-bit channels).

    Full-mode reconstruction SKIPS ambiguous pixels, so an `.index` sidecar
    listing emitted data_pixel_idx per 7-byte block is required for precise
    position attribution. If absent, assumes contiguous `range(n_blocks)`
    indexing — only correct for streams with no skips.
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

    out: List[Tuple[int, int, int]] = []
    for b, data_idx in enumerate(indices):
        chunk = data[b * 7:(b + 1) * 7]
        acc = int.from_bytes(chunk, "little")
        for ch in range(CHANNELS):
            out.append((data_idx, ch, (acc >> (ch * DATA_BITS_PER_CHANNEL)) & 0x7F))
    return out


# --------------------------------------------------------------------------
# Pluggable chainhash adapter
# --------------------------------------------------------------------------

def precompute_const_all(
    total_pixels: int,
    nonce: bytes,
    chainhash_fn: Callable[[bytes, Sequence[int]], int],
    n_seed_components: int,
) -> np.ndarray:
    """For every pixel p ∈ [0, total_pixels), compute
    `const(p) = chainhash_fn(pixel_le_u32 || nonce, seed = all-zero)`.

    This is attacker-computable public-info baseline; recovering the
    compound key K reduces to XOR-subtracting const(p) from observed
    channelXOR values. Precomputed once to enable O(1) lookup during
    brute-force shift scans.
    """
    zero_seed = [0] * n_seed_components
    out = np.zeros(total_pixels, dtype=np.uint64)
    for p in range(total_pixels):
        pixel_le = struct.pack("<I", p)
        out[p] = chainhash_fn(pixel_le + nonce, zero_seed) & MASK64
    return out


def chainhash_const_at_pixel(
    pixel_idx: int,
    nonce: bytes,
    chainhash_fn: Callable[[bytes, Sequence[int]], int],
    n_seed_components: int,
) -> int:
    """One-off `const(p)` for predictions / validation without precompute."""
    pixel_le = struct.pack("<I", pixel_idx)
    return chainhash_fn(pixel_le + nonce, [0] * n_seed_components) & MASK64


# --------------------------------------------------------------------------
# Axis-2 — prediction accuracy of a recovered compound key
# --------------------------------------------------------------------------

def prediction_accuracy(
    K: int,
    known_mask: int,
    per_pixel_truth: Sequence[dict],
    const_all: np.ndarray,
    pixel_shift: int,
    total_pixels: int,
    test_pixels: Sequence[int],
) -> Tuple[int, int, float, int, int, float]:
    """Given a recovered compound key K and the lab-only `per_pixel`
    ground truth (from `config.truth.json`), score how well K predicts
    the actual per-channel xorMask at held-out pixels.

    For each test container-position `cp` in `test_pixels`:
      - hash_pixel = (cp + pixel_shift) mod total_pixels
      - data_pixel_idx = hash_pixel (both indexes are in [0, total_pixels);
        per_pixel_truth is indexed by data pixel which equals hash pixel
        for mode=known_ascii where data_pixels == total_pixels).
      - predicted `h_seeded = K XOR const_all[hash_pixel]` (GF(2)-linear
        assumption; for PRFs this relation is meaningless noise).
      - for each channel ch in 0..7:
          predicted_xor[ch] = (h_seeded >> (3 + 7*ch)) & 0x7F
        compare to per_pixel_truth[hash_pixel]["channel_xor_8"][ch].
      - count per-bit matches only at bit-positions marked in known_mask
        (positions not pinned by the bias probe return 0 predictive info).

    Returns `(channels_matched, channels_total, channels_accuracy,
              bits_matched, bits_total, bits_accuracy)`.

    **Primary signal: `bits_accuracy`.** In ITB's raw-ciphertext mode,
    each observation passes through rotate7 + noise-bit injection before
    the bias probe sees it. Majority-vote per K-bit therefore recovers K
    through a shuffled-bit channel: per-bit accuracy is ~50 % under a
    PRF (±√(1/N) binomial noise) and empirically ~55–62 % under a
    GF(2)-linear primitive at the correct / shadow-alias shift. The 5-12
    percentage-point gap is the discriminator.

    `channels_accuracy` (all 7 bits of a slot matching together) is
    essentially zero in both regimes — (0.55)^7 ≈ 0.015 for CRC128 and
    1/128 ≈ 0.008 for PRFs — so it does not separate the two classes
    under raw-mode masking. It is reported for diagnostic completeness
    only. (A demasked stream would give a clean channel-accuracy signal
    but is unavailable to a real-world attacker — demasking requires
    nonce-reuse, which in ITB with a 512-bit nonce has negligible
    probability.)
    """
    channels_matched = 0
    channels_total = 0
    bits_matched = 0
    bits_total = 0
    K = int(K) & MASK64

    # Precompute per-channel bit-position masks that are pinned by the
    # probe. Channels whose slot sits entirely above bit 63 (channel 7 at
    # bits 52..58 is the highest — within range) contribute 0..7 bits.
    for cp in test_pixels:
        hash_pixel = (cp + pixel_shift) % total_pixels
        if hash_pixel >= len(per_pixel_truth):
            continue
        truth_entry = per_pixel_truth[hash_pixel]
        truth_xor = truth_entry.get("channel_xor_8")
        if truth_xor is None:
            continue

        h_zero = int(const_all[hash_pixel]) & MASK64
        h_seeded_pred = K ^ h_zero

        for ch in range(CHANNELS):
            # Predict the 7-bit channelXOR at bits 3 + 7*ch + {0..6}.
            bit_mask_7 = 0
            bit_count = 0
            for k in range(DATA_BITS_PER_CHANNEL):
                bp = 3 + 7 * ch + k
                if bp >= 64:
                    continue
                if (known_mask >> bp) & 1:
                    bit_mask_7 |= 1 << k
                    bit_count += 1
            if bit_count == 0:
                continue
            # Extract predicted and truth 7-bit values restricted to the
            # mask of pinned bits.
            pred7_full = 0
            for k in range(DATA_BITS_PER_CHANNEL):
                bp = 3 + 7 * ch + k
                if bp >= 64:
                    continue
                pred7_full |= ((h_seeded_pred >> bp) & 1) << k
            pred7 = pred7_full & bit_mask_7
            truth7 = int(truth_xor[ch]) & bit_mask_7

            channels_total += 1
            bits_total += bit_count
            if pred7 == truth7:
                channels_matched += 1
            # bit-level match count
            diff = pred7 ^ truth7
            mismatches = bin(diff).count("1")
            bits_matched += bit_count - mismatches

    ch_acc = channels_matched / channels_total if channels_total else 0.0
    bit_acc = bits_matched / bits_total if bits_total else 0.0
    return channels_matched, channels_total, ch_acc, bits_matched, bits_total, bit_acc


# --------------------------------------------------------------------------
# Observation → numpy
# --------------------------------------------------------------------------

def observations_to_numpy(
    observations: Sequence[Tuple[int, int, int]],
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Convert a list of `(px, ch, val)` triples into three numpy arrays of
    matching length. One-time cost amortised over any downstream brute-force
    scan."""
    n = len(observations)
    obs_px = np.zeros(n, dtype=np.int64)
    obs_ch = np.zeros(n, dtype=np.uint8)
    obs_val = np.zeros(n, dtype=np.uint8)
    for i, (px, ch, val) in enumerate(observations):
        obs_px[i] = px
        obs_ch[i] = ch
        obs_val[i] = val
    return obs_px, obs_ch, obs_val


# --------------------------------------------------------------------------
# Compound-key recovery — majority voting per K bit across observations
# --------------------------------------------------------------------------

def recover_compound_key_cached(
    observations: Sequence[Tuple[int, int, int]],
    total_pixels: int,
    const_all: np.ndarray,
    pixel_shift: int = 0,
) -> Tuple[int, int, int, int]:
    """Pure-Python reference implementation. For each observation, derive
    candidate K bits at positions `3 + 7*ch + k` (k in 0..6 with bit_pos
    < 64) via `K_bit = observed_bit XOR const_bit`, majority-vote per K
    bit position.

    Returns `(K, known_mask, n_observations_used, n_conflicts)` where
    known_mask marks which of the 64 K bits got pinned and n_conflicts
    counts observations outvoted by the per-bit majority (a wrong
    pixel_shift produces ~50 % conflicts; correct shift produces
    near-zero conflicts aside from stream-seam noise).
    """
    counts = [[0, 0] for _ in range(64)]
    n_used = 0
    for (px, ch, observed_val) in observations:
        hash_pixel = (px + pixel_shift) % total_pixels
        const_p = int(const_all[hash_pixel])
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


# Precompute a (CHANNELS, 7) table of bit positions; each (ch, k) maps to
# the K-bit-index it pins. Re-used by the numpy fast-path below.
_BIT_POS_TABLE: Optional[np.ndarray] = None


def _bit_pos_table() -> np.ndarray:
    global _BIT_POS_TABLE
    if _BIT_POS_TABLE is None:
        t = np.zeros((CHANNELS, 7), dtype=np.int16)
        for ch in range(CHANNELS):
            for k in range(7):
                bp = ch * 7 + 3 + k
                t[ch, k] = bp if bp < 64 else -1
        _BIT_POS_TABLE = t
    return _BIT_POS_TABLE


def recover_compound_key_cached_np(
    obs_px: np.ndarray,
    obs_ch: np.ndarray,
    obs_val: np.ndarray,
    total_pixels: int,
    const_all: np.ndarray,
    pixel_shift: int = 0,
) -> Tuple[int, int, int, int]:
    """Numpy-vectorized equivalent of `recover_compound_key_cached`.

    Arguments are pre-flattened observation arrays produced once by
    `observations_to_numpy`. Returns the same tuple signature. Typically
    10-50× faster than the pure-Python version for probe sizes in the
    thousands, which makes brute-force scans over 600k+ shift candidates
    practical on commodity hardware.
    """
    n = obs_px.shape[0]
    if n == 0:
        return 0, 0, 0, 0
    # Hash-pixel gather
    hash_pixels = (obs_px + pixel_shift) % total_pixels
    const_vals = const_all[hash_pixels].astype(np.uint64)

    # Expand (N,) → (N, 7): per observation, 7 bit pins at k ∈ 0..6
    bit_pos_table = _bit_pos_table()          # shape (8, 7) int16
    bit_pos_per_obs = bit_pos_table[obs_ch]   # shape (N, 7) int16
    k_vec = np.arange(7, dtype=np.uint64)     # shape (7,)

    # observed_bit[i, k] = (obs_val[i] >> k) & 1
    observed_bits = ((obs_val.astype(np.uint64)[:, None]) >> k_vec) & np.uint64(1)
    # const_bit[i, k] = (const_vals[i] >> bit_pos_per_obs[i, k]) & 1
    # Guard against bit_pos == -1 (invalid) — shift by 0 and then mask out.
    safe_shifts = np.where(bit_pos_per_obs >= 0, bit_pos_per_obs, 0).astype(np.uint64)
    const_bits = (const_vals[:, None] >> safe_shifts) & np.uint64(1)

    # K-bit candidate per (obs, k)
    k_bit_candidates = (observed_bits ^ const_bits).astype(np.int64)

    # Mask out invalid positions
    valid_mask = bit_pos_per_obs >= 0
    flat_bit_pos = bit_pos_per_obs[valid_mask].astype(np.int64)
    flat_k_bit = k_bit_candidates[valid_mask]

    # Per-bit-position counts of ones and totals
    ones_per_pos = np.bincount(flat_bit_pos, weights=flat_k_bit, minlength=64).astype(np.int64)
    totals_per_pos = np.bincount(flat_bit_pos, minlength=64).astype(np.int64)
    zeros_per_pos = totals_per_pos - ones_per_pos

    # Majority per bit_pos; mask out bits never pinned.
    K = 0
    known_mask = 0
    n_conflicts = 0
    for bit_pos in range(64):
        total = int(totals_per_pos[bit_pos])
        if total == 0:
            continue
        ones = int(ones_per_pos[bit_pos])
        zeros = total - ones
        majority = 1 if ones > zeros else 0
        K |= majority << bit_pos
        known_mask |= 1 << bit_pos
        n_conflicts += min(ones, zeros)

    return K, known_mask, int(n), n_conflicts
