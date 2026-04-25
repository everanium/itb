#!/usr/bin/env python3
"""Axis A lab bias harness for t1ha1_64le (HARNESS.md § 3.1).

Runs SMHasher-subset statistical bias tests on the **native 64-bit
t1ha1_64le output** — which equals the hLo projection that ITB's encoding
path observes when t1ha1 is wrapped via the parallel two-lane 128-bit
adapter (lo lane = t1ha1_64le(data, seed_lo)). hHi is constructed by a
separate t1ha1_64le call with seed_hi and is discarded at the ITB encoding
boundary; the quantity that actually reaches ChainHash composition is
what this harness measures.

Tests:
  * Avalanche bias across key sizes — the published SMHasher failure mode
    for t1ha1_64le (`rurban/smhasher` t1ha1_64le.txt: worst bias 3.77 % at
    512-bit keys, 3.95 % at 1024-bit keys vs ~0.6 % cryptographic baseline).
    Large-key avalanche scaling is the property that makes t1ha1 the top
    pedagogical priority in HARNESS.md § 4.1 — it matches ITB's
    flagship key-size operating point (keyBits = 512 / 1024 / 2048).
  * MomentChi2 — output byte distribution uniformity on 2²⁰ random
    inputs.
  * Sparse-keyset collision rate on all 160-bit keys with ≤ 2 bits set.
    Directly relates to the Crib-KPA threat model: schema token headers
    are sparse by construction.

Usage:
  python3 scripts/redteam/phase2_theory_t1ha1/lab_bias_t1ha1.py \\
      --n-keys 4096 --key-sizes 8,16,32,64,128,256 \\
      --chi2-samples 1048576 \\
      --sparse-bits 2 \\
      --json-report tmp/attack/t1ha1stress/axis_a_lab_bias.json

Default sample sizes are deliberately small for quick iteration (single-
digit minutes on commodity 16-core); scale up `--n-keys` to 65536 for
publication-grade CI on the avalanche measurement (published bias signals
of 1 – 4 % sit well above noise at 4096 samples already).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats

HERE = Path(__file__).resolve().parent
PROJ = HERE.parents[2]
sys.path.insert(0, str(PROJ / "scripts" / "redteam" / "phase2_theory"))

from chainhashes.t1ha1 import t1ha1_64le  # noqa: E402

OUTPUT_BITS = 64  # t1ha1_64le native output width
MASK64 = (1 << 64) - 1


# ============================================================================
# Avalanche test
# ============================================================================


def avalanche_test(n_keys: int, key_bytes: int, rng_seed: int) -> dict[str, Any]:
    """Flip each input bit one at a time for each of `n_keys` random keys;
    measure per-(input_bit, output_bit) flip probability. Worst-case
    |P(flip) - 0.5| is the avalanche bias reported by SMHasher.

    Two common conventions in the literature:
      * Raw bias = |P(flip) - 0.5|, max ≈ 0.5
      * SMHasher-style bias = 2 × |P(flip) - 0.5|, reported as % (max 100 %)
    Both are reported below; the rurban/smhasher numbers use the SMHasher-
    style convention.
    """
    rng = random.Random(rng_seed)
    key_bits = key_bytes * 8

    # Track XOR of (base ^ flipped) across samples, per (input_bit, output_bit).
    # Accumulate bit-flip counts as uint64 (output_bits bits packed per row),
    # then unpack at the end via numpy bit tricks for vectorised stats.
    flip_counts = np.zeros((key_bits, OUTPUT_BITS), dtype=np.int64)

    t0 = time.time()
    for _ in range(n_keys):
        key = bytearray(rng.randbytes(key_bytes))
        base_hash = t1ha1_64le(bytes(key), 0)

        for input_bit in range(key_bits):
            byte_idx = input_bit // 8
            bit_mask = 1 << (input_bit % 8)
            key[byte_idx] ^= bit_mask
            flipped_hash = t1ha1_64le(bytes(key), 0)
            key[byte_idx] ^= bit_mask  # restore

            diff = base_hash ^ flipped_hash
            # Unpack 64 bits via numpy for vectorised accumulation.
            diff_bytes = diff.to_bytes(8, "little")
            bits = np.unpackbits(np.frombuffer(diff_bytes, dtype=np.uint8),
                                 bitorder="little")
            flip_counts[input_bit] += bits

    elapsed = time.time() - t0

    # Compute bias matrix.
    p_flip = flip_counts / float(n_keys)
    raw_bias = np.abs(p_flip - 0.5)
    smhasher_bias = 2.0 * raw_bias

    return {
        "key_bytes": key_bytes,
        "key_bits": key_bits,
        "n_keys": n_keys,
        "output_bits": OUTPUT_BITS,
        "elapsed_s": round(elapsed, 2),
        "raw_bias_max": float(raw_bias.max()),
        "raw_bias_mean": float(raw_bias.mean()),
        "raw_bias_p99": float(np.percentile(raw_bias, 99)),
        "smhasher_bias_max_pct": float(smhasher_bias.max() * 100),
        "smhasher_bias_mean_pct": float(smhasher_bias.mean() * 100),
        "smhasher_bias_p99_pct": float(np.percentile(smhasher_bias, 99) * 100),
        "binomial_noise_pct": float(100.0 / np.sqrt(n_keys)),  # rough 1-sigma
    }


# ============================================================================
# MomentChi2 — output byte distribution uniformity
# ============================================================================


def momentchi2_test(n_samples: int, rng_seed: int) -> dict[str, Any]:
    """Chi-square test on the byte distribution of t1ha1_64le output.
    Generate `n_samples` random 64-byte keys, hash each with seed=0, split
    each 8-byte output into 8 bytes, and test uniformity over 256 bin
    frequencies (df=255). p < 1e-3 indicates measurable distributional
    deviation at this sample size.
    """
    rng = random.Random(rng_seed)
    byte_counts = np.zeros(256, dtype=np.int64)

    t0 = time.time()
    for _ in range(n_samples):
        key = rng.randbytes(64)
        h = t1ha1_64le(key, 0)
        for octet in h.to_bytes(8, "little"):
            byte_counts[octet] += 1
    elapsed = time.time() - t0

    # Chi-square against uniform distribution.
    expected = byte_counts.sum() / 256.0
    chi2, p = stats.chisquare(byte_counts, f_exp=[expected] * 256)

    return {
        "n_samples": n_samples,
        "total_bytes_observed": int(byte_counts.sum()),
        "elapsed_s": round(elapsed, 2),
        "chi2_stat": float(chi2),
        "chi2_p": float(p),
        "chi2_df": 255,
        "max_byte_freq": int(byte_counts.max()),
        "min_byte_freq": int(byte_counts.min()),
        "expected_per_bin": float(expected),
    }


# ============================================================================
# Sparse-keyset collision test
# ============================================================================


def sparse_keyset_test(n_bits_set_max: int, key_bytes: int,
                       rng_seed: int) -> dict[str, Any]:
    """Enumerate all keys of width `key_bytes` with ≤ `n_bits_set_max`
    bits set, hash each, count collisions. rurban/smhasher reports
    t1ha0_32le: 2.38 × 10⁶× over-expected collisions at 160-bit keys with
    ≤ 4 bits set. t1ha1_64le's sparse behaviour is not individually
    reported in rurban — this test establishes the baseline.
    """
    from itertools import combinations

    key_bits = key_bytes * 8
    # Count how many keys we'll test.
    n_keys = 0
    for k in range(1, n_bits_set_max + 1):
        n_keys += len(list(combinations(range(key_bits), k)))

    t0 = time.time()
    hashes: dict[int, int] = {}  # hash -> count
    collision_pairs = 0
    for k in range(1, n_bits_set_max + 1):
        for bit_positions in combinations(range(key_bits), k):
            key = bytearray(key_bytes)
            for bp in bit_positions:
                key[bp // 8] |= (1 << (bp % 8))
            h = t1ha1_64le(bytes(key), 0)
            if h in hashes:
                collision_pairs += hashes[h]  # number of prior keys that collide
                hashes[h] += 1
            else:
                hashes[h] = 1
    elapsed = time.time() - t0

    # Expected collisions under uniform 64-bit output: C(n, 2) / 2^64.
    expected_collisions = (n_keys * (n_keys - 1) / 2) / (2 ** 64)
    if expected_collisions > 0:
        collision_multiplier = collision_pairs / expected_collisions
    else:
        collision_multiplier = 0.0 if collision_pairs == 0 else float("inf")

    return {
        "key_bytes": key_bytes,
        "key_bits": key_bits,
        "n_bits_set_max": n_bits_set_max,
        "n_keys_enumerated": n_keys,
        "elapsed_s": round(elapsed, 2),
        "collision_pairs": collision_pairs,
        "expected_collision_pairs": expected_collisions,
        "collision_multiplier_over_expected": collision_multiplier,
    }


# ============================================================================
# Driver
# ============================================================================


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Axis A lab bias on t1ha1_64le hLo projection")
    p.add_argument("--n-keys", type=int, default=4096,
                   help="random keys per avalanche key-size (default 4096)")
    p.add_argument("--key-sizes", type=str, default="8,16,32,64,128",
                   help="comma-separated key sizes in BYTES for avalanche "
                        "(default '8,16,32,64,128' → 64–1024 bits)")
    p.add_argument("--chi2-samples", type=int, default=1048576,
                   help="samples for MomentChi2 test (default 2^20)")
    p.add_argument("--sparse-bits", type=int, default=2,
                   help="max bits-set for sparse keyset test; 2 gives "
                        "12880 keys on 160-bit, 3 gives 681040 keys "
                        "(default 2)")
    p.add_argument("--sparse-key-bytes", type=int, default=20,
                   help="key size in bytes for sparse keyset test "
                        "(default 20 → 160-bit, matches rurban convention)")
    p.add_argument("--rng-seed", type=int, default=1,
                   help="deterministic RNG seed (default 1)")
    p.add_argument("--skip-tests", type=str, default="",
                   help="comma-separated test names to skip: "
                        "avalanche, momentchi2, sparse")
    p.add_argument("--json-report", type=str, default="",
                   help="output JSON file path (default: stdout-only)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    skip = set(s.strip() for s in args.skip_tests.split(",") if s.strip())

    report: dict[str, Any] = {
        "primitive": "t1ha1_64le",
        "axis": "A",
        "scope": "hLo projection on raw primitive (native 64-bit output)",
        "published_reference": {
            "source": "rurban/smhasher t1ha1_64le.txt",
            "avalanche_512bit_pct": 3.77,
            "avalanche_1024bit_pct": 3.95,
        },
        "timestamp": int(time.time()),
        "args": vars(args),
        "results": {},
    }

    if "avalanche" not in skip:
        print("[avalanche] running across key sizes...", file=sys.stderr)
        sizes = [int(s) for s in args.key_sizes.split(",")]
        avalanche = []
        for key_bytes in sizes:
            print(f"  key_bytes={key_bytes} ({key_bytes*8}-bit) "
                  f"n_keys={args.n_keys}...", file=sys.stderr, end=" ",
                  flush=True)
            r = avalanche_test(args.n_keys, key_bytes, args.rng_seed)
            print(f"max_bias={r['smhasher_bias_max_pct']:.3f}%  "
                  f"elapsed={r['elapsed_s']}s", file=sys.stderr)
            avalanche.append(r)
        report["results"]["avalanche"] = avalanche

    if "momentchi2" not in skip:
        print("[momentchi2] running...", file=sys.stderr, end=" ",
              flush=True)
        r = momentchi2_test(args.chi2_samples, args.rng_seed)
        print(f"chi2_p={r['chi2_p']:.4e}  elapsed={r['elapsed_s']}s",
              file=sys.stderr)
        report["results"]["momentchi2"] = r

    if "sparse" not in skip:
        print("[sparse] running...", file=sys.stderr, end=" ", flush=True)
        r = sparse_keyset_test(args.sparse_bits, args.sparse_key_bytes,
                               args.rng_seed)
        print(f"collisions={r['collision_pairs']}  "
              f"multiplier={r['collision_multiplier_over_expected']:.3e}  "
              f"elapsed={r['elapsed_s']}s", file=sys.stderr)
        report["results"]["sparse"] = r

    if args.json_report:
        out = Path(args.json_report)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[report] wrote {out}", file=sys.stderr)
    else:
        print(json.dumps(report, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
