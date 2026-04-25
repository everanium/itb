#!/usr/bin/env python3
"""Axis A' — structural-input bias on seahash64 hLo projection.

Companion to lab_bias_seahash.py. Differs in methodology per the ITB-attack-
realistic threat model rather than the standard SMHasher random-input
avalanche:

  * Seeds are FIXED (single deterministic seed) — mirrors ITB deployment
    reality where seeds are per-deployment invariants across many messages
  * Input data VARIES across N instances, but each instance carries the
    SAME JSON schema with repeated field names / values differing per
    instance — mirrors real traffic patterns where attackers observe many
    ciphertexts of structurally-similar plaintexts

Formats: `json_structured` (primary — fixed-width records, byte-aligned
field-name repetition) and `html_structured` (secondary — tag-wrapped
records with variable-length content between tags). Both formats sit in
the printable ASCII alphabet and match the
[Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2)
known_json_structured / known_html_structured convention so Axis A' rows
are directly comparable to the existing Axis B audit across the same
three plaintext kinds (ascii already covered by lab_bias_seahash.py random
avalanche). JSON is the more sensitive detector on the hypothesis that
seahash's 32-byte block loop + 1..31-byte tail handler responds to
repetition-at-fixed-offset; HTML serves as a complementary check on
variable-length structural patterns.

Tests:
  1. Per-bit output frequency — each output bit should be 50 % across N
     instances. Bias > binomial noise indicates structural leakage.
  2. Byte-distribution chi-square — joint byte uniformity (df=255).
  3. Sequential autocorrelation (XOR of adjacent hashes) — should be
     itself uniform. Correlation between consecutive instances indicates
     the primitive preserves schema-level correlation into the output.

Usage:
  python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \\
      --n-instances 64 --instance-size 4096 \\
      --json-report tmp/attack/seahashstress/axis_a_struct_smoke.json

Sample-size scaling (for publication, scale up):
  n=64     bit_bias noise ≈ 6.25 %  (smoke only — tests pipeline)
  n=1024   bit_bias noise ≈ 1.56 %
  n=16384  bit_bias noise ≈ 0.39 %
  n=65536  bit_bias noise ≈ 0.20 %  (publication-grade)
"""

from __future__ import annotations

import argparse
import json
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

from chainhashes.seahash import seahash64  # noqa: E402

OUTPUT_BITS = 64
MASK64 = (1 << 64) - 1

# Record alphabets — deliberately small ASCII subsets so record bytes are
# in the printable range (matches ITB known_ascii regime for Axis B
# comparability) and varying-value content has constrained entropy.
ALPHABET_NAME = b"abcdefghijklmnopqrstuvwxyz"
ALPHABET_VALUE = b"abcdefghijklmnopqrstuvwxyz0123456789"

# Record format:
#   '  {"seq": "NNNNNN", "name": "<13-char>", "value": "<33-char>"},\n'
# With the comma-newline, total = 2+8+6+12+13+13+33+4 = 91 bytes per record.
# Not exactly 32-byte aligned but every record is the SAME length, so
# schema bytes (field names, quotes, braces) appear at identical positions
# modulo 91 bytes across every record in the instance.
NAME_LEN = 13
VALUE_LEN = 33


def generate_json_instance(size_bytes: int, instance_seed: int) -> bytes:
    """Generate one instance of structured JSON plaintext with fixed
    schema but varying field values. Total output padded to exactly
    size_bytes. Deterministic given instance_seed."""
    rng = random.Random(instance_seed)
    out = bytearray(b"[\n")
    i = 0
    # Leave ~50 bytes room for closing bracket + padding.
    while len(out) < size_bytes - 50:
        i += 1
        seq = f'"{i:06d}"'.encode("ascii")
        name = bytes(rng.choices(ALPHABET_NAME, k=NAME_LEN))
        value = bytes(rng.choices(ALPHABET_VALUE, k=VALUE_LEN))
        rec = (
            b'  {"seq": ' + seq
            + b', "name": "' + name
            + b'", "value": "' + value
            + b'"},\n'
        )
        out += rec
    # Close array + pad to exact size.
    out += b'  {"end": true}\n]\n'
    if len(out) < size_bytes:
        out += b" " * (size_bytes - len(out))
    else:
        out = out[:size_bytes]
    return bytes(out)


def generate_html_instance(size_bytes: int, instance_seed: int) -> bytes:
    """Generate one instance of tag-wrapped HTML plaintext with fixed
    schema but varying text content. Parallels the
    known_html_structured mode in redteam_lab_test.go: records are
    <div class="item">...</div> wrappers around inner <span>/<a>/<p>
    tags with varying text. Total output padded to exactly size_bytes.
    Deterministic given instance_seed.

    HTML is less byte-aligned than JSON (tag lengths vary slightly
    depending on inner-tag lengths) — useful as a complementary probe
    for bias that requires variable-length structural patterns rather
    than consistent-offset repetition."""
    rng = random.Random(instance_seed)
    out = bytearray(b"<html><body>\n")
    i = 0
    # Leave ~100 bytes room for closing tags + padding.
    while len(out) < size_bytes - 100:
        i += 1
        seq = f"{i:06d}".encode("ascii")
        name = bytes(rng.choices(ALPHABET_NAME, k=NAME_LEN))
        value = bytes(rng.choices(ALPHABET_VALUE, k=VALUE_LEN))
        rec = (
            b'  <div class="item"><span class="seq">' + seq
            + b'</span><a href="#">' + name
            + b'</a><p class="content">' + value
            + b"</p></div>\n"
        )
        out += rec
    out += b"</body></html>\n"
    if len(out) < size_bytes:
        out += b" " * (size_bytes - len(out))
    else:
        out = out[:size_bytes]
    return bytes(out)


_INSTANCE_GENERATORS = {
    "json": generate_json_instance,
    "html": generate_html_instance,
}


def generate_instance(fmt: str, size_bytes: int, instance_seed: int) -> bytes:
    gen = _INSTANCE_GENERATORS.get(fmt)
    if gen is None:
        raise ValueError(f"unknown --format {fmt!r}; "
                         f"expected one of {sorted(_INSTANCE_GENERATORS)}")
    return gen(size_bytes, instance_seed)


def struct_bias_test(n_instances: int, instance_size: int,
                     fixed_seed: int, rng_base: int,
                     fmt: str = "json") -> dict[str, Any]:
    """Generate n_instances structured plaintexts of instance_size bytes
    each under the requested format, hash each with fixed_seed, analyze
    output distribution."""
    hashes = np.zeros(n_instances, dtype=np.uint64)

    t0 = time.time()
    for i in range(n_instances):
        instance = generate_instance(fmt, instance_size, rng_base + i)
        hashes[i] = seahash64(instance, fixed_seed)
    elapsed = time.time() - t0

    # 1. Per-bit output frequency across N instances.
    bit_counts = np.zeros(OUTPUT_BITS, dtype=np.int64)
    for h in hashes:
        h_int = int(h)
        for b in range(OUTPUT_BITS):
            if (h_int >> b) & 1:
                bit_counts[b] += 1
    bit_prob = bit_counts / float(n_instances)
    bit_bias = np.abs(bit_prob - 0.5)

    # 2. Byte distribution chi-square (joint uniformity over 256 values).
    byte_counts = np.zeros(256, dtype=np.int64)
    for h in hashes:
        for octet in int(h).to_bytes(8, "little"):
            byte_counts[octet] += 1
    expected = n_instances * 8 / 256.0
    chi2_stat, chi2_p = stats.chisquare(byte_counts, f_exp=[expected] * 256)

    # 3. Sequential autocorrelation. XOR of adjacent hashes should itself
    # be distributed uniformly (~0.5 per bit).
    if n_instances > 1:
        adj_xor = np.bitwise_xor(hashes[1:], hashes[:-1])
        adj_bit_counts = np.zeros(OUTPUT_BITS, dtype=np.int64)
        for h in adj_xor:
            h_int = int(h)
            for b in range(OUTPUT_BITS):
                if (h_int >> b) & 1:
                    adj_bit_counts[b] += 1
        adj_prob = adj_bit_counts / float(len(adj_xor))
        adj_bias = np.abs(adj_prob - 0.5)
        adj_max = float(adj_bias.max() * 100)
        adj_mean = float(adj_bias.mean() * 100)
    else:
        adj_max = None
        adj_mean = None

    return {
        "n_instances": n_instances,
        "instance_size": instance_size,
        "elapsed_s": round(elapsed, 2),
        # Per-bit frequency
        "bit_bias_max_pct": float(bit_bias.max() * 100),
        "bit_bias_mean_pct": float(bit_bias.mean() * 100),
        "binomial_noise_1sigma_pct": float(100 / (2 * np.sqrt(n_instances))),
        # Byte chi-square
        "byte_chi2_stat": float(chi2_stat),
        "byte_chi2_p": float(chi2_p),
        "byte_chi2_df": 255,
        "byte_max_freq": int(byte_counts.max()),
        "byte_min_freq": int(byte_counts.min()),
        # Sequential autocorrelation
        "adj_xor_bit_bias_max_pct": adj_max,
        "adj_xor_bit_bias_mean_pct": adj_mean,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Axis A' structural-input bias on seahash64")
    p.add_argument("--n-instances", type=int, default=64,
                   help="number of structured JSON instances (default 64)")
    p.add_argument("--instance-size", type=int, default=4096,
                   help="bytes per JSON instance (default 4096)")
    p.add_argument("--fixed-seed", type=str, default="0xA17B1CE",
                   help="fixed hash seed — decimal or hex (default 0xA17B1CE)")
    p.add_argument("--rng-base", type=int, default=1000000,
                   help="base RNG seed for per-instance value generation")
    p.add_argument("--format", type=str, default="json",
                   choices=sorted(_INSTANCE_GENERATORS),
                   help="structured plaintext format: 'json' (default, "
                        "fixed-width records with byte-aligned field-name "
                        "repetition) or 'html' (tag-wrapped, less byte-"
                        "aligned)")
    p.add_argument("--json-report", type=str, default="",
                   help="output JSON report path (default stdout only)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    fixed_seed = int(args.fixed_seed, 0) & MASK64

    print(f"[struct] generating {args.n_instances} {args.format.upper()} "
          f"instances × {args.instance_size}B, seed=0x{fixed_seed:016x}...",
          file=sys.stderr)
    result = struct_bias_test(
        args.n_instances, args.instance_size, fixed_seed, args.rng_base,
        fmt=args.format)

    report = {
        "primitive": "seahash64",
        "axis": "A-prime",
        "scope": ("structural-input bias on hLo projection "
                  f"(fixed seed, varying structured {args.format.upper()} "
                  "instances)"),
        "format": f"{args.format}_structured",
        "methodology": ("ITB-attack-realistic: seeds fixed across trials, "
                        "plaintext varies across instances but shares a "
                        "JSON schema with repeated field names"),
        "fixed_seed_hex": f"0x{fixed_seed:016x}",
        "timestamp": int(time.time()),
        "args": vars(args),
        "results": result,
    }

    print(f"[struct] bit_bias     max={result['bit_bias_max_pct']:.3f}% "
          f"mean={result['bit_bias_mean_pct']:.3f}% "
          f"noise_1sigma={result['binomial_noise_1sigma_pct']:.2f}%",
          file=sys.stderr)
    print(f"[struct] byte_chi2    p={result['byte_chi2_p']:.4f} "
          f"(df=255, clean≳0.01)", file=sys.stderr)
    if result['adj_xor_bit_bias_max_pct'] is not None:
        print(f"[struct] adj_xor_bit  max={result['adj_xor_bit_bias_max_pct']:.3f}% "
              f"mean={result['adj_xor_bit_bias_mean_pct']:.3f}%",
              file=sys.stderr)
    print(f"[struct] elapsed={result['elapsed_s']}s", file=sys.stderr)

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
