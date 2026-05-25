#!/usr/bin/env python3
"""SAT-free XOR-differential pre-screen for ChainHash inner primitives.

Companion to avalanche_screen.py. Where the avalanche screen measures
FIRST-ORDER marginal diffusion (per-output-bit flip probability) and exact
algebraic degree, this screen measures the JOINT output-difference
distribution for a fixed single-bit input difference — a differential-
cryptanalysis statistic the avalanche columns cannot express, because they
aggregate each output bit independently.

WHAT IT MEASURES
----------------
For a single-bit input difference delta on the (rounds*64)-bit lo-lane
key-component input, and a chosen output projection, the output difference

    Delta = chain_lo(x) XOR chain_lo(x XOR delta)

is sampled over random bases x. The 8-bit projection (Delta & 0xFF) is
histogrammed into 256 buckets; the most-probable bucket is the differential
probability of the best low-byte characteristic through delta. For an ideal
function the low byte of Delta is ~uniform over 256 values, so every bucket
sits near 1/256 and the per-delta MAX bucket sits a few binomial sigma above
it. A primitive with a biased differential pushes one bucket far above the
uniform band, exposing a characteristic a differential / solver attack can
ride.

  * ddt8_max  — worst (largest) low-byte differential-bucket probability over
                all probed input-bit differences. The headline number.
  * ddt8_mean — mean of the per-delta max-bucket probabilities. A diffuse
                rise here (not just one bad delta) indicates structural bias.
  * uni_band  — the expected uniform max-bucket probability +/- ~3 sigma at
                this sample size, printed once per run, so a row is read
                against the right baseline rather than against a bare 1/256.
  * const8    — fraction of probed deltas whose low-byte output difference is
                CONSTANT across all bases (ddt8_max == 1.0). The byte-level
                analogue of avalanche_screen's lin_score; non-zero means that
                input direction is affine on the low byte -> trivially
                solvable on those bits. CRC-like -> 1.0.

RELATION TO THE AVALANCHE SCREEN
--------------------------------
avalanche_screen.lin_score flags a FULL 64-bit constant output difference
(a globally affine direction). const8 here flags a constant LOW-BYTE
difference, a strictly weaker (more sensitive) condition that catches partial
affinity the full-width test misses. ddt8_max then quantifies non-constant
but biased differentials. Treat a clean differential row exactly as the
avalanche screen's caveat states: necessary, not sufficient. It rejects
biased-differential primitives; it does not prove SAT-hardness, and it is
blind to the cheap-inverse structure the `inv` column in avalanche_screen
carries (FNV-1a passes the differential screen yet is solver-tractable).

Usage:
    python3 .../differential_screen.py --all --rounds-max 3
    python3 .../differential_screen.py --primitive splitmix64 --samples 8192
"""

from __future__ import annotations

import argparse
import importlib
import math
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # chainhashes.<name>
sys.path.insert(0, str(HERE))         # avalanche_screen (sibling module)

# Reuse the primitive resolver and the single-lane chain from the avalanche
# screen rather than re-deriving the (subtle) chain shape — same source of
# truth, no divergence.
from avalanche_screen import (  # type: ignore  # noqa: E402
    DEFAULT_PRIMITIVES,
    MASK64,
    chain_lo,
    resolve_primitive128,
)


def uniform_max_band(samples: int, buckets: int = 256, sigma: float = 3.0):
    """Expected max-bucket probability under a uniform 8-bit output diff.

    Each bucket count is ~Binomial(samples, 1/buckets); the per-delta max over
    `buckets` buckets sits above the mean. Returns (low, high) on the bucket
    probability as mean +/- sigma*std of a single bucket, scaled for the max
    via a mild log(buckets) inflation — a guide band, not a hypothesis test."""
    p = 1.0 / buckets
    mean = p
    std = math.sqrt(p * (1 - p) / samples)
    # max over `buckets` near-independent buckets sits ~sqrt(2 ln buckets) std
    # above the mean; fold that into the high edge.
    infl = math.sqrt(2.0 * math.log(buckets))
    return mean, mean + (sigma + infl) * std


def differential(prim128, rounds: int, data: bytes, samples: int,
                 probe_bits: int, rng: random.Random) -> dict:
    """Low-byte XOR-differential battery for one round count."""
    nbits = rounds * 64
    probe = rng.sample(range(nbits), min(probe_bits, nbits))

    per_delta_max = []
    const_count = 0
    for bit in probe:
        comp, off = divmod(bit, 64)
        hist = [0] * 256
        first = None
        constant = True
        for _ in range(samples):
            base = [rng.getrandbits(64) for _ in range(rounds)]
            out0 = chain_lo(prim128, data, base)
            base[comp] ^= (1 << off)
            d = (out0 ^ chain_lo(prim128, data, base)) & 0xFF
            hist[d] += 1
            if first is None:
                first = d
            elif d != first:
                constant = False
        per_delta_max.append(max(hist) / samples)
        if constant:
            const_count += 1

    return {
        "ddt8_max": max(per_delta_max),
        "ddt8_mean": sum(per_delta_max) / len(per_delta_max),
        "const8": const_count / len(probe),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--primitive", help="single chainhashes.<name> module")
    g.add_argument("--all", action="store_true",
                   help=f"screen the default set: {', '.join(DEFAULT_PRIMITIVES)}")
    ap.add_argument("--rounds-max", type=int, default=3)
    ap.add_argument("--samples", type=int, default=4096,
                    help="random bases per probed input difference (default 4096)")
    ap.add_argument("--probe-bits", type=int, default=32,
                    help="sampled single-bit input differences (default 32)")
    ap.add_argument("--data-len", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    if args.primitive:
        names = [args.primitive]
    elif args.all:
        names = DEFAULT_PRIMITIVES
    else:
        ap.error("specify --primitive <name> or --all")

    rng = random.Random(args.seed)
    data = bytes(rng.getrandbits(8) for _ in range(args.data_len))
    lo, hi = uniform_max_band(args.samples)

    print(f"# XOR-differential pre-screen  (samples={args.samples}, "
          f"probe_bits={args.probe_bits}, data_len={args.data_len}, "
          f"rng_seed={args.seed})")
    print(f"# lo-lane 64-bit ChainHash; data fixed = {data.hex()}")
    print(f"# low-byte uniform band: mean={lo:.5f}, ~max<={hi:.5f} "
          f"(ddt8_max above this edge flags a biased differential)")
    print(f"{'primitive':<12}{'rounds':>7}{'ddt8_max':>11}"
          f"{'ddt8_mean':>11}{'const8':>9}")
    print("-" * 50)

    for name in names:
        try:
            mod = importlib.import_module(f"chainhashes.{name}")
        except Exception as e:  # noqa: BLE001
            print(f"{name:<12}  import failed: {e}")
            continue
        prim = resolve_primitive128(mod)
        if prim is None:
            print(f"{name:<12}  no 2-lane adapter (GF(2)-linear; const8=1.0 "
                  f"by construction) — skipped")
            continue
        for r in range(1, args.rounds_max + 1):
            m = differential(prim, r, data, args.samples, args.probe_bits, rng)
            flag = "  <-- biased" if m["ddt8_max"] > hi else ""
            print(f"{name:<12}{r:>7}{m['ddt8_max']:>11.5f}"
                  f"{m['ddt8_mean']:>11.5f}{m['const8']:>9.3f}{flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
