#!/usr/bin/env python3
"""SAT-free avalanche / linearity pre-screen for ChainHash inner primitives.

This is a cheap triage tool that runs BEFORE the (expensive, hours-long)
SAT calibration. It measures three Monte-Carlo statistics of the lo-lane
ChainHash output as a function of the round count, so the degree-saturation
"cliff" of a candidate primitive is visible in seconds instead of waiting
on a solver.

WHY THE LO LANE ONLY
--------------------
The 128-bit ChainHash (mirrored in harness_test.go and seed512.go) runs two
INDEPENDENT 64-bit lanes: lo = P(data, seed_lo); hi = P(data, seed_hi), and
the feedforward keeps them separate (k_lo = seed[i] ^ h_lo, k_hi =
seed[i+1] ^ h_hi). ITB's encoding observes only h[0] (the lo lane); the hi
lane is discarded. The attacker therefore inverts a single 64-bit lo chain,
so that is exactly what this screen exercises:

    lo = P(data, k[0], 0)
    for i in 1..rounds-1:
        lo = P(data, k[i] ^ lo, 0)            # hi input pinned to 0; ignored
    return lo

(Chain shape ported from Seed512.ChainHash512, seed512.go:160, and the
chainHash128* harness helpers. Inner primitive reused from the sibling
chainhashes.<name> modules via their `_<name>_128` adapter.)

THREE METRICS, PER ROUND COUNT
------------------------------
  * lin_score   — fraction of probed single-bit input differences whose
                  output difference is CONSTANT across all random bases.
                  A constant output difference means that input direction
                  is GF(2)-affine -> trivially solvable. CRC/LFSR -> 1.0;
                  a saturated multiply/Sbox mixer -> 0.0. This is the
                  cleanest discriminator of the "collapses like CRC128"
                  failure mode.
  * sac_bias    — Strict Avalanche Criterion deviation. Over sampled
                  (input bit, output bit) pairs, P(output bit flips |
                  input bit flips) should be 0.5. Reports mean and worst
                  |p - 0.5|. High at low rounds, -> 0 once saturated.
  * avw_mean    — avalanche weight: mean number of the 64 output bits that
                  flip per single input-bit flip. Ideal ~32.
  * deg@m       — EXACT GF(2) algebraic degree of the 64-bit lo output,
                  computed over an m-bit SUB-CUBE of the key-component
                  input: freeze all but m input bits to a fixed random
                  constant, enumerate the 2^m truth table, read the top
                  monomial via a Mobius (Zhegalkin) transform. Restricting
                  variables can only DROP monomials, so deg@m is a SOUND
                  LOWER BOUND on the true degree — and it is measured on the
                  REAL primitive, not a scaled-down toy. Saturated mixer ->
                  ~m already at round 1; GF(2)-affine -> 1. --degree-bits 0
                  disables it.
  * inv         — STRUCTURAL "cheap inverse" flag, declared by the primitive
                  module's `INVERTIBLE` attribute (Y when set, ? when absent).
                  Y marks a primitive whose round map hands a solver a CHEAP
                  structural inverse — a triangular carry-up T-function
                  (FNV-1a) or a by-design invertible mixer composed of
                  word-level bijections (splitmix64). Such a primitive is
                  solver-tractable at the primitive layer no matter how clean
                  its lin/sac/deg columns read: splitmix64 saturates every
                  diffusion and degree column yet is peeled step-by-step,
                  FNV-1a reads weak on diffusion but is inverted plane-by-
                  plane — opposite statistical profiles, same cheap-inverse
                  root cause. This is the one axis the Monte-Carlo columns
                  CANNOT see, and it is structural knowledge, not a
                  measurement: mere bijectivity of the seed map (true of most
                  mixers for a fixed short input) is NOT the property that
                  helps a solver, so a by-design one-way hash with no
                  documented shortcut is left ? — the screen makes no claim
                  and defers to the SAT calibration.
  * worst       — the single (input_bit -> output_bit) pair carrying the
                  largest SAC bias (the sac_max argmax). Surfaces a lane bit
                  that never mixes even when sac_mean looks healthy — the
                  t1ha1 failure mode that mean-aggregation hides.

Sweeping rounds = 1, 2, 3, ... shows where the cliff lands. Observed: mx3
and siphash13 sit at the Monte-Carlo noise floor (sac_mean ~ 0.399/sqrt(N))
already at round 1.

AVALANCHE != DEGREE. The lin/sac/avw columns measure FIRST-ORDER diffusion;
they can read "ideal" for a function of low algebraic degree (a quadratic
can have perfect SAC yet fall to a higher-order differential / cube attack).
deg@m is the separate algebraic check. Cite the avalanche columns as "no
first-order linear/diffusion shortcut" and deg@m as the degree evidence —
never conflate the two.

IMPORTANT — NECESSARY, NOT SUFFICIENT
-------------------------------------
This screen reliably REJECTS the obvious collapse modes: GF(2)-linear
primitives (CRC128 -> lin_score 1.0) and slow / unsaturated diffusion
(high sac_bias at low rounds). It does NOT prove SAT-hardness. A primitive
can pass the avalanche screen and still carry a primitive-specific
algebraic shortcut a solver exploits (FNV-1a is the cautionary example:
acceptable avalanche, yet SAT-invertible via its structure). So treat a
pass as "worth a SAT calibration run", never as a security verdict. The
honest claim a green row supports is "no obvious linear/diffusion collapse
at the sampled size", not "hard to invert".

Usage:
    python3 scripts/redteam/phase2_theory/chainhashes/avalanche_screen.py \
        --primitive mx3 --rounds-max 4
    python3 .../avalanche_screen.py --all --rounds-max 3 --samples 1024
"""

from __future__ import annotations

import argparse
import importlib
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Add phase2_theory to sys.path so `import chainhashes.<name>` resolves,
# mirroring the import idiom in _parity_test.py.
sys.path.insert(0, str(HERE.parent))

MASK64 = (1 << 64) - 1

# Default non-crypto candidates that ship a 2-lane adapter. crc128 is omitted:
# it has no `_*_128` adapter and is GF(2)-linear by construction, so its
# lin_score is analytically 1.0 (it collapses without any measurement).
# splitmix64 / fnv1a are listed last as the two INVERTIBLE controls — their
# round map is a bijection in the seed, so they read ideal on every diffusion
# / degree column yet stay solver-tractable (see the `inv` column below).
DEFAULT_PRIMITIVES = [
    "mx3", "t1ha1", "seahash", "siphash13", "murmur3", "xxhash64",
    "splitmix64", "fnv1a",
]


def _popcount(x: int) -> int:
    try:
        return x.bit_count()  # Python 3.10+
    except AttributeError:  # pragma: no cover
        return bin(x).count("1")


def resolve_primitive128(mod):
    """Return the module's P(data, s0, s1) -> (lo, hi) 2-lane adapter.

    Ports name it `_<stem>_128` (mx3, t1ha1, seahash, siphash13) or
    `_<stem>128` (fnv1a). Falls back to scanning for any callable attribute
    ending in `_128` / `128`.
    """
    stem = mod.__name__.rsplit(".", 1)[-1]
    for cand in (f"_{stem}_128", f"_{stem}128"):
        fn = getattr(mod, cand, None)
        if callable(fn):
            return fn
    for name in dir(mod):
        if (name.endswith("_128") or name.endswith("128")) and callable(
            getattr(mod, name)
        ):
            return getattr(mod, name)
    return None


def chain_lo(prim128, data: bytes, kcomps: list[int]) -> int:
    """Single-lane (lo) ChainHash over len(kcomps) rounds. hi input pinned
    to 0 (independent lane, ignored)."""
    lo, _ = prim128(data, kcomps[0] & MASK64, 0)
    for i in range(1, len(kcomps)):
        lo, _ = prim128(data, (kcomps[i] ^ lo) & MASK64, 0)
    return lo & MASK64


def screen(prim128, rounds: int, data: bytes, samples: int,
           probe_bits: int, rng: random.Random) -> dict:
    """Run the avalanche / linearity battery for one round count."""
    nbits = rounds * 64
    probe = rng.sample(range(nbits), min(probe_bits, nbits))

    # Per probed input bit: count of distinct output differences (capped at 2
    # — we only need to know "constant" vs "varies"), one representative diff,
    # and per-output-bit flip counts for SAC.
    distinct_first = [None] * len(probe)
    is_constant = [True] * len(probe)
    flip_counts = [[0] * 64 for _ in probe]
    weight_sum = [0] * len(probe)

    for _ in range(samples):
        base = [rng.getrandbits(64) for _ in range(rounds)]
        out0 = chain_lo(prim128, data, base)
        for pi, bit in enumerate(probe):
            comp, off = divmod(bit, 64)
            flipped = base[:]
            flipped[comp] ^= (1 << off)
            d = out0 ^ chain_lo(prim128, data, flipped)
            if distinct_first[pi] is None:
                distinct_first[pi] = d
            elif d != distinct_first[pi]:
                is_constant[pi] = False
            weight_sum[pi] += _popcount(d)
            fc = flip_counts[pi]
            dd = d
            while dd:
                fc[(dd & -dd).bit_length() - 1] += 1
                dd &= dd - 1

    lin_score = sum(1 for c in is_constant if c) / len(probe)

    bias_sum = 0.0
    bias_n = 0
    sac_max = 0.0
    sac_worst = (-1, -1)  # (input bit, output bit) of the largest SAC bias
    for pi in range(len(probe)):
        for ob in range(64):
            b = abs(flip_counts[pi][ob] / samples - 0.5)
            bias_sum += b
            bias_n += 1
            if b > sac_max:
                sac_max = b
                sac_worst = (probe[pi], ob)
    sac_mean = bias_sum / bias_n

    avw = [w / samples for w in weight_sum]
    avw_mean = sum(avw) / len(avw)

    return {
        "lin_score": lin_score,
        "sac_mean": sac_mean,
        "sac_max": sac_max,
        "sac_worst": sac_worst,
        "avw_mean": avw_mean,
    }


def degree_subcube(prim128, rounds: int, data: bytes, m: int,
                   rng: random.Random) -> int:
    """Exact GF(2) algebraic degree of the 64-bit lo output over an m-bit
    sub-cube of the (rounds*64)-bit key-component input.

    Freezes all but m randomly chosen input bits to a fixed random base,
    enumerates the 2^m sub-cube into a truth table (each entry the packed
    64-bit output), runs a bit-parallel Mobius transform over all 64 output
    bits at once, and returns the max monomial degree. Fixing variables can
    only remove monomials, so the result is a sound LOWER BOUND on the full
    degree. Cost: 2^m primitive evals + m*2^m word XORs (m <= ~20 is cheap).
    """
    nbits = rounds * 64
    m = min(m, nbits)
    varbits = rng.sample(range(nbits), m)

    # Random frozen base with the m variable bits cleared to 0.
    clear = [0] * rounds
    for vb in varbits:
        comp, off = divmod(vb, 64)
        clear[comp] |= (1 << off)
    base = [rng.getrandbits(64) & (~clear[c] & MASK64) for c in range(rounds)]

    size = 1 << m
    tt = [0] * size
    for pat in range(size):
        comps = base[:]
        p, k = pat, 0
        while p:
            if p & 1:
                comp, off = divmod(varbits[k], 64)
                comps[comp] |= (1 << off)
            p >>= 1
            k += 1
        tt[pat] = chain_lo(prim128, data, comps)

    # In-place Mobius (Zhegalkin) transform; XOR carries all 64 output lanes.
    i = 0
    while (1 << i) < size:
        step = 1 << i
        for b in range(0, size, step << 1):
            for j in range(b, b + step):
                tt[j + step] ^= tt[j]
        i += 1

    deg = 0
    for mask in range(size):
        if tt[mask]:
            pc = _popcount(mask)
            if pc > deg:
                deg = pc
                if deg == m:  # cannot exceed the sub-cube dimension
                    break
    return deg


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--primitive", help="single chainhashes.<name> module")
    g.add_argument("--all", action="store_true",
                   help=f"screen the default set: {', '.join(DEFAULT_PRIMITIVES)}")
    ap.add_argument("--rounds-max", type=int, default=4)
    ap.add_argument("--samples", type=int, default=512,
                    help="random base seeds per round (default 512)")
    ap.add_argument("--probe-bits", type=int, default=48,
                    help="sampled input bit positions (default 48)")
    ap.add_argument("--data-len", type=int, default=5,
                    help="domain-tag buffer length, mimics ITB's small buf")
    ap.add_argument("--seed", type=int, default=1, help="RNG seed")
    ap.add_argument("--degree-bits", type=int, default=16,
                    help="sub-cube dimension m for the exact algebraic-degree "
                         "lower bound deg@m (0 disables; <=~20 stays fast)")
    args = ap.parse_args()

    if args.primitive:
        names = [args.primitive]
    elif args.all:
        names = DEFAULT_PRIMITIVES
    else:
        ap.error("specify --primitive <name> or --all")

    rng = random.Random(args.seed)
    data = bytes(rng.getrandbits(8) for _ in range(args.data_len))

    print(f"# avalanche pre-screen  (samples={args.samples}, "
          f"probe_bits={args.probe_bits}, data_len={args.data_len}, "
          f"rng_seed={args.seed})")
    print(f"# lo-lane 64-bit ChainHash; data fixed = {data.hex()}")
    deg_hdr = f"deg@{args.degree_bits}" if args.degree_bits else "deg"
    print(f"{'primitive':<12}{'rounds':>7}{'lin_score':>11}"
          f"{'sac_mean':>11}{'sac_max':>10}{'avw/64':>9}"
          f"{deg_hdr:>9}{'inv':>5}{'worst':>12}")
    print("-" * 86)

    for name in names:
        try:
            mod = importlib.import_module(f"chainhashes.{name}")
        except Exception as e:  # noqa: BLE001
            print(f"{name:<12}  import failed: {e}")
            continue
        prim = resolve_primitive128(mod)
        if prim is None:
            print(f"{name:<12}  no 2-lane adapter (GF(2)-linear collapse, "
                  f"lin_score=1.0 by construction) — skipped")
            continue
        inv = getattr(mod, "INVERTIBLE", None)
        inv_s = "Y" if inv is True else "N" if inv is False else "?"
        for r in range(1, args.rounds_max + 1):
            m = screen(prim, r, data, args.samples, args.probe_bits, rng)
            if args.degree_bits:
                deg_s = f"{degree_subcube(prim, r, data, args.degree_bits, rng):>9d}"
            else:
                deg_s = f"{'-':>9}"
            wi, wo = m["sac_worst"]
            worst_s = f"{wi}->{wo}"
            print(f"{name:<12}{r:>7}{m['lin_score']:>11.3f}"
                  f"{m['sac_mean']:>11.4f}{m['sac_max']:>10.3f}"
                  f"{m['avw_mean']:>9.1f}{deg_s}{inv_s:>5}{worst_s:>12}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
