#!/usr/bin/env python3
"""EXPERIMENT — Malicious-SHA-1 collision absorption by ITB's
ChainHash-style input-XOR keying and feedforward rounds.

Sources:
    Ange Albertini, Jean-Philippe Aumasson, Maria Eichlseder,
    Florian Mendel, Martin Schläffer -
    «Malicious Hashing: Eve's Variant of SHA-1»
    SAC 2014, LNCS 8781. IACR ePrint 2014/694.

    Production wrap references: `hashes/blake3.go` `BLAKE3WithKey`
    (input-XOR keying), `seed128.go` `ChainHash128` (feedforward loop).

Scope. This probe tests, on the ChainHash pre-wire layer only, whether
Malicious-SHA-1's chosen-constants collision trapdoor projects through
ITB's ChainHash-style wrap. No wire, no interlock, no Encrypt3x128Cfg
— everything is measured at the digest layer directly, so the observable
is digest equality / Hamming distance between the two ciphertexts, not
byte statistics of any wire encoding.

Attribution honesty. The mechanism this probe demonstrates is:

    ChainHash never exposes raw colliding input to the primitive:
    input-XOR keying moves it out of the engineered collision space.

This follows from two properties in combination — (a) ChainHash does
not feed the primitive raw caller data, (b) engineered collisions are
brittle to any deterministic input modification. It is NOT a
collision-specific defense; the same absorbance would hold for any
wrapping that non-trivially modifies the input. The BEA-1 partition
trapdoor is absorbed by a distinct mechanism (feedforward depth), so
the two controls together demonstrate ChainHash absorbs different
trapdoor classes via different mechanisms — richer coverage than a
single-mechanism repeat.

Sub-probes:

  A — raw baseline (positive control): `sha1_core(m1) == sha1_core(m2)`
      under `SHA1_K_MALICIOUS_EVE`. The trapdoor is measurably alive on
      the isolated primitive; without this the probe has no baseline.

  seed=0 invariant test: `wrap_r1(seed=0, m1)` reduces to `sha1_core(m1)`
      by construction (XOR by zero is identity). If the collision holds
      here and breaks under non-zero seed, the mechanism attribution
      (seed-XOR moves input out of collision space) is confirmed. If
      the collision breaks even at seed=0, the wrap function is doing
      something extra (padding / framing / a hidden tag) and the
      mechanism attribution must be revised.

  B — random-seed wrap at r=1: `wrap_r1(random_seed, m1)` vs
      `wrap_r1(random_seed, m2)`. Expected: Hamming distance ≈ 80 bits
      (n/2 for a 160-bit digest), corresponding to full-random
      divergence — the collision does not merely weaken, it is
      absorbed to statistical independence.

  C — feedforward depth sweep r ∈ {1, 2, 4, 8}: `wrap_r(key_list, m1, R)`
      vs `wrap_r(..., m2, R)`. Expected: plateau at Hamming ≈ 80 bits
      for every R ≥ 1. Feedforward-depth rounds add no incremental
      absorbance for this trapdoor class (in contrast to BEA-1, where
      feedforward-depth is the carrying mechanism — collision-brittle
      trapdoors snap at r=1, partition trapdoors degrade with r).

Attacker realism. Statistics operate on public colliding pair + freshly
drawn seed material only; the primitive's round constants and the
colliding pair are attacker-known from the paper. `sha1_core` is called
on inputs the attacker (or the harness) constructs; no ground truth
about the seed material is consulted in a decision path (there is no
decision path — the observable is digest equality directly).

Output: `~/scratch/redteam/msha1/collision_absorption.json`.
Override the parent directory via `REDTEAM_MSHA1_OUTPUT_DIR`.

Env:
    REDTEAM_MSHA1_TRIALS=64   number of random-seed trials per
                              (r, wrap-shape) cell for B/C statistics.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from sha1_malicious import sha1_core, SHA1_K_MALICIOUS_EVE, SHA1_K_STANDARD
from sha1_chainhash import wrap_r1, wrap_r
from sha1_collide import EVE1_SH, EVE2_SH, EXPECTED_COLLIDING_DIGEST


def hamming_bits(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def out_dir() -> Path:
    return Path(os.environ.get(
        "REDTEAM_MSHA1_OUTPUT_DIR",
        str(Path.home() / "scratch" / "redteam" / "msha1"),
    ))


def emit(name: str, payload: dict) -> None:
    d = out_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{name}.json"
    with p.open("w") as f:
        json.dump(payload, f, indent=2)
    print(f"[emit] {p}")


def sub_probe_a() -> dict:
    """A — raw baseline: primitive collision alive under malicious K."""
    d1 = sha1_core(EVE1_SH, k=SHA1_K_MALICIOUS_EVE)
    d2 = sha1_core(EVE2_SH, k=SHA1_K_MALICIOUS_EVE)
    d1_std = sha1_core(EVE1_SH, k=SHA1_K_STANDARD)
    d2_std = sha1_core(EVE2_SH, k=SHA1_K_STANDARD)
    return {
        "digest_eve1_malicious":   d1.hex(),
        "digest_eve2_malicious":   d2.hex(),
        "collide_under_malicious": d1 == d2,
        "matches_expected":        d1 == EXPECTED_COLLIDING_DIGEST,
        "hamming_bits_malicious":  hamming_bits(d1, d2),
        "digest_eve1_standard":    d1_std.hex(),
        "digest_eve2_standard":    d2_std.hex(),
        "collide_under_standard":  d1_std == d2_std,
        "hamming_bits_standard":   hamming_bits(d1_std, d2_std),
    }


def sub_probe_seed_zero_invariant() -> dict:
    """seed=0 invariant: wrap_r1(0, m) should reduce to sha1_core(m)
    exactly, and the collision should still hold. Any deviation
    indicates the wrap adds work beyond input-XOR keying and the
    mechanism attribution must be revisited."""
    key_zero = bytes(16)
    d1 = wrap_r1(key_zero, EVE1_SH)
    d2 = wrap_r1(key_zero, EVE2_SH)
    d1_raw = sha1_core(EVE1_SH)
    d2_raw = sha1_core(EVE2_SH)
    return {
        "reduces_to_raw": d1 == d1_raw and d2 == d2_raw,
        "collide":        d1 == d2,
        "digest_eve1":    d1.hex(),
        "digest_eve2":    d2.hex(),
        "hamming_bits":   hamming_bits(d1, d2),
    }


def sub_probe_b(trials: int) -> dict:
    """B — random-seed r=1: collision should break to full-random
    Hamming distance (≈ n/2 = 80 bits for a 160-bit digest)."""
    hammings = []
    collisions_survived = 0
    for _ in range(trials):
        key = secrets.token_bytes(16)
        d1 = wrap_r1(key, EVE1_SH)
        d2 = wrap_r1(key, EVE2_SH)
        hammings.append(hamming_bits(d1, d2))
        if d1 == d2:
            collisions_survived += 1
    return {
        "trials":                       trials,
        "collisions_survived":          collisions_survived,
        "hamming_min":                  min(hammings),
        "hamming_max":                  max(hammings),
        "hamming_mean":                 sum(hammings) / len(hammings),
        "hamming_bits_total_out_of":    160,
        "expected_random_mean":         80.0,
    }


def sub_probe_c(trials: int, rounds_list=(1, 2, 4, 8)) -> dict:
    """C — feedforward depth sweep: Hamming should plateau at ≈ 80 bits
    for every R ≥ 1 because the collision-brittleness snaps at r=1;
    feedforward depth adds no incremental absorbance for this trapdoor
    class (distinct from BEA-1's partition trapdoor where feedforward
    depth carries the absorbance graceful-degradation curve)."""
    cells = {}
    for R in rounds_list:
        hammings = []
        collisions_survived = 0
        for _ in range(trials):
            key_list = [secrets.token_bytes(16) for _ in range(R)]
            d1 = wrap_r(key_list, EVE1_SH, R)
            d2 = wrap_r(key_list, EVE2_SH, R)
            hammings.append(hamming_bits(d1, d2))
            if d1 == d2:
                collisions_survived += 1
        cells[str(R)] = {
            "rounds":              R,
            "trials":              trials,
            "collisions_survived": collisions_survived,
            "hamming_min":         min(hammings),
            "hamming_max":         max(hammings),
            "hamming_mean":        sum(hammings) / len(hammings),
        }
    return {
        "rounds_swept":              list(rounds_list),
        "cells":                     cells,
        "hamming_bits_total_out_of": 160,
        "expected_random_mean":      80.0,
    }


def main() -> int:
    trials = int(os.environ.get("REDTEAM_MSHA1_TRIALS", "64"))

    print("=" * 70)
    print("Malicious-SHA-1 collision absorption by ChainHash-style wrap")
    print("=" * 70)

    print("\n--- Sub-probe A (raw baseline) ---")
    a = sub_probe_a()
    print(f"  digest under malicious K: {a['digest_eve1_malicious']}")
    print(f"  collides under malicious K: {a['collide_under_malicious']} "
          f"(matches paper: {a['matches_expected']})")
    print(f"  collides under standard K:  {a['collide_under_standard']} "
          f"(Hamming {a['hamming_bits_standard']}/160)")
    assert a["collide_under_malicious"], "positive control failed: raw collision does not hold"
    assert a["matches_expected"], "digest does not match the paper's expected value"
    assert not a["collide_under_standard"], "sanity control failed: standard SHA-1 also collides"

    print("\n--- seed=0 invariant test ---")
    z = sub_probe_seed_zero_invariant()
    print(f"  wrap_r1(seed=0, m) reduces to sha1_core(m): {z['reduces_to_raw']}")
    print(f"  collision holds at seed=0: {z['collide']} (Hamming {z['hamming_bits']}/160)")
    assert z["reduces_to_raw"], "wrap does not reduce to identity at seed=0 — mechanism attribution invalid"
    assert z["collide"], "collision fails at seed=0 — wrap adds work beyond input-XOR keying"

    print(f"\n--- Sub-probe B (r=1 random seed, N={trials} trials) ---")
    b = sub_probe_b(trials)
    print(f"  collisions survived: {b['collisions_survived']} / {b['trials']}")
    print(f"  Hamming min / mean / max: "
          f"{b['hamming_min']} / {b['hamming_mean']:.1f} / {b['hamming_max']} out of 160")
    print(f"  expected under full-random divergence: {b['expected_random_mean']}")

    print(f"\n--- Sub-probe C (feedforward depth sweep, N={trials} trials each) ---")
    c = sub_probe_c(trials)
    for R_str, cell in c["cells"].items():
        print(f"  r={cell['rounds']}: "
              f"survived={cell['collisions_survived']}/{cell['trials']}, "
              f"Hamming min/mean/max = "
              f"{cell['hamming_min']}/{cell['hamming_mean']:.1f}/{cell['hamming_max']} / 160")

    payload = {
        "description":             "Malicious-SHA-1 collision absorption by ChainHash-style input-XOR keying (r=1) and feedforward (r>=2). The observable is direct digest equality / Hamming distance between the two ciphertexts, measured at the pre-wire ChainHash layer — no wire, no interlock, no Encrypt3x128Cfg.",
        "attribution":             "ChainHash never exposes raw colliding input to the primitive: input-XOR keying moves it out of the engineered collision space. Two properties in combination: (a) ChainHash does not feed the primitive raw caller data, (b) engineered collisions are brittle to any deterministic input modification. Not a collision-specific defense — the same absorbance would hold for any wrapping that non-trivially modifies the input.",
        "primitive_source":        "IACR ePrint 2014/694 — Malicious Hashing: Eve's Variant of SHA-1 (Albertini, Aumasson, Eichlseder, Mendel, Schläffer, SAC 2014).",
        "colliding_pair_source":   "pocs/sh/eve{1,2}.sh from Maria Eichlseder's Malicious SHA-1 project (malicioussha1.github.io).",
        "wrap_source":             "hashes/blake3.go BLAKE3WithKey input-XOR keying; seed128.go ChainHash128 feedforward.",
        "colliding_pair_len_bytes": len(EVE1_SH),
        "diff_positions_count":    sum(1 for i in range(len(EVE1_SH)) if EVE1_SH[i] != EVE2_SH[i]),
        "diff_positions_first":    min(i for i in range(len(EVE1_SH)) if EVE1_SH[i] != EVE2_SH[i]),
        "diff_positions_last":     max(i for i in range(len(EVE1_SH)) if EVE1_SH[i] != EVE2_SH[i]),
        "diff_overlaps_wrap_region": any(EVE1_SH[i] != EVE2_SH[i] for i in range(16)),
        "sub_probe_a_raw_baseline":              a,
        "sub_probe_seed_zero_invariant":         z,
        "sub_probe_b_random_seed_r1":            b,
        "sub_probe_c_feedforward_depth_sweep":   c,
    }
    emit("collision_absorption", payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
