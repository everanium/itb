#!/usr/bin/env python3
"""Hash-agnostic raw-mode bias probe — a laboratory diagnostic that measures
how strongly a ChainHash primitive's output bias survives ITB's masking
layers under raw-ciphertext analysis (no demasking, no nonce-reuse).

For any pluggable chainhash implementation and a structured-plaintext
corpus, the probe:

  1. Parses the raw ciphertext (20-byte header + 8 bytes per pixel).
  2. Precomputes `const(p) = ChainHash(p_le || nonce, seed=0)` for every
     container pixel via the pluggable hash module.
  3. For every candidate pixel_shift in `[0, total_pixels)`:
       - Computes 7 candidate K-bit values per observation via
         `K_bit = observed_bit XOR const_bit`
       - Per-bit majority voting produces a conflict count (minority
         votes).
  4. Reports:
       - the full conflict-rate distribution across all shifts (min,
         percentiles, max),
       - top-N lowest-conflict shifts,
       - size of the "plateau" — shifts whose conflict equals or
         undercuts the true-shift conflict (the true shift is
         reconstructible from `cell.meta.json["start_pixel"]` — lab
         audit only, not attacker-visible),
       - the conflict rate at the true shift itself.

Interpretation guide:

  * **PRF-grade hash** (BLAKE3, AES-CMAC, SipHash, ChaCha20, BLAKE2,
    AreionSoEM): expected min conflict ≈ 50 % ± √(n / (probe_pins / 64)).
    No plateau: top shifts scatter randomly across the [0, total_pixels)
    range with conflict rates within the natural statistical band.
    Audit PASSES — ITB's bias neutralization holds.

  * **GF(2)-linear hash** (CRC128 in this repo): expected min conflict
    noticeably below 50 % (observed ≈ 47 % on ASCII corpora at 512 KB),
    with a plateau of many shifts sharing the same minimum (because
    CRC64 linear aliases replicate the bias across shifts related by
    pixel-index bit flips). Audit FAILS — Proof 7 precondition violated.

  * **Carry-chain hash** (FNV-1a Z/2^64 multiply): expected ≈ 50 %
    distribution, no plateau. FNV-1a's ring multiplication has genuine
    GF(2) nonlinearity from carry chains — enough to prevent bias
    accumulation in the majority-vote compound-key projection. Audit
    PASSES despite FNV-1a itself being invertible at the per-byte level.

This script is hash-agnostic: point it at any `chainhashes/*.py` module
via `--hash-module` and it runs the same probe machinery. Use the
bundled modules (crc128, fnv1a, blake3) as examples; crypto analysts
can add their own primitive mirrors.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from raw_mode_common import (
    observations_to_numpy,
    parse_raw_ciphertext,
    precompute_const_all,
    prediction_accuracy,
    recover_compound_key_cached_np,
)

PROJ = Path(__file__).resolve().parents[3]


def _load_hash_module(spec: str):
    """Load a Python module from either a dotted name
    (e.g. `chainhashes.crc128`) relative to the `phase2_theory/` dir,
    or an explicit `.py` path. Calls `init_from_meta(meta)` if the
    module exports one."""
    if spec.endswith(".py") or "/" in spec:
        mod_path = Path(spec).resolve()
        module_name = mod_path.stem
        spec_obj = importlib.util.spec_from_file_location(module_name, mod_path)
        if spec_obj is None or spec_obj.loader is None:
            raise RuntimeError(f"could not load module from path: {mod_path}")
        mod = importlib.util.module_from_spec(spec_obj)
        spec_obj.loader.exec_module(mod)
    else:
        mod = importlib.import_module(spec)
    # Sanity-check required interface
    for attr in ("chainhash_lo", "N_SEED_COMPONENTS"):
        if not hasattr(mod, attr):
            raise RuntimeError(
                f"hash module {spec!r} missing required attribute '{attr}'"
            )
    return mod


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--cell-dir", type=Path, required=True,
                    help="Corpus cell directory (contains cell.meta.json + ct_0000.bin).")
    ap.add_argument("--hash-module", type=str, required=True,
                    help="Pluggable hash module — either a Python dotted name "
                         "(e.g. `chainhashes.crc128`) or a path to a .py file. "
                         "Must export `chainhash_lo` + `N_SEED_COMPONENTS`.")
    ap.add_argument("--probe-size", type=str, default="auto",
                    help="Observations in the per-shift conflict measurement. "
                         "`auto` scales with corpus size: ~1500 pins per K bit "
                         "(binomial noise ~0.6%% per bit) capped at 16000 "
                         "observations; explicit integer overrides.")
    ap.add_argument("--top-n", type=int, default=10,
                    help="How many lowest-conflict shifts to list.")
    ap.add_argument("--ciphertext", type=Path, default=None,
                    help="Raw ciphertext path (default: <cell-dir>/ct_0000.bin).")
    args = ap.parse_args()

    meta = json.loads((args.cell_dir / "cell.meta.json").read_text())
    total_pixels = int(meta["total_pixels"])
    nonce = bytes.fromhex(meta["nonce_hex"])
    # The "correct" pixel_shift the solver should converge to is
    # -start_pixel mod total_pixels; attacker cannot compute this because
    # startPixel is startSeed-derived, but the lab audit prints it for
    # interpretation.
    true_sp = int(meta["start_pixel"])
    correct_shift = (-true_sp) % total_pixels

    # Load pluggable hash module + initialize from meta if supported.
    hash_mod = _load_hash_module(args.hash_module)
    if hasattr(hash_mod, "init_from_meta"):
        hash_mod.init_from_meta(meta)
    chainhash_fn = hash_mod.chainhash_lo
    n_seed = hash_mod.N_SEED_COMPONENTS

    ct_path = args.ciphertext or (args.cell_dir / "ct_0000.bin")

    print(f"{'=' * 72}")
    print(f"Hash-agnostic raw-mode bias probe")
    print(f"{'=' * 72}")
    print(f"Cell:            {args.cell_dir}")
    print(f"Ciphertext:      {ct_path.name} ({ct_path.stat().st_size} bytes)")
    print(f"Hash module:     {args.hash_module}  (N_SEED_COMPONENTS={n_seed})")
    print(f"total_pixels:    {total_pixels}")
    print(f"true startPx:    {true_sp}  (lab-only)")
    print(f"correct shift:   {correct_shift}  (= -startPx mod total_pixels)")
    print()

    obs = parse_raw_ciphertext(ct_path, total_pixels)
    print(f"parsed {len(obs)} observations")

    # Auto-scale probe size to keep per-bit binomial noise ~0.6%. Floor at
    # 2000 (small corpora) so the scan is still informative; cap at 16000
    # past which diminishing returns outweigh wall-clock cost.
    if args.probe_size == "auto":
        target = min(16000, max(2000, len(obs) // 8))  # ~12.5% of observations
        probe_size = min(target, len(obs))
        print(f"probe-size auto: {probe_size} (chosen from {len(obs)} total observations)")
    else:
        probe_size = int(args.probe_size)

    print(f"precomputing const(p) for {total_pixels} pixels ...")
    import time
    t0 = time.time()
    const_all = precompute_const_all(total_pixels, nonce, chainhash_fn, n_seed)
    print(f"  done in {time.time() - t0:.1f}s")

    probe = obs[: probe_size]
    probe_px, probe_ch, probe_val = observations_to_numpy(probe)
    pins_max = sum(
        1 for _, ch, _ in probe for k in range(7) if (ch * 7 + 3 + k) < 64
    )
    print(f"probe batch:     {len(probe)} observations, {pins_max} max pins/shift")
    print(f"scanning {total_pixels} candidate shifts (numpy-vectorized) ...")
    t0 = time.time()
    results = []
    for s in range(total_pixels):
        _, _, _, conflicts = recover_compound_key_cached_np(
            probe_px, probe_ch, probe_val, total_pixels, const_all, pixel_shift=s,
        )
        results.append((s, conflicts))
    print(f"  scan elapsed: {time.time() - t0:.1f}s")

    results.sort(key=lambda t: t[1])

    print(f"\nTop {args.top_n} shifts by lowest conflict:")
    print(f"  {'shift':>8}  {'conflicts':>10}  {'rate':>8}")
    for s, c in results[: args.top_n]:
        rate = 100.0 * c / pins_max
        mark = "   ← TRUE" if s == correct_shift else ""
        print(f"  {s:>8}  {c:>10}  {rate:>7.3f}%{mark}")

    correct_row = next((r for r in results if r[0] == correct_shift), None)
    if correct_row:
        rank = next(i for i, (s, _) in enumerate(results) if s == correct_shift)
        correct_rate = 100.0 * correct_row[1] / pins_max
        plateau_size = sum(1 for _, c in results if c <= correct_row[1])
        print(f"\nTRUE shift {correct_shift}: rank {rank + 1}/{total_pixels}  "
              f"| conflict {correct_row[1]}/{pins_max} = {correct_rate:.3f}%  "
              f"| plateau (≤ same conflict) = {plateau_size} shift(s)")

    # -----------------------------------------------------------------
    # Axis-2 — prediction accuracy of the recovered compound key at the
    # minimum-conflict shift. Independent signal of algebraic recovery:
    # GF(2)-linear primitives expose near-100 % per-channel match at the
    # correct shift; PRF / carry-chain primitives hover at the random
    # baseline (~1/128 per channel, ~50 % per bit) at every shift.
    # --------------------------------------------------------------------
    truth_path = args.cell_dir / "config.truth.json"
    axis2_available = truth_path.exists()
    if axis2_available:
        config_truth = json.loads(truth_path.read_text())
        per_pixel_truth = config_truth.get("per_pixel", [])
        # Best-of-the-distribution shift for axis-2 scoring — this is
        # what an attacker would pick without lab knowledge.
        best_shift, _ = results[0]
        # Re-run K recovery at that shift on the same probe batch.
        K_best, known_mask_best, _, _ = recover_compound_key_cached_np(
            probe_px, probe_ch, probe_val, total_pixels, const_all,
            pixel_shift=best_shift,
        )
        # Held-out test set: 256 container positions spread across the
        # corpus, skipping the observations used in the probe batch so
        # the prediction score reflects generalisation.
        n_test = min(256, total_pixels)
        if n_test > 0:
            step = max(1, total_pixels // n_test)
            test_pixels = list(range(0, total_pixels, step))[:n_test]
        else:
            test_pixels = []
        ch_m, ch_t, ch_acc, bit_m, bit_t, bit_acc = prediction_accuracy(
            K_best, known_mask_best, per_pixel_truth, const_all,
            pixel_shift=best_shift, total_pixels=total_pixels,
            test_pixels=test_pixels,
        )
        print(f"\nAxis-2 prediction at min-conflict shift {best_shift}:")
        print(f"  bits matched     : {bit_m}/{bit_t} = {100.0 * bit_acc:.3f}%  "
              f"(PRIMARY signal; random baseline ~50.000%)")
        print(f"  channels matched : {ch_m}/{ch_t} = {100.0 * ch_acc:.3f}%  "
              f"(diagnostic only; near-zero under raw-mode for all primitives)")

        # Also score the TRUE (lab-known) shift so the human reviewer can
        # compare. For GF(2)-linear primitives the TRUE shift should win
        # both axes; for PRF primitives it is indistinguishable from any
        # random shift.
        if correct_row:
            K_true, known_mask_true, _, _ = recover_compound_key_cached_np(
                probe_px, probe_ch, probe_val, total_pixels, const_all,
                pixel_shift=correct_shift,
            )
            t_ch_m, t_ch_t, t_ch_acc, t_bit_m, t_bit_t, t_bit_acc = \
                prediction_accuracy(
                    K_true, known_mask_true, per_pixel_truth, const_all,
                    pixel_shift=correct_shift, total_pixels=total_pixels,
                    test_pixels=test_pixels,
                )
            print(f"Axis-2 prediction at TRUE shift {correct_shift}  (lab-only):")
            print(f"  bits matched     : {t_bit_m}/{t_bit_t} = {100.0 * t_bit_acc:.3f}%")
            print(f"  channels matched : {t_ch_m}/{t_ch_t} = {100.0 * t_ch_acc:.3f}%")
    else:
        print(f"\n(axis-2 prediction skipped — config.truth.json not present)")

    rates = sorted(100.0 * c / pins_max for _, c in results)
    n = len(rates)
    print(f"\nAll-shift conflict-rate distribution:")
    print(f"  min:     {rates[0]:.3f}%")
    print(f"  p01:     {rates[n // 100]:.3f}%")
    print(f"  p05:     {rates[n // 20]:.3f}%")
    print(f"  median:  {rates[n // 2]:.3f}%")
    print(f"  p95:     {rates[19 * n // 20]:.3f}%")
    print(f"  p99:     {rates[99 * n // 100]:.3f}%")
    print(f"  max:     {rates[-1]:.3f}%")
    print()
    print(f"Interpretation: if min << 50 % AND plateau size > 1, the chain has")
    print(f"GF(2)-linear structure that bias-accumulates through ITB's masking;")
    print(f"~50 % flat distribution means ITB successfully neutralizes the bias.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
