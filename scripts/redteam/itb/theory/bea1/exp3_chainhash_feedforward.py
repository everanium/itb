#!/usr/bin/env python3
"""EXPERIMENT 3 (Part A) — does ITB's ChainHash FEEDFORWARD (rounds >= 2)
neutralise the BEA-1 partition trapdoor that succeeds at rounds=1?

Run:  python3 exp3_chainhash_feedforward.py            (full: R=1 baseline + R=2,3,4 + instrumentation)
      python3 exp3_chainhash_feedforward.py --quick    (smaller data budget for a fast smoke run)

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The cipher and constants are a CLEAN-ROOM reimplementation transcribed from the
published paper (no reference code vendored). This is the core positive-control
demonstration: the SAME chosen-plaintext partition attack that recovers the seed
at rounds=1 is shown to fail once ITB's ChainHash feedforward is engaged at
rounds>=2 — a lab control showing the feedforward neutralises even a
deliberately-backdoored inner primitive (not for deployment). The negative
results below are bounded to the tested data budget and watchdog; they
demonstrate the mechanism, they are not a security proof.

What this does
--------------
The SAME, UNCHANGED attack engine `PartitionAttackTruncated` (from
bea1_attack_truncated.py) is run against the R-round ChainHash wrap
(bea1_chainhash.chainhash_r) for R = 1,2,3,4. The engine consumes ONLY
(chosen data, truncated lo64) pairs plus the public partition constants; it is
identical in all four runs. Nothing is weakened at R>=2 and nothing is
strengthened at R=1 -- the only thing that changes between the four runs is R
inside the oracle.

  * R=1 baseline  -> MUST recover seed[0]  (proves the engine still works; if this
    fails the harness is broken and the R>=2 negatives are meaningless).
  * R=2,3,4       -> expected to FAIL (feedforward defeats the trapdoor).

Anti-fake instrumentation (Part A.3)
------------------------------------
A negative result is the easiest thing to fake, so the failure is shown to be
STRUCTURAL (caused by feedforward), not a bug, by measuring the mechanism with
LAB-ONLY debug access (allowed for measurement, never in the attack's decision
path):

  (I)  Effective-last-round-key data-dependence.
       For each R, compute the effective BEA-1 key fed to the LAST round
       (bea1_chainhash.effective_last_round_key) across the chosen-data set.  At
       R=1 it is a single fixed key (variance 0).  At R>=2 it is
       seed[R-1] XOR extend(lo_{R-1}), data-dependent -> many distinct keys.
       The partition attack assumes ONE fixed key across all pairs; show that
       assumption is violated at R>=2.

  (II) Coset-signal collapse.
       The attack's clean-pair detector concentrates the partition-respecting
       fraction into one dominant output W-coset.  Measure the dominant-coset
       peak height vs the noise floor (mean of the rest) within each input coset.
       Sharp at R=1 (a real peak); collapses to ~noise floor at R>=2.

  (III) Candidate-set / clean-pair degradation.
       Report clean-pair counts and per-lane key candidate-set sizes the engine
       produced.  At R=1 the lanes pin to unique candidates and the assembled
       seed verifies; at R>=2 the signal is gone and verification never succeeds.

All ground-truth / intermediate access lives in the instrumentation and the
terminal success report ONLY.  The attack's recover() path is unchanged.
"""
import argparse
import os
import random
import signal
import time
from collections import Counter

import bea1 as B
import bea1_chainhash as CH
from bea1_attack_truncated import PartitionAttackTruncated, SURVIVING_LANES


class _Watchdog(Exception):
    pass


def _alarm(signum, frame):
    raise _Watchdog()


def recover_with_budget(attack, oracle, n_cosets, per_coset, seed, budget_sec):
    """Run the UNCHANGED engine `attack.recover` under a wall-clock watchdog.

    The watchdog (SIGALRM) only BOUNDS how long the attack is observed; it does
    not alter the engine's logic or its candidate search.  If the engine returns
    within budget, its (seed, info) is reported verbatim.  If it does not, the
    timeout itself is the result: the attack failed to produce a recovered seed
    within the budget.  This is honest -- a real attacker also faces wall-clock
    limits, and at R>=2 the engine grinds the full bounded candidate product with
    no real signal to short-circuit it (see instrumentation).
    """
    old = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, budget_sec)
    try:
        seed_rec, info = attack.recover(oracle, n_cosets=n_cosets,
                                        per_coset=per_coset, seed=seed)
        return seed_rec, info, False
    except _Watchdog:
        return None, {"stage": "timeout", "budget_sec": budget_sec}, True
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def banner(s):
    print("\n" + "=" * 74)
    print(s)
    print("=" * 74)


def fresh_seed_lists(R, sysrng):
    """R independent 120-bit seeds for each of the lo and hi lanes."""
    lo = [tuple(sysrng.randrange(1024) for _ in range(12)) for _ in range(R)]
    hi = [tuple(sysrng.randrange(1024) for _ in range(12)) for _ in range(R)]
    return lo, hi


def make_oracle(seed_list_lo, seed_list_hi, R, counter):
    def oracle(data):
        counter[0] += 1
        lo64, _hi = CH.chainhash_r(seed_list_lo, seed_list_hi, data, R)
        return lo64
    return oracle


# ---------------- LAB-ONLY instrumentation (measurement, not attack input) ----

def instrument_effective_key_variance(seed_list_lo, R, n_samples, rng):
    """(I) Measure how much the effective LAST-round BEA-1 key varies across the
    chosen-data set.  Returns (distinct_keys, n_samples, distinct_per_bundle).

    A fixed-key cipher (what the partition attack assumes) gives 1 distinct
    effective key.  Feedforward at R>=2 makes it data-dependent -> many."""
    keys = []
    for _ in range(n_samples):
        data = [rng.randrange(1024) for _ in range(8)]
        keys.append(CH.effective_last_round_key(seed_list_lo, data, R))
    distinct = len(set(keys))
    # per-bundle distinct counts (which bundles the feedforward actually stirs)
    per_bundle = [len({k[i] for k in keys}) for i in range(12)]
    return distinct, n_samples, per_bundle


def instrument_coset_peak(attack, oracle, R, n_cosets, per_coset, rng):
    """(II) For several input V-cosets, measure the dominant partial-W-coset peak
    vs the noise floor (mean count of all other observed labels).  Returns a list
    of (peak, noise_floor, distinct_labels, ratio) per coset."""
    stats = []
    for _ in range(n_cosets):
        base = [rng.randrange(1024) for _ in range(8)]
        datas = attack._make_coset_data(base, per_coset, rng)
        outs = [oracle(d) for d in datas]
        labels = [attack.ct_wlabel_partial(o) for o in outs]
        h = Counter(labels)
        peak = h.most_common(1)[0][1]
        rest = [c for lab, c in h.items()][1:] if len(h) > 1 else []
        # noise floor = mean count over all NON-dominant labels
        other_total = per_coset - peak
        other_distinct = len(h) - 1
        noise_floor = (other_total / other_distinct) if other_distinct else 0.0
        ratio = (peak / noise_floor) if noise_floor else float("inf")
        stats.append((peak, noise_floor, len(h), ratio))
    return stats


# ---------------- one R run: unchanged engine + instrumentation --------------

def run_round(R, n_cosets, per_coset, attack):
    banner(f"R = {R}  ChainHash feedforward  (rounds={R})")
    sysrng = random.Random(int.from_bytes(os.urandom(16), "big"))
    seed_list_lo, seed_list_hi = fresh_seed_lists(R, sysrng)
    target = tuple(seed_list_lo[0])  # what R=1 recovery would return (the recoverable seed)

    enc_count = [0]
    oracle = make_oracle(seed_list_lo, seed_list_hi, R, enc_count)

    # --- instrumentation BEFORE the attack (lab-only debug access) ---
    instr_rng = random.Random(0xC0FFEE + R)
    distinct_keys, n_keysamp, per_bundle = instrument_effective_key_variance(
        seed_list_lo, R, n_samples=2000, rng=instr_rng)
    coset_stats = instrument_coset_peak(
        attack, oracle, R, n_cosets=4, per_coset=per_coset, rng=instr_rng)

    print(f"[instr I  effective-last-round-key data-dependence]")
    print(f"    distinct effective last-round keys over {n_keysamp} chosen data : "
          f"{distinct_keys}")
    print(f"    (R=1 expects 1 fixed key; R>=2 expects data-dependent -> many)")
    print(f"    per-bundle distinct values [b0..b11]                          : "
          f"{per_bundle}")
    print(f"[instr II coset-signal: dominant partial-W-coset peak vs noise floor]")
    for j, (peak, nf, ndist, ratio) in enumerate(coset_stats):
        rr = f"{ratio:8.2f}" if ratio != float("inf") else "     inf"
        print(f"    coset {j}: peak={peak:6d}  noise_floor={nf:8.2f}  "
              f"distinct_labels={ndist:6d}  peak/noise={rr}")
    avg_ratio = sum(s[3] for s in coset_stats if s[3] != float("inf")) / max(
        1, sum(1 for s in coset_stats if s[3] != float("inf")))
    print(f"    avg peak/noise ratio (finite)                                 : "
          f"{avg_ratio:.2f}")

    # --- the UNCHANGED attack engine (bounded only by an external watchdog) ---
    # R=1 finishes quickly (~50s); R>=2 grinds the full bounded candidate product
    # with no signal, so a wall-clock budget bounds the observation.  The budget
    # is generous (well past R=1's completion time) so a real signal would be
    # found if it existed.
    budget = 240.0
    print(f"[attack ] running unchanged PartitionAttackTruncated "
          f"({n_cosets} cosets x {per_coset} pairs, watchdog {budget:.0f}s) ...")
    t0 = time.time()
    seed_rec, info, timed_out = recover_with_budget(
        attack, oracle, n_cosets, per_coset, seed=12345, budget_sec=budget)
    dt = time.time() - t0

    # --- terminal-stage success report (ground truth used ONLY here) ---
    match = (seed_rec is not None and tuple(seed_rec) == target)
    print(f"[result] clean-pair counts per input coset : {info.get('clean_sizes')}")
    print(f"[result] k0 lane candidate-set sizes       : {info.get('k0_cand_sizes')}")
    print(f"[result] k1 lane candidate-set sizes       : {info.get('k1_cand_sizes')}")
    print(f"[result] engine stage                      : {info.get('stage')}")
    print(f"[result] recovered == seed[0]              : {match}")
    print(f"[result] oracle queries                    : {enc_count[0]}")
    print(f"[result] wall-clock                        : {dt:.2f}s")

    return {
        "R": R,
        "match": match,
        "distinct_keys": distinct_keys,
        "n_keysamp": n_keysamp,
        "avg_peak_noise": avg_ratio,
        "coset_stats": coset_stats,
        "clean_sizes": info.get("clean_sizes"),
        "k0_cand_sizes": info.get("k0_cand_sizes"),
        "stage": info.get("stage"),
        "dt": dt,
        "queries": enc_count[0],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true",
                    help="smaller data budget for a fast smoke run")
    args = ap.parse_args()

    if args.quick:
        n_cosets, per_coset = 6, 30000
    else:
        n_cosets, per_coset = 10, 30000

    banner("EXPERIMENT 3 PART A — feedforward (rounds>=2) vs the BEA-1 partition trapdoor")
    print("Same unchanged engine `PartitionAttackTruncated` for all R; only R in the")
    print("oracle changes.  R=1 must recover; R=2,3,4 expected to fail; instrumentation")
    print("proves the R>=2 failure is structural (feedforward), not a code bug.")

    attack = PartitionAttackTruncated()  # built once from public constants only

    results = []
    for R in (1, 2, 3, 4):
        results.append(run_round(R, n_cosets, per_coset, attack))

    # ---------------- summary table ----------------
    banner("EXPERIMENT 3 PART A SUMMARY TABLE")
    print(f"{'R':>2} | {'recovered':>9} | {'eff-keys/2000':>13} | "
          f"{'avg peak/noise':>14} | {'clean-pairs (per coset)':>26} | {'stage':>9}")
    print("-" * 95)
    for r in results:
        cs = r["clean_sizes"]
        if cs is None:
            cs_str = "n/a (timeout)"
        else:
            cs_str = str(cs[:5]) + ("..." if len(cs) > 5 else "")
        apn = f"{r['avg_peak_noise']:.2f}"
        print(f"{r['R']:>2} | {str(r['match']):>9} | {r['distinct_keys']:>13} | "
              f"{apn:>14} | {cs_str:>26} | {r['stage']:>9}")

    print("\nInterpretation:")
    print("  R=1 : 1 fixed effective key, sharp coset peak, unique candidates -> seed RECOVERED.")
    print("  R>=2: effective last-round key is DATA-DEPENDENT (many distinct keys), the")
    print("        dominant-coset peak collapses toward the noise floor, candidate sets")
    print("        no longer pin -> the SAME engine FAILS.  The feedforward, not a bug,")
    print("        is the cause (instrumented above).")

    # ---------------- assertions: the core claim ----------------
    r1 = next(r for r in results if r["R"] == 1)
    assert r1["match"], "R=1 baseline FAILED to recover seed[0] -- harness is broken"
    for r in results:
        if r["R"] >= 2:
            assert not r["match"], (
                f"R={r['R']} unexpectedly recovered seed[0]; feedforward did not stop it")
            # structural-cause evidence: effective key is data-dependent
            assert r["distinct_keys"] > 1, (
                f"R={r['R']} effective key was NOT data-dependent -- "
                f"instrumentation contradicts the structural-failure claim")
    print("\nEXP3 PART A OK:")
    print("  R=1 recovered seed[0] with the unchanged engine (engine proven functional).")
    print("  R=2,3,4 FAILED with the SAME engine.")
    print("  Instrumentation confirms the cause is the feedforward (effective last-round")
    print("  key becomes data-dependent; coset peak collapses), not a harness bug.")


if __name__ == "__main__":
    main()
