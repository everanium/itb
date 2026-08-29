#!/usr/bin/env python3
"""BEA-1 lo-lane seed recovery from (chosen-data, truncated-64-bit-output) pairs
at ITB ChainHash rounds=1.

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The cipher and constants are a CLEAN-ROOM reimplementation transcribed from the
published paper (no reference code vendored). This adapts the full-key partition
trapdoor attack (bea1_partition_attack.py) to the reduced observable surface of
the ITB ChainHash-r1 wrap, as a positive-control lab demonstration (not for
deployment). It establishes that at rounds=1 (no feedforward) truncation alone
is a weak barrier; whether the seed is recoverable is bounded to the tested
chosen-data budget.

The wrap truncates each BEA-1 lane's 80-bit output to its low 64 bits
(bea1_chainhash.truncate80to64), and the ITB encoder discards the hi lane, so
the attacker observes ONLY:

    lo64_i = truncate80to64( block_to_uint80( BEA1_encrypt(seed0, data_i) ) )

for chosen data_i under a fixed secret seed0.

What truncation removes (see bea1_chainhash.py for the bundle bit-ranges)
-------------------------------------------------------------------------
The W-coset label (bea1_partition_attack.PartitionAttack.ct_wlabel) is 8 lanes
x 5 bits, read from the 8 ciphertext bundles. The W-coordinate projection masks
(td["B_basis"]) span the full 10 bits of each bundle, so a lane's 5-bit label is
readable only if ALL 10 bits of that bundle survive truncation. Under the
low-64 truncation:

    lane 0 (bundle 0, bits 70..79) -- bundle fully DROPPED -> label UNREADABLE
    lane 1 (bundle 1, bits 60..69) -- only low 4 bits survive -> label UNREADABLE
    lanes 2..7 (bundles 2..7)      -- fully survive          -> label READABLE

So the attacker reads a PARTIAL 6-lane W-label (30 of the 40 label bits) for
clean-pair clustering. The recovery of each k0 bundle (the seed) does NOT read
ciphertext bits at all -- it reads only the chosen plaintext bundle (known to the
attacker) and the clean-pair set. Clean-pair identification is the only step
that touches the ciphertext, and it is exactly the step degraded by truncation.

This file ports PartitionAttack except for two surgical changes:
  1. ct_wlabel_partial: read the W-label of only the 6 surviving lanes (2..7).
  2. clustering / dominant-coset detection runs on the 6-lane partial label.
The per-lane key recovery (_lane_candidates) and key-schedule reconstruction
mirror bea1_partition_attack, since they never read ciphertext bits.

Decision-path inputs (NO cheat)
-------------------------------
The attack consumes ONLY:
  * the chosen data_i it generates, and
  * the truncated 64-bit lo-lane outputs lo64_i (an oracle returning a uint64),
  * the public design constants (S-boxes, partition V/W from bea1_trapdoor).
It never reads seed0, seed1, intermediate round state, or oracle internals.
"""
import bea1 as B
import bea1_trapdoor as TD
from bea1_chainhash import MASK10

PERM = [0, 5, 2, 7, 4, 1, 6, 3]  # ShiftRows lane permutation (involution)

# Lanes whose ciphertext bundle fully survives the low-64 truncation.
# bundle i occupies bits [10*(7-i) .. 10*(7-i)+9]; it survives iff 10*(7-i)+9 < 64.
SURVIVING_LANES = tuple(i for i in range(8) if 10 * (7 - i) + 9 < 64)  # -> (2,3,4,5,6,7)


def _parity(v):
    return bin(v).count("1") & 1


def _proj5(val, masks5):
    o = 0
    for t, a in enumerate(masks5):
        o |= _parity(a & val) << t
    return o


def uint64_to_surviving_bundles(lo64):
    """Recover the BEA-1 ciphertext bundles that fully survive the low-64
    truncation.  Returns a dict {lane_index: bundle_value} for lanes 2..7.

    bundle i sits at bits [10*(7-i) .. 10*(7-i)+9] of the 80-bit value; for the
    surviving lanes that whole 10-bit field lies within bits 0..63 of lo64.
    """
    out = {}
    for i in SURVIVING_LANES:
        shift = 10 * (7 - i)
        out[i] = (lo64 >> shift) & MASK10
    return out


class PartitionAttackTruncated:
    """seed0 recovery via the partition trapdoor under 80->64 lo-lane truncation.

    Constructed from public design constants only.  recover() takes an oracle
    mapping a chosen 8-bundle data block to a single uint64 (the truncated lo
    lane) and returns the recovered 12-bundle seed0.
    """

    def __init__(self):
        td = TD.derive_trapdoor()
        self.A = td["A_basis"]
        self.Bm = td["B_basis"]
        self.V = td["V"]
        self.Vlists = [sorted(self.V[k]) for k in range(4)]
        self.PROJ_W = [[_proj5(x, self.Bm[k]) for x in range(1024)] for k in range(4)]

    # ---- partial public coset label (surviving lanes only) ----
    def ct_wlabel_partial(self, lo64):
        """Partial W-coset label from the truncated lo-lane output: the 5-bit
        W-coordinate of each SURVIVING lane only (lanes 2..7).

        As in the full attack, the final round emits no MixColumns, so ciphertext
        lane i is the ShiftRows image of S-box output lane PERM[i]; its
        W-coordinate uses Bm[PERM[i] % 4].
        """
        bundles = uint64_to_surviving_bundles(lo64)
        return tuple(_proj5(bundles[i], self.Bm[PERM[i] % 4]) for i in SURVIVING_LANES)

    def _make_coset_data(self, base, n, rng):
        out = []
        for _ in range(n):
            out.append([base[i] ^ rng.choice(self.Vlists[i % 4]) for i in range(8)])
        return out

    def _clean_pairs(self, datas, outs):
        """Clean pairs = those whose PARTIAL (6-lane) output W-coset label equals
        the dominant partial label.  Truncation costs lanes 0,1 of the label; the
        remaining 30 bits still isolate the partition-respecting fraction because
        the dominant output coset is a single full W-coset, so its 6-lane
        projection is also a single value standing out above the noise floor."""
        from collections import Counter
        h = Counter(self.ct_wlabel_partial(o) for o in outs)
        dom, _ = h.most_common(1)[0]
        return [datas[i] for i in range(len(outs)) if self.ct_wlabel_partial(outs[i]) == dom]

    def _lane_candidates(self, clean_sets, states_fn):
        """Per-lane key-bundle candidate lists, best-first.  Identical logic to
        the full attack: for a key bundle sitting before a Sub layer, the correct
        guess g makes proj_W(S(state[i] ^ g)) constant across clean pairs of one
        input coset.  Reads only the chosen-plaintext-derived state and the
        clean-pair set -- no ciphertext bits, so truncation does not touch it."""
        from collections import Counter
        per_lane = []
        for i in range(8):
            S = B.SBOX[i % 4]
            PW = self.PROJ_W[i % 4]
            vals = [[states_fn(p)[i] for p in clean] for clean in clean_sets]
            surv = set(range(1024))
            for vi in vals:
                gok = set()
                for g in range(1024):
                    labs = {PW[S[v ^ g]] for v in vi}
                    if len(labs) == 1:
                        gok.add(g)
                surv &= gok
            if not surv:
                surv = set(range(1024))
            scored = []
            for g in surv:
                score = 0
                for vi in vals:
                    h = Counter(PW[S[v ^ g]] for v in vi)
                    score += h.most_common(1)[0][1]
                scored.append((score, g))
            scored.sort(reverse=True)
            per_lane.append([g for _, g in scored])
        return per_lane

    def recover(self, oracle, n_cosets=10, per_coset=30000, seed=None):
        """Recover the 120-bit lo-lane seed (seed0) as a 12-tuple of 10-bit
        bundles, or None on failure.

        oracle : callable(data_8_bundles) -> uint64   (truncated lo lane only).

        Reconstruction of the full 120-bit seed uses BEA-1's key schedule
        identity (Algorithm 1): K[0:8] = round_key_0, K[8:12] = round_key_1[0:4].
        round_key_0 (= seed bundles 0..7) is recovered at the first Sub; one round
        is then applied forward and round_key_1[0:4] (seed bundles 8..11) recovered
        at the second Sub.  Self-verification trial-encrypts held-out data through
        the same truncated lane and checks the uint64 matches.
        """
        import random
        import itertools
        rng = random.Random(seed)

        clean_sets = []
        total_pairs = 0
        clean_sizes = []
        verify_pairs = []  # (data, lo64) held out for trial-encryption check
        for _ in range(n_cosets):
            base = [rng.randrange(1024) for _ in range(8)]
            datas = self._make_coset_data(base, per_coset, rng)
            outs = [oracle(d) for d in datas]
            total_pairs += per_coset
            clean = self._clean_pairs(datas, outs)
            clean_sizes.append(len(clean))
            clean_sets.append(clean)
            verify_pairs.append((datas[0], outs[0]))

        info = {"n_cosets": n_cosets, "per_coset": per_coset,
                "total_pairs": total_pairs, "clean_sizes": clean_sizes,
                "surviving_lanes": SURVIVING_LANES}

        # round key 0 (= seed[0:8]) at the first Sub
        k0_cands = self._lane_candidates(clean_sets, states_fn=lambda p: p)
        info["k0_cand_sizes"] = [len(c) for c in k0_cands]

        def make_one_round(k0):
            def one_round(p):
                x = [p[i] ^ k0[i] for i in range(8)]
                x = B._sub_bundles(x); x = B._shift_rows(x); x = B._mix_columns(x)
                return x
            return one_round

        # Attacker-visible self-verification: trial-encrypt through the SAME
        # truncated lo lane and compare the uint64 (the only thing observed).
        from bea1_chainhash import bea1_lane

        def full_verify(K12):
            try:
                rk = B.expand_key(tuple(K12))
            except Exception:
                return False
            for (d, lo64) in verify_pairs[:3]:
                if bea1_lane(tuple(K12), d, rk) != lo64:
                    return False
            return True

        k0_opts = [c[:6] for c in k0_cands]

        def k0_iter():
            top = [c[0] for c in k0_cands]
            yield top
            seen = {tuple(top)}
            for i in range(8):
                for alt in k0_cands[i][1:6]:
                    cand = list(top); cand[i] = alt
                    if tuple(cand) not in seen:
                        seen.add(tuple(cand)); yield cand
            for combo in itertools.product(*k0_opts):
                if tuple(combo) not in seen:
                    seen.add(tuple(combo)); yield list(combo)

        for k0 in k0_iter():
            one_round = make_one_round(k0)
            k1_cands = self._lane_candidates(clean_sets, states_fn=one_round)
            k1_opts = [c[:6] for c in k1_cands[:4]]
            k1_top = [c[0] for c in k1_cands[:4]]

            def k1_iter():
                yield k1_top
                t = {tuple(k1_top)}
                for i in range(4):
                    for alt in k1_cands[i][1:6]:
                        cand = list(k1_top); cand[i] = alt
                        if tuple(cand) not in t:
                            t.add(tuple(cand)); yield cand
                for combo in itertools.product(*k1_opts):
                    if tuple(combo) not in t:
                        t.add(tuple(combo)); yield list(combo)

            for k1head in k1_iter():
                K = tuple(k0) + tuple(k1head[0:4])
                if full_verify(K):
                    info["stage"] = "complete"
                    info["k0_cand_sizes"] = [len(c) for c in k0_cands]
                    info["k1_cand_sizes"] = [len(c) for c in k1_cands[:4]]
                    return K, info

        info["stage"] = "exhausted"
        return None, info
