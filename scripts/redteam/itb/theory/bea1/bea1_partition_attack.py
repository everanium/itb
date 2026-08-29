#!/usr/bin/env python3
"""BEA-1 full 120-bit master-key recovery via the published partition trapdoor.

Sources:
    BEA-1 cipher        — arXiv:1702.06475 (Bannier & Filiol, 2017)
    partition trapdoor  — IACR ePrint 2016/493 (Bannier, Bodin & Filiol)

The cipher and constants are a CLEAN-ROOM reimplementation transcribed from the
published paper (no reference code vendored). This attack is part of a
positive-control demonstration: against bare BEA-1 the trapdoor recovers the
full key, establishing the baseline that ITB's ChainHash feedforward later
neutralises. A lab control, not for deployment — analogous in role to the
below-spec CRC128 / FNV-1a controls, but using a primitive with a real,
published, working key-recovery trapdoor. Recovery is demonstrated at the
tested chosen-plaintext budget; it is not a security proof of anything.

Algorithm (partition-based trapdoor key recovery)
-------------------------------------------------
Each S-box S_k maps cosets of a hidden 5-dim subspace V_k onto cosets of a
5-dim subspace W_k, ShiftRows permutes lanes, and MixColumns maps the
W-product partition exactly onto the V-product partition. Consequently one full
round of BEA-1 maps the V-partition of the state to itself with probability
(944/1024)^6 * (925/1024)^2 ~= 2^-1 (RusCrypto 2017 slides, p.18); the whole
11-round cipher maps an input V-coset to an output W-coset with probability
~2^-11. The hidden partition V/W is the published design constant, re-derived
in bea1_trapdoor.py from the S-boxes and M alone (no secret input).

Observable signal (no key needed). Fix ~30000 plaintexts in a single input
V-coset. About 30000 * 2^-11 ~= 15 of them traverse all 11 rounds respecting
the partition; their ciphertexts land in one common output W-coset (the
"dominant coset"), standing out ~15 vs ~1 above the noise floor. These
"clean" pairs are identified purely from the final ciphertext's W-coset label.

Key-recovery primitive. In the forward direction BEA-1 starts with
    Sub(p XOR k0)
so the first round key k0 sits *before* the nonlinear S-box (RusCrypto 2017,
"Principle of the Cryptanalysis", p.16: right key concentrates, wrong key
spreads). For the clean pairs of one input coset, the W-coset of Sub(p XOR k0)
is a single fixed value. Hence the correct k0 bundle is the unique guess g for
which proj_W( S_k(p_i XOR g) ) is CONSTANT across all clean pairs of that coset
(per lane). A single coset leaves a few candidate g per lane; intersecting the
candidate sets across several independent input cosets pins each bundle of k0
to a unique value. This is the partition distinguisher of ePrint 2016/493 §6.3
applied at the cipher's first nonlinearity.

Master-key reconstruction. BEA-1's key schedule (Algorithm 1) satisfies
    master_key K = round_key_0  ||  round_key_1[0:4]
(k[0..11] in ExpandKey: round key 0 is k[0..7] = K[0..7]; round key 1's first
four bundles are k[8..11] = K[8..11]). So recovering all 8 bundles of k0 yields
K[0:8] directly. With k0 known, one round is applied forward
(z0 = MixColumns(ShiftRows(Sub(p XOR k0)))) and the identical distinguisher is
run at round 1 (Sub(z0 XOR k1)) to recover k1, whose first four bundles are
K[8:12]. Concatenating gives the full 120-bit master key.

Cost. ~8 input cosets * ~30000 chosen plaintexts each, all under one fixed
unknown key; recovery is a few 1024-wide scans per lane. Far below 2^120.

Decision-path inputs (NO cheat)
-------------------------------
The attack consumes ONLY:
  * an encryption oracle that maps a chosen plaintext to its FINAL 11-round
    ciphertext under the fixed secret key (i.e. (plaintext, final-ciphertext)
    pairs the attacker obtains), and
  * the public design constants: S-boxes (SBOX), the partition V/W and its
    coordinate masks (from bea1_trapdoor.derive_trapdoor()).
It never reads the master key, the key schedule of the target key, or any
intermediate round state. Plaintexts are *chosen* by the attack (a
chosen-plaintext backdoor, exactly as in the paper); the input-coset structure
is built from the public V partition, not from any secret.
"""
import bea1 as B
import bea1_trapdoor as TD

MASK10 = 0x3FF
PERM = [0, 5, 2, 7, 4, 1, 6, 3]  # ShiftRows lane permutation (involution)


def _parity(v):
    return bin(v).count("1") & 1


def _proj5(val, masks5):
    o = 0
    for t, a in enumerate(masks5):
        o |= _parity(a & val) << t
    return o


class PartitionAttack:
    """Full BEA-1 master-key recovery via the partition trapdoor.

    Construction takes only the public design constants (S-boxes + re-derived
    partition).  The recover() entry point takes an encryption oracle and
    returns the recovered 120-bit master key as a 12-tuple of 10-bit bundles.
    """

    def __init__(self):
        td = TD.derive_trapdoor()
        self.A = td["A_basis"]   # input-mask (V-coordinate) bases per S-box
        self.Bm = td["B_basis"]  # output-mask (W-coordinate) bases per S-box
        self.V = td["V"]         # per-S-box V subspace (set of ints)
        # Vlists[k] = sorted elements of V_k, used to enumerate within-coset offsets.
        self.Vlists = [sorted(self.V[k]) for k in range(4)]
        # Precomputed projection tables: PROJ_W[k][x] = 5-bit W-label of x.
        self.PROJ_W = [[_proj5(x, self.Bm[k]) for x in range(1024)] for k in range(4)]

    # ---- public coset labels (used only on attacker-visible data) ----
    def ct_wlabel(self, c):
        """W-coset label of a FINAL ciphertext (8 lanes, 5 bits each).

        Last round emits no MixColumns: the ciphertext lane i is the ShiftRows
        image of S-box output lane PERM[i], so its W-coordinate uses Bm[PERM[i]%4].
        """
        return tuple(_proj5(c[i], self.Bm[PERM[i] % 4]) for i in range(8))

    def _make_coset_plaintexts(self, base, n, rng):
        """n chosen plaintexts in the input V-coset of `base` (add V-elements)."""
        out = []
        for _ in range(n):
            out.append([base[i] ^ rng.choice(self.Vlists[i % 4]) for i in range(8)])
        return out

    def _clean_pairs(self, pts, cts):
        """Clean pairs = those whose final ciphertext lies in the dominant
        output W-coset (the partition-respecting ~2^-11 fraction)."""
        from collections import Counter
        h = Counter(self.ct_wlabel(c) for c in cts)
        dom, _ = h.most_common(1)[0]
        return [pts[i] for i in range(len(cts)) if self.ct_wlabel(cts[i]) == dom]

    def _lane_candidates(self, clean_sets, states_fn):
        """For a round key sitting before a Sub layer, return per-lane candidate
        bundle lists, best-first.

        states_fn(plaintext) -> the 8-bundle state fed into that round's
        AddRoundKey (for k0 this is the plaintext itself; for k1 it is the
        one-round-forward state z0).

        Per lane i, the correct key bundle g makes proj_W(S_{i%4}(state[i] ^ g))
        CONSTANT across all clean pairs of one input coset (the dominant output
        coset is a single W-coset, so the round-1 input W-coset is fixed).  The
        agreement filter (intersection over cosets of "g gives one W-label")
        isolates a small candidate set; within it, candidates are ranked by total
        mode-concentration (sum over cosets of the largest W-bin), which breaks
        residual ties.  Returning ranked lists lets the caller verify by trial
        encryption when the top pick is not unique.
        """
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
                surv = set(range(1024))  # fall back (should not happen)
            # rank survivors by total mode-concentration across cosets, best first
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
        """Recover the 120-bit master key.

        Parameters
        ----------
        oracle : callable(plaintext_8_bundles) -> ciphertext_8_bundles
            Encrypts a chosen plaintext to its FINAL 11-round ciphertext under
            the fixed (secret) target key.  This is the ONLY channel to the key.
        n_cosets, per_coset : data budget (chosen plaintexts per input coset).

        Returns
        -------
        (K, info) where K is a 12-tuple of 10-bit bundles (the master key) or
        None on failure, and info is a dict with diagnostics.
        """
        import random
        rng = random.Random(seed)

        # --- gather chosen-plaintext data in several input V-cosets ---
        clean_sets = []
        total_pairs = 0
        clean_sizes = []
        # Hold out a few (plaintext, ciphertext) pairs purely for final
        # trial-encryption verification of the assembled key.
        verify_pairs = []
        for _ in range(n_cosets):
            base = [rng.randrange(1024) for _ in range(8)]
            pts = self._make_coset_plaintexts(base, per_coset, rng)
            cts = [oracle(p) for p in pts]
            total_pairs += per_coset
            clean = self._clean_pairs(pts, cts)
            clean_sizes.append(len(clean))
            clean_sets.append(clean)
            verify_pairs.append((pts[0], cts[0]))

        info = {"n_cosets": n_cosets, "per_coset": per_coset,
                "total_pairs": total_pairs, "clean_sizes": clean_sizes}

        # --- recover round key 0 (= K[0:8]) at the first Sub ---
        k0_cands = self._lane_candidates(clean_sets, states_fn=lambda p: p)
        info["k0_cand_sizes"] = [len(c) for c in k0_cands]

        # --- with a candidate k0, advance one round and get k1 candidates ---
        def make_one_round(k0):
            def one_round(p):
                x = [p[i] ^ k0[i] for i in range(8)]
                x = B._sub_bundles(x); x = B._shift_rows(x); x = B._mix_columns(x)
                return x
            return one_round

        # Final, attacker-visible verification: trial-encrypt held-out plaintexts.
        def full_verify(K12):
            try:
                rk = B.expand_key(tuple(K12))
            except Exception:
                return False
            for (p, c) in verify_pairs[:3]:
                if B.encrypt(tuple(K12), p, rk) != list(c):
                    return False
            return True

        # Try k0 top picks first, widening lanes as needed; for each k0 candidate
        # recover k1 and assemble + verify the master key.
        import itertools
        k0_opts = [c[:6] for c in k0_cands]
        # front-load: try all-top, then single-lane widenings, then full product.
        def k0_iter():
            top = [c[0] for c in k0_cands]
            yield top
            seen = {tuple(top)}
            # widen one lane at a time
            for i in range(8):
                for alt in k0_cands[i][1:6]:
                    cand = list(top); cand[i] = alt
                    if tuple(cand) not in seen:
                        seen.add(tuple(cand)); yield cand
            # full bounded product as last resort
            for combo in itertools.product(*k0_opts):
                if tuple(combo) not in seen:
                    seen.add(tuple(combo)); yield list(combo)

        for k0 in k0_iter():
            one_round = make_one_round(k0)
            k1_cands = self._lane_candidates(clean_sets, states_fn=one_round)
            # only the first four bundles of k1 enter the master key
            k1_opts = [c[:6] for c in k1_cands[:4]]
            k1_top = [c[0] for c in k1_cands[:4]]
            # try k1 top, then bounded product over first-4 lanes
            tried = set()
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
