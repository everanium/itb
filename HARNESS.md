# HARNESS.md — Non-cryptographic Hash Primitive Analysis Shelf

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

*(public sibling of [REDTEAM.md](REDTEAM.md) / [ITB.md](ITB.md) / [SCIENCE.md](SCIENCE.md) / [PROOFS.md](PROOFS.md). Three-axis empirical study of non-cryptographic hash primitives wrapped into ITB `ChainHash128` — bias-absorption (Axes A, A', B) and SAT KPA seed-recovery resistance (Axis C). Scope restricted to primitives whose Go reference and Python mirror each fit in ≤ ~500 LOC.)*

## 1. Scope

The shelf measures four non-cryptographic hash primitives plugged into ITB `ChainHash128` to validate two architectural properties:

1. **Bias absorption** — whether ITB's encoding pipeline (rotation + noise barrier + COBS framing + CSPRNG fill) neutralises a primitive's documented SMHasher weaknesses on the attacker-observable ciphertext surface (Axes A, A', B).
2. **SAT-based seed-recovery resistance** — whether commodity-scale Bitwuzla / Z3 KPA can recover the per-primitive seed at minimum ITB deployment (`keyBits = 512`, ChainHash-4 lo-lane) within reasonable wall-clock (Axis C).

The shelf complements [REDTEAM.md Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) (which targets the four cryptographic primitives in the Hash matrix) by extending bias-absorption coverage to non-cryptographic hashes, and complements [REDTEAM.md Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) by characterising raw-chain SAT KPA cost on each primitive in isolation.

Primitive selection criteria:

- Non-cryptographic (primary design goal is speed / distribution quality).
- Multi-round ARX or multiply-and-mix structure; no closed-form seed recovery known.
- Not publicly broken under KPA (no published seed-recovery paper, no packaged inverter).
- Reference + Python mirror each ≤ ~500 LOC.

Four primitives in scope: **t1ha1_64le**, **SeaHash**, **mx3**, **SipHash-1-3**.

## 2. Methodology

Four orthogonal axes:

**Axis A — hLo-projected lab bias.** SMHasher-style avalanche on the local Python mirror, projected onto the hLo lane that ITB observes through `ChainHash128`'s parallel two-lane wrapper. Random-input flip-1-bit measurement; max bias is `2 × |P(flip) − 0.5| × 100 %` over all (input_bit, output_bit) pairs.

**Axis A' — structural-input bias.** Per-bit output frequency, byte-distribution chi-square (df = 255), and adjacency XOR statistics, all at fixed seed against varying structured inputs (`json_structured`, `html_structured`). Mirrors the ITB-realistic threat model where seeds are deployment invariants and inputs share schema.

**Axis B — ITB-wrapped bias.** [Phase 2a extension probe](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) against `known_ascii` corpora encrypted with the primitive plugged into `ChainHash128` at `keyBits = 1024`, BF = 1, N = 2 nonce-reuse. Verdict `neutralized ✓` when `|Δ50|` of the per-shift conflict-rate distribution is below 1 %.

**Axis C — SAT KPA seed recovery.** Bitwuzla / Z3 KPA against synthetic `(message, hash(message, k))` pairs at raw chain hash and `ChainHash-1` wrap levels. Cells classified by tier:

| Tier | Criterion | Cryptographic meaning |
|------|-----------|------------------------|
| **0 TRASH** | training-forward fails | SAT encoding drift |
| **1 TRAINING-ONLY** | valid + holdout = 0 / N | multi-seed collision restricted to training |
| **2 PARTIAL** | valid + 0 < holdout < N | partial functional similarity |
| **3 FUNCTIONAL-EQ** | valid + holdout = N / N | functionally indistinguishable from ground truth — usable K |
| **4 BIT-EXACT** | recovered = ground truth byte-for-byte | identical seed |

False-positive rate at N = 32 holdout: `2⁻²⁰⁴⁸`, astronomically small.

## 3. Results

### 3.1. Axis A — lab bias on raw primitive

Random-input avalanche. Reference: published [`rurban/smhasher`](https://github.com/rurban/smhasher) numbers.

| Primitive | key_bits | n_keys | measured max bias | published (rurban) | reproduction ratio |
|:----------|---------:|------:|------------------:|-------------------:|:-------------------|
| **t1ha1_64le** | 256 | 65 536 | 1.82 % | not separately reported | noise-dominated (max-noise floor ≈ 1.78 %) |
| **t1ha1_64le** | 512 | 65 536 | **3.19 %** | 3.77 % | **85 %** |
| **t1ha1_64le** | 1024 | 65 536 | **3.24 %** | 3.95 % | **82 %** |
| **SeaHash**    | 256 | 65 536 | 1.45 % | not separately reported (clean) | at noise (PerlinNoise is the documented weakness, not avalanche) |
| **SeaHash**    | 512 | 65 536 | 1.87 % | not separately reported (clean) | at noise |
| **SeaHash**    | 1024 | 65 536 | 1.68 % | not separately reported (clean) | at noise |
| **mx3**        | 256  | 65 536 | 1.55 % | not separately reported (clean) | at noise (PerlinNoise AV 1.48 × 10¹² × is the documented weakness, not avalanche) |
| **mx3**        | 2048 | 65 536 | 1.89 % | not separately reported (clean) | at noise |
| **mx3**        | 8192 | 65 536 | 2.08 % | not separately reported (clean) | at noise |
| **SipHash-1-3** | 256  | 65 536 | 1.88 % | ~0.9 % (reduced-round profile) | at noise (max-noise floor ≈ 1.66 %; ~13 % above floor — borderline, consistent with reduced-round avalanche signature surviving into the hLo projection) |
| **SipHash-1-3** | 2048 | 65 536 | 1.78 % | ~0.9 % (reduced-round profile) | at noise; bias stable across key size (ARX scaling) |
| **SipHash-1-3** | 8192 | 65 536 | 1.71 % | ~0.9 % (reduced-round profile) | at noise; bias stable |

t1ha1's published avalanche scaling is partially reproduced (82–85 % of rurban magnitude). SeaHash and mx3 are at-noise on avalanche (their documented weaknesses are PerlinNoise on coordinate-structured inputs, not exercised by random-flip avalanche). SipHash-1-3 sits at-noise but slightly above max-noise floor — consistent with the reduced 1+3 round avalanche signature.

### 3.2. Axis A' — structural-input bias (fixed seed + varying schema)

| Primitive | format | n_instances × instance_size | bit_bias max | noise-max floor | byte χ² p | adj_xor max | verdict |
|:----------|:-------|:----------------------------|-------------:|----------------:|----------:|------------:|:--------|
| **t1ha1_64le** | json_structured | 65 536 × 4 KB  | 0.51 % | 0.58 % | 0.40 | 0.36 % | **no bias detected** |
| **t1ha1_64le** | json_structured | 4 096 × 64 KB | 2.30 % | 2.25 % | 0.44 | 1.77 % | **no bias detected** |
| **t1ha1_64le** | html_structured | 65 536 × 4 KB  | 0.45 % | 0.58 % | 0.63 | 0.58 % | **no bias detected** |
| **t1ha1_64le** | html_structured | 4 096 × 64 KB | 2.39 % | 2.25 % | 0.13 | 2.04 % | **no bias detected** |
| **SeaHash**    | json_structured | 65 536 × 4 KB  | 0.48 % | 0.58 % | 0.24 | 0.48 % | **no bias detected** |
| **SeaHash**    | json_structured | 4 096 × 64 KB | 2.42 % | 2.25 % | 0.82 | 1.70 % | **no bias detected** |
| **SeaHash**    | html_structured | 65 536 × 4 KB  | 0.54 % | 0.58 % | 0.11 | 0.47 % | **no bias detected** |
| **SeaHash**    | html_structured | 4 096 × 64 KB | 2.34 % | 2.25 % | 0.64 | 2.38 % | **no bias detected** |
| **mx3**        | json_structured | 65 536 × 4 KB  | 0.41 % | 0.58 % | 0.08 | 0.43 % | **no bias detected** |
| **mx3**        | json_structured | 4 096 × 64 KB | 2.00 % | 2.25 % | 0.13 | 1.89 % | **no bias detected** |
| **mx3**        | html_structured | 65 536 × 4 KB  | 0.49 % | 0.58 % | 0.91 | 0.46 % | **no bias detected** |
| **mx3**        | html_structured | 4 096 × 64 KB | 2.12 % | 2.25 % | 0.40 | 2.72 % | **no bias detected** |
| **SipHash-1-3** | json_structured | 65 536 × 4 KB  | 0.46 % | 0.58 % | 0.54 | 0.43 % | **no bias detected** |
| **SipHash-1-3** | json_structured | 4 096 × 64 KB | 2.39 % | 2.25 % | 0.17 | 1.99 % | **no bias detected** |
| **SipHash-1-3** | html_structured | 65 536 × 4 KB  | 0.53 % | 0.58 % | 0.16 | 0.45 % | **no bias detected** |
| **SipHash-1-3** | html_structured | 4 096 × 64 KB | 2.08 % | 2.25 % | 0.62 | 1.87 % | **no bias detected** |

Every cell within noise envelope. Under fixed seed + varying structured input, the hLo projection is statistically indistinguishable from random at the probe's resolution.

### 3.3. Axis B — ITB-wrapped raw-mode bias

| Primitive | size | format | Single \|Δ50\| | Triple Byte Level \|Δ50\| | Triple Bit Soup \|Δ50\| | shelf verdict |
|:----------|-----:|:-------|---------------:|--------------------------:|------------------------:|:--------------|
| **t1ha1_64le** | 512 KB | ascii | **0.607 %** ✓ | — | — | **neutralized ✓** on Single |
| **t1ha1_64le** | 1 MB   | ascii | **0.244 %** ✓ | — | — | **neutralized ✓** on Single |
| **SeaHash**    | 512 KB | ascii | **0.816 %** ✓ | — | — | **neutralized ✓** on Single |
| **SeaHash**    | 1 MB   | ascii | **0.140 %** ✓ | — | — | **neutralized ✓** on Single |
| **mx3**        | 512 KB | ascii | **0.363 %** ✓ | — | — | **neutralized ✓** on Single |
| **mx3**        | 1 MB   | ascii | **0.119 %** ✓ | — | — | **neutralized ✓** on Single |
| **SipHash-1-3** | 512 KB | ascii | **0.559 %** ✓ | — | — | **neutralized ✓** on Single |
| **SipHash-1-3** | 1 MB   | ascii | **0.489 %** ✓ | — | — | **neutralized ✓** on Single |

`—` in Triple columns: not measured because Single already established absorption. All measured primitives `neutralized ✓` at the 1 % threshold on both corpus sizes. The published SMHasher weaknesses (avalanche-scaling for t1ha1, PerlinNoise for SeaHash and mx3, reduced-round avalanche for SipHash-1-3) do not reach the attacker-observable ITB ciphertext surface.

### 3.4. Axis C — SAT KPA seed-recovery resistance

Axis C asks whether commodity-scale Bitwuzla / Z3 KPA recovers a primitive's seed from `(message, ChainHash(message, seed))` pairs. The table consolidates every primitive at **rounds = 1** (the bare round map — at this depth the ChainHash composition degenerates to a single hash call, no feedforward) and at **rounds ≥ 2** (the minimum ITB deployment, ChainHash-4, where the inter-round feedforward `k = seed[r] ⊕ h_prev` is active), and records whether the hi-lane discard alone walls the primitive before any round structure contributes. Rows are grouped by the deciding mechanism, not by shelf order: **(A)** invertible round maps that fall at rounds = 1, **(B)** a primitive walled by the internal discard alone, **(C)** primitives with no invertibility hook for SAT to grab.

| Primitive | round map / lane structure | hi-lane discard | r = 1 SAT | r ≥ 2 SAT (deployment) | verdict |
|:----------|:---------------------------|:----------------|:----------|:-----------------------|:--------|
| **fnv1a** (reference) | carry-up T-function, no right-shift | off — lo lane independent of hi | falls | **falls** — triangular structure survives the feedforward (isolated chain r = 4 ≈ 146 s Bitwuzla / ≈ 0.16 s T-solver) | cautionary control |
| **splitmix64** | right-shift bijection, no T-function; second lane is a 128-compat prototype, discarded | off — lo lane self-contained | falls ≈ 20 s (Z3) / ≈ 25 s (Bitwuzla), bit-exact | **resists at the 24 h budget** | **Dangerous** (r = 1); Resistant (r ≥ 2) |
| **mx3** | right-shift bijection, no T-function | off — two parallel lanes independent | falls ≈ 2–5 s (Tier 3, holdout 32 / 32) | **resists at the 24 h budget** | **Dangerous** (r = 1); Resistant (r ≥ 2) |
| **murmur3** | right-shift + internal h1 / h2 **mix** | **on** — 128 → 64 projection of mixed state | **resists** (full-128 ≈ 2.1 s vs lo-only timeout) | resists | **128-bit invertible**; lo-discard walls even at r = 1 |
| **t1ha1_64le** | multiply-and-mix, no invertibility hook | off — two parallel lanes | times out — structurally inapplicable | times out — structurally inapplicable | Resistant — differential-only hook |
| **SeaHash** | ARX, no invertibility hook | off — two parallel lanes | times out — structurally inapplicable | times out — structurally inapplicable | Resistant — differential-only hook |
| **SipHash-1-3** | reduced-round ARX, two parallel 64-bit lanes (k1 = 0), no invertibility hook | off — two parallel lanes | times out — structurally inapplicable | times out — structurally inapplicable | Resistant — clean on every axis |

**(A) Invertible round maps fall at rounds = 1; only a carry-up T-function carries the break into deployment.** splitmix64, mx3, and fnv1a are all `inv = Y` ([§3.5](#35-sat-free-algebraic--differential-pre-screen)) — a single round is a bijection the solver inverts directly: splitmix64 ≈ 20 s (Z3) / ≈ 25 s (Bitwuzla); mx3 ≈ 2–5 s, where the rounds = 1 chain degenerates to one `mx3_hash` call with the hi-lane seed unconstrained and the lo-lane seed recovered functionally-equivalent to ground truth. At rounds ≥ 2 the feedforward masks the intermediate output, so the solver can no longer peel round-by-round; the seed must be solved through the whole composition, which is tractable only when the round map is a **carry-up T-function** (output bit t depends on input bits 0..t, solvable plane-by-plane LSB → MSB). fnv1a's ×0x13B lo-lane has exactly that structure and stays solvable — the isolated ChainHash falls even at rounds = 4 in ≈ 146 s (Bitwuzla) / ≈ 0.16 s (the structure-aware T-function solver). splitmix64 and mx3 lack it: mix64's right-shifts (`z ^ (z>>30 / >>27 / >>31)`) push high bits down into low, destroying the triangularity, so both resist at the 24 h budget at rounds = 2 despite equal invertibility. splitmix64 is the clean control — its lo lane is literally splitmix64 (the hi lane is only a parallel second instance to fit the 128-bit two-lane interface, and the discard drops it), so its rounds ≥ 2 resistance is a property of splitmix64's own internal structure, not of any lane interaction. This is the decisive evidence that fnv1a's SAT-tractability is its carry-up triangular structure, not invertibility or round count. (The ≈ 8 h figure cited for fnv1a elsewhere is the FULL Phase 2g ITB break — ChainHash + the ~90-bit per-pixel noise_pos barrier + 4 public-schema cribs — not this isolated chain inversion.)

**(B) The hi-lane discard walls a lane-mixing primitive with no round structure required.** murmur3 (MurmurHash3_x64_128) is the only primitive here with a genuine 128-bit internal state whose halves cross-mix in finalisation: the full-128 seed recovers in ≈ 2.1 s, but ITB observes only the lo lane — a 128 → 64 projection of the already-mixed state — and that projection alone times out, walling murmur3 at rounds = 1 before the feedforward contributes anything. For the lane-parallel primitives (every other row) the hi-lane discard is **off**: the lo lane is computed independently of the hi lane, so dropping the hi lane removes no constraint a lo-lane attacker could have used. The two barriers are independent, and real ITB stacks both plus the per-pixel noise_pos / rotation barrier and the optional Lock Soup overlay on top.

**(C) No invertibility hook makes seed-recovery SAT structurally inapplicable.** For t1ha1, SeaHash, and SipHash-1-3 the SAT budget is not the meaningful axis: they carry no invertibility hook, so seed-recovery SAT times out at the 24 h budget (SeaHash across all 4 encodings — `{native, explicit}` × `{native, case-split}` — on both backends, 8 cells), not for want of compute. A larger budget does not change the verdict, which is why it is reported as a structural property, not a budget-bounded timeout. Their only surfaced weakness is differential (t1ha1 persistent, SeaHash round-dependent) — see [§3.5](#35-sat-free-algebraic--differential-pre-screen); SipHash-1-3 is clean on every axis. "Resistant at tested budget" for this group is better read as "no SAT invertibility hook"; the differential hook lives in a separate attack class the SAT axis structurally cannot reach (and, per [Axis B](#33-axis-b--itb-wrapped-raw-mode-bias), ITB's encoding neutralises it before it reaches a ciphertext anyway).

### 3.5. SAT-free algebraic & differential pre-screen

Axis C is hours-long; it is the wrong instrument for triaging a candidate primitive. This pre-screen is the cheap triage that runs first. Two Monte-Carlo / exact-algebra batteries — [`avalanche_screen.py`](scripts/redteam/phase2_theory/chainhashes/avalanche_screen.py) and [`differential_screen.py`](scripts/redteam/phase2_theory/chainhashes/differential_screen.py) — measure the **ChainHash lo-lane as a function of the seed at a fixed data buffer**: the inner primitive in the chain, not the full ITB envelope. The envelope's barrier (per-pixel `noise_pos` / rotation) is primitive-independent and is characterised separately in [REDTEAM.md Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based); the pre-screen asks only the upstream question a solver depends on — **does the inner primitive hand a SAT/SMT solver a structural hook to grab?** A primitive with no hook is exactly the case where, under its PRF assumption, no efficient recovery exists and Bitwuzla / Z3 cannot help the attacker; a primitive with a hook is a candidate for the expensive Axis C confirmation.

The pre-screen extends coverage beyond the four full-axis shelf primitives to three additional non-cryptographic mixers chosen to span the failure modes: **murmur3** (MurmurHash3_x64_128) and **xxhash64** (XXH64) as one-way table mixers of a different topology (accumulator vs multiply-xorshift), and **splitmix64** as an explicitly **invertible** mixer. These three are pre-screen primitives only — they are not wired into the Go harness and are not taken through Axis A–C; the pre-screen is precisely the SAT-free substitute for that wiring. Their Python mirrors are parity-checked bit-for-bit against the `mmh3` / `xxhash` reference libraries (murmur3, xxhash64) and the canonical seed-0 vector sequence (splitmix64).

**Algebraic battery (`avalanche_screen.py`).** Representative values at round 1 (`samples = 512`, `probe_bits = 48`, `data_len = 5`); the columns are stable across rounds 1–3. `lin_score` = fraction of single-bit input directions with a constant (GF(2)-affine) output difference; `sac_mean` / `sac_max` = mean / worst Strict Avalanche Criterion bias; `avw/64` = mean output bits flipped per input flip (ideal ≈ 32); `deg@m` = exact GF(2) algebraic-degree lower bound over an m-bit input sub-cube; `inv` = structural cheap-inverse flag (Y = a triangular T-function or by-design invertible mixer; ? = no documented shortcut, the screen makes no claim). Rows are grouped by pre-screen verdict, not by the §4 shelf order.

| Primitive | lin_score | sac_mean | sac_max | avw/64 | deg@16 | deg@20 | inv |
|:----------|----------:|---------:|--------:|-------:|-------:|-------:|:---:|
| **mx3**        | 0.000 | 0.018 | 0.074 | 32.0 | 16 | 20 | **Y** |
| **SipHash-1-3** | 0.000 | 0.018 | 0.088 | 32.0 | 16 | 20 | ? |
| **murmur3**    | 0.000 | 0.018 | 0.084 | 32.0 | 16 | 20 | ? |
| **xxhash64**   | 0.000 | 0.018 | 0.084 | 32.0 | 16 | 20 | ? |
| **t1ha1_64le** | 0.000 | 0.079 | **0.484** | 32.4 | 16 | 20 | ? |
| **SeaHash**    | **0.021** | 0.032 | **0.500** | 31.0 | 16 | 20 | ? |
| **splitmix64** | 0.000 | 0.018 | 0.088 | 32.0 | 16 | 20 | **Y** |
| **fnv1a**      | **0.021** | **0.375** | **0.500** | **15.3** | **15** | **19** | **Y** |
| **aes2r** ([§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)) | 0.000 | 0.213 | 0.500 | **19.7** | **7** | **10** | **N** |

**Differential battery (`differential_screen.py`).** Worst low-byte XOR-differential bucket probability `ddt8_max` over probed single-bit input differences (`samples = 4096`, `probe_bits = 32`), and `const8` = fraction of input directions with a constant low-byte output difference (the byte-level analogue of `lin_score`). The uniform baseline at this sample size is `~max ≤ 0.0101`; a value above it flags a biased differential a solver / differential attack can ride. `ddt8_max` is reported as the worst over rounds 1–3.

| Primitive | ddt8_max | const8 | reading |
|:----------|---------:|-------:|:--------|
| **mx3**        | 0.009 | 0.000 | at uniform baseline |
| **SipHash-1-3** | 0.008 | 0.000 | at uniform baseline |
| **murmur3**    | 0.009 | 0.000 | at uniform baseline |
| **xxhash64**   | 0.008 | 0.000 | at uniform baseline |
| **t1ha1_64le** | **0.220** | 0.000 | **biased** — persistent low-byte differential across all rounds |
| **SeaHash**    | **1.000** | 0.031 | **biased** — round-dependent; a deterministic low-byte characteristic appears at round 3 |
| **splitmix64** | 0.008 | 0.000 | at uniform baseline |
| **fnv1a**      | **1.000** | **0.938** | **biased** — near-deterministic low-byte differential (the carry-up T-function signature) |
| **aes2r** ([§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)) | **1.000** | 0.562 | **biased** — dominated by the final-AddRoundKey key term, not an exploitable data-differential |

**aes2r — the [§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash) reduced-round-cipher control, screened for completeness.** Unlike the single-call mixers above, aes2r (2-round AES) is **not saturated at round 1**: its seed → output avalanche fills in over the chain (`deg@16` 7 → 15, `avw/64` 19.7 → 29.5 by round 3) because each call is two AES rounds, not one mix. It carries no GF(2)-affine hook (`lin_score` 0) and no cheap structural inverse (`inv` N), and the differential battery flags it (`ddt8_max` 1.000) — but that signal is dominated by the final-round AddRoundKey (the seed is the AES key, XORed past the last S-box), not an exploitable data-differential, which in any case dies through the feedforward by rounds = 2 ([§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)). Critically, **neither battery sees the integral** — the actual break of 2-round AES (chosen-plaintext Λ-set, [§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)). It is the clearest case on this shelf that the pre-screen is **necessary, not sufficient**: a primitive can read clean on the affine / degree hooks and still fall to an attack class these batteries do not measure.

**What the pre-screen concludes — which primitives a solver could ride.** The screen surfaces four independent solver hooks; a primitive flagged on any one is a candidate for SAT recovery, a primitive clean on all four with `inv = ?` is the only verdict that genuinely requires the Axis C calibration to settle:

1. **GF(2)-affine directions** (`lin_score` or `const8` > 0). SeaHash carries a small affine fraction on both the full-width and low-byte tests — partial linear leakage a solver anchors on. fnv1a shows the same small full-width affine fraction (`lin_score` 0.021) on top of its dominant carry-up T-function signature (`const8` 0.938).
2. **Biased differential** (`ddt8_max` above the uniform band). t1ha1 (persistent) and SeaHash (round-3 deterministic) expose differential characteristics. This is a hook for a **differential attack** — a different attack class from the seed-recovery the Axis C SAT calibration probes, which times out at the 24 h budget precisely because the weakness is differential, not invertibility. So "Resistant at tested budget" for these two is better read as "no SAT invertibility hook"; the differential hook lives in a separate class the SAT axis structurally cannot reach (and, per [Axis B](#33-axis-b--itb-wrapped-raw-mode-bias), ITB's encoding neutralises it before it reaches a ciphertext anyway).
3. **Low algebraic degree** (`deg@m < m`). None of the mixers are low-degree — all saturate to the sub-cube dimension (deg@16 = 16, deg@20 = 20) at round 1, so there is no cube / higher-order-differential shortcut. fnv1a lags by a single degree (15 / 19), consistent with its simpler carry structure.
4. **Cheap structural inverse** (`inv = Y`) — a ROUND-1 signal only, and the one hook the Monte-Carlo columns are blind to. splitmix64 is visually identical to murmur3 / xxhash64 on every battery column above, yet at rounds = 1 (no feedforward) it inverts in seconds because its mix64 is a composition of word-level bijections — the columns cannot see that. But invertibility alone is NOT the SAT hook at deployment: under the rounds ≥ 2 feedforward the solver can no longer peel round-by-round, and tractability then needs a further property `inv` does not capture — a triangular carry-up T-function. fnv1a has it and stays solvable; the right-shift mixers (splitmix64, mx3) lack it and resist. So `inv = Y` predicts only rounds-1 breakability; whether it carries into deployment is decided by that structure, not the flag — and high degree / perfect avalanche likewise do not imply SAT-hardness. The mechanism, the unified r = 1 / r ≥ 2 table, and the empirical splitmix64-vs-fnv1a confirmation are in [§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance).

SipHash-1-3, murmur3, and xxhash64 are clean on all four axes with `inv = ?` — the screen surfaces no hook and defers to the SAT calibration (SipHash-1-3 timed out at the tested budget; murmur3 is additionally walled at rounds = 1 by its internal 128 → 64 discard). mx3 carries `inv = Y`, and the flag correctly predicts its rounds = 1 break (the [§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance) `Dangerous` label). The pre-screen is therefore **necessary, not sufficient**: a clean algebraic / differential row with `inv = ?` remains a "worth a SAT calibration" signal, never a security verdict.

**The two screens are complementary.** SAT calibration targets seed recovery (invertibility / T-function) and so catches fnv1a (and mx3 / splitmix64 at rounds = 1), but TIMES OUT on t1ha1, SeaHash, and SipHash-1-3 — they carry no invertibility hook. The differential screen targets a different attack class and catches what SAT misses: **t1ha1** (a persistent biased low-byte differential, ddt8_max ≈ 0.10–0.22 across rounds) and **SeaHash** (a round-dependent differential up to 1.0 plus partial GF(2)-affinity, const8 = 0.031, lin_score = 0.021) are **differential-only** — SAT-resistant yet differentially flagged. **SipHash-1-3** is clean on both (only the Axis A reduced-round avalanche signature marks it). No differential attack is pursued: [Axis B](#33-axis-b--itb-wrapped-raw-mode-bias) already shows ITB's encoding (rotation + noise barrier + COBS) neutralises these raw-primitive differential biases on the attacker-observable ciphertext surface (`|Δ50| < 1 %`), so the hook does not reach a deployed ciphertext. The screen's value is cheap triage of the raw primitive, not an exploit path.

### 3.6. Trapdoor-primitive control — BEA-1 partition backdoor through ChainHash

[§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance) measures seed-recovery resistance for below-spec primitives (CRC128 / FNV-1a — weak by accident). This control goes further: it plugs in a primitive with a **deliberate, published, working** mathematical backdoor and asks whether ChainHash neutralises it. The primitive is **BEA-1** (Bannier & Filiol, arXiv:1702.06475; partition-trapdoor theory in IACR ePrint 2016/493) — an 80-bit-block AES-like cipher whose S-boxes and diffusion layer hide a linear partition that lets the designer recover the 120-bit key from chosen (plaintext, ciphertext) pairs while the cipher still passes standard differential / linear / statistical tests. The trapdoor is re-derived here purely from the published constants (the S-boxes carry a max |LAT| = 256 against the paper's claimed ≤ 128; the partition is a structural property of the design, not the secret key).

Methodology is the Axis-C lab style of §3.4 — synthetic `(data, ChainHash-lo)` pairs under a fixed secret seed — with a **partial discard (truncate 80 → 64)** because the 80-bit primitive output is packed into the 64-bit lane. The attacker is granted generous lab access (chosen `data`, the full published partition) so that any failure is attributable to the construction, not to a weak attacker.

| Stage | Construction | Trapdoor outcome |
|:------|:-------------|:-----------------|
| Pure BEA-1 | the cipher alone, no ChainHash | **Full 120-bit key recovered** from chosen (plaintext, ciphertext) pairs — confirms the backdoor is real and reproduced. |
| ChainHash, rounds = 1 | 2×BEA-1 lane, truncate 80 → 64, no feedforward | **Full lo-lane seed recovered.** The truncation drops 2 of the 8 partition lanes, yet the attack clusters on the surviving 30 of 40 coset-label bits and still succeeds. Rounds = 1 offers no protection — consistent with §3.4 / §3.5 (structured primitives fall at rounds = 1). |
| ChainHash, rounds ≥ 2 | feedforward `k = seed[r] ⊕ extend(lo_{r-1})` | **The same engine fails — structurally.** The feedforward makes the effective last-round key **data-dependent** (one fixed key at rounds = 1 → all-distinct at rounds ≥ 2), so the dominant-coset concentration the partition attack rides **collapses to the noise floor** (peak / noise ≈ 1.0 versus ≈ 25 at rounds = 1). With no coset peak there is nothing to recover. |

A structure-aware SMT solver — the partition-quotient analogue of the §3.5 T-function solver — was also tried against the feedforward. It inverts a single S-box layer but gains **no algebraic shortcut through a full BEA-1 round**: the per-S-box partition quotient is only probabilistic (no exact quotient cipher to lift), and the round feedforward breaks the coset homomorphism the trapdoor relies on, so the structure offers the solver nothing the plain composition does not.

**Conclusion.** At rounds = 1 the trapdoor survives the 80 → 64 truncation untouched; at rounds ≥ 2 ChainHash's feedforward **neutralises it** — the same intermediate-masking mechanism that walls invertible primitives in §3.4 / §3.5, here dissolving the fixed-key coset structure a working partition backdoor requires, with the partial discard as a secondary barrier. The wrap is deliberately generous to the attacker (chosen plaintext, minimum-scrambling feedforward leaving 56 of 120 key bits untouched), so the result is conservatively framed: it is the published BEA-1 partition attack and a structure-aware solver that are neutralised at rounds ≥ 2, not a proof that no exploitation path exists.

### 3.7. Reduced-round primitive control — 2-round AES integral break through ChainHash

[§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance) probes primitives weak by accident (CRC128 / FNV-1a) and [§3.6](#36-trapdoor-primitive-control--bea-1-partition-backdoor-through-chainhash) one with a hidden partition trapdoor (BEA-1). This control plugs in a **strong** primitive deliberately crippled by **round reduction** — **AES cut to 2 rounds** — and asks whether ChainHash neutralises its textbook break. 2-round AES is integral-broken: a Λ-set (256 chosen `data` values, one active byte) makes every output byte balanced (XOR-sum over the set = 0), and because the final round omits MixColumns each active output byte obeys `SB(a·SB(pt⊕k0)⊕C)⊕k2` (a ∈ {1, 2, 3}, C constant), peeled to a unique master-key byte in ≈ 2¹⁶. The break is the **integral (chosen-plaintext structure), not a SAT invertibility hook**: the AES S-box is not a carry-up T-function, so generic z3 / CryptoMiniSat seed recovery from known-plaintext pairs times out even at rounds = 1 (group (C) of §3.4), and the §3.5 pre-screen reads aes2r as clean on the affine / cheap-inverse hooks (`lin_score` = 0, `inv` N) while flagging only its final-AddRoundKey differential — neither instrument sees the integral.

Methodology is the Axis-C lab style — synthetic `(data, ChainHash-lo)` pairs under a fixed secret seed, the attacker granted chosen `data` (the Λ-set) and the full integral structure — with the standard lo-lane discard (128 → 64, "discard hHi"). The inner primitive is `chainhashes/aes2r.py` (FIPS-197-validated building blocks); `rounds` is the ChainHash call count (rounds = 1 = one 2-round-AES call, no feedforward = the raw primitive).

| Stage | Construction | Integral outcome |
|:------|:-------------|:-----------------|
| rounds = 1 | one AES2R call (= raw 2-round AES), discard hHi, no feedforward | **Key recovered.** One Λ-set recovers a master-key byte uniquely (≈ 2¹⁶). The lo-lane discard drops 2 of the 4 active output bytes; the surviving 2 still carry the balance. Rounds = 1 offers no protection — consistent with §3.4 / §3.6 (structured primitives fall at rounds = 1). |
| rounds = 2 | feedforward `k = seed[r] ⊕ h_{r-1}` active | **Distinguisher survives; key recovery fails.** A Λ-set still leaves balanced output bytes — 1st order 4 (discard off) / 2 (on), 2nd order 12 / 6 — against a random floor ≈ 0.06 / 0.03, a strong PRF distinguisher. But the feedforward makes the round-1 key `K₁ = seed₁ ⊕ ct₀` **data-dependent** (distinct across the Λ-set), so the integral's last-round peel has no fixed key to guess and **recovery fails** (0 / 5, both discard modes). The data-differential is already dead at this depth (per-byte differential probability at the max-of-buckets noise floor). |
| rounds = 4 (deployment) | ChainHash-4 | **The integral is neutralised entirely.** 1st-, 2nd-, and 3rd-order Λ-sets all return **0 balanced output bytes** (both discard on and off) — at the random floor. No distinguisher, no recovery. |

**Mechanism — the feedforward dissolves the fixed-key balance the integral requires.** The same intermediate-masking that walls invertible primitives in §3.4 and the partition trapdoor in §3.6: at rounds ≥ 2 the round key is data-dependent, so the integral's "fixed key, structured plaintext" premise breaks. The decisive contrast with FNV-1a is that the integral structure is **not** compatible with the feedforward — it degrades to a distinguisher at rounds = 2 and vanishes by rounds = 4 — whereas FNV-1a's carry-up T-function **is** compatible and survives into deployment ([§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance)). Which reduced-round / below-spec primitive ChainHash neutralises is decided by whether its structured attack survives the data-dependent key, not by the primitive's pedigree. The hi-lane discard is a **secondary** barrier — it halves the surviving rounds = 2 signal (4 → 2, 12 → 6 balanced bytes) — but the feedforward **depth** is what closes the channel: at rounds = 4 the discard is irrelevant (0 either way).

**Conclusion.** At rounds = 1 the integral key-recovery survives the lo-lane truncation untouched; at rounds = 2 only a non-recovering PRF distinguisher survives; at rounds ≥ 4 ChainHash's feedforward neutralises the integral (orders 1–3) and the data-differential entirely. The result is conservatively framed: it is the integral / higher-order integral (orders 1–3), the data-differential, and the no-hook SAT seed-recovery routes that are neutralised at deployment depth, not a proof that no exploitation path exists for so weak a primitive.

## 4. Primitive shelf

Provenance and the published SMHasher weakness each primitive is selected to stress. The per-axis measured results are in [§3](#3-results); the consolidated Axis C seed-recovery verdicts (with the rounds = 1 vs rounds ≥ 2 split) are in the [§3.4 table](#34-axis-c--sat-kpa-seed-recovery-resistance).

| # | Primitive | Published Axis A signature |
|--:|-----------|:---------------------------|
| 1 | **t1ha1_64le** (Yuriev) | Avalanche 3.77–3.95 % at 512–1024-bit keys |
| 2 | **SeaHash** (Ticki, 2016) | PerlinNoise 2.2 × 10¹² × |
| 3 | **mx3** (Maiga, 2022) | PerlinNoise AV 1.48 × 10¹² × |
| 4 | **SipHash-1-3** (reduced-round) | 0.9 % avalanche bias (reduced-round) |

Shelf verdict labels:

- **neutralized ✓** — Axis B passes (`|Δ50| < 1 %`) on Single Ouroboros; Triple modes redundant once Single absorption is established.
- **Resistant at tested budget** — Axis C SAT KPA timed out across all tested encodings × backends within the budget. The weakest positive label this shelf emits — always qualified with the measured budget.
- **Dangerous** — the bare or rounds = 1 chain is SAT-broken in commodity time; the deployment-depth (rounds ≥ 2) behaviour is recorded separately in the [§3.4 table](#34-axis-c--sat-kpa-seed-recovery-resistance).
- **Fully broken** — Axis C produced functionally-equivalent K at rounds = 1 AND the rounds ≥ 2 chain is breakable in the same regime.

## 5. Reproduction

### 5.1. t1ha1_64le

```bash
# Axis A — avalanche on raw primitive
python3 scripts/redteam/phase2_theory_t1ha1/lab_bias_t1ha1.py \
    --n-keys 65536 --key-sizes 32,64,128 \
    --json-report tmp/attack/t1ha1stress/axis_a_lab_bias.json

# Axis A' — structural-input bias (json + html × 4 KB / 64 KB)
python3 scripts/redteam/phase2_theory_t1ha1/lab_struct_t1ha1.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/t1ha1stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/phase2_theory_t1ha1/lab_struct_t1ha1.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/t1ha1stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/phase2_theory_t1ha1/lab_struct_t1ha1.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/t1ha1stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/phase2_theory_t1ha1/lab_struct_t1ha1.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/t1ha1stress/axis_a_struct_html_n4096_65536.json

# Axis B — ITB-wrapped raw-mode bias
bash scripts/redteam/harness_bias_audit_t1ha1.sh

# Axis C — raw chain SAT KPA (rounds = 1 obs = 8, 24 h budget)
python3 scripts/redteam/phase2_theory_t1ha1/sat_calibration_raw_t1ha1.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver z3 \
    --json-report tmp/attack/t1ha1stress/axis_c_raw_z3.json
python3 scripts/redteam/phase2_theory_t1ha1/sat_calibration_raw_t1ha1.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver bitwuzla \
    --json-report tmp/attack/t1ha1stress/axis_c_raw_bw.json
```

### 5.2. SeaHash

```bash
# Axis A
python3 scripts/redteam/phase2_theory_seahash/lab_bias_seahash.py \
    --n-keys 65536 --key-sizes 32,64,128 \
    --json-report tmp/attack/seahashstress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/seahashstress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/seahashstress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/seahashstress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/seahashstress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/harness_bias_audit_seahash.sh

# Axis C — raw chain SAT KPA (4 encodings × 2 backends, 24 h budget)
for MUL in native explicit; do for VAR in native case-split; do for SOLVER in z3 bitwuzla; do
    python3 scripts/redteam/phase2_theory_seahash/sat_calibration_raw_seahash.py \
        --rounds 1 --obs 8 --timeout-sec 86400 --solver "$SOLVER" \
        --mul-encoding "$MUL" --var-shift-encoding "$VAR" \
        --json-report "tmp/attack/seahashstress/axis_c_raw_${SOLVER}_${MUL}_${VAR}.json"
done; done; done
```

### 5.3. mx3

```bash
# Axis A
python3 scripts/redteam/phase2_theory_mx3/lab_bias_mx3.py \
    --n-keys 65536 --key-sizes 32,256,1024 \
    --json-report tmp/attack/mx3stress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/phase2_theory_mx3/lab_struct_mx3.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/mx3stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/phase2_theory_mx3/lab_struct_mx3.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/mx3stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/phase2_theory_mx3/lab_struct_mx3.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/mx3stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/phase2_theory_mx3/lab_struct_mx3.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/mx3stress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/harness_bias_audit_mx3.sh

# Axis C — Z3 reaches Tier 3 in ~5 s on rounds = 1 obs = 8
python3 scripts/redteam/phase2_theory_mx3/sat_calibration_raw_mx3.py \
    --rounds 1 --obs 8 --timeout-sec 60 --solver z3 \
    --json-report tmp/attack/mx3stress/axis_c_raw_z3.json
# Axis C — Bitwuzla reaches Tier 3 in ~2 s on the same cell
python3 scripts/redteam/phase2_theory_mx3/sat_calibration_raw_mx3.py \
    --rounds 1 --obs 8 --timeout-sec 60 --solver bitwuzla \
    --json-report tmp/attack/mx3stress/axis_c_raw_bw.json
```

### 5.4. SipHash-1-3

```bash
# Axis A
python3 scripts/redteam/phase2_theory_siphash13/lab_bias_siphash13.py \
    --n-keys 65536 --key-sizes 32,256,1024 \
    --json-report tmp/attack/siphash13stress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/phase2_theory_siphash13/lab_struct_siphash13.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/siphash13stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/phase2_theory_siphash13/lab_struct_siphash13.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/siphash13stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/phase2_theory_siphash13/lab_struct_siphash13.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/siphash13stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/phase2_theory_siphash13/lab_struct_siphash13.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/siphash13stress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/harness_bias_audit_siphash13.sh

# Axis C — raw chain SAT KPA (rounds = 1 obs = 8, 24 h budget)
python3 scripts/redteam/phase2_theory_siphash13/sat_calibration_raw_siphash13.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver z3 \
    --json-report tmp/attack/siphash13stress/axis_c_raw_z3.json
python3 scripts/redteam/phase2_theory_siphash13/sat_calibration_raw_siphash13.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver bitwuzla \
    --json-report tmp/attack/siphash13stress/axis_c_raw_bw.json
```

### 5.5. Self-parity tests

Cross-check concrete vs Z3 symbolic for each primitive's chain-hash mirror:

```bash
python3 scripts/redteam/phase2_theory/chainhashes/_parity_test.py
python3 scripts/redteam/phase2_theory_t1ha1/t1ha1_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/phase2_theory_seahash/seahash_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/phase2_theory_mx3/mx3_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/phase2_theory_siphash13/siphash13_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
```

### 5.6. SAT-free pre-screen (§3.5)

Algebraic / avalanche battery and the low-byte XOR-differential battery over the full primitive set (the four shelf primitives plus murmur3 / xxhash64 / splitmix64):

```bash
# Algebraic + avalanche + degree + invertibility (rounds 1-3, deg@16)
python3 scripts/redteam/phase2_theory/chainhashes/avalanche_screen.py \
    --all --rounds-max 3 --samples 512 --degree-bits 16
# Higher degree-saturation point (rounds 1, deg@20)
python3 scripts/redteam/phase2_theory/chainhashes/avalanche_screen.py \
    --all --rounds-max 1 --samples 64 --degree-bits 20

# Low-byte XOR-differential uniformity (rounds 1-3)
python3 scripts/redteam/phase2_theory/chainhashes/differential_screen.py \
    --all --rounds-max 3 --samples 4096 --probe-bits 32
```

Pre-screen primitive parity (bit-for-bit vs the reference libraries / canonical vectors) and the splitmix64 `inv = Y` SAT confirmation:

```bash
# Reference-library parity (mmh3 / xxhash) and canonical-vector self-checks
python3 scripts/redteam/phase2_theory/chainhashes/murmur3.py
python3 scripts/redteam/phase2_theory/chainhashes/xxhash64.py
python3 scripts/redteam/phase2_theory/chainhashes/splitmix64.py

# splitmix64 chain concrete-vs-Z3 parity, then raw-chain SAT recovery
python3 scripts/redteam/phase2_theory_splitmix64/splitmix64_chain_lo_concrete.py \
    --rounds 1,2,4 --vectors 8
python3 scripts/redteam/phase2_theory_splitmix64/sat_calibration_raw_splitmix64.py \
    --rounds 1 --obs 8 --timeout-sec 300 --solver bitwuzla
```

### 5.7. Trapdoor-primitive control (BEA-1, §3.6)

The BEA-1 cipher and its trapdoor are a clean-room reimplementation transcribed from arXiv:1702.06475 (Bannier & Filiol) / IACR ePrint 2016/493; `bea1_validate.py` self-checks the transcription and `bea1_trapdoor.py` re-derives the partition from the published constants.

```bash
# Experiment 1 — pure BEA-1: reproduce the published partition trapdoor
# (full 120-bit key recovery from chosen plaintext/ciphertext pairs).
python3 scripts/redteam/phase2_theory_bea1/exp1_pure_bea1.py

# Experiment 2 — BEA-1 through ChainHash, rounds = 1, partial discard 80->64
# (the trapdoor still recovers the lo-lane seed).
python3 scripts/redteam/phase2_theory_bea1/exp2_chainhash_r1.py

# Experiment 3 — BEA-1 through ChainHash, rounds = 2,3,4 (feedforward):
# the same engine fails; the instrumentation shows the coset signal collapses.
python3 scripts/redteam/phase2_theory_bea1/exp3_chainhash_feedforward.py

# Experiment 3, structure-aware SMT solver (partition-quotient analogue).
python3 scripts/redteam/phase2_theory_bea1/exp3_structure_solver.py
```

### 5.8. Reduced-round-primitive control (2-round AES, §3.7)

`chainhashes/aes2r.py` is the 2-round-AES inner primitive (FIPS-197-validated, self-tested on import). The scripts below are in `scripts/redteam/phase2_theory_aes2r/`.

```bash
cd scripts/redteam/phase2_theory_aes2r

# Raw 2-round AES is integral-broken: unique master-key byte from one Λ-set.
python3 integral_aes2r.py

# Pre-screen the aes2r primitive — avalanche reads clean, differential flags it (§3.5 style).
python3 ../phase2_theory/chainhashes/avalanche_screen.py    --primitive aes2r --rounds-max 4
python3 ../phase2_theory/chainhashes/differential_screen.py --primitive aes2r --rounds-max 4

# Integral distinguisher survival through ChainHash (rounds 1/2/4 × discard on/off).
python3 distinguisher_chainhash.py      # 1st order
python3 higher_order_chainhash.py       # 2nd order
python3 order3_chainhash.py             # 3rd order at rounds = 4 (slow, ~1-2 h)

# Integral KEY-RECOVERY fails at rounds = 2 (feedforward); rounds = 1 control recovers.
python3 keyrecover_r2.py

# Data-differential dies at rounds = 2.
python3 differential_chainhash.py

# Generic seed recovery has no hook: z3 and CryptoMiniSat both time out at rounds = 1.
python3 sat_calibration_aes2r.py
python3 cms_xor_aes2r.py

# Word-level guess-and-determine model for the ChainHash composition (autoguess backend).
python3 gd_chainhash_aes2r.py     # emits relationfile_chainhash_r{1,2}_discard{0,1}.txt
# autoguess -i relationfile_chainhash_r1_discard0.txt -s sat -sats cadical195 -mg 12 -ms 20
```
