# HARNESS.md — Non-cryptographic Hash Primitive Analysis Shelf

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

*(public sibling of [REDTEAM.md](REDTEAM.md) / [ITB.md](ITB.md) / [SCIENCE.md](SCIENCE.md) / [PROOFS.md](PROOFS.md). Three-axis empirical study of non-cryptographic hash primitives wrapped into ITB `ChainHash128` — bias-absorption (Axes A, A', B) and SAT KPA seed-recovery resistance (Axis C). Scope restricted to primitives whose Go reference and Python mirror each fit in ≤ ~500 LOC.)*

*The prior harness record — the wider primitive shelf under Single Ouroboros with the overlay optional — is preserved verbatim in [archive/HARNESS.md](archive/HARNESS.md).*

## 1. Scope

The shelf measures four non-cryptographic hash primitives plugged into ITB `ChainHash128` to validate two architectural properties:

1. **Bias absorption** — whether ITB's encoding pipeline (rotation + noise barrier + COBS framing + DRBG fill from `internal/drbg` — AES-CTR or ChaCha20 seeded per call from CSPRNG) neutralises a primitive's documented SMHasher weaknesses on the attacker-observable ciphertext surface (Axes A, A', B).
2. **SAT-based seed-recovery resistance** — whether commodity-scale Bitwuzla / Z3 KPA can recover the per-primitive seed at minimum ITB deployment (`keyBits = 512`, ChainHash-4 lo-lane) within reasonable wall-clock (Axis C).

The shelf complements the archived [Phase 2a extension](archive/REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) (four cryptographic primitives in the Hash matrix) by extending bias-absorption coverage to non-cryptographic hashes, and complements [archive/REDTEAM.md Phase 2g](archive/REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) by characterising raw-chain SAT KPA cost on each primitive in isolation.

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

**Axis B — ITB-wrapped bias.** Raw-mode bias probe against `known_ascii` corpora encrypted with the primitive plugged into `ChainHash128` at `keyBits = 1024`, `BarrierFill = 1` (`DefaultBarrierFill`), N = 2 nonce-reuse. The probe operates on attacker-visible wire bytes: it treats the container body (behind the dual-nonce header and the always-on 48-bit Interlocked Barrier) as a flat 8-byte-per-pixel stream, brute-force-scans every candidate pixel-shift under a zero-seed `ChainHash(pixel_le || main_nonce)` oracle, and reports the per-shift conflict-rate distribution. Verdict `neutralized ✓` when `|Δ50|` — the deviation of that distribution's median from the 50 % mid-point — is below 1 %. The metric is coarse: the barrier's per-chunk mask permutation and the three-region distribution scramble any per-pixel bias into the wire before the probe sees it, so a passing measurement is the barrier's absorption doing its job through a channel the probe deliberately does not try to invert.

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

| Primitive | size | format | \|Δ50\| | shelf verdict |
|:----------|-----:|:-------|--------:|:--------------|
| **t1ha1_64le** | 512 KB | ascii | **0.891 %** ✓ | **neutralized ✓** |
| **t1ha1_64le** | 1 MB   | ascii | **0.890 %** ✓ | **neutralized ✓** |
| **SeaHash**    | 512 KB | ascii | **0.890 %** ✓ | **neutralized ✓** |
| **SeaHash**    | 1 MB   | ascii | **0.889 %** ✓ | **neutralized ✓** |
| **mx3**        | 512 KB | ascii | **0.890 %** ✓ | **neutralized ✓** |
| **mx3**        | 1 MB   | ascii | **0.890 %** ✓ | **neutralized ✓** |
| **SipHash-1-3** | 512 KB | ascii | **0.890 %** ✓ | **neutralized ✓** |
| **SipHash-1-3** | 1 MB   | ascii | **0.889 %** ✓ | **neutralized ✓** |

The raw-mode bias-audit probe measures the per-shift conflict-rate distribution on the attacker-observable ciphertext surface (the wire body behind the dual-nonce header and the always-on 48-bit Interlocked Barrier); the `|Δ50|` column is the deviation of that distribution's median from the 50 % mid-point. All measured primitives `neutralized ✓` at the 1 % threshold on both corpus sizes. The published SMHasher weaknesses (avalanche-scaling for t1ha1, PerlinNoise for SeaHash and mx3, reduced-round avalanche for SipHash-1-3) do not reach the attacker-observable ITB ciphertext surface. The absorption is a property of ITB's encoding pipeline (rotation + noise barrier + COBS framing + DRBG fill under the always-on 48-bit Interlocked Barrier), independent of the primitive that keys it — the eight cells converge to nearly identical `|Δ50|` values (0.889–0.891 %) across both corpus sizes and all four primitives, corroborating primitive-independent absorption at the metric's resolution.

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
| **aes2r** ([§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)) | AES S-box (GF(2⁸)-inverse + affine), no carry-up T-function | off — full-128 SAT times out too; not the deciding barrier | times out — no T-function hook | times out — no T-function hook | Resistant to SAT KPA — **broken by the integral, not SAT** ([§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)) |

`aesitb128` is measured separately in [§3.10](#310-aes-itb-128-standalone-breaks-and-cascade-dissolution): the Non-PRF inner-role primitive is characterised at both shipped inner-Barrier surfaces, and Axis C on the raw ChainHash is not the appropriate observable for that primitive.

The three groupings share one mechanism narrative:

**(A) Invertible round maps fall at rounds = 1; only a carry-up T-function carries the break into deployment.** splitmix64, mx3, and fnv1a are all `inv = Y` ([§3.5](#35-sat-free-algebraic--differential-pre-screen)) — a single round is a bijection the solver inverts directly (splitmix64 ≈ 20–25 s across Z3 / Bitwuzla; mx3 ≈ 2–5 s, hi-lane seed unconstrained, lo-lane seed functionally-equivalent to ground truth). At rounds ≥ 2 the feedforward masks the intermediate output; the seed then solves only through the whole composition, tractable only when the round map is a **carry-up T-function** (output bit t depends on input bits 0..t, plane-by-plane LSB → MSB). fnv1a's ×0x13B lo-lane has that structure and stays solvable at rounds = 4 in ≈ 146 s (Bitwuzla) / ≈ 0.16 s (structure-aware T-function solver). splitmix64 and mx3 lack it — mix64's right-shifts (`z ^ (z>>30 / >>27 / >>31)`) push high bits into low and destroy triangularity — so both resist at the 24 h budget at rounds = 2 despite equal invertibility. splitmix64 is the clean control (lo lane is literally splitmix64; hi lane is only a parallel second instance and the discard drops it), so its rounds ≥ 2 resistance is a property of splitmix64's own structure. fnv1a's SAT-tractability is therefore its carry-up triangular structure, not invertibility or round count. The ≈ 8 h figure cited for fnv1a elsewhere is the FULL Phase 2g ITB break (ChainHash + the ~90-bit per-pixel noise_pos barrier + 4 public-schema cribs), not this isolated chain inversion.

**(B) The hi-lane discard walls a lane-mixing primitive with no round structure required.** murmur3 (MurmurHash3_x64_128) is the only primitive here with a genuine 128-bit internal state whose halves cross-mix in finalisation: the full-128 seed recovers in ≈ 2.1 s, but ITB observes only the lo lane — a 128 → 64 projection of the already-mixed state — and that projection alone times out, walling murmur3 at rounds = 1 before the feedforward contributes. For the lane-parallel primitives (every other row) the discard is **off**: the lo lane is computed independently of the hi lane, so dropping the hi lane removes no constraint. Real ITB stacks both barriers plus the per-pixel noise_pos / rotation and the always-on 48-bit Interlocked Barrier permutation on top.

**(C) No invertibility hook makes seed-recovery SAT structurally inapplicable.** For t1ha1, SeaHash, and SipHash-1-3 the SAT budget is not the meaningful axis: no invertibility hook, so seed-recovery SAT times out at the 24 h budget (SeaHash across all 4 encodings — `{native, explicit}` × `{native, case-split}` — on both backends, 8 cells), not for want of compute. A larger budget does not change the verdict — a structural property, not a budget-bounded timeout. Their only surfaced weaknesses are differential (t1ha1 persistent, SeaHash round-dependent — [§3.5](#35-sat-free-algebraic--differential-pre-screen)); SipHash-1-3 is clean on every axis. "Resistant at tested budget" here reads as "no SAT invertibility hook"; the differential hook lives in a separate class the SAT axis structurally cannot reach, and [Axis B](#33-axis-b--itb-wrapped-raw-mode-bias) shows ITB's encoding neutralises it before it reaches a ciphertext. aes2r (2-round AES, [§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)) extends group (C) — its S-box is a GF(2⁸)-inverse + affine map, not a T-function, so SAT (z3 / CryptoMiniSat) times out even at rounds = 1 with the full-128 instance timing out too (lo-lane discard is not the deciding barrier). Unlike t1ha1 / SeaHash, aes2r's actual break is the **integral** (chosen-plaintext Λ-set), an attack class SAT structurally cannot reach and one ChainHash neutralises through the feedforward at deployment depth. "Resistant to SAT KPA" is a statement about the absence of a SAT hook, not about security.

### 3.5. SAT-free algebraic & differential pre-screen

Axis C is hours-long and the wrong instrument for triaging a candidate primitive. This pre-screen is the cheap triage. Two Monte-Carlo / exact-algebra batteries — [`avalanche_screen.py`](scripts/redteam/itb/theory/_common/chainhashes/avalanche_screen.py) and [`differential_screen.py`](scripts/redteam/itb/theory/_common/chainhashes/differential_screen.py) — measure the **ChainHash lo-lane as a function of the seed at a fixed data buffer** (the inner primitive, not the full ITB envelope; the envelope's Pixel Barrier is primitive-independent and lives in [archive/REDTEAM.md Phase 2g](archive/REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based)). The upstream question a solver depends on: **does the inner primitive hand a SAT/SMT solver a structural hook to grab?** No hook → under the PRF assumption no efficient recovery exists; hook → candidate for the expensive Axis C confirmation.

Coverage extends beyond the four shelf primitives to three additional non-cryptographic mixers spanning the failure modes: **murmur3** (MurmurHash3_x64_128) and **xxhash64** (XXH64) as one-way table mixers of different topologies (accumulator vs multiply-xorshift), and **splitmix64** as an explicitly **invertible** mixer. These three are pre-screen only — not wired into the Go harness and not taken through Axis A–C. Python mirrors parity-check bit-for-bit against `mmh3` / `xxhash` references and the canonical seed-0 vector sequence (splitmix64).

**Algebraic battery (`avalanche_screen.py`).** Representative values at round 1 (`samples = 512`, `probe_bits = 48`, `data_len = 5`); the columns are stable across rounds 1–3. `lin_score` = fraction of single-bit input directions with a constant (GF(2)-affine) output difference; `sac_mean` / `sac_max` = mean / worst Strict Avalanche Criterion bias; `avw/64` = mean output bits flipped per input flip (ideal ≈ 32); `deg@m` = exact GF(2) algebraic-degree lower bound over an m-bit input sub-cube; `inv` = structural cheap-inverse flag (Y = a triangular T-function or by-design invertible mixer; N = actively declared to carry no such shortcut; ? = no documented shortcut, the screen makes no claim). Rows are grouped by pre-screen verdict, not by the §4 shelf order.

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
| **aesitb128** ([§3.10](#310-aes-itb-128-standalone-breaks-and-cascade-dissolution)) | 0.000 | 0.018 | 0.086 | 32.0 | 16 | 20 | **Y** |

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
| **aesitb128** ([§3.10](#310-aes-itb-128-standalone-breaks-and-cascade-dissolution)) | 0.009 | 0.000 | at uniform baseline — yet one-pair invertible (`inv` Y) |

**aes2r and aesitb128 — the two reduced-round controls, placed together as sibling rows.** aes2r (2-round AES, [§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)) is **not saturated at round 1**: its seed → output avalanche fills in over the chain (`deg@16` 7 → 15, `avw/64` 19.7 → 29.5 by round 3), and the differential battery flags it (`ddt8_max` 1.000) — dominated by the final-round AddRoundKey rather than an exploitable data-differential, and dead through the feedforward by rounds = 2 ([§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)). AES-ITB-128 ([§3.10](#310-aes-itb-128-standalone-breaks-and-cascade-dissolution)) **saturates at round 1** on every Monte-Carlo column (three full AES rounds ahead of a single seed XOR is enough first-order diffusion) and reads ideal at the uniform band on the differential; the one column that sees its break is the structural flag `inv = Y`, because the seed is a pre-whitening XOR ahead of a public permutation and one (data, full 16-byte output) pair inverts to the seed under the full-state lab grant. **Neither battery sees the integral break** of either primitive (chosen-plaintext Λ-set — 2-round AES for aes2r; 3-round Square for AES-ITB-128 at the one-block lab shape). Both are the clearest cases on this shelf that the pre-screen is **necessary, not sufficient**: a primitive can read clean on the affine / degree hooks and still fall to an attack class these batteries do not measure. The head-to-head harness (`scripts/redteam/itb/theory/_common/stats_comparison_a2r_a128.py`) reads the same signatures directly on data avalanche at M = 10⁵: aes2r 16.06 ± 2.79 output bits per input flip (64 ± 5.66 ideal), 11 520 of 15 360 pairs dead — the 2-round truncated differential in Hamming form; AES-ITB-128 64.00 ± 5.66, SAC max 0.0077 (ceiling 0.0082), 0 dead pairs, at the urandom control's sampling floor.

**Half-cross diffusion (block shape; ideal 32 ± 4 per cell; aesitb128 / aes2r at M = 10⁵ over 3 trials, fnv1a at M = 10⁵ over 1 trial — digits identical at M = 10⁴ over 3 trials).** For each single-bit input flip, the mean Hamming weight of the output-half difference, split by input and output halves. fnv1a is the known-unmixed reference; `inv = Y` on the key path shows directly as a zero cell.

| Primitive | Flips | bit in lo → out lo / out hi | bit in hi → out lo / out hi | Reading |
|:----------|:------|-----------------------------:|-----------------------------:|:--------|
| **aesitb128** | data or key | 32.0 ± 4.0 / 32.0 ± 4.0 | 32.0 ± 4.0 / 32.0 ± 4.0 | fully mixed |
| **aes2r** | data | 8.0 ± 2.0 / 8.0 ± 2.0 | 8.0 ± 2.0 / 8.0 ± 2.0 | partially mixed (symmetric, ¼ of ideal — 4 active bytes, 2 per half) |
| **aes2r** | key | 19.4 – 19.5 ± 5.1 / 19.6 ± 6.1 | 19.6 ± 4.6 / 19.2 – 19.3 ± 4.6 | partially mixed (symmetric, ≈ 61 % of ideal) |
| **fnv1a** | data | 18.7 ± 8.7 / 12.8 ± 6.8 | 30.8 ± 4.0 / 30.1 ± 5.0 | partially mixed |
| **fnv1a** | key | 18.3 ± 9.9 / 31.2 ± 3.5 | **0.0 ± 0.0** / 18.7 ± 10.3 | half-independent (T-function fingerprint — a hi-half key bit never reaches the lo output half) |

aesitb128 reads 32 / 32 ideal in every cell (data and key), and 32.0 / 32.0 in every cell at shapes 13 / 20 / 36 / 68 (M = 10⁴; shape 20 also at M = 10⁵). aes2r reads a symmetric 8 / 8 on data at the block shape (4 active output bytes across one round of ShiftRows, 2 landing in each half) and ≤ 16 / 16 on data at every wrapper shape (20 / 36 / 68 at M = 10⁴); on key it reads a symmetric ≈ 19.5. Neither AES primitive is half-independent — ShiftRows crosses the column-pair boundary in one round. The fnv1a key-flip zero is the didactic case: the 128-bit state is initialised from the key and the multiply by 2⁸⁸ + 0x13B (mod 2¹²⁸) is a carry-up T-function, so a hi-half state bit's influence never propagates down to the lo output half. A data-bit flip enters the low byte regardless of position and does not exhibit the T-function zero.

**What the pre-screen concludes — which primitives a solver could ride.** The screen surfaces four independent solver hooks; a primitive flagged on any one is a candidate for SAT recovery, a primitive clean on all four with `inv = ?` requires the Axis C calibration to settle:

1. **GF(2)-affine directions** (`lin_score` or `const8` > 0). SeaHash carries a small affine fraction on both the full-width and low-byte tests. fnv1a shows the same full-width fraction (`lin_score` 0.021) on top of its dominant carry-up T-function signature (`const8` 0.938).
2. **Biased differential** (`ddt8_max` above the uniform band). t1ha1 (persistent) and SeaHash (round-3 deterministic) expose differential characteristics — a **differential attack** hook, a class distinct from seed recovery. SAT calibration times out at 24 h on both precisely because the weakness is differential, not invertibility, so "Resistant at tested budget" reads as "no SAT invertibility hook". [Axis B](#33-axis-b--itb-wrapped-raw-mode-bias) shows ITB's encoding neutralises the differential bias before it reaches a ciphertext (`|Δ50| < 1 %`), so no attack is pursued from this hook.
3. **Low algebraic degree** (`deg@m < m`). None of the mixers are low-degree — all saturate to the sub-cube dimension (deg@16 = 16, deg@20 = 20) at round 1. fnv1a lags by a single degree (15 / 19), consistent with its simpler carry structure.
4. **Cheap structural inverse** (`inv = Y`) — a rounds-1 signal only, and the one hook Monte-Carlo columns are blind to. splitmix64 is visually identical to murmur3 / xxhash64 on every column, yet at rounds = 1 it inverts in seconds because its mix64 is a composition of word-level bijections. Invertibility alone is NOT the SAT hook at deployment: under the rounds ≥ 2 feedforward the solver can no longer peel round-by-round, and tractability then needs a triangular carry-up T-function — fnv1a has it and stays solvable; the right-shift mixers (splitmix64, mx3) lack it and resist. High degree and perfect avalanche likewise do not imply SAT-hardness. Mechanism, unified table, empirical splitmix64-vs-fnv1a confirmation: [§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance).

SipHash-1-3, murmur3, and xxhash64 are clean on all four axes with `inv = ?` — the screen surfaces no hook and defers to the SAT calibration (SipHash-1-3 timed out; murmur3 additionally walled at rounds = 1 by its internal 128 → 64 discard). mx3 carries `inv = Y`, and the flag predicts its rounds = 1 break ([§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance) `Dangerous` label). The pre-screen is **necessary, not sufficient**: a clean algebraic / differential row with `inv = ?` remains a "worth a SAT calibration" signal, never a security verdict. The two screens are complementary — SAT catches the invertibility / T-function class (fnv1a; mx3, splitmix64 at rounds = 1) and times out on the differential-only class (t1ha1, SeaHash); the differential battery catches that second class.

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
| rounds = 1 | one AES2R call (= raw 2-round AES), no feedforward | **Standalone key recovery.** One Λ-set recovers a master-key byte uniquely (≈ 2¹⁶). Fifteen such Λ-sets (plaintext bytes 0–14) plus a 2⁸ brute force of the pad-position byte recover the full 128-bit master key at ≈ 2²⁰ work (3 / 3, `fullkey_aes2r.py`; every Λ-set keeps at least one active output byte inside the lo lane, so the lo-lane discard removes no constraint the recovery uses). Rounds = 1 offers no protection — consistent with §3.4 / §3.6 (structured primitives fall at rounds = 1). **Under the shipped observable** (lo lane, active Λ-set bytes confined to LE32(idx) bytes 0..3, random nonce per set), the same engine at a higher round count (NR = 4 aes2r as an internal round-count control) leaves the 8 visible last-round-key bytes uniquely resolved (8 / 8, 3 trials, `square5_go --model realistic`) while the remaining 8 master-key bytes stay behind the hidden hi lane (2⁶⁴ enumeration, not a recovery): a **partial**, not a break. |
| rounds = 2 | feedforward `k = seed[r] ⊕ h_{r-1}` active | **Distinguisher survives; key recovery fails.** Under the shipped observable (lo lane, order-4 idx cube {0,1,2,3}, 2³² texts × 2 seeds), NR = 2 leaves the lo lane balanced 8 / 8 (`order5_aes2r_go --active 0,1,2,3`) — the raw-primitive r = 2 signal survives at order 4 on the shipped observable, a stronger PRF distinguisher than the earlier order-1 / order-2 lo-lane figures (2, 6). But the feedforward makes the round-1 key `K₁ = seed₁ ⊕ ct₀` **data-dependent** (distinct across the Λ-set), so the integral's last-round peel has no fixed key to guess and **recovery fails** (0 / 5, `keyrecover_r2.py`, both discard modes). The data-differential is already dead at this depth (per-byte differential probability at the max-of-buckets noise floor). |
| rounds = 3 | feedforward accumulated over three calls | **Neutralised on the shipped observable.** Under the same lo lane / idx-only order-4 idx cube {0,1,2,3}, NR = 2 returns 0 balanced lo-lane bytes across 2³² texts × 2 seeds. No distinguisher, no recovery. |
| rounds = 4 (deployment) | ChainHash-4 | **The integral is neutralised entirely.** Under the same shipped observable at NR = 2, the order-4 idx cube returns 0 balanced lo-lane bytes across 2³² texts × 2 seeds; the 1st-, 2nd-, and 3rd-order diagonal Λ-sets (chosen-data lab grants, discard on and off) also return **0 balanced output bytes** — at the random floor. No distinguisher, no recovery. |

**Mechanism — the feedforward dissolves the fixed-key balance the integral requires.** The same intermediate-masking that walls invertible primitives in §3.4 and the partition trapdoor in §3.6: at rounds ≥ 2 the round key is data-dependent, so the integral's "fixed key, structured plaintext" premise breaks. The contrast with FNV-1a is decisive — the integral is **not** compatible with the feedforward (distinguisher at rounds = 2, vanishes by rounds = 4), whereas FNV-1a's carry-up T-function **is** compatible and survives into deployment ([§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance)). Which reduced-round / below-spec primitive ChainHash neutralises depends on whether its structured attack survives the data-dependent key, not on the primitive's pedigree. The hi-lane discard is a **secondary** barrier (the standalone break survives it — full 128-bit master key on the lo lane alone); feedforward **depth** closes the channel — lo-lane cube at the floor at rounds = 3, diagonal set at 0 at rounds = 4.

**Conclusion.** At rounds = 1 the standalone key-recovery pierces the lo-lane truncation entirely; on the shipped observable at a higher round count only a resolved-visible-half partial survives (8 master-key bytes behind 2⁶⁴). At rounds = 2 a stronger PRF distinguisher persists on the shipped observable (lo 8 / 8 at order 4) but key recovery fails. At rounds ≥ 3 the shipped observable is at the floor for orders 1–4; at rounds ≥ 4 the integral (orders 1–3) and the data-differential are neutralised on the diagonal set as well. Conservatively framed: these specific engines at these sample sizes and depths are neutralised, not a proof that no exploitation path exists for so weak a primitive.

**Mechanism generalisation.** The feedforward-depth mechanism — data-dependent effective round key at r ≥ 2 defeating the fixed-round-key premise — generalises to any chosen-input structured attack requiring a fixed round key across the input structure. Three measured instances: BEA-1's partition coset ([§3.6](#36-trapdoor-primitive-control--bea-1-partition-backdoor-through-chainhash)), aes2r's Λ-set integral (this section), and shipped AES-ITB-128's Square integral on the shipped observable ([§3.10](#310-aes-itb-128-standalone-breaks-and-cascade-dissolution) — the data-dependent term lands in the pre-whitening XOR rather than a key schedule; idx-only counter-byte cubes at the shipped shapes at the floor from r = 2 through r = 16). The same mechanism is predicted to absorb related-tweak differential trapdoors and any other attack sharing the fixed-round-key premise; no additional empirical confirmation this cycle. Prediction scoped to the fixed-key premise itself — primitives independently weakened by other structural properties (algebraic attacks on the linear layer, key-schedule breaks, etc.) are outside the argument's coverage.

### 3.8. Chosen-constants primitive control — Malicious-SHA-1 collision through ChainHash

[§3.6](#36-trapdoor-primitive-control--bea-1-partition-backdoor-through-chainhash) plugs in a **partition** trapdoor and shows ChainHash's feedforward-depth mechanism dissolves it. [§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash) plugs in a **round-reduced** primitive whose textbook integral break is neutralised by the same feedforward mechanism. This control plugs in a primitive whose **round constants have been maliciously chosen to produce collisions** — Malicious-SHA-1 (Albertini, Aumasson, Eichlseder, Mendel, Schläffer, SAC 2014; IACR ePrint 2014/694) — and asks which layer of ChainHash's wrap prevents the trapdoor from projecting through. Under the K constants `SHA1_K_MALICIOUS_EVE = (5A827999, 88E8EA68, 578059DE, 54324A39)` the paper's proof-of-concept shell-script pair (`eve1.sh` / `eve2.sh`, 243 bytes each; the byte-level differential is entirely inside the first 512-bit SHA-1 block, with six of the 28 differing positions falling in the [0, 15] region the wrap's seed-XOR touches) share the digest `96ED59BE 04518A27 C30F17DE 6F0037F9 B3C3257E`.

Methodology is the pre-wire ChainHash layer only — no wire, no interlock, no `Encrypt3x128Cfg`. The observable is direct digest equality / Hamming distance between the two ciphertexts. The wrap is a Python mirror of the two production references (`hashes/blake3.go` `BLAKE3WithKey` for input-XOR keying, `seed128.go` `ChainHash128` for feedforward); the colliding pair is fed as caller data at every wrap variant. Trial count for the random-seed / depth sweeps: N = 64 per cell.

| Stage | Construction | Collision outcome |
|:------|:-------------|:------------------|
| Raw primitive | one call to Malicious-SHA-1 with standard SHA-1 IV | **Collision holds** — `sha1_core(eve1) == sha1_core(eve2)` matches the paper's expected digest. Sanity: under standard SHA-1 K the same pair does NOT collide (Hamming 83 / 160), so the trapdoor is specific to the malicious K, not to the input pair. |
| Invariant test (seed = 0) | `wrap_r1(seed = 0, m)` reduces to `sha1_core(m)` by construction (XOR by zero is identity) | **Collision holds; wrap reduces to raw exactly.** Confirms the wrap does no work beyond input-XOR keying — any absorbance under non-zero seed is attributable to the seed-XOR itself, not to a hidden framing / padding side-effect. |
| `wrap_r1`, random seed | 16-byte random seed XORed into the first 16 bytes of the caller's data, primitive called on the mixed buffer | **Collision snaps — Hamming distance jumps to ≈ 80 / 160 (n / 2, full-random divergence).** Across N = 64 random-seed trials: 0 / 64 collisions survive; Hamming mean 80.5 (min 68, max 98). The seed-XOR moves both `m1` and `m2` out of the input space the collision was engineered for. |
| `wrap_r` at r ∈ {2, 4, 8} | feedforward `k = seed[r] ⊕ h_{r-1}` layered on top of input-XOR keying | **Plateau at Hamming ≈ 80 / 160 for every r ≥ 1** (mean 80.1–80.9 across the sweep). Feedforward-depth rounds add no incremental absorbance for this trapdoor class. Distinct from BEA-1's coset-collapse curve where the same feedforward IS the carrying mechanism — collision-brittleness trapdoors snap at r = 1, partition trapdoors degrade with r. |

**Attribution — narrow scope.** ChainHash never exposes raw colliding input to the primitive: input-XOR keying moves it out of the engineered collision space. Two properties in combination — (a) ChainHash does not feed the primitive raw caller data, (b) engineered collisions are brittle to any deterministic input modification. Not a collision-specific defense — the same absorbance would hold for any wrapping that non-trivially modifies the input. The interest here is coverage: partition ([§3.6](#36-trapdoor-primitive-control--bea-1-partition-backdoor-through-chainhash)) is absorbed by feedforward depth; chosen-constants collision is absorbed by input-XOR keying. Two ChainHash mechanisms absorb two different trapdoor classes.

**Conclusion.** The Malicious-SHA-1 collision trapdoor does not project through ChainHash's input-XOR keying: at r = 1 the collision snaps to full-random Hamming distance, and feedforward depth (r ≥ 2) is redundant for this class. The result is conservatively framed: it is the paper's specific chosen-constants collision pair that fails to project, not a proof that no adaptive-attacker collision could be engineered against the wrapped construction. Attribution: ChainHash's input-XOR keying, not its feedforward depth.

### 3.9. Construction-level structural harness — barrier core, primitive-agnostic

§3.1–§3.7 measure the inner primitive through `ChainHash128`. A separate
primitive-agnostic harness measures the **48-bit Interlocked Barrier core**
directly — the mask-space cardinality and lane-independence the KPA closure
argument rests on — and the wire the Triple facade produces. Go tests
(`harness_test.go` for the barrier kernels; `triple/harness_wire_test.go` for
the facade wire) with full-sample statistical loops gated behind
`ITB_HARNESS_FULL=1`; characterised in
[REDTEAM.md Phase 4](REDTEAM.md#phase-4--construction-level-creative-probes-triple--interlocked-barrier).

The barrier-core measurements are independent of the lockSeed-keying primitive
and belong at the construction layer rather than per shelf primitive:

- **Mask-space uniformity + balance.** The per-chunk mask-triple derivation
  produces balanced 16-of-48 lane partitions on 100 % of draws (union covers
  all 48 bits, lanes pairwise disjoint); each bit lands in lane 0 at 16/48 ±
  the sampling floor (max 2.45 sigma at N = 200 000), and the reduced indices
  are uniform (chi-square 256.5 / 238.7 over 256 bins, band [142, 368]).
- **gcd anti-collapse trap.** The shipped two-step reduction spreads the reduced
  indices across the full residue grid: the fraction on the diagonal
  `idx0 ≡ idx1 (mod 66861)` is 1.00 × 10⁻⁵, matching the full-space expectation
  `1/66861 ≈ 1.50 × 10⁻⁵`, where the rejected same-rank double-mod would confine
  every draw to that diagonal (fraction 1.0).
- **Lane independence.** Cross-lane Pearson correlation at the barrier kernel
  sits at the sampling floor (max |r| 0.00238 vs floor 0.00224 at N = 200 000).

One wire-level finding from that harness bears on this shelf's Axis B reading:
Triple + Interlocked Barrier without the outer cipher wrapper leaves a marginal
byte-histogram signature (relative ≈ +5 % on the W‖H dimension-header byte
values, absolute ≈ 0.02 pp on the `0x00` rate; entropy stays ≈ 8 bits/byte and
the wire is incompressible). Axis B's `|Δ50|` metric measures a per-shift
distribution, not the raw histogram, and is insensitive to this signature — the
`neutralized ✓` verdicts stand. Wire-level format-deniability is the outer
cipher wrapper's property; the full characterisation is
[REDTEAM.md Phase 4](REDTEAM.md#phase-4--construction-level-creative-probes-triple--interlocked-barrier).

### 3.10. AES-ITB-128 standalone breaks and cascade dissolution

[§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash) plugs in a **lab** reduced-round primitive (AES cut to 2 rounds, the seed as the AES key) and shows ChainHash's feedforward neutralises its textbook integral. This control repeats the treatment on the reduced-round primitive that **ships** in the registry — **AES-ITB-128** (`aesitb128`, `aesitb.go`; the `ClassNone` inner-PRF-only entry) — and asks the same question at every cascade depth up to the 2048-bit deployment. One AES-ITB-128 call is a nonce-free sponge: `state = fixedKey ⊕ (LE64(seed0) ‖ LE64(seed1))`, then `state = AESRound(state ⊕ block_i, RC[i mod 8])` over the PKCS#7-padded input, then two finalising rounds under `RC[0]`, `RC[1]` — every round a full AESENC (MixColumns included), the constants the NUMS table. The seed enters **once, by XOR, ahead of a fixed public permutation** — there is no key schedule. For a one-block lab input (≤ 15 bytes) the call is exactly three full rounds, a public permutation **P** applied to `fixedKey ⊕ seed ⊕ pad(data)`; the shipped per-pixel inputs (`LE32(idx) ‖ nonce`, 20 / 36 / 68 bytes) absorb 2 / 3 / 5 blocks and run 4 / 5 / 7 rounds.

**Two observable surfaces.** `aesitb128` operates at two disjoint inner-Barrier sites; the shipped wire exposes a different observable at each and the defence composition differs in kind:

- **(A) Pixel Barrier** — per-pixel buffer shapes 20 / 36 / 68 B. Shipped observable = `lo(h_r)` alone (the byte conveyor discards the upper 8 bytes; the `lo`-lane restriction is itself half of the two-stage defence, `[hashes/CONSTRUCTIONS.md](hashes/CONSTRUCTIONS.md#aes-itb-128-registry-aesitb128)`). This section and [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) measure recovery / distinguisher screens against this surface across cascade depths r ∈ {1, 2, 3, 4, 5, 6, 7, 8, 12, 16}; r = 4 / 8 / 16 are the shipped cascade depths at 512 / 1024 / 2048-bit keys. Lab-grant reference rows are kept alongside the shipped-observable rows because they isolate which grant is load-bearing at which depth.
- **(B) Interlocked Barrier fill** — 13-byte fill input `[0x03 ‖ LE64(groupIdx) ‖ 0⁴]`. Shipped observable = a 16-of-48 mask triple produced by consuming the full `(lo, hi)` output monolithically through the divmod-then-combinadic-unrank chain (`interlock48_cascade.go` `buildLockBatchPRF48_128`; both lanes participate, no lane truncation exists at this site). The lane-discard semantic present at surface (A) is inapplicable here. [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain) documents the fill consumption chain and its absorption bound; the lo-lane-only figures at the 13-byte shape appearing in this section and in [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) are lab probes against a hypothetical exposure the wire does not admit, retained because they name raw-primitive properties.

Three standalone-primitive properties follow from the one-block shape, and none is aes2r's — but each carries a strict attacker-observability caveat spelled out inline:

- **Square integral, probability 1** (distinguisher, not a recovery). A Λ-set (one active data byte) through three full AES rounds leaves every output byte balanced for any key — the key only translates the set. On surface (A) this reduces to `lo(h_r)`, 8 / 8 balanced at r = 1 on the one-block lab shape.
- **One-pair inversion** — requires the full 16-byte `h_r`. P is public and invertible; with the full 128-bit output visible, `seed = P⁻¹(output) ⊕ pad(data) ⊕ fixedKey` from one known (data, output) pair. **Neither shipped surface exposes the full 16-byte output** — surface (A) consumes `lo(h_r)` only, surface (B) consumes both lanes into a mask triple not itself on the wire. The full-state route is a strictly-stronger-than-shipped lab grant kept as a comparative reference below.
- **Structured lo-lane recovery, ≈ 2²⁰** — requires the raw-primitive one-block shape and 15 chosen Λ-sets over plaintext bytes 0..14. The last round peels on the two lo-lane columns (RC[1] public, InvMixColumns per-column, InvSubBytes); over a Λ-set active in one input byte each cell is `m·S(a·S(k_b ⊕ v) ⊕ c) ⊕ e`, and a per-byte 2¹⁶ constancy search over `(k_b, c)` recovers `K = fixedKey ⊕ seed` from the lo lane alone (3840 chosen texts, `keyrecover_r1_2p20.py`; 5 / 5 at the one-block lab shape). Two caveats: (i) this survives only at r = 1 — from r = 2 the feedforward removes the Λ-set ([§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth)); (ii) surface (A) shapes 20 / 36 / 68 confine active bytes to LE32(idx) bytes 0..3, and the engine is out of regime at those shapes (0 / 0 at every position at r = 1 and r = 4, `keyrecover_r1_2p20.py --shape-probe`, 3 trials each). The ≈ 2²⁰ recovery is a raw-primitive fact about the one-block shape, not a wire attack on either shipped surface.

Methodology is the §3.7 lab style — synthetic `(data, ChainHash)` pairs under a fixed secret seed, primitive mirrored bit-exact in `chainhashes/aesitb128.py` (self-checked on import against the 16 `aesitb/aesitb_test.go` vectors; `fixedKey` pinned to the reference key and treated as attacker-known — at r = 1 the inversion recovers the effective key block `fixedKey ⊕ seed` whether or not the fixed key is secret). Two strictly-stronger-than-shipped lab grants sit alongside the surface (A) rows: **full-state lab grant, raw** (the whole 16-byte `h_r`) and **full-state lab grant, P⁻¹-peeled** (attacker's free P⁻¹ through the last call, exposing `seed_r ⊕ h_{r−1}` — at r = 1 the seed block itself). A distinct **lo-lane column peel** is an accumulator-side distinguisher step (`w = InvMixColumns(lo ⊕ RC[1][0:8])` on lo-lane state columns 0 / 1) — surface-(A) observable, no key candidate on its own. The P⁻¹ peel needs the full 16-byte state and never reaches either wire; the column peel operates on the 8-byte `lo(h_r)`.

**Standalone (r = 1, no feedforward).**

| Screen | Sample | Lo lane — shipped observable | Full state — lab grant (not on the wire) |
|:-------|:-------|:-----------------------------|:-----------------------------------------|
| Λ-set integral, orders 1 / 2 / 3, one-block shape (3 rounds; input all-chosen at that shape) | 2⁸ / 2¹⁶ / 2²⁴ texts per set; 8 seeds (1 at order 3) | **8 / 8 bytes balanced** at every order | **16 / 16 balanced** at every order (lab reference) |
| Λ-set integral, orders 1 / 2 / 3, shipped shapes 20 / 36 / 68 B (4 / 5 / 7 rounds), realistic (idx-only Λ-sets, random nonce per set) | same | 0.0–0.1 balanced (random floor 0.03) | 0.0–0.2 balanced (floor 0.06) — lab reference |
| Λ-set integral, order 4 diagonal set (classic 4-round Square, active bytes 0 / 5 / 10 / 15), shipped 20 B, chosen-nonce lab grant | 2³² texts, 1 set (1087 s on 16 cores) | **8 / 8 balanced** (chosen nonce required) | **16 / 16 balanced** (chosen nonce required) — lab reference |
| Λ-set integral, order 4 idx cube {0,1,2,3} (realistic — attacker holds only the four counter bytes), shipped 20 B (r = 1 raw primitive) | 2³² texts, 1 set × 1 seed (2-seed check applies at r = 2 in the "Through ChainHash" table) | 0 / 8 (column set — 3-round property only; negative control) | 0 / 16 (same — lab reference) |
| One-pair inversion | 5 trials; 1 query + 4 verification queries | **not on the wire** — surface (A) consumes `lo(h_r)` only; the ≈ 2²⁰ row below is the hypothetical partial lo-lane inverse | **5 / 5 full 128-bit seed blocks recovered** (lab grant only) |
| Structured lo-lane recovery ≈ 2²⁰ (one-block shape, 15 chosen Λ-sets over plaintext bytes 0..14) | 3840 chosen texts, 5 trials | **5 / 5** K = fixedKey ⊕ seed recovered (raw-primitive fact about the one-block shape; the engine is out of regime at surface (A) shapes 20 / 36 / 68 — 0 / 0 at every position at r = 1 and r = 4, `keyrecover_r1_2p20.py --shape-probe`, 3 trials each) | not applicable (lo-lane engine) |
| Data-differential, single active byte | N = 8192 bases × 3 Δ | `max_dp` 0.0070, **0** zero-diff bytes (uniform band ≤ 0.0083) | `max_dp` 0.0070, 0 zero-diff bytes (lab reference) |
| Output uniformity, random inputs | N = 10⁵ × 4 seeds and N = 10⁶ × 3 trials × 10 head-to-head cells | χ² max ≤ 313.6 (Bonferroni ceiling 330.5 at N = 10⁶, 332 at N = 10⁵), bit bias max ≤ 0.0049, birthday \|z\| max ≤ 2.36 (ceiling 3.14), Shannon ≥ 7.9998, byte entropy ≥ 7.998 | χ² max ≤ 326.9 (ceiling 334.7 / 336), bit bias max ≤ 0.0049, birthday \|z\| max ≤ 3.17 (ceiling 3.34) (lab reference) |
| Output uniformity, shipped counter pattern | N = 10⁶ × 3 trials, shapes block / 13 / 20 / 36 / 68 (worst over 15 cells) | χ² max ≤ 327.1 (ceiling 330.5), bit bias max ≤ 0.00153 (ceiling 0.00202), min-entropy ≥ 7.902, birthday \|z\| max ≤ 2.67 (ceiling 3.14) — floor on every shape (shape 13 is the fill-input pattern; see [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)) | χ² max ≤ 327.1 (ceiling 334.7), bit bias max ≤ 0.00161 (ceiling 0.00210), min-entropy ≥ 7.902, birthday \|z\| max ≤ 2.67 (ceiling 3.34) — same floor on the full state (lab reference) |

Two readings. The integral is probability-1 at orders 1–3 on the one-block shape and at the random floor at the shipped shapes (the extra absorbed block(s) add the fourth-plus round a 1st–3rd-order Λ-set does not cross). The order-4 diagonal set restores balance at the 20-byte shape on both lanes but requires a **chosen-nonce** grant the wire does not admit; the realistic counter-byte cube {0,1,2,3} is a state column with only the 3-round property and is at the floor across every shipped shape and every r ∈ {2, 3, 4, 8, 16} (one r = 3 shape-68 Poisson event at p ≈ 8 / 256 the sole exception). The primitive also reads **uniform on every marginal statistic** — §3.5 avalanche battery saturated at round 1, data-differential at uniform band standalone (every round carries MixColumns — contrast aes2r's final-round-without-MixColumns signature), byte / bit marginals at floor — while being one-pair invertible under the full-state lab grant. The pre-screen's only column that sees the standalone break is `inv = Y`, and that flag alone does not translate to a wire attack: every r = 1 standalone recovery requires either the full-state lab grant or the raw-primitive one-block shape, neither of which the shipped per-pixel pipeline exposes.

**Through ChainHash — the shipped observable (lo lane, idx-only Λ-sets, random nonce per set).**

| Stage | Construction | Outcome on the shipped observable |
|:------|:-------------|:----------------------------------|
| rounds = 1 | one AES-ITB-128 call (= raw primitive), no feedforward | **Integral distinguisher on the lo lane; no key recovery on the shipped shapes.** Order 1 balances the lo lane 8 / 8 at the one-block lab shape (raw 3-round AES property); at surface (A) 20 B the order-1 lo-lane column peel `w = InvMixColumns(lo ⊕ RC[1][0:8])` is balanced 8 / 8 as a **distinguisher only** (raw lo lane 0 / 8 at the same cell). Counter-byte cubes at surface (A) are otherwise at the floor for orders 1–3; the classic order-4 diagonal set requires a chosen-nonce grant the wire does not admit. The ≈ 2²⁰ structured lo-lane recovery is a raw-primitive fact about the one-block shape and is out of regime at surface (A) shapes 20 / 36 / 68 as measured. One-pair inversion needs the full state and is not on the wire. |
| rounds = 2 | feedforward `k = seed[r] ⊕ h_{r−1}` active | **At the floor on every shipped-observable cell.** Realistic order-4 idx cube {0,1,2,3} at shape 20: 0 / 8 raw, 0 / 8 column-peeled (2 seeds × 1 set, ≈ 30 s / set at 15 threads); at shape 68: 0 / 8 raw and column-peeled (32.5 s / set, 1 seed × 1 set). Realistic orders 1 / 2 / 3 at shape 20: raw ≤ 0.22 / column-peeled ≤ 0.07 on 15 sets, at the floor. Recovery: **no candidate (structural: κ peel needs the hi lane; 2⁶⁴ residual)**. |
| rounds = 3 | ChainHash-3 | **Integral neutralised on the shipped observable.** Realistic order-4 idx cube at shapes 20 / 36: 0 / 8 raw and column-peeled (1 seed × 1 set each; ≈ 190 s at shape 20); shape 68: 1 / 8 raw (single Poisson event p ≈ 8 / 256), 0 / 8 column-peeled. Realistic order 1 at all three shapes: ≤ 0.05 / 8 balanced (floor 0.03). No recovery (structural). |
| rounds = 4 (512-bit) … 16 (2048-bit) | ChainHash-4 … ChainHash-16 | **At the floor throughout.** Realistic order-4 idx cube at shapes 20 / 36 / 68 at r ∈ {4, 8, 16}: 0 / 8 raw and 0 / 8 column-peeled at every depth (1 seed × 1 set; 29 s – 1625 s per set at 15 threads across the matrix). Order 1 at the same shapes: 0.03–0.07 / 8 raw at the floor. Data-differential `max_dp` 0.0063–0.0076, 0 zero-diff bytes; output uniformity χ² max 294–329 (ceilings 332 / 336), bit bias max ≤ 0.0053 (ceilings 0.0065 / 0.0068) at every r. No recovery at any r on the shipped observable (structural). |

**Attribution — lab-grant reference (isolates which grant is load-bearing at which shape).** Three shape-specific cells recover both seed blocks under strictly-stronger-than-shipped grants. Grant attribution across observable (surface (A) `lo(h_r)` vs full-state lab grant) and nonce (idx-only vs chosen); the 13-byte row is a lab probe against a hypothetical surface (B) exposure the wire does not admit ([§3.10.3](#3103-interlocked-barrier-fill-consumption-chain) documents the shipped surface (B) defence).

| Cell | Surface (A), lo lane, idx-only | Surface (A), lo lane, chosen data | Full-state lab grant, idx-only | Full-state lab grant, chosen | Load-bearing grant(s) |
|:-----|:-------------------------------|:----------------------------------|:-------------------------------|:-----------------------------|:----------------------|
| Fill shape 13 B (T = 3 primitive), r = 2, order 1 (256 chosen texts) — lab probe on hypothetical lo-lane exposure (fill site consumes both lanes monolithically — see [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)) | floor at r ∈ {2, 3, 4} (raw 0.00–0.07 / column-peeled 0.03–0.05; 5 trials × 8 sets) | floor 0.03 / 0.00 (byte 0) | **recovers 5 / 5** (counter byte 1) | **recovers 5 / 5** (byte 0) | Full-state lab grant carries the hypothetical recovery; the wire emits no lane individually at this site. |
| Shipped 20 B (T = 4), r = 2, 3 Λ-sets — classical 4-round κ-byte engine, `keyrecover_r2_20byte.py` | floor 0 / 5 (5 trials × 8 sets, `keyrecover_kbyte_go --model realistic`) | floor (κ peel needs the hi lane) | **recovers 5 / 5** (768 chosen texts, ≈ 2¹³·⁶ κ guess-sums) | recovers | Full-state lab grant is the sole load-bearing grant (idx-only sets suffice under it; fails on lo lane under either nonce model). |
| Shipped 36 B (T = 5), r = 2, order-4 diagonal set (2³² texts) | floor 0 / 8 raw and column-peeled | floor 0 / 8 raw and column-peeled (missing κ peel) | fails (idx-only column {0,1,2,3} carries only the 3-round property) | **recovers 1 / 1** (22 s at 15 threads; three-hedge cell: full-state grant, chosen nonce, below shipped depth r = 4) | Both grants individually load-bearing — either grant alone leaves the cell at the floor. |

The 20 B r = 2 cell rests on the full-state lab grant alone; surface (A) sits at the floor regardless of nonce model. The 36 B r = 2 cell needs both grants and still sits below the shallowest shipped cascade (r = 4). No shipped-observable cell recovers a seed block at any r ≥ 2.

**Mechanism and comparison with aes2r.** Two structural differences account for every contrast measured: (i) where the seed enters — AES-ITB-128 XORs it as pre-whitening ahead of a fixed public permutation; aes2r derives round keys through the AES key schedule — and (ii) whether the last round carries MixColumns — AES-ITB-128 yes on every round; aes2r no on the last (standard 2-round-AES shape). The feedforward lands in the data slot for AES-ITB-128 (`pad(data) ⊕ seed_r ⊕ h_{r−1}(data)` at r ≥ 2 is no longer a Λ-set; integral at the floor from r = 2) and in the key slot for aes2r (Λ-set plaintext still enters the S-box layer intact; integral degrades to a distinguisher at r = 2, dies at r = 4). Standalone breaks track the same asymmetry: aes2r's raw break is a master-key-byte peel per 256-text Λ-set at ≈ 2¹⁶ work (full key from 15 Λ-sets = 3840 chosen texts, either lane); AES-ITB-128's is a one-query full-seed inversion under the full-state lab grant plus a lo-lane structured ≈ 2²⁰ recovery on the raw-primitive one-block shape. aes2r's integral is a key-dependent recovery; AES-ITB-128's a key-independent distinguisher. aes2r flags the §3.5 differential battery (`ddt8_max` 1.000, final-AddRoundKey term); AES-ITB-128 reads at the uniform band.

The full-state lab grant matters for AES-ITB-128 and not for aes2r for one reason: AES-ITB-128's last call is a public permutation, so `P⁻¹` is free once the 16-byte output is visible — Square-style recovery on the peeled input succeeds at r = 2 on the one-block lab shape (≈ 2²⁵ work) and at surface (A) 20 B (≈ 2¹³·⁶ κ guess-sums). aes2r's last call is a keyed permutation, so `P⁻¹` needs the key and no free peel exists. That is why the surface (A) `lo`-only consumption is the load-bearing barrier for AES-ITB-128 and neither recovery reaches the wire. On the shipped observable, the lo-lane cell sits at the floor at every r ≥ 2 on every shape measured; the residual through the hi lane is a 2⁶⁴ enumeration constant in r. On the counter-byte cube, aes2r NR = 2 leaves the lo lane balanced 8 / 8 at r = 2 (PRF distinguisher, no recovery) and floors at r ≥ 3; AES-ITB-128 is already at the floor at r ≥ 2. Both dissolution depths on surface (A) — integral at r ≥ 2, no-candidate-structural recovery at r ≥ 2 — sit below the shallowest shipped cascade (r = 4); AES-ITB-128 is one depth earlier on the distinguisher.

**Head-to-head statistical comparison.** A single-harness statistical comparison of the two raw primitives under one seed stream and byte-identical input arrays, with `urandom` as the sampling-floor control and `fnv1a` as the half-cross reference (`scripts/redteam/itb/theory/_common/stats_comparison_a2r_a128.py`). Marginal statistics at N = 10⁶ × 3 trials × 10 (config × shape) cells per primitive; avalanche and half-cross at M = 10⁵ × 3 bases on the block shape and M = 10⁴ × 3 at every shape. Worst-of-3-trials figures below; "floor" = every listed statistic below its α = 0.01 Bonferroni ceiling. The five axes on which aes2r departs structurally map cleanly onto the mechanism paragraph above: missing final MixColumns explains the counter-pattern and low-byte DDT signatures; the 2-round diffusion depth explains the data / key avalanche and the half-cross truncation.

| Axis | Shape / N | aesitb128 | aes2r | urandom control | Reading |
|:-----|:----------|:----------|:------|:----------------|:--------|
| Byte χ² max (full, ceiling 334.7) | rand_pt / rand_key, N = 10⁶ | 297.8 – 326.9 | 286.9 – 320.7 | 283.9 – 323.4 | both at floor |
| Bit bias max (ceiling 0.00210) | rand_pt / rand_key, N = 10⁶ | ≤ 0.00176 | ≤ 0.00227 (one single-trial event above the ceiling; otherwise ≤ 0.00189) | ≤ 0.00223 (one single-trial event above the ceiling; otherwise ≤ 0.00204) | both at floor apart from the two single-trial events |
| Shannon / min-entropy | rand_pt / rand_key, N = 10⁶ | 7.9998 / 7.909 – 7.920 | 7.9998 / 7.888 – 7.919 | 7.9998 / 7.885 – 7.919 | identical within floor |
| Birthday \|z\| max (ceiling 3.34) | rand_pt / rand_key, N = 10⁶ | ≤ 3.17 | ≤ 3.23 | ≤ 2.66 | both at floor |
| Counter χ², shape 13 (shipped fill input) | counter, N = 10⁶ | 304.1 — floor | **2.55 × 10⁸** | 303.4 — floor | **structural: 4 of 16 output bytes constant, 4 confined to 16 values, 8 near-uniform** |
| Counter χ², shape block | counter, N = 10⁶ | 294.3 — floor | **2.55 × 10⁸** | 294.3 — floor | **structural: same as shape 13 — a one-block absorption** |
| Counter χ² / bit bias, shape 20 / 36 / 68 | counter, N = 10⁶ | 313.6 / 306.6 / 327.1 — floor | **χ² ≈ 1.2 × 10⁶, bit bias 0.08 – 0.10, min-entropy 5.39** | 305.4 / 299.8 / 303.6 — floor | **structural: the wrapper re-encrypts a structured first-block output under the same key** |
| Data avalanche, block (M = 10⁵; ideal 64 ± 5.66) | aval_data | 64.00 ± 5.66; SAC max 0.0077 (ceiling 0.0082); 0 / 15 360 dead | **16.06 ± 2.79; SAC max 0.500; 11 520 / 15 360 (75 %) dead** | 64.00 ± 5.66; SAC max 0.0068; 0 dead | **structural: single-column diffusion at NR = 2 leaves 96 of 128 output bits fixed per input bit** |
| Data avalanche, shape 20 / 36 / 68 (M = 10⁴) | aval_data | 64.00 ± 5.66; 0 dead | 28.8 / 30.2 / 31.1 ± 5 – 7; 50 – 55 % dead | not run | wrapper spreads the differential over two encryptions; still half the pairs dead |
| Key avalanche, block (M = 10⁵) | aval_key | 64.00 ± 5.66; 0 dead | **38.95 ± 6.63; SAC max 0.500; 6 528 / 16 384 (40 %) dead** | 64.00 ± 5.66; 0 dead | **structural: 2-round key schedule leaves 40 % of (key bit, output bit) pairs uninteracting** |
| Half-cross diffusion, block (ideal 32 / 32 per cell) | aval_data / aval_key | 32.0 / 32.0 in every (input half × output half) cell, data and key | data 8 / 8 in every cell (symmetric, ¼ of ideal); key 19.2 – 19.6 across the four cells (symmetric, ≈ 61 % of ideal) | 32.0 / 32.0 in every cell | fully mixed vs partially mixed (see § 3.5 half-cross mini-table) |
| Low-byte DDT (`ddt8_max` / `const8`, block, M = 10⁵) | aval_data | 0.0047 / 0 (uniform edge 0.0045) | **1.000 / 0.733** | 0.0047 / 0 | matches the § 3.5 differential-battery contrast under one harness |

On random-input marginals and the joint 24-bit-window birthday test the three sources show no measurable difference from each other at N ≤ 10⁶ (every figure below the α = 0.01 Bonferroni ceiling except two single-trial bit-bias events — aes2r 0.00227 clean on fresh seeds 11–13, urandom 0.00223 not re-run as it is the expected family-wise rate on the control). On the shipped counter-input pattern aesitb128 sits at the sampling floor at every shape while aes2r shows a two-part structural signature — 4 constant + 4 sixteen-valued output bytes at the one-block shapes, χ² ≈ 10⁶ with min-entropy 5.39 at the wrapper shapes — traceable to the missing final MixColumns and to the same structured first-block output being re-encrypted under the same key. On data / key avalanche, half-cross diffusion, and low-byte DDT aes2r departs structurally (75 % dead data pairs, 40 % dead key pairs, ¼-ideal half-cross flips, `ddt8_max` 1.000); aesitb128 delivers the control's ideal on all of them. Bounded reading: at these sample sizes and shapes aesitb128's raw output shows no measurable departure from the urandom control; aes2r shows structural departures on five axes. No security implication is asserted at either end — the compound defence stack (surface (A) ChainHash cascade + `lo`-lane-only consumption; surface (B) ChainHash cascade + divmod-then-combinadic-unrank of `(lo, hi)`, [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)) is what closes both primitives' standalone weaknesses.

**Conclusion.** At r = 1, AES-ITB-128 is broken outright as a standalone primitive under lab grants — a one-pair full-state seed inversion, a probability-1 Square integral on either lane, and a measured ≈ 2²⁰ structured Square-style recovery on the raw-primitive one-block lo-lane shape. None reach the shipped wire: surface (A) consumes `lo(h_r)` only and the ≈ 2²⁰ engine is out of regime at shapes 20 / 36 / 68 (0 / 0 at every position, r = 1 and r = 4); surface (B) consumes both lanes monolithically through divmod-then-combinadic-unrank and emits no lane individually ([§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)). At r = 2 on surface (A) every cell measured is at the floor; the two r = 2 lab-grant recoveries — one-block lab shape (≈ 2²⁵, `keyrecover_r2.py`) and shipped 20 B (≈ 2¹³·⁶, `keyrecover_r2_20byte.py`) — sit behind the full-state lab grant; the shape-36 order-4 diagonal recovery sits behind both the full-state grant and a chosen-nonce grant (below shipped depth r = 4). At r ≥ 3 on surface (A) no screen returns a signal — counter-byte cube at shapes 36 / 68 / 20 across r ∈ {3, 4, 8, 16} at the floor (one r = 3 shape-68 raw Poisson event p ≈ 8 / 256 aside), single-byte data-differential (N = 8192 × 3 Δ), byte / bit uniformity (N = 10⁵) all at their sampling floors through r = 16. The shipped cascades (r = 4 / 8 / 16) sit above the dissolution depth. The `lo`-lane consumption that separates r = 2 from a key recovery is architectural (only `h[0]` reaches the encoder, through noise-position / rotation / xor-mask projections across two seeds — see `process_generic.go` `blockHash128`). Conservatively framed: these specific screens at these sample sizes and depths read at the floor on the shipped observable, not a proof that no exploitation path exists for a primitive that inverts from one pair standalone; the standalone-weak / inner-PRF-only classification of `aesitb128` stands as measured. Surface (B)'s consumption chain absorbs the hypothetically visible lo-lane fill output separately in [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain).

#### 3.10.2. Dissolution mode — cost versus cascade depth

Whether a cascade defence is **structural** (the attack stops working at some depth regardless of budget), **polynomial** (cost grows slowly with r), or **exponential** (cost blows up but the attack still succeeds in principle) is decided per screen by the shape of the cost-versus-r series. Cost metrics tracked across r ∈ {1, 2, 3, 4, 5, 6, 7, 8, 12, 16}: Λ-set order d (N = 256^d chosen texts) for the integral, texts × work for key recovery, sample size N for the differential and uniformity screens. Rows are keyed by observable — surface (A) `lo(h_r)` under idx-only Λ-sets and a random nonce per set is the shipped surface for the Pixel Barrier; full-state lab-grant rows are kept as labelled references because they isolate which grant is load-bearing at which depth. The shape-13 fill-input row is a lab probe on a hypothetical lo-only exposure that surface (B) never emits ([§3.10.3](#3103-interlocked-barrier-fill-consumption-chain) documents the shipped fill defence).

| Screen (observable) | r = 1 | r = 2 | r = 3 | r = 4 … 16 | Mode |
|:--------------------|:------|:------|:------|:-----------|:-----|
| Λ-set integral, `lo(h_r)`, surface (A) shapes 20 / 36 / 68 (idx-only cube {0,1,2,3}, random nonce; d ≤ 4 on-wire ceiling — the counter-byte cube caps at 4 active bytes) | shape 20 d = 4 cube: 0 / 8 (negative control — column set, 3-round property only, 1 seed × 1 set) | 0 / 8 raw and 0 / 8 column-peeled at every shape (20: 2 seeds × 1 set; 36 / 68: 1 seed × 1 set each) | 0 / 8 at shapes 20 / 36; shape 68 raw 1 / 8, column-peeled 0 / 8 (single Poisson event at p ≈ 8 / 256) | 0 / 8 raw and column-peeled at every shape at r ∈ {4, 8, 16}, 1 seed × 1 set | **Structural on surface (A).** Order-d floor on the counter-byte cube says the degree in the data variables saturates the sub-cube from r = 2. |
| Λ-set integral, lo-lane probe at shape 13 fill input (hypothetical — surface (B) emits no lane individually, see [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)) | order 1 raw 8 / 8 (the 3-round Square on the lane — never on wire) | 0 / 8 at r ∈ {2, 3, 4} on the pair-constancy engine (5 trials × 8 sets) | same | same at every r | Lab probe; the fill site consumes both lanes monolithically. |
| Λ-set integral, full-state lab grant | one-block shape balanced at d = 1..3 probability 1; shape 20 d = 4 diagonal set (2³² texts, chosen-nonce grant): 16 / 16 | one-block lab shape d = 4 diagonal at data-len 15 (2³² texts): `h_1` balanced at r = 2; shipped 20 d = 4 diagonal (chosen-nonce): 0 / 16 (feedforward removes the Λ-set from r = 2) | floor at d ≤ 4 | floor at d ≤ 4 at every r | Lab reference — wire never exposes the full state. |
| Key recovery, surface (A) (`lo(h_r)`, idx-only, random nonce) | one-block lab shape (raw-primitive): ≈ 2²⁰ structured Square-style recovery of K = fixedKey ⊕ seed (3840 chosen texts, 5 / 5); shipped shapes 20 / 36 / 68 out of regime (0 / 0 at every position, r = 1 and r = 4) | **no candidate (structural: κ peel needs the hidden hi lane; residual 2⁶⁴ hi-lane enumeration)** — lo-lane accumulator at floor at shapes 20 / 36 / 68 | same at r = 3 | same at r ∈ {4, 8, 16} | **Structural on surface (A).** Recovery needs the counter-byte cube to survive the primitive as a Λ-set (r = 1 only, out of regime at shipped shapes) or the full state (never); at r ≥ 2 the accumulator returns no consistent candidate. 2⁶⁴ residual is depth-independent. |
| Key recovery, full-state lab grant | 1 known text ≈ 2⁰ (one-pair inversion) | one-block lab shape 256 chosen texts ≈ 2²⁵ (`keyrecover_r2.py`); shipped 20 B shape 768 chosen texts ≈ 2¹³·⁶ κ guess-sums (`keyrecover_r2_20byte.py`); shipped 36 B shape 2³² texts on the order-4 diagonal set at 22 s / set (three-hedge cell — full-state grant, chosen nonce, below shipped depth r = 4) | fails at every engine (0 / 5) | fails at every engine (0 / 5 at r = 4, 20 B; not run beyond) | Lab reference; every recovery sits behind at least one grant the wire does not admit. |
| Data-differential (single active byte) | `max_dp` 0.0070 at N = 2¹³ → 0.0042 at N = 2²⁰ (uniform 1/256 = 0.0039), 0 zero-diff bytes | same | same | same at every r | **No transition** — no measurable signal at N ≤ 2²⁰ at any r including the raw primitive. |
| Output uniformity (byte χ², bit bias) | at floor at N = 10⁵ and N = 10⁶; head-to-head N = 10⁶ × 3 trials × 3 configs × 5 shapes at floor on surface (A), four α = 0.01 family-ceiling events in 192 lane-cells across both matrices (expected ≈ 1 per criterion under Bonferroni, all non-recurring on fresh seeds) | same | same | same at every r (one family-ceiling exceedance in 20 lane-cells at r = 12 full state, 329.8 vs 327.9 — within multiple-comparison expectation) | **No transition** — marginals of a permutation over uniform input are uniform by construction. |

**Verdict.** On surface (A) every screen carrying a standalone signal is at the floor from r = 2 on (integral orders 1–4 on the counter-byte cube at shapes 20 / 36 / 68; key recovery a no-candidate-structural cell with a 2⁶⁴ residual). No cell shows a cost growing with r while the attack keeps succeeding — neither the polynomial nor the exponential reading applies. The one r = 1 surface-(A) recovery lives on the raw-primitive one-block shape the shipped per-pixel pipeline never uses. Lab-grant reference rows locate the load-bearing grants: full-state alone at shipped 20 B r = 2; full-state plus chosen nonce at shipped 36 B r = 2; none at r ≥ 3 — every recovery sits behind at least one grant the wire does not admit and below the shallowest shipped cascade (r = 4). The shape-13 fill-input row is a lab probe on a hypothetical surface (B) exposure the wire does not emit ([§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)). Claim bounded to these ranges and engines: an on-wire structured attack of order d ≥ 5 has no set to run on at any per-pixel shape (counter-byte cube caps at 4 active bytes); no such attack is claimed excluded by extrapolation.

#### 3.10.3. Interlocked Barrier fill consumption chain

The barrier fill in the Triple pipeline runs the lockSeed's primitive on the 13-byte fill input `[0x03 ‖ LE64(groupIdx) ‖ 0⁴]` as a full ChainHash cascade under `lockComps = [K, c[0], …, c[n-1]]` — a secret ChainHash-derived key `K` of the primitive's width (the pair `(lockLo, lockHi)` at width 128) followed by the lockSeed's session components — for every shipped primitive at every width. Every hot-loop call runs at depth r = 1 + `keyBits` / `width`: 5 / 9 / 17 at width 128, 3 / 5 / 9 at width 256, 2 / 3 / 5 at width 512 (for `keyBits` 512 / 1024 / 2048; `interlock48_cascade.go` `buildLockBatchPRF48_{128,256,512}`). The cascade is the wire — no hook on the lockSeed selects it; a primitive's batch-16 kernel only evaluates it. `fillRanks` writes `(lo, hi)` of one cascade per group at width 128 into one 128-by-30 divmod through `fillLockMasksTriple48Super`, producing one `(idx0, idx1)` → one mask triple → one 6-byte chunk; at widths 256 / 512 the wider cascade output is sliced into 128-bit pairs, each feeding one chunk under the same divmod. The full 128-bit output is therefore consumed **monolithically** per 128-bit slice, not sliced into 48-bit pieces the lo-lane accumulator could ride.

The key `K` heading the hot-loop cascade is not the lockSeed itself — it is the full-cascade output `ChainHash(0x04 ‖ interlock nonce)` on the lockSeed at the primitive's width (`seed128.go` / `seed256.go` / `seed512.go` `deriveInterLockSeed`), computed once per container and prepended to the session components at build time (inner seeds never rotate, so `lockComps` is fixed for the session). Two cascade depths compose across the two stages: setup runs at the shipped cascade depth (r = `keyBits` / `width` — 4 / 8 / 16 at width 128 for `keyBits` 512 / 1024 / 2048, above dissolution for `aesitb128` per [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth)), and every hot-loop call runs one round deeper (round 1 under the derived key binding the nonce; rounds 2 .. r under the session components). Input domains are disjoint by the leading tag byte (`0x04` at setup, `0x03` in the hot loop); the setup output never reaches the wire, only its role as the first key of the hot-loop cascade. No hot-loop call runs the primitive below the shallowest shipped cascade depth: the r = 1 standalone breaks and the r = 2 lab-grant recoveries of [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) all sit below every depth the fill uses; the consumption chain below applies on top as defence in depth. The same construction applies to every other shipped primitive at every width.

Under this consumption chain the leakage bound is:

- **A · B = 1355345464406015082330 ≈ 2⁷⁰·² admissible triples**, so at most log₂(A · B) ≈ 70.2 of the 128 output bits reach any observable derived from a single mask triple, with **2¹²⁸ / (A · B) ≈ 2⁵⁷·⁸ preimages per triple** (verified empirically: `rank + A · B` → identical triple 1000 / 1000; a single hi-lane bit flip → different triple 1000 / 1000; a single lo-lane bit flip → different triple 1000 / 1000; partition invariant held throughout).
- The three lanes emerging from a mask triple are Pixel Barrier plaintext, so any wire attack on the barrier fill must **first break the Pixel Barrier** to see a lane byte at all; every recovery in the standalone table above precedes that step.
- Even the hypothetical grant that supplies a lo-lane fill output admits Λ-sets on plaintext bytes 1..8 only (byte 0 is the fixed `0x03` domain tag, bytes 9..12 are zero padding). The counter-byte cube at the fill shape is at most order 8 in principle, and the shape-13 r = 1 lo-lane balance retained in [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) is exactly this hypothetical — a raw-primitive property, not a wire exposure.

The composite bound: a wire attack on the fill output would require breaking the Pixel Barrier, then holding a monolithic 128-bit consumption of `(lo, hi)` in which the Λ-set structure survives the divmod through C(48, 16), with a residual 2⁵⁷·⁸ preimage ambiguity per triple even under a full mask read. The r = 1 standalone breaks in the section above are raw-primitive properties; no exploitation path on the shipped wire is known through this fill regime.

**Empirical closure of the divmod-preservation caveat.** The order-4 idx cube {0,1,2,3} at shapes 20 / 36 / 68 at r = 4 (the shallowest shipped depth for `keyBits = 512`) is passed through the full fill chain — `ChainHash-4` → `(lo, hi)` split → `splitRank48` divmod → `rankToMaskTriple48` combinadic unrank — and the byte-level XOR-sum balance across the resulting mask triple is measured over the 2³² texts per set. At every shape the mask-triple bytes register **0 / 6 balanced on m0 / m1 / m2** (1 seed × 1 set × 2³² texts per shape, ≈ 295 s per set at 15 threads, `scripts/redteam/itb/theory/aesitb128/order4_unrank_go`), matching the `h_r` primary-observable floor from [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) at the same cells (0 / 8 raw `h_r` on shape 20 / 36 / 68 at r = 4). The Λ-set has been fully absorbed by the cascade before the divmod stage — the divmod + unrank composition sees uniform-band input and produces uniform-band mask-triple output. The composite bound reads as measured, not argued.

## 4. Primitive shelf

Provenance and the published SMHasher weakness each primitive is selected to stress. The per-axis measured results are in [§3](#3-results); the consolidated Axis C seed-recovery verdicts (with the rounds = 1 vs rounds ≥ 2 split) are in the [§3.4 table](#34-axis-c--sat-kpa-seed-recovery-resistance).

| # | Primitive | Published Axis A signature |
|--:|-----------|:---------------------------|
| 1 | **t1ha1_64le** (Yuriev) | Avalanche 3.77–3.95 % at 512–1024-bit keys |
| 2 | **SeaHash** (Ticki, 2016) | PerlinNoise 2.2 × 10¹² × |
| 3 | **mx3** (Maiga, 2022) | PerlinNoise AV 1.48 × 10¹² × |
| 4 | **SipHash-1-3** (reduced-round) | 0.9 % avalanche bias (reduced-round) |
| 5 | **aesitb128** — Non-PRF inner-role only (see [§3.10](#310-aes-itb-128-standalone-breaks-and-cascade-dissolution)) | One-pair inversion under full-state lab grant; ≈ 2²⁰ structured lo-lane recovery on raw-primitive one-block shape; probability-1 Square integral (all raw-primitive standalone, none on the wire — safe only under the two-stage inner-Barrier defence compositions) |

Shelf verdict labels:

- **neutralized ✓** — Axis B passes (`|Δ50| < 1 %`); the published SMHasher weakness does not reach the attacker-observable ciphertext surface.
- **Resistant at tested budget** — Axis C SAT KPA timed out across all tested encodings × backends within the budget. The weakest positive label this shelf emits — always qualified with the measured budget.
- **Dangerous** — the bare or rounds = 1 chain is SAT-broken in commodity time; the deployment-depth (rounds ≥ 2) behaviour is recorded separately in the [§3.4 table](#34-axis-c--sat-kpa-seed-recovery-resistance).
- **Fully broken** — Axis C produced functionally-equivalent K at rounds = 1 AND the rounds ≥ 2 chain is breakable in the same regime.

## 5. Reproduction

Reproduction commands that invoke a `go test` step (directly or through a shell driver) require the `redteam` build tag: `go test -tags redteam ...`. The Axis-B shell drivers (one `harness_bias_audit.sh` per primitive under `scripts/redteam/itb/theory/<primitive>/`) already pass the tag internally. The self-parity tests in [§5.5](#55-self-parity-tests) and the pre-screen invocations in [§5.6](#56-sat-free-pre-screen-35) are Python-only and do not require the tag. The four shelf primitives (t1ha1_64le, SeaHash, mx3, SipHash-1-3) share the [§5.1](#51-shelf-primitives--axis-a--a--b--c-template) template; §5.5–§5.10 cover the auxiliary controls and reduced-round rows.

### 5.1. Shelf primitives — Axis A / A' / B / C template

The four shelf primitives share a common reproduction shape; the per-primitive parameter table below fills the `$PRIM`, `$STRESSDIR`, `$KEY_SIZES` and Axis C variant slots. Report paths follow `~/scratch/redteam/${STRESSDIR}/`.

```bash
# Axis A — raw-primitive avalanche
python3 scripts/redteam/itb/theory/${PRIM}/lab_bias_${PRIM}.py \
    --n-keys 65536 --key-sizes ${KEY_SIZES} \
    --json-report ~/scratch/redteam/${STRESSDIR}/axis_a_lab_bias.json

# Axis A' — structural-input bias (json + html × 4 KB / 64 KB, four cells)
for FMT in json html; do
  for SPEC in "65536 4096" "4096 65536"; do
    read N SZ <<< "$SPEC"
    python3 scripts/redteam/itb/theory/${PRIM}/lab_struct_${PRIM}.py \
        --format $FMT --n-instances $N --instance-size $SZ \
        --json-report ~/scratch/redteam/${STRESSDIR}/axis_a_struct_${FMT}_n${N}_${SZ}.json
  done
done

# Axis B — ITB-wrapped raw-mode bias (shell driver passes -tags redteam internally)
bash scripts/redteam/itb/theory/${PRIM}/harness_bias_audit.sh

# Axis C — see per-primitive row below (default: rounds = 1 obs = 8, 24 h budget, z3 + bitwuzla)
python3 scripts/redteam/itb/theory/${PRIM}/sat_calibration_raw_${PRIM}.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver z3 \
    --json-report ~/scratch/redteam/${STRESSDIR}/axis_c_raw_z3.json
python3 scripts/redteam/itb/theory/${PRIM}/sat_calibration_raw_${PRIM}.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver bitwuzla \
    --json-report ~/scratch/redteam/${STRESSDIR}/axis_c_raw_bw.json
```

| `$PRIM` | `$STRESSDIR` | `$KEY_SIZES` | Axis C variant |
|:--------|:-------------|:-------------|:---------------|
| `t1ha1` | `t1ha1stress` | `32,64,128` | template defaults |
| `seahash` | `seahashstress` | `32,64,128` | 4 encodings × 2 backends — see block below |
| `mx3` | `mx3stress` | `32,256,1024` | 60 s timeout suffices (Tier 3 in ≈ 5 s Z3 / ≈ 2 s Bitwuzla) |
| `siphash13` | `siphash13stress` | `32,256,1024` | template defaults |

**SeaHash Axis C — 4 encodings × 2 backends sweep** (24 h budget each cell):

```bash
for MUL in native explicit; do for VAR in native case-split; do for SOLVER in z3 bitwuzla; do
    python3 scripts/redteam/itb/theory/seahash/sat_calibration_raw_seahash.py \
        --rounds 1 --obs 8 --timeout-sec 86400 --solver "$SOLVER" \
        --mul-encoding "$MUL" --var-shift-encoding "$VAR" \
        --json-report "~/scratch/redteam/seahashstress/axis_c_raw_${SOLVER}_${MUL}_${VAR}.json"
done; done; done
```

### 5.5. Self-parity tests

Cross-check concrete vs Z3 symbolic for each primitive's chain-hash mirror:

```bash
python3 scripts/redteam/itb/theory/_common/chainhashes/_parity_test.py
python3 scripts/redteam/itb/theory/t1ha1/t1ha1_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/itb/theory/seahash/seahash_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/itb/theory/mx3/mx3_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/itb/theory/siphash13/siphash13_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
```

### 5.6. SAT-free pre-screen (§3.5)

Algebraic / avalanche battery and the low-byte XOR-differential battery over the full primitive set (the four shelf primitives plus murmur3 / xxhash64 / splitmix64):

```bash
# Algebraic + avalanche + degree + invertibility (rounds 1-3, deg@16)
python3 scripts/redteam/itb/theory/_common/chainhashes/avalanche_screen.py \
    --all --rounds-max 3 --samples 512 --degree-bits 16
# Higher degree-saturation point (rounds 1, deg@20)
python3 scripts/redteam/itb/theory/_common/chainhashes/avalanche_screen.py \
    --all --rounds-max 1 --samples 64 --degree-bits 20

# Low-byte XOR-differential uniformity (rounds 1-3)
python3 scripts/redteam/itb/theory/_common/chainhashes/differential_screen.py \
    --all --rounds-max 3 --samples 4096 --probe-bits 32
```

Pre-screen primitive parity (bit-for-bit vs the reference libraries / canonical vectors) and the splitmix64 `inv = Y` SAT confirmation:

```bash
# Reference-library parity (mmh3 / xxhash) and canonical-vector self-checks
python3 scripts/redteam/itb/theory/_common/chainhashes/murmur3.py
python3 scripts/redteam/itb/theory/_common/chainhashes/xxhash64.py
python3 scripts/redteam/itb/theory/_common/chainhashes/splitmix64.py

# splitmix64 chain concrete-vs-Z3 parity, then raw-chain SAT recovery
python3 scripts/redteam/itb/theory/splitmix64/splitmix64_chain_lo_concrete.py \
    --rounds 1,2,4 --vectors 8
python3 scripts/redteam/itb/theory/splitmix64/sat_calibration_raw_splitmix64.py \
    --rounds 1 --obs 8 --timeout-sec 300 --solver bitwuzla
```

### 5.7. Trapdoor-primitive control (BEA-1, §3.6)

The BEA-1 cipher and its trapdoor are a clean-room reimplementation transcribed from arXiv:1702.06475 (Bannier & Filiol) / IACR ePrint 2016/493; `bea1_validate.py` self-checks the transcription and `bea1_trapdoor.py` re-derives the partition from the published constants.

```bash
# Experiment 1 — pure BEA-1: reproduce the published partition trapdoor
# (full 120-bit key recovery from chosen plaintext/ciphertext pairs).
python3 scripts/redteam/itb/theory/bea1/exp1_pure_bea1.py

# Experiment 2 — BEA-1 through ChainHash, rounds = 1, partial discard 80->64
# (the trapdoor still recovers the lo-lane seed).
python3 scripts/redteam/itb/theory/bea1/exp2_chainhash_r1.py

# Experiment 3 — BEA-1 through ChainHash, rounds = 2,3,4 (feedforward):
# the same engine fails; the instrumentation shows the coset signal collapses.
python3 scripts/redteam/itb/theory/bea1/exp3_chainhash_feedforward.py

# Experiment 3, structure-aware SMT solver (partition-quotient analogue).
python3 scripts/redteam/itb/theory/bea1/exp3_structure_solver.py
```

### 5.8. Reduced-round-primitive control (2-round AES, §3.7)

`chainhashes/aes2r.py` is the 2-round-AES inner primitive (FIPS-197-validated, self-tested on import). The scripts below are in `scripts/redteam/itb/theory/aes2r/`.

```bash
cd scripts/redteam/itb/theory/aes2r

# Raw 2-round AES is integral-broken: unique master-key byte from one Λ-set.
python3 integral_aes2r.py

# Pre-screen the aes2r primitive — avalanche reads clean, differential flags it (§3.5 style).
python3 ../_common/chainhashes/avalanche_screen.py    --primitive aes2r --rounds-max 4
python3 ../_common/chainhashes/differential_screen.py --primitive aes2r --rounds-max 4

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
python3 gd_chainhash_aes2r.py     # emits relationfile_chainhash_r{1,2}_discard{0,1}.txt into ~/scratch/redteam/gd_chainhash_aes2r/
# autoguess -i ~/scratch/redteam/gd_chainhash_aes2r/relationfile_chainhash_r1_discard0.txt -s sat -sats cadical195 -mg 12 -ms 20
```

### 5.9. Chosen-constants collision control (Malicious-SHA-1, §3.8)

The Malicious-SHA-1 core is a clean-room transcription of RFC 3174 with the round constants exposed as a parameter (`sha1_malicious.py`); the modified K set and the colliding shell-script pair are embedded verbatim as bytes literals in `sha1_collide.py` — attribution: Albertini, Aumasson, Eichlseder, Mendel, Schläffer, IACR ePrint 2014/694; Maria Eichlseder's PoC bundle at `malicioussha1.github.io`. The wrap function (`sha1_chainhash.py`) mirrors the two production references cited inline: `hashes/blake3.go` `BLAKE3WithKey` (input-XOR keying) and `seed128.go` `ChainHash128` (feedforward).

```bash
# Single script — sub-probes A (raw baseline), seed=0 invariant test,
# B (r=1 random-seed snap), C (r=1/2/4/8 feedforward-depth plateau).
# JSON output emitted to ~/scratch/redteam/msha1/collision_absorption.json
# (override via REDTEAM_MSHA1_OUTPUT_DIR); trial count via REDTEAM_MSHA1_TRIALS.
python3 scripts/redteam/itb/theory/msha1/exp1_snap.py
```

### 5.10. Reduced-round-primitive control (AES-ITB-128, §3.10)

`chainhashes/aesitb128.py` is the shipped AES-ITB-128 sponge mirrored in Python (self-tested on import against the `aesitb/aesitb_test.go` generic vectors and its own numpy batched evaluator; AES building blocks imported from `chainhashes/aes2r.py`). Scripts live in `scripts/redteam/itb/theory/aesitb128/`; every cascade screen sweeps r ∈ {1, 2, 3, 4, 5, 6, 7, 8, 12, 16}. `--data-len 20|36|68` switches any cascade screen to a shipped per-pixel shape. Attacker-model flags follow `--model {lab, realistic}`: `realistic` = lo lane, idx-only Λ-sets (active bytes ⊆ `LE32(idx)` bytes 0..3), random nonce per set; `lab` = full 128-bit output, chosen data across all input bytes. Recovery scripts default to lab grants and print the realistic-model result under `--model realistic`.

```bash
cd scripts/redteam/itb/theory/aesitb128

# Raw AES-ITB-128 standalone: Λ-set integral (orders 1-3 × shapes) + full-state one-pair inversion.
python3 integral_aesitb128.py

# §3.5-style pre-screen — both batteries read clean; `inv` = Y.
python3 ../_common/chainhashes/avalanche_screen.py    --primitive aesitb128 --rounds-max 4
python3 ../_common/chainhashes/differential_screen.py --primitive aesitb128 --rounds-max 4

# Integral survival through ChainHash (r-sweep × observables: lo lane shipped, full state lab,
# full-state P^-1 column peel lab; lo-lane column peel `w = InvMixColumns(lo ^ RC[1][0:8])` is
# a surface-(A)-observable distinguisher step, no key candidate on its own).
python3 distinguisher_chainhash.py      # 1st order, 256 texts/set, 8 seeds/cell
python3 higher_order_chainhash.py       # 2nd order, 2^16 texts/set, 8 seeds/cell
python3 order3_chainhash.py             # 3rd order, 2^24 texts/set, 1 set/cell (~10 min)
python3 order4_chainhash.py --data-len 20 --rounds 1 --workers 16                     # 4th order diagonal at 20 B (chosen-nonce lab; ~18 min)
python3 order4_chainhash.py --data-len 15 --rounds 2 --workers 16                     # 4th order diagonal at one-block lab, r = 2 (~17 min)
python3 order4_chainhash.py --data-len 20 --rounds 1 --workers 16 --active 0,1,2,3    # surface-(A) order 4 idx cube {0,1,2,3} at 20 B — negative control
python3 order4_chainhash.py --data-len 68 --rounds 2 --workers 16 --active 0,1,2,3    # surface-(A) order 4 idx cube at 68 B, r = 2 (~30 s / set)

# Larger-N distribution screens (§3.10.2).
python3 differential_chainhash.py --samples 1048576
python3 uniformity_chainhash.py --samples 1000000 --reps 1

# KEY-RECOVERY on surface (A) (lo lane, idx-only, random nonce) at shapes 20 / 36 / 68 B,
# depths 1..16: no candidate (structural — κ peel needs the hi lane; 2^64 residual).
# `--lab-control` (default) runs the lab-grant engine on the same seeds as positive control.
cd keyrecover_kbyte_go && go build -o kbyte . && cd ..
./keyrecover_kbyte_go/kbyte --model realistic --rounds 2,3,4,8,16 --sets 8 --trials 5

# INTEGRAL through the full fill chain (surface (B)): order-4 idx cube {0,1,2,3} at shapes
# 20 / 36 / 68 at r = 4, through cascade + splitRank48 divmod-by-C(48,16) + rankToMaskTriple48
# combinadic unrank; measures byte-level XOR balance across the mask triple m0/m1/m2 (6 bytes
# each) plus lo/hi lane balance for reference. Closes the divmod-preservation caveat of §3.10.3.
cd order4_unrank_go && go build -o unrank . && cd ..
./order4_unrank_go/unrank --cells 20:4,36:4,68:4 --trials 1 --workers 16

# KEY-RECOVERY, lab references — full-state lab grant:
#   - pair-constancy engine at one-block lab shape (T = 3; r = 2 recovers both seed blocks
#     from one Λ-set, ≈ 2^25 work; r >= 3 fails)
#   - classical 4-round Square κ-byte engine at 20 B shape (T = 4; r = 2 from 3 Λ-sets = 768
#     chosen texts; `--model realistic` reruns on surface (A) — floor at every depth)
python3 keyrecover_r2.py
python3 keyrecover_r2_20byte.py
python3 keyrecover_r2_20byte.py --model realistic

# Standalone lo-lane KEY-RECOVERY at r = 1, one-block lab shape: ≈ 2^20 structured Square-style
# recovery of K = fixedKey ^ seed from 15 chosen Λ-sets over plaintext bytes 0..14 (5 / 5). Splits
# via `--trials` / `--skip-negative` / `--only-negative`. `--shape-probe DATA_LEN --rounds R
# --positions P0,P1,...` runs the same engine on a shipped shape at idx-eligible positions only
# (winning score margin; no key verification — the model does not hold at shipped shapes).
python3 keyrecover_r1_2p20.py
python3 keyrecover_r1_2p20.py --shape-probe 20 --rounds 1 --positions 0,1,2,3
python3 keyrecover_r1_2p20.py --shape-probe 20 --rounds 4 --positions 0,1,2,3

# Data-differential (N = 8192 bases/Δ) — no truncated differential at any r.
python3 differential_chainhash.py

# Output uniformity (byte χ², per-bit bias, N = 10^5) at r = 1 and every cascade depth.
python3 uniformity_chainhash.py

# aes2r cross-references (raw-primitive full-master-key recovery from 15 Λ-sets + 2^8 pad-byte
# brute force; NR = 4 surface-(A) partial resolution of 8 visible last-round-key bytes behind
# 2^64 hi-lane; NR = 2 surface-(A) order-4 idx cube distinguisher).
python3 ../aes2r/fullkey_aes2r.py
cd ../aes2r/square5_go && go build -o square5 . && cd -
../aes2r/square5_go/square5 --model realistic --nr 4 --rounds 1,2,4 --trials 3
cd ../aes2r/order5_aes2r_go && go build -o order5aes2r . && cd -
../aes2r/order5_aes2r_go/order5aes2r --active 0,1,2,3 --nr 2 --rounds 1,2,3,4 --seed 20260906

# Head-to-head statistical comparison against aes2r (raw primitives, one harness, byte-identical
# inputs). Full matrix N = 10^5 (~6 min); marginal confirmation N = 10^6 (~15 min); half-cross
# + data-avalanche confirmation M = 10^5 on block shape (~10 min). Repeat with `--primitive
# aes2r / urandom / fnv1a` for those rows. `--report <jsonl>` prints summary tables.
python3 ../_common/stats_comparison_a2r_a128.py --all --samples 100000 --bases 10000 --trials 3 --seed 1 --json ~/scratch/redteam/aesitb128/stats_comparison_1e5.jsonl
python3 ../_common/stats_comparison_a2r_a128.py --config marginal --samples 1000000 --trials 3 --seed 1 --json ~/scratch/redteam/aesitb128/stats_comparison_1e6.jsonl
python3 ../_common/stats_comparison_a2r_a128.py --primitive aesitb128 --shape block --config avalanche --bases 100000 --trials 3 --seed 1 --json ~/scratch/redteam/aesitb128/stats_comparison_aval1e5.jsonl
python3 ../_common/stats_comparison_a2r_a128.py --report ~/scratch/redteam/aesitb128/stats_comparison_1e6.jsonl
```
