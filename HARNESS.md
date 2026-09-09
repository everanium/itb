# HARNESS.md — Non-cryptographic Hash Primitive Analysis Shelf

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

*(public sibling of [REDTEAM.md](REDTEAM.md) / [ITB.md](ITB.md) / [SCIENCE.md](SCIENCE.md) / [PROOFS.md](PROOFS.md). Three-axis empirical study of non-cryptographic hash primitives wrapped into ITB `ChainHash128` — bias-absorption (Axes A, A', B) and SAT KPA seed-recovery resistance (Axis C). Scope restricted to primitives whose Go reference and Python mirror each fit in ≤ ~500 LOC.)*

*The prior harness record — the wider primitive shelf under Single Ouroboros with the overlay optional — is preserved verbatim in [archive/HARNESS.md](archive/HARNESS.md).*

## 1. Scope

The shelf measures four non-cryptographic hash primitives plugged into ITB `ChainHash128` to validate two architectural properties:

1. **Bias absorption** — whether ITB's encoding pipeline (rotation + noise barrier + COBS framing + CSPRNG fill) neutralises a primitive's documented SMHasher weaknesses on the attacker-observable ciphertext surface (Axes A, A', B).
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

**Axis B — ITB-wrapped bias.** Raw-mode bias probe against `known_ascii` corpora encrypted with the primitive plugged into `ChainHash128` at `keyBits = 1024`, `BarrierFill = 1` (`DefaultBarrierFill`), N = 2 nonce-reuse. The probe operates on attacker-visible wire bytes: it treats the container body (behind the dual-nonce header and the always-on 48-bit Interlocked Barrier) as a flat 8-byte-per-pixel stream, brute-force-scans every candidate pixel-shift under a zero-seed `ChainHash(pixel_le || main_nonce)` oracle, and reports the per-shift conflict-rate distribution. Verdict `neutralized ✓` when `|Δ50|` — the deviation of that distribution's median from the 50 % mid-point — is below 1 %. The metric is coarse: the barrier's per-chunk mask permutation and the three-snake distribution scramble any per-pixel bias into the wire before the probe sees it, so a passing measurement is the barrier's absorption doing its job through a channel the probe deliberately does not try to invert.

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

The raw-mode bias-audit probe measures the per-shift conflict-rate distribution on the attacker-observable ciphertext surface (the wire body behind the dual-nonce header and the always-on 48-bit Interlocked Barrier); the `|Δ50|` column is the deviation of that distribution's median from the 50 % mid-point. All measured primitives `neutralized ✓` at the 1 % threshold on both corpus sizes. The published SMHasher weaknesses (avalanche-scaling for t1ha1, PerlinNoise for SeaHash and mx3, reduced-round avalanche for SipHash-1-3) do not reach the attacker-observable ITB ciphertext surface. The absorption is a property of ITB's encoding pipeline (rotation + noise barrier + COBS framing + CSPRNG fill under the always-on 48-bit Interlocked Barrier), independent of the primitive that keys it — the eight cells converge to nearly identical `|Δ50|` values (0.889–0.891 %) across both corpus sizes and all four primitives, corroborating primitive-independent absorption at the metric's resolution.

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

**(A) Invertible round maps fall at rounds = 1; only a carry-up T-function carries the break into deployment.** splitmix64, mx3, and fnv1a are all `inv = Y` ([§3.5](#35-sat-free-algebraic--differential-pre-screen)) — a single round is a bijection the solver inverts directly: splitmix64 ≈ 20 s (Z3) / ≈ 25 s (Bitwuzla); mx3 ≈ 2–5 s, where the rounds = 1 chain degenerates to one `mx3_hash` call with the hi-lane seed unconstrained and the lo-lane seed recovered functionally-equivalent to ground truth. At rounds ≥ 2 the feedforward masks the intermediate output, so the solver can no longer peel round-by-round; the seed must be solved through the whole composition, which is tractable only when the round map is a **carry-up T-function** (output bit t depends on input bits 0..t, solvable plane-by-plane LSB → MSB). fnv1a's ×0x13B lo-lane has exactly that structure and stays solvable — the isolated ChainHash falls even at rounds = 4 in ≈ 146 s (Bitwuzla) / ≈ 0.16 s (the structure-aware T-function solver). splitmix64 and mx3 lack it: mix64's right-shifts (`z ^ (z>>30 / >>27 / >>31)`) push high bits down into low, destroying the triangularity, so both resist at the 24 h budget at rounds = 2 despite equal invertibility. splitmix64 is the clean control — its lo lane is literally splitmix64 (the hi lane is only a parallel second instance to fit the 128-bit two-lane interface, and the discard drops it), so its rounds ≥ 2 resistance is a property of splitmix64's own internal structure, not of any lane interaction. This is the decisive evidence that fnv1a's SAT-tractability is its carry-up triangular structure, not invertibility or round count. (The ≈ 8 h figure cited for fnv1a elsewhere is the FULL Phase 2g ITB break — ChainHash + the ~90-bit per-pixel noise_pos barrier + 4 public-schema cribs — not this isolated chain inversion.)

**(B) The hi-lane discard walls a lane-mixing primitive with no round structure required.** murmur3 (MurmurHash3_x64_128) is the only primitive here with a genuine 128-bit internal state whose halves cross-mix in finalisation: the full-128 seed recovers in ≈ 2.1 s, but ITB observes only the lo lane — a 128 → 64 projection of the already-mixed state — and that projection alone times out, walling murmur3 at rounds = 1 before the feedforward contributes anything. For the lane-parallel primitives (every other row) the hi-lane discard is **off**: the lo lane is computed independently of the hi lane, so dropping the hi lane removes no constraint a lo-lane attacker could have used. The two barriers are independent, and real ITB stacks both plus the per-pixel noise_pos / rotation barrier and the always-on 48-bit Interlocked Barrier permutation on top.

**(C) No invertibility hook makes seed-recovery SAT structurally inapplicable.** For t1ha1, SeaHash, and SipHash-1-3 the SAT budget is not the meaningful axis: they carry no invertibility hook, so seed-recovery SAT times out at the 24 h budget (SeaHash across all 4 encodings — `{native, explicit}` × `{native, case-split}` — on both backends, 8 cells), not for want of compute. A larger budget does not change the verdict, which is why it is reported as a structural property, not a budget-bounded timeout. Their only surfaced weakness is differential (t1ha1 persistent, SeaHash round-dependent) — see [§3.5](#35-sat-free-algebraic--differential-pre-screen); SipHash-1-3 is clean on every axis. "Resistant at tested budget" for this group is better read as "no SAT invertibility hook"; the differential hook lives in a separate attack class the SAT axis structurally cannot reach (and, per [Axis B](#33-axis-b--itb-wrapped-raw-mode-bias), ITB's encoding neutralises it before it reaches a ciphertext anyway).

**(C) extends to the [§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash) control.** aes2r (2-round AES) sits in this group for the same structural reason — its AES S-box is a GF(2⁸)-inverse + affine map, not a carry-up T-function, so seed-recovery SAT (z3 and CryptoMiniSat) times out even at rounds = 1, and not for want of compute (the full-128 instance times out too, so the lo-lane discard is not the deciding barrier). But unlike the differential-flagged t1ha1 / SeaHash, aes2r's actual break is the **integral** (chosen-plaintext Λ-set) — an attack class the SAT axis structurally cannot reach, and one ChainHash neutralises through the feedforward at deployment depth ([§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)). It is the sharpest illustration on this shelf that "Resistant to SAT KPA" is a statement about the absence of a SAT hook, not about security.

### 3.5. SAT-free algebraic & differential pre-screen

Axis C is hours-long; it is the wrong instrument for triaging a candidate primitive. This pre-screen is the cheap triage that runs first. Two Monte-Carlo / exact-algebra batteries — [`avalanche_screen.py`](scripts/redteam/itb/theory/_common/chainhashes/avalanche_screen.py) and [`differential_screen.py`](scripts/redteam/itb/theory/_common/chainhashes/differential_screen.py) — measure the **ChainHash lo-lane as a function of the seed at a fixed data buffer**: the inner primitive in the chain, not the full ITB envelope. The envelope's barrier (per-pixel `noise_pos` / rotation) is primitive-independent and is characterised separately in [archive/REDTEAM.md Phase 2g](archive/REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based); the pre-screen asks only the upstream question a solver depends on — **does the inner primitive hand a SAT/SMT solver a structural hook to grab?** A primitive with no hook is exactly the case where, under its PRF assumption, no efficient recovery exists and Bitwuzla / Z3 cannot help the attacker; a primitive with a hook is a candidate for the expensive Axis C confirmation.

The pre-screen extends coverage beyond the four full-axis shelf primitives to three additional non-cryptographic mixers chosen to span the failure modes: **murmur3** (MurmurHash3_x64_128) and **xxhash64** (XXH64) as one-way table mixers of a different topology (accumulator vs multiply-xorshift), and **splitmix64** as an explicitly **invertible** mixer. These three are pre-screen primitives only — they are not wired into the Go harness and are not taken through Axis A–C; the pre-screen is precisely the SAT-free substitute for that wiring. Their Python mirrors are parity-checked bit-for-bit against the `mmh3` / `xxhash` reference libraries (murmur3, xxhash64) and the canonical seed-0 vector sequence (splitmix64).

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
| **aesitb128** ([§3.10](#310-reduced-round-primitive-control--aes-itb-128-shipped-through-chainhash)) | 0.000 | 0.018 | 0.086 | 32.0 | 16 | 20 | **Y** |

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
| **aesitb128** ([§3.10](#310-reduced-round-primitive-control--aes-itb-128-shipped-through-chainhash)) | 0.009 | 0.000 | at uniform baseline — yet one-pair invertible (`inv` Y) |

**aes2r — the [§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash) reduced-round-cipher control, screened for completeness.** Unlike the single-call mixers above, aes2r (2-round AES) is **not saturated at round 1**: its seed → output avalanche fills in over the chain (`deg@16` 7 → 15, `avw/64` 19.7 → 29.5 by round 3) because each call is two AES rounds, not one mix. It carries no GF(2)-affine hook (`lin_score` 0) and no cheap structural inverse (`inv` N), and the differential battery flags it (`ddt8_max` 1.000) — but that signal is dominated by the final-round AddRoundKey (the seed is the AES key, XORed past the last S-box), not an exploitable data-differential, which in any case dies through the feedforward by rounds = 2 ([§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)). Critically, **neither battery sees the integral** — the actual break of 2-round AES (chosen-plaintext Λ-set, [§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash)). It is the clearest case on this shelf that the pre-screen is **necessary, not sufficient**: a primitive can read clean on the affine / degree hooks and still fall to an attack class these batteries do not measure. The head-to-head harness (`scripts/redteam/itb/theory/_common/stats_comparison_a2r_a128.py`) reads the same 2-round diffusion floor directly on the data-avalanche axis at M = 10⁵: 16.06 ± 2.79 output bits flip per data-bit flip against the 64 ± 5.66 ideal, and 11 520 of 15 360 (input bit, output bit) pairs are dead at the block shape — 75 % of the output bits never move for a given input bit, the 2-round truncated differential in Hamming form.

**aesitb128 — the [§3.10](#310-reduced-round-primitive-control--aes-itb-128-shipped-through-chainhash) shipped reduced-round control, the sibling row.** The two reduced-round rows are placed together as sibling controls, not in shelf order. Where aes2r fills in over the chain, AES-ITB-128 **saturates at round 1** on every Monte-Carlo column (`lin_score` 0, `sac_mean` 0.018, `avw/64` 32.0, `deg@16` 16, `ddt8_max` 0.009 at the uniform band, `const8` 0) — three full AES rounds ahead of a single seed XOR is enough first-order diffusion. The one column that sees its break is the structural flag: `inv` = **Y**, because the seed is a pre-whitening XOR ahead of a public permutation, and one (data, full 16-byte output) pair inverts to the seed under the discard-off lab grant ([§3.10](#310-reduced-round-primitive-control--aes-itb-128-shipped-through-chainhash)) — a raw-primitive property; the shipped pipeline consumes `lo(h_r)` only and never emits the full 16-byte output. Neither battery sees its Square integral either. Alongside aes2r it is the second reduced-round case on this shelf where the pre-screen is necessary, not sufficient — and the one where every measured column reads ideal. The head-to-head harness confirms the ideal data avalanche directly at M = 10⁵: 64.00 ± 5.66 output bits flip per data-bit flip, SAC max 0.0077 against the 0.0082 Bonferroni ceiling, 0 dead pairs of 15 360, at the urandom control's sampling floor on every column.

**Half-cross diffusion (block shape; ideal 32 ± 4 per cell; aesitb128 / aes2r at M = 10⁵ over 3 trials, fnv1a at M = 10⁵ over 1 trial — the digits are identical at M = 10⁴ over 3 trials).** A separate axis of the head-to-head harness — for each single-bit input flip, the mean Hamming weight of the output-half difference, split by input half (lo / hi) and output half (lo / hi). fnv1a is the reference row for a known-unmixed primitive; the pre-screen `inv = Y` flag already names its carry-up T-function on the key path, and the half-cross column exhibits it directly as a zero cell.

| Primitive | Flips | bit in lo → out lo / out hi | bit in hi → out lo / out hi | Reading |
|:----------|:------|-----------------------------:|-----------------------------:|:--------|
| **aesitb128** | data or key | 32.0 ± 4.0 / 32.0 ± 4.0 | 32.0 ± 4.0 / 32.0 ± 4.0 | fully mixed |
| **aes2r** | data | 8.0 ± 2.0 / 8.0 ± 2.0 | 8.0 ± 2.0 / 8.0 ± 2.0 | partially mixed (symmetric, ¼ of ideal — 4 active bytes, 2 per half) |
| **aes2r** | key | 19.4 – 19.5 ± 5.1 / 19.6 ± 6.1 | 19.6 ± 4.6 / 19.2 – 19.3 ± 4.6 | partially mixed (symmetric, ≈ 61 % of ideal) |
| **fnv1a** | data | 18.7 ± 8.7 / 12.8 ± 6.8 | 30.8 ± 4.0 / 30.1 ± 5.0 | partially mixed |
| **fnv1a** | key | 18.3 ± 9.9 / 31.2 ± 3.5 | **0.0 ± 0.0** / 18.7 ± 10.3 | half-independent (T-function fingerprint — a hi-half key bit never reaches the lo output half) |

The half-cross reads the 32 / 32 ideal in every (input half × output half) cell for aesitb128, a symmetric but truncated 8 / 8 for aes2r on data (4 active output bytes across one round of ShiftRows, 2 landing in each half), and a symmetric ≈ 19.5 for aes2r on key. Neither AES primitive is half-independent — ShiftRows crosses the column-pair boundary in one round for both — but the two differ in amount: aesitb128 also reads 32.0 / 32.0 in every cell at shapes 13 / 20 / 36 / 68 (M = 10⁴; shape 20 also at M = 10⁵), and aes2r reads ≤ 16 / 16 on data at every wrapper shape measured (20 / 36 / 68 at M = 10⁴). The fnv1a key-flip row is the didactic zero: the 128-bit state is initialised from the key, and the multiply by 2⁸⁸ + 0x13B (mod 2¹²⁸) is a carry-up T-function, so a hi-half state bit's influence never propagates down to the lo output half. A data-bit flip enters the low byte regardless of position and therefore does not exhibit the T-function zero.

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
| rounds = 1 | one AES2R call (= raw 2-round AES), no feedforward | **Standalone key recovery.** One Λ-set recovers a master-key byte uniquely (≈ 2¹⁶). Fifteen such Λ-sets (plaintext bytes 0–14) plus a 2⁸ brute force of the pad-position byte recover the full 128-bit master key at ≈ 2²⁰ work (3 / 3, `fullkey_aes2r.py`; every Λ-set keeps at least one active output byte inside the lo lane, so the lo-lane discard removes no constraint the recovery uses). Rounds = 1 offers no protection — consistent with §3.4 / §3.6 (structured primitives fall at rounds = 1). **Under the shipped observable** (lo lane, active Λ-set bytes confined to LE32(idx) bytes 0..3, random nonce per set), the same engine at a higher round count (NR = 4 aes2r as an internal round-count control) leaves the 8 visible last-round-key bytes uniquely resolved (8 / 8, 3 trials, `square5_go --model realistic`) while the remaining 8 master-key bytes stay behind the hidden hi lane (2⁶⁴ enumeration, not a recovery): a **partial**, not a break. |
| rounds = 2 | feedforward `k = seed[r] ⊕ h_{r-1}` active | **Distinguisher survives; key recovery fails.** Under the shipped observable (lo lane, order-4 idx cube {0,1,2,3}, 2³² texts × 2 seeds), NR = 2 leaves the lo lane balanced 8 / 8 (`order5_aes2r_go --active 0,1,2,3`) — the raw-primitive r = 2 signal survives at order 4 on the shipped observable, a stronger PRF distinguisher than the earlier order-1 / order-2 lo-lane figures (2, 6). But the feedforward makes the round-1 key `K₁ = seed₁ ⊕ ct₀` **data-dependent** (distinct across the Λ-set), so the integral's last-round peel has no fixed key to guess and **recovery fails** (0 / 5, `keyrecover_r2.py`, both discard modes). The data-differential is already dead at this depth (per-byte differential probability at the max-of-buckets noise floor). |
| rounds = 3 | feedforward accumulated over three calls | **Neutralised on the shipped observable.** Under the same lo lane / idx-only order-4 idx cube {0,1,2,3}, NR = 2 returns 0 balanced lo-lane bytes across 2³² texts × 2 seeds. No distinguisher, no recovery. |
| rounds = 4 (deployment) | ChainHash-4 | **The integral is neutralised entirely.** Under the same shipped observable at NR = 2, the order-4 idx cube returns 0 balanced lo-lane bytes across 2³² texts × 2 seeds; the 1st-, 2nd-, and 3rd-order diagonal Λ-sets (chosen-data lab grants, discard on and off) also return **0 balanced output bytes** — at the random floor. No distinguisher, no recovery. |

**Mechanism — the feedforward dissolves the fixed-key balance the integral requires.** The same intermediate-masking that walls invertible primitives in §3.4 and the partition trapdoor in §3.6: at rounds ≥ 2 the round key is data-dependent, so the integral's "fixed key, structured plaintext" premise breaks. The decisive contrast with FNV-1a is that the integral structure is **not** compatible with the feedforward — it degrades to a distinguisher at rounds = 2 and vanishes by rounds = 4 — whereas FNV-1a's carry-up T-function **is** compatible and survives into deployment ([§3.4](#34-axis-c--sat-kpa-seed-recovery-resistance)). Which reduced-round / below-spec primitive ChainHash neutralises is decided by whether its structured attack survives the data-dependent key, not by the primitive's pedigree. The hi-lane discard is a **secondary** barrier — the standalone break survives the discard entirely (the full 128-bit master key recovers on the lo lane alone) — and the feedforward **depth** is what closes the channel: at rounds = 3 the lo-lane cube is already at the floor, at rounds = 4 the diagonal set is 0 as well.

**Conclusion.** At rounds = 1 the standalone key-recovery pierces the lo-lane truncation entirely; under the shipped observable at a higher round count only a resolved-visible-half partial survives (8 master-key bytes behind 2⁶⁴). At rounds = 2 a stronger PRF distinguisher persists on the shipped observable (lo 8 / 8 at order 4), but key recovery fails. At rounds ≥ 3 the shipped observable is at the floor for orders 1–4 on the counter-byte cube; at rounds ≥ 4 the integral (orders 1–3) and the data-differential are neutralised on the diagonal set as well. The result is conservatively framed: it is these specific engines at these sample sizes and depths that are neutralised, not a proof that no exploitation path exists for so weak a primitive.

**Mechanism generalisation.** The feedforward-depth mechanism — the data-dependent effective round key at r ≥ 2 defeating the fixed-round-key premise — generalises to any chosen-input structured attack that requires a fixed round key across the input structure. BEA-1's partition coset ([§3.6](#36-trapdoor-primitive-control--bea-1-partition-backdoor-through-chainhash)), aes2r's Λ-set integral (this section), and the shipped AES-ITB-128's Square integral on the shipped observable ([§3.10](#310-reduced-round-primitive-control--aes-itb-128-shipped-through-chainhash) — there the data-dependent term lands in the pre-whitening XOR rather than a key schedule, and the set entering the permutation stops being a Λ-set from r = 2 on the lane ITB exposes; on the lo lane at the shipped shapes idx-only counter-byte cubes are at the floor from r = 2 through r = 16) are three measured instances; the same mechanism is predicted to absorb related-tweak differential trapdoors and any other attack sharing the fixed-round-key premise. No instance beyond the three measured ones is empirically confirmed this cycle, and the prediction is scoped to the fixed-key premise itself — a primitive independently weakened by other structural properties (algebraic attacks on its linear layer, key-schedule breaks, and so on) is outside the argument's coverage.

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

§3.1–§3.7 measure the inner primitive through `ChainHash128`. A separate,
primitive-agnostic harness measures the **48-bit Interlocked Barrier core**
directly — the mask-space cardinality and lane-independence the KPA closure
argument rests on — and the wire the Triple facade produces. It ships as Go
tests (`harness_test.go` in the root package for the barrier kernels;
`triple/harness_wire_test.go` for the facade wire) and is characterised in
[REDTEAM.md Phase 4](REDTEAM.md#phase-4--construction-level-creative-probes-triple--interlocked-barrier).
The full-sample statistical loops gate behind `ITB_HARNESS_FULL=1`; the default
`go test ./...` run exercises every assertion on a small sample.

The barrier-core measurements are independent of which primitive keys the
lockSeed, so they belong once at the construction layer rather than per shelf
primitive:

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
the Triple + Interlocked Barrier layer alone (outer cipher off) produces a
COBS-framed container whose byte histogram carries a fixed low-mass signature
— the two byte values that appear in the big-endian 4-byte cleartext W‖H
dimension header written ahead of every container are over-represented by a
relative ≈ +5 % (an absolute excess of ≈ 0.02 pp on the `0x00` rate). The COBS
terminator itself is barrier-scrambled inside a pixel and does not surface as a
raw byte value. Entropy stays ≈ 8 bits/byte and the wire is incompressible. Engaging the outer cipher wrapper whitens the
byte histogram to the uniform floor. Axis B's `|Δ50|` conflict-rate metric is
insensitive to this marginal byte-value signature (it measures a per-shift
distribution, not the raw histogram), so the `neutralized ✓` verdicts stand; the
wire-level format-deniability property is the outer cipher's, scoped in
[REDTEAM.md Phase 4](REDTEAM.md#phase-4--construction-level-creative-probes-triple--interlocked-barrier).

### 3.10. Reduced-round primitive control — AES-ITB-128 (shipped) through ChainHash

[§3.7](#37-reduced-round-primitive-control--2-round-aes-integral-break-through-chainhash) plugs in a **lab** reduced-round primitive (AES cut to 2 rounds, the seed as the AES key) and shows ChainHash's feedforward neutralises its textbook integral. This control repeats the treatment on the reduced-round primitive that **ships** in the registry — **AES-ITB-128** (`aesitb128`, `aesitb.go`; the `ClassNone` inner-PRF-only entry) — and asks the same question at every cascade depth up to the 2048-bit deployment. One AES-ITB-128 call is a nonce-free sponge: `state = fixedKey ⊕ (LE64(seed0) ‖ LE64(seed1))`, then `state = AESRound(state ⊕ block_i, RC[i mod 8])` over the PKCS#7-padded input, then two finalising rounds under `RC[0]`, `RC[1]` — every round a full AESENC (MixColumns included), the constants the NUMS table. The seed enters **once, by XOR, ahead of a fixed public permutation** — there is no key schedule. For a one-block lab input (≤ 15 bytes) the call is exactly three full rounds, a public permutation **P** applied to `fixedKey ⊕ seed ⊕ pad(data)`; the shipped per-pixel inputs (`LE32(idx) ‖ nonce`, 20 / 36 / 68 bytes) absorb 2 / 3 / 5 blocks and run 4 / 5 / 7 rounds. Three standalone-primitive properties follow from the one-block shape, and none is aes2r's — but each carries a strict attacker-observability caveat spelled out inline:

- **Square integral, probability 1** (distinguisher, not a recovery). A Λ-set (one active data byte) through three full AES rounds leaves every output byte balanced for any key — the key only translates the set. Key-independent balance means there is no round key to peel. On the shipped pipeline this reduces to the 8-byte lane the encoder consumes: `lo(h_r)`, 8 / 8 balanced at r = 1 on the one-block lab shape.
- **One-pair inversion** — requires the full 16-byte `h_r`. P is public and invertible; with the full 128-bit output visible, `seed = P⁻¹(output) ⊕ pad(data) ⊕ fixedKey` from one known (data, output) pair. **The shipped pipeline never exposes the full 16-byte output** — only `lo(h_r)` reaches the encoder, and only through the noise-position / rotation / xor-mask projections across two seeds (see `process_generic.go` `blockHash128` and the two-seed loop that follows); the full-state route is a strictly-stronger-than-shipped lab grant kept as a comparative reference below and marked as such.
- **Structured lo-lane recovery, ≈ 2²⁰** — requires the raw-primitive one-block shape and 15 chosen Λ-sets over plaintext bytes 0..14. The last round peels on the two lo-lane columns alone (RC[1] public, InvMixColumns per-column, InvSubBytes), exposing 8 bytes of the round-2 state at the two state diagonals; over a Λ-set active in one input byte each is `m·S(a·S(k_b ⊕ v) ⊕ c) ⊕ e`, and a per-byte 2¹⁶ constancy search over `(k_b, c)` recovers `K = fixedKey ⊕ seed` from the lo lane alone (3840 chosen texts, `keyrecover_r1_2p20.py`; 5 / 5 at the one-block lab shape). Two shipped-observability caveats: (i) this survives only at r = 1 — from r = 2 the feedforward removes the Λ-set (measured, [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth)); (ii) the shipped per-pixel shapes 20 / 36 / 68 confine the attacker's active bytes to the counter-byte column LE32(idx) bytes 0..3 (every other data byte a fresh random constant per message = one message per Λ-set = one fresh nonce per Λ-set), and the engine is out of regime at the shipped 20 / 36 / 68-byte shapes as measured (score 0 / 0 at every position at r = 1 and r = 4, `keyrecover_r1_2p20.py --shape-probe --data-len 20 / --data-len 36 / --data-len 68`, 3 trials each). The ≈ 2²⁰ recovery is therefore a raw-primitive fact about the one-block shape, not a wire attack on any shipped shape.

Methodology is the §3.7 lab style — synthetic `(data, ChainHash)` pairs under a fixed secret seed — with the primitive mirrored bit-exact in `chainhashes/aesitb128.py` (self-checked on import against the 16 `aesitb/aesitb_test.go` generic vectors; `fixedKey` pinned to the reference key and treated as attacker-known, a generous grant — at r = 1 the inversion recovers the effective key block `fixedKey ⊕ seed` whether or not the fixed key is secret). The single attacker observable the shipped pipeline actually presents is `lo(h_r)` (the 8 bytes the encoder consumes), and the shipped nonce model is random-per-encrypt (seen, not chosen). Two strictly-stronger-than-shipped grants are kept as labelled lab comparisons: **discard off, raw** — the full 16-byte `h_r`; and **discard off, P⁻¹-peeled** — the free attacker step P⁻¹ through the last call, which exposes `seed_r ⊕ h_{r−1}` (at r = 1 the seed block itself). A distinct **lo-lane column peel** is an accumulator-side distinguisher step (`w = InvMixColumns(lo ⊕ RC[1][0:8])` on the two lo-lane state columns 0 / 1); it is realistic-observable, produces no key candidate on its own, and is called out inline as a distinguisher wherever it appears. The two names are not interchangeable — the P⁻¹ peel requires the full 16-byte state and never reaches the wire, whereas the column peel operates on the 8-byte `lo(h_r)` the encoder consumes. `rounds` is the ChainHash call count, swept over r ∈ {1, 2, 3, 4, 5, 6, 7, 8, 12, 16}; r = 4 / 8 / 16 are the shipped cascade depths at 512 / 1024 / 2048-bit keys.

**Standalone (r = 1, no feedforward).**

| Screen | Sample | Lo lane — shipped observable | Full state — lab grant (not on the wire) |
|:-------|:-------|:-----------------------------|:-----------------------------------------|
| Λ-set integral, orders 1 / 2 / 3, one-block shape (3 rounds; input all-chosen at that shape) | 2⁸ / 2¹⁶ / 2²⁴ texts per set; 8 seeds (1 at order 3) | **8 / 8 bytes balanced** at every order | **16 / 16 balanced** at every order (lab reference) |
| Λ-set integral, orders 1 / 2 / 3, shipped shapes 20 / 36 / 68 B (4 / 5 / 7 rounds), realistic (idx-only Λ-sets, random nonce per set) | same | 0.0–0.1 balanced (random floor 0.03) | 0.0–0.2 balanced (floor 0.06) — lab reference |
| Λ-set integral, order 4 (four active bytes on a state diagonal — the classic 4-round Square set), shipped 20 B shape, chosen-nonce lab grant (diagonal spans nonce bytes 5 / 10 / 15) | 2³² texts, 1 set (1087 s on 16 cores) | **8 / 8 balanced** (chosen nonce required) | **16 / 16 balanced** (chosen nonce required) — lab reference |
| Λ-set integral, order 4 idx cube {0,1,2,3} (realistic — attacker holds only the four counter bytes), shipped 20 B shape (r = 1 the raw primitive) | 2³² texts, 1 set × 1 seed (the 2-seed check applies at r = 2 in the "Through ChainHash" table below) | 0 / 8 (column set carries only the 3-round property — negative control at the shipped shape) | 0 / 16 (same — lab reference) |
| One-pair inversion | 5 trials; 1 query + 4 attacker-side verification queries | **not exposed on the wire** — the encoder consumes `lo(h_r)` only, so the full-state inverse is unavailable to a wire attacker; a hypothetical partial inverse on the lo-lane columns is the ≈ 2²⁰ structured recovery below | **5 / 5 full 128-bit seed blocks recovered** (lab grant only) |
| Structured lo-lane recovery ≈ 2²⁰ (one-block shape, 15 chosen Λ-sets over plaintext bytes 0..14) | 3840 chosen texts, 5 trials | **5 / 5** K = fixedKey ⊕ seed recovered (raw-primitive fact about the one-block shape; the shipped per-pixel shapes confine the attacker to the counter bytes, and the engine is out of regime at the shipped 20 / 36 / 68-byte shapes — 0 / 0 score at every position at r = 1 and r = 4, `keyrecover_r1_2p20.py --shape-probe --data-len 20 / --data-len 36 / --data-len 68`, 3 trials each) | not applicable (this is the lo-lane engine) |
| Data-differential, single active byte | N = 8192 bases × 3 Δ | `max_dp` 0.0070, **0** zero-diff bytes (uniform band ≤ 0.0083) | `max_dp` 0.0070, 0 zero-diff bytes (lab reference) |
| Output uniformity | N = 10⁵ random inputs × 4 seeds | χ² max 292 / mean 261 (df 255; Bonferroni ceiling 332), bit bias max 0.0049 (ceiling 0.0065), byte entropy ≥ 7.998 | χ² max 303 (ceiling 336), bit bias max 0.0049 (ceiling 0.0068) (lab reference) |
| Output uniformity, head-to-head harness (`rand_pt` / `rand_key`) | N = 10⁶ × 3 trials × 10 (config × shape) cells | χ² max ≤ 313.6 (Bonferroni ceiling 330.5), bit bias max ≤ 0.00176 (ceiling 0.00202), birthday \|z\| max ≤ 2.36 (ceiling 3.14), Shannon ≥ 7.9998 | χ² max ≤ 326.9 (ceiling 334.7), bit bias max ≤ 0.00176 (ceiling 0.00210), birthday \|z\| max ≤ 3.17 (ceiling 3.34) (lab reference) |
| Output uniformity, shipped counter pattern | N = 10⁶ × 3 trials, shapes block / 13 / 20 / 36 / 68 (worst over 15 cells) | χ² max ≤ 327.1 (ceiling 330.5), bit bias max ≤ 0.00153 (ceiling 0.00202), min-entropy ≥ 7.902, birthday \|z\| max ≤ 2.67 (ceiling 3.14) — floor on every shape (shape 13 is the fill-input pattern; see [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)) | χ² max ≤ 327.1 (ceiling 334.7), bit bias max ≤ 0.00161 (ceiling 0.00210), min-entropy ≥ 7.902, birthday \|z\| max ≤ 2.67 (ceiling 3.34) — same floor reading on the full state (lab reference) |

Two readings. The integral is probability-1 at orders 1–3 on the one-block shape and at the random floor at the shipped shapes for those orders — the extra absorbed block(s) add the fourth-plus round a 1st–3rd-order Λ-set does not cross. The classic order-4 diagonal set (2³² texts, active bytes 0 / 5 / 10 / 15) restores balance at the 20-byte shape on both lanes, but the diagonal spans nonce bytes 5 / 10 / 15 and therefore requires a **chosen-nonce** grant the shipped pipeline does not provide (nonces are random per encrypt, seen by the attacker but not chosen); the realistic-attacker counterpart — the counter-byte cube {0,1,2,3} — is a state column, carries only the 3-round property, and is at the floor at the shipped shape (0 / 8 lo, 0 / 16 full, 2 seeds), the expected negative control. The 36 / 68-byte shapes at order 4 all sit at the floor across every shipped depth (r ∈ {2, 3, 4, 8, 16} at shape 36: 0 / 8 raw and 0 / 8 column-peeled at every r; r ∈ {2, 3, 4, 8, 16} at shape 68: 0 / 8 raw and 0 / 8 column-peeled at every r except r = 3 where raw hit 1 / 8 balanced as a single Poisson event at p ≈ 8 / 256). And the primitive reads **uniform on every marginal statistic** — the §3.5 avalanche battery saturates at round 1 (`lin_score` 0, `sac_mean` 0.018, `avw/64` 32.0, `deg@16` 16), the data-differential shows no truncated differential even standalone (every round carries MixColumns; contrast aes2r's final-round-without-MixColumns signature), and the byte / bit marginals sit at the sampling floor — while being one-pair invertible with the full state visible. It is the sharpest illustration on this shelf that avalanche, differential, and uniformity batteries are necessary, not sufficient: the only pre-screen column that sees the standalone break is the structural `inv` flag (Y), and that flag alone does not translate to a shipping-wire attack — every one of the r = 1 standalone recoveries above requires either the discard-off grant or the raw-primitive one-block shape, neither of which the shipped per-pixel pipeline exposes.

**Through ChainHash — the shipped observable (lo lane, idx-only Λ-sets, random nonce per set).**

| Stage | Construction | Outcome on the shipped observable |
|:------|:-------------|:----------------------------------|
| rounds = 1 | one AES-ITB-128 call (= raw primitive), no feedforward | **Integral distinguisher on the lo lane; no key recovery on the shipped shapes.** Order 1 balances the lo lane 8 / 8 at the one-block lab shape (raw 3-round AES property); on the shipped 20-byte shape the order-1 lo-lane column peel `w = InvMixColumns(lo ⊕ RC[1][0:8])` is balanced 8 / 8 as a **distinguisher only** (no key candidate — the 4-round Square distinguisher survives the column peel; raw lo lane 0 / 8 at the same cell); the counter-byte cubes at the shipped shapes are otherwise at the floor for orders 1–3, and the classic order-4 diagonal set that restores balance at the 20-byte shape requires a chosen-nonce grant the wire does not admit. The ≈ 2²⁰ structured lo-lane recovery is a raw-primitive fact about the one-block lab shape and is out of regime at the shipped 20 / 36 / 68-byte shapes as measured (0 / 0 score at every position at r = 1 and r = 4, `keyrecover_r1_2p20.py --shape-probe --data-len 20 / --data-len 36 / --data-len 68`, 3 trials each). The one-pair inversion needs the full state and is not on the wire. |
| rounds = 2 | feedforward `k = seed[r] ⊕ h_{r−1}` active | **At the floor on every shipped-observable cell.** Realistic order 4 = the full 2³² idx cube {0,1,2,3} at the shipped 20-byte shape: 0 / 8 raw, 0 / 8 lo-lane column peel, **2 seeds × 1 set** (`keyrecover_kbyte_go --model realistic`; ≈ 30 s per set at 15 threads). At the shipped 68-byte shape r = 2 same cube: 0 / 8 raw, 0 / 8 column-peeled (32.5 s / set, 1 seed × 1 set). Realistic orders 1 / 2 / 3 at r = 2 shape 20: raw ≤ 0.22 / column-peeled ≤ 0.07 on 15 sets, at the floor. Recovery: **no candidate (structural: the κ peel needs the hidden hi lane; residual = 2⁶⁴ hi-lane enumeration)**. |
| rounds = 3 | ChainHash-3 | **The integral is neutralised on the shipped observable.** Realistic order-4 idx cube at the shipped 20-byte shape: 0 / 8 raw and 0 / 8 column-peeled (1 seed × 1 set, ≈ 190 s at 15 threads); at the shipped 36-byte shape: 0 / 8 raw and 0 / 8 column-peeled (1 seed × 1 set); at the shipped 68-byte shape: 1 / 8 raw (a single balanced byte in one set — one Poisson event at p ≈ 8 / 256), 0 / 8 column-peeled. Realistic order 1 at the 20 / 36 / 68-byte shapes: ≤ 0.05 / 8 balanced (floor 0.03). No recovery (structural). |
| rounds = 4 (512-bit) … 16 (2048-bit) | ChainHash-4 … ChainHash-16 | **At the floor throughout.** Realistic order-4 idx cube at the shipped 20-byte shape at r ∈ {4, 8, 16}: 0 / 8 raw and 0 / 8 column-peeled at each depth (1 seed × 1 set, 29–50 s per set at 15 threads). At the shipped 36-byte shape at r ∈ {2, 4, 8, 16}: 0 / 8 raw and 0 / 8 column-peeled at every depth (1 seed × 1 set, 160–1134 s per set). At the shipped 68-byte shape at r ∈ {4, 8, 16}: 0 / 8 raw and 0 / 8 column-peeled at every depth (1 seed × 1 set, 415–1625 s per set). Order 1 at r ∈ {4, 8, 16}: 0.03–0.07 / 8 raw at the shipped shapes, at the floor. Data-differential `max_dp` 0.0063–0.0076, 0 zero-diff bytes at every r. Output uniformity χ² max 294–329 (ceilings 332 / 336), bit bias max ≤ 0.0053 (ceilings 0.0065 / 0.0068) at every r. No recovery at any r on the shipped observable (structural). |

**Attribution — lab-grant reference (kept because it isolates which grant is load-bearing at which shape).** Three shape-specific cells recover both seed blocks under strictly-stronger-than-shipped grants; the 2 × 2 grant attribution across observable (lo lane vs full state = discard off) and nonce (idx-only vs chosen) shows which grant carries each recovery.

| Cell | Realistic (lo, idx-only) | Chosen data, lo lane | Discard off, idx-only | Discard off, chosen | Load-bearing grant(s) |
|:-----|:-------------------------|:---------------------|:----------------------|:--------------------|:----------------------|
| Fill shape 13 B (T = 3 primitive), r = 2, order 1 (256 chosen texts) — pair-constancy engine, `keyrecover_r2.py` on counter byte 1 | floor at r ∈ {2, 3, 4} (raw 0.00–0.07 / column-peeled 0.03–0.05; 5 trials × 8 sets) | floor 0.03 / 0.00 (byte 0) | **recovers 5 / 5** (counter byte 1) | **recovers 5 / 5** (byte 0) | **discard off** is the sole load-bearing grant (recovery works with idx-only sets under discard off; fails on the lo lane under either nonce model) |
| Shipped 20 B shape (T = 4 primitive), r = 2, 3 Λ-sets — classical 4-round κ-byte engine, `keyrecover_r2_20byte.py` | floor 0 / 5 (5 trials × 8 sets, `keyrecover_kbyte_go --model realistic`) | floor (κ peel needs the hidden hi lane) | **recovers 5 / 5** (768 chosen texts, ≈ 2¹³·⁶ κ guess-sums) | recovers | **discard off** is the sole load-bearing grant (recovery works with idx-only sets under discard off; fails on the lo lane under either nonce model) |
| Shipped 36 B shape (T = 5 primitive), r = 2, order-4 diagonal set (2³² texts) | floor 0 / 8 raw, 0 / 8 column-peeled | floor 0 / 8 raw, 0 / 8 column-peeled (missing κ peel) | fails (idx-only column {0,1,2,3} carries only the 3-round property — set geometry) | **recovers 1 / 1** (22 s at 15 threads; three-hedge cell: discard-off, chosen nonce, below shipped depth r = 4) | **both grants individually load-bearing** — either grant alone leaves the cell at the floor |

The 13-byte and 20-byte r = 2 cells stand or fall on the discard-off grant alone; the wire never emits the hidden hi lane, so both cells sit at the floor on the shipped observable regardless of the nonce model. The 36-byte r = 2 cell needs both grants and still sits below the shallowest shipped cascade (r = 4). No shipped-observable cell in the table above recovers a seed block at any r ≥ 2.

**Mechanism — the feedforward lands in the data slot, not a key schedule; the hi-lane discard is what closes the depth on the shipped observable.** In aes2r the feedforward makes the AES **round key** data-dependent and the Λ-set plaintext still enters the S-box layer intact, so the integral degrades to a distinguisher at r = 2 and dies at r = 4. In AES-ITB-128 the feedforward XORs `h_{r−1}` into the same 16-byte slot the data occupies: from r = 2 the value entering P is `pad(data) ⊕ seed_r ⊕ h_{r−1}(data)`, no longer a Λ-set, so on the lane ITB exposes the integral is at the floor one depth earlier (r ≥ 2) than aes2r's, and any inversion route returns a data-dependent block rather than the seed. The comparative reason a full-state grant would matter for AES-ITB-128 but not aes2r sits in one structural fact: **AES-ITB-128's last call is a public permutation** with the seed as pre-whitening (so `P⁻¹` is free once the full 16-byte output is visible, and Square-style recovery on the peeled input succeeds at r = 2 on the one-block lab shape at ≈ 2²⁵ work and at the shipped 20-byte shape at ≈ 2¹³·⁶ κ guess-sums — the 2 × 2 attribution table above); **aes2r's last call is a keyed permutation** (round keys derived from the seed through the key schedule), so `P⁻¹` needs the key and no free peel exists. This is precisely why the discard-off grant is the load-bearing one for AES-ITB-128 at r = 2 and not for aes2r — and precisely why the shipped pipeline's monolithic-lo-lane consumption is the barrier that supplies the missing depth for AES-ITB-128. On the shipped observable, the lo-lane cell sits at the floor at every r ≥ 2 on every shape measured; the residual generic route through the hidden hi lane is a 2⁶⁴ enumeration, constant in r. Both dissolution depths on the shipped observable (integral at r ≥ 2, no-candidate structural for recovery at r ≥ 2) are below the shallowest shipped cascade (r = 4).

**Comparison with aes2r.** The two reduced-round controls differ in where the seed enters (key schedule vs pre-whitening XOR) and in whether the last round carries MixColumns, and those two differences account for every contrast measured: aes2r's raw break is a master-key-byte peel per 256-text Λ-set at ≈ 2¹⁶ work — the full key from 15 Λ-sets, 3840 chosen texts, discard on or off (`fullkey_aes2r.py`); AES-ITB-128's standalone raw break is a one-query full-seed inversion (with the full 16-byte output visible — a lab grant, not on the wire) plus a lo-lane structured ≈ 2²⁰ recovery on the raw-primitive one-block shape (out of regime at the shipped 20 / 36 / 68-byte shapes as measured). aes2r's integral is key-dependent (a recovery); AES-ITB-128's is key-independent (a distinguisher). aes2r flags the §3.5 differential battery (`ddt8_max` 1.000, final-AddRoundKey term) and shows a truncated data-differential at r = 1; AES-ITB-128 reads at the uniform band on both. On the shipped observable on the counter-byte cube, aes2r NR = 2 leaves the lo lane balanced 8 / 8 at r = 2 (a PRF distinguisher, no recovery) and reaches the floor at r ≥ 3; AES-ITB-128 is already at the floor at r ≥ 2 (0 / 8 raw, 0 / 8 lo-lane column peel). The one-depth advantage AES-ITB-128 shows on the shipped observable follows from where the feedforward lands: in the data slot for AES-ITB-128 (removing the Λ-set at r = 2) versus the key slot for aes2r (leaving the Λ-set intact and only defeating the fixed-key premise the recovery uses). Under the full-state lab grant on AES-ITB-128 the picture reverses — the public-permutation peel puts r = 2 into Square-recovery range at both the one-block shape and the shipped 20-byte shape, an angle aes2r's keyed permutation does not admit — but neither reaches the wire. Identical shipped-observable dissolution depth for the recovery (structural at r ≥ 2 for both); one depth earlier for AES-ITB-128 on the distinguisher.

**Head-to-head statistical comparison.** The mechanism-side account above is complemented by a single-harness statistical comparison of the two raw primitives — the shipped AES-ITB-128 sponge and the aes2r lab control measured under one seed stream, byte-identical input arrays, and one set of shapes / configurations, with `urandom` as the sampling-floor control and `fnv1a` as the half-cross reference for a known unmixed primitive (`scripts/redteam/itb/theory/_common/stats_comparison_a2r_a128.py`). Marginal statistics run at N = 10⁶ × 3 trials × 10 (config × shape) cells per primitive; avalanche and half-cross at M = 10⁵ × 3 bases on the block shape and M = 10⁴ × 3 at every shape. Worst-of-3-trials figures below; "floor" = every listed statistic below its α = 0.01 Bonferroni ceiling. The five axes where aes2r departs structurally from the control map cleanly onto the mechanism paragraph above: the missing final MixColumns (standard last-round shape) explains the counter-pattern and low-byte DDT signatures, and the 2-round diffusion depth explains the data / key avalanche and the half-cross truncation.

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

The table reads: on the random-input marginals and the joint 24-bit-window birthday test aesitb128, aes2r and the urandom control show no measurable difference from each other at N ≤ 10⁶ (every figure below the α = 0.01 Bonferroni ceiling except two single-trial bit-bias events — one on aes2r at 0.00227, clean on fresh seeds 11 – 13, and one on the urandom control at 0.00223, not re-run since it is the expected family-wise rate on the control itself); on the shipped counter-input pattern aesitb128 sits at the control's sampling floor at every shape while aes2r shows a two-part structural signature — 4 constant and 4 sixteen-valued output bytes at the one-block shapes and χ² ≈ 10⁶ with min-entropy 5.39 at the wrapper shapes — traceable in the first case to the last round omitting MixColumns (standard last-round shape) so the column fed by counter byte 2 alone takes exactly as many values as that byte, and in the second case to the same structured first-block output being re-encrypted under the same key; on data avalanche, key avalanche, half-cross diffusion and low-byte DDT aes2r shows structural departures traceable to the 2-round diffusion depth (75 % dead data pairs, 40 % dead key pairs, ¼-ideal half-cross flips, `ddt8_max` 1.000), all of which aesitb128 delivers at the control's ideal. Bounded reading: at these sample sizes and shapes aesitb128's raw output shows no measurable departure from the urandom control on any statistic; aes2r shows structural departures on five axes. No security implication asserted at either end — the compound defence stack (ChainHash cascade, lo-lane discard, the Interlocked Barrier fill consumption chain of [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain), Barrier Part 2) is what closes both primitives' standalone weaknesses, and the mechanism-side account of where and why the two primitives diverge sits above under **Comparison with aes2r**.

**Conclusion.** At rounds = 1, AES-ITB-128 is broken outright as a standalone primitive under lab grants — a one-pair seed inversion with the full 16-byte output visible, a probability-1 Square integral on either lane, and, on the lo lane alone, a measured ≈ 2²⁰ structured Square-style recovery on the raw-primitive one-block shape (3840 chosen texts, `keyrecover_r1_2p20.py`). None of these reach the shipped wire: the encoder consumes `lo(h_r)` only, and the ≈ 2²⁰ engine is out of regime at the shipped 20 / 36 / 68-byte shapes as measured (0 / 0 at every position, r = 1 and r = 4). At rounds = 2 on the shipped observable every cell measured is at the floor (order-4 idx cube {0,1,2,3} at the shipped 20-byte shape: 0 / 8, **2 seeds × 1 set**; at the shipped 68-byte shape: 0 / 8, 1 seed × 1 set); the two r = 2 lab-grant recoveries — one-block lab shape (256 chosen texts, ≈ 2²⁵, `keyrecover_r2.py`) and shipped 20-byte shape (768 chosen texts, ≈ 2¹³·⁶, `keyrecover_r2_20byte.py`) — sit behind the discard-off grant (the wire never emits the hidden hi lane); the shape-36 order-4 diagonal recovery sits behind **both** discard-off **and** chosen-nonce grants (a three-hedge cell also below the shallowest shipped cascade r = 4). At rounds ≥ 3 on the shipped observable no screen returns a signal — the counter-byte cube at shape 36 (r = 3: 0 / 8 raw and column-peeled) and shape 68 (r = 3: 1 / 8 raw = a single Poisson event at p ≈ 8 / 256, 0 / 8 column-peeled), the counter-byte cube at shape 20 at r ∈ {4, 8, 16} (0 / 8 raw and 0 / 8 column-peeled at each depth), the single-byte data-differential (N = 8192 × 3 Δ), and byte / bit uniformity (N = 10⁵) all sit at their sampling floors through r = 16. The shipped cascades (r = 4 / 8 / 16) sit above the dissolution depth on the shipped observable. The lo-lane consumption that separates r = 2 from a key recovery is architectural (only `h[0]` reaches the encoder, and even that only through the noise-position / rotation / xor-mask projections across two seeds — see `process_generic.go` `blockHash128` and the two-seed loop that follows). The result is conservatively framed: it is these specific screens at these sample sizes and depths that read at the floor on the shipped observable, not a proof that no exploitation path exists for a primitive that inverts from one pair standalone; the standalone-weak / inner-PRF-only classification of `aesitb128` stands as measured, and the Interlocked Barrier consumption chain that further absorbs any hypothetically visible lo-lane fill output is described in [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain).

#### 3.10.2. Dissolution mode — cost versus cascade depth

Whether a cascade defence is **structural** (the attack stops working at some depth regardless of budget), **polynomial** (it keeps working at a cost that grows slowly with r), or **exponential** (it keeps working in principle but the cost blows up) is decided per screen by the shape of the cost-versus-r series. For each screen the natural cost metric is tracked across r ∈ {1, 2, 3, 4, 5, 6, 7, 8, 12, 16}: Λ-set order d (N = 256^d chosen texts) for the integral, texts × work for key recovery, sample size N for the differential and uniformity screens. Every row states the attacker observable: the shipped observable is `lo(h_r)` under idx-only Λ-sets and a random nonce per set; lab grants (full state, chosen nonce, raw-primitive one-block shape) are kept as labelled reference rows because they isolate which grant is load-bearing at which depth. Where a cell was not run to completion the reason is the budget, and the cell says so.

| Screen (observable) | r = 1 | r = 2 | r = 3 | r = 4 … 16 | Mode |
|:--------------------|:------|:------|:------|:-----------|:-----|
| Λ-set integral, lo lane, shipped observable (idx-only Λ-sets in LE32(idx) bytes 0..3, random nonce per set) | one-block lab shape (all-chosen input at that raw-primitive shape): balanced at d = 1 (2⁸), probability 1; shipped shape 20 B: floor at d ≤ 3; d = 4 idx cube {0,1,2,3} at the 20-byte shape (2³² texts, 1 seed × 1 set at r = 1) is the negative control — a state column, 3-round property only, 0 / 8; shape 13 (fill-shape counter bytes 1..8, order 1, hypothetical lo-lane exposure): raw 8 / 8 balanced (the 3-round Square on the lane — the output is not exposed on the wire, see [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)) | floor at d = 1..4 on the shipped-shape counter-byte cube (order 4 idx cube {0,1,2,3} at 20 B: 0 / 8 raw, 0 / 8 lo-lane column peel, **2 seeds × 1 set**; at 36 B: 0 / 8 raw, 0 / 8 column-peeled, 1 seed × 1 set; at 68 B: 0 / 8 / 0 / 8 raw / column-peeled, 1 seed × 1 set) | floor at d ≤ 4 on the shipped-shape counter-byte cube — shape 20 at r = 3: 0 / 8 raw, 0 / 8 column-peeled (1 seed × 1 set); shape 36 at r = 3: 0 / 8 raw, 0 / 8 column-peeled (1 seed × 1 set); shape 68 at r = 3: raw 1 / 8, column-peeled 0 / 8 (a single balanced byte in one set, one Poisson event at p ≈ 8 / 256) | floor at d ≤ 4 at every r on the shipped-shape counter-byte cube (order 4 idx cube {0,1,2,3} at shape 20, r ∈ {4, 8, 16}: 0 / 8 raw and 0 / 8 column-peeled at each depth, 1 seed × 1 set; at shape 36, r ∈ {4, 8, 16}: 0 / 8 raw and 0 / 8 column-peeled at every depth; at shape 68, r ∈ {4, 8, 16}: 0 / 8 raw and 0 / 8 column-peeled at every depth) | **Structural on the shipped observable.** The order-d test is the top-monomial test on the d-byte data sub-cube; a floor at every order 1..4 on the counter-byte cube says the degree in the data variables saturates that sub-cube from r = 2 on. Under the shipped-nonce model the attacker holds at most four counter bytes at the per-pixel shapes 20 / 36 / 68 (eight at the fill shape 13, but the fill output is not on the wire, see [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain)), so an on-wire order d ≥ 5 attack has no set to run on at any r; the on-wire ceiling is d = 4 and it is at the floor. |
| Λ-set integral, full state, lab reference (discard off) | one-block shape: balanced at d = 1..3, probability 1; shape 20 B d = 4 diagonal set (2³² texts, chosen-nonce grant — the diagonal spans nonce bytes 5 / 10 / 15): 16 / 16 balanced | one-block lab shape d = 4 diagonal set at data-len 15 (2³² texts, `order4_chainhash.py --data-len 15 --rounds 2`): `h_1` balanced at r = 2 (lab); shipped 20 B d = 4 diagonal set (chosen-nonce grant, 2³² texts, `order4_chainhash.py --data-len 20 --rounds 2`): 0 / 16 (the feedforward removes the Λ-set from r = 2 on) | floor at d ≤ 4 | floor at d ≤ 4 at every r | Lab reference; the shipped pipeline never exposes the full state. |
| Key recovery, shipped observable (lo lane, idx-only, random nonce) | one-block lab shape (raw-primitive): ≈ 2²⁰ structured Square-style recovery of K = fixedKey ⊕ seed (`keyrecover_r1_2p20.py`, 3840 chosen texts, 5 / 5) — the raw-primitive shape the shipped per-pixel pipeline does not use; the shipped 20 / 36 / 68-byte shapes are all out of regime as measured (0 / 0 at every position, r = 1 and r = 4, `keyrecover_r1_2p20.py --shape-probe --data-len 20 / --data-len 36 / --data-len 68`, 3 trials each) | **no candidate (structural: the κ peel needs the hidden hi lane; residual = 2⁶⁴ hi-lane enumeration)** — the lo-lane accumulator on the idx cube is at the floor at shape 20 (5 trials × 8 sets, `keyrecover_kbyte_go --model realistic`), shape 36 (1 seed × 1 set), and shape 68 (1 seed × 1 set) | same at shapes 20 / 36 / 68 at r = 3 — no candidate (structural, 2⁶⁴ residual) | same at shapes 20 / 36 / 68 for r ∈ {4, 8, 16} — no candidate (structural, 2⁶⁴ residual) | **Structural on the shipped observable.** The lo-lane recovery route requires the counter-byte cube to survive the primitive as a Λ-set (r = 1 only, and out of regime at the shipped shapes) or the full state to be visible (never); at r ≥ 2 the accumulator returns no consistent key candidate. The 2⁶⁴ residual is the depth-independent hi-lane enumeration bound. |
| Key recovery, lab reference (discard off) | 1 known text, ≈ 2⁰ (inversion) — full state visible | one-block lab shape: 256 chosen texts, ≈ 2²⁵ (pair-constancy engine, `keyrecover_r2.py`); shipped 20-byte shape: 768 chosen texts, ≈ 2¹³·⁶ κ guess-sums (16 × 2⁸ × 3 Λ-sets; ≈ 2¹² per Λ-set — classical 4-round Square κ-byte engine, `keyrecover_r2_20byte.py`); shipped 36-byte shape: 2³² texts on the order-4 diagonal set at 22 s / set (three-hedge cell — discard off, chosen nonce, below shipped depth r = 4) | fails: inversion 0 / 5; both Square engines 0 / 5 at the 20-byte shape, pair-constancy 0 / 5 at the lab shape (no consistent κ candidate) | fails: inversion 0 / 5 at every r; both Square engines 0 / 5 at r = 4, 20-byte shape (not run beyond) | Lab reference. The shipped pipeline never exposes the full state; every recovery cell in this row sits behind at least one grant the wire does not admit. |
| Data-differential (single active byte) | `max_dp` 0.0070 at N = 2¹³ → 0.0042 at N = 2²⁰ (uniform 1/256 = 0.0039; the band shrinks with N), 0 zero-diff bytes | same | same | same at every r | **No transition** — no measurable signal at N ≤ 2²⁰ at any r including the raw primitive (three full rounds already diffuse a one-byte difference to every byte). |
| Output uniformity (byte χ², bit bias) | at the floor at N = 10⁵ and N = 10⁶; head-to-head harness N = 10⁶ × 3 trials × 3 configurations (`rand_pt` / `rand_key` / `counter`) × 5 shapes (block / 13 / 20 / 36 / 68) all at the floor on the shipped observable, with four α = 0.01 family-ceiling events in 192 lane-cells across the two matrices (two on aesitb128, both at N = 10⁵; one on aes2r; one on the urandom control) — ≈ 1 per criterion per matrix expected under Bonferroni multiple comparison, all non-recurring on fresh seeds (the urandom event not re-run since it is the expected family-wise rate on the control itself) | same | same | same at every r (one α = 0.01 family-ceiling exceedance in 20 lane-cells at N = 10⁶, r = 12 full state, 329.8 vs 327.9 — within the multiple-comparison expectation) | **No transition** — the marginals of a permutation over uniform input are uniform by construction; the screen has no standalone signal to dissolve. |

**Verdict.** On the shipped observable every screen that carries a standalone signal is at the floor from r = 2 on (integral orders 1–4 on the counter-byte cube at shapes 20 / 36 / 68; key recovery is a no-candidate-structural cell with a 2⁶⁴ residual bound). No cell shows a cost that grows with r while the attack keeps succeeding, so neither the polynomial nor the exponential reading applies. The one r = 1 shipped-observable recovery — the ≈ 2²⁰ structured Square-style recovery of K — lives on the raw-primitive one-block shape, which the shipped per-pixel pipeline never uses (the engine is out of regime at the shipped 20 / 36 / 68-byte shapes as measured); the shape-13 fill-shape r = 1 lo-lane balance is a hypothetical that never reaches the wire because the fill output is consumed monolithically through the Interlocked Barrier unrank, see [§3.10.3](#3103-interlocked-barrier-fill-consumption-chain). The lab-grant reference rows show which grant is load-bearing where: discard off alone at the shipped 20-byte shape at r = 2 (idx-only recovers), discard off alone at the fill shape 13 at r = 2 (idx-only on counter byte 1 recovers), discard off plus chosen nonce at the shipped 36-byte shape at r = 2, none at r ≥ 3 anywhere; every recovery on those rows sits behind at least one grant the wire does not admit and below the shallowest shipped cascade (r = 4). The claim is bounded to these ranges and engines: an on-wire structured attack of order ≥ 5 has no set to run on at any per-pixel shape (the counter-byte cube caps at four active bytes), and no such attack is claimed excluded by extrapolation.

#### 3.10.3. Interlocked Barrier fill consumption chain

The barrier fill in the Triple pipeline runs the lockSeed's primitive on the 13-byte one-block shape as a full ChainHash cascade under the prepend construction `lockComps = [K, c[0], …, c[n-1]]` — a secret ChainHash-derived key `K` of the primitive's width (the pair `(lockLo, lockHi)` at width 128) followed by the lockSeed's session components — for every shipped primitive at every width, so every hot-loop call runs the primitive at r = 1 + `keyBits` / `width`: 5 / 9 / 17 at width 128, 3 / 5 / 9 at width 256, 2 / 3 / 5 at width 512, for `keyBits` 512 / 1024 / 2048 (`interlock48_cascade.go` `buildLockBatchPRF48_{128,256,512}`; the cascade is the wire — no hook on the lockSeed selects it, and a primitive's batch-16 kernel, when the name-keyed constructors of the `hashes` package attach it, only evaluates it). The regime where the standalone table's ≈ 2²⁰ lo-lane recovery and the one-pair inversion of `aesitb128` succeed — r = 1 under the derived key — is round 1 of that cascade alone, and its state never leaves the kernel; the cascade output is not visible either. `fillRanks` writes exactly `(lo, hi)` of one cascade over `lockComps` on `0x03 ‖ LE64(groupIdx) ‖ 0⁴` per group at width 128 (measured empirically — one factor per group, one 128-by-30 divmod on the resulting pair through `fillLockMasksTriple48Super`, producing one `(idx0, idx1)` → one mask triple → one 6-byte chunk); at widths 256 / 512 the wider cascade output is sliced into 128-bit pairs, each pair feeding one chunk under the same divmod. The full 128-bit output is therefore consumed **monolithically** per 128-bit slice, not sliced into 48-bit pieces the lo-lane accumulator could ride.

The key `K` heading the hot-loop cascade is not the lockSeed itself — it is the full-cascade output `ChainHash(0x04 ‖ interlock nonce)` on the lockSeed at the primitive's width (`seed128.go` / `seed256.go` / `seed512.go` `deriveInterLockSeed`), computed once per container on both encrypt and decrypt and prepended to the session components at build time (`interlock48_cascade.go`; inner seeds never rotate, so `lockComps` is fixed for the session). Two cascade depths therefore compose across the two stages: the setup runs the primitive at the shipped cascade depth (r = `keyBits` / `width` — 4 / 8 / 16 at width 128 for `keyBits` 512 / 1024 / 2048, the regime [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) places above dissolution for `aesitb128`), and every hot-loop call runs it one round deeper: round 1 under the derived key, which binds the nonce, and rounds 2 .. r under the session components, which keep every component word in the hot loop. The two input domains are disjoint by the leading tag byte — `0x04` at setup, `0x03` in the hot loop — so no fill input coincides with a setup input, and the setup output never reaches the wire, only its role as the first key of the hot-loop cascade. No hot-loop call therefore runs the primitive below the shallowest shipped cascade depth: the r = 1 standalone breaks of the table above and the r = 2 lab-grant recoveries of [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) sit below every depth the fill uses, and the consumption chain below applies on top as defence in depth — the leakage bound does not rest on the cascade depth. The same construction applies to every other shipped primitive at every width: the fill output is a cascade output at every width, and no single-call evaluation of any primitive reaches it.

Under this consumption chain the leakage bound is:

- **A · B = 1355345464406015082330 ≈ 2⁷⁰·² admissible triples**, so at most log₂(A · B) ≈ 70.2 of the 128 output bits reach any observable derived from a single mask triple, with **2¹²⁸ / (A · B) ≈ 2⁵⁷·⁸ preimages per triple** (verified empirically: `rank + A · B` → identical triple 1000 / 1000; a single hi-lane bit flip → different triple 1000 / 1000; a single lo-lane bit flip → different triple 1000 / 1000; partition invariant held throughout).
- The three lanes emerging from a mask triple are Part 2 plaintext, so any wire attack on the barrier fill must **first break Part 2** to see a lane byte at all; every recovery in the standalone table above precedes that step.
- Even the hypothetical grant that supplies a lo-lane fill output admits Λ-sets on plaintext bytes 1..8 only (byte 0 is the fixed domain-separation tag `0x03`, bytes 9..12 are the four zero-padding bytes). The counter-byte cube at the fill shape is at most order 8 in principle, and the shape-13 fill-shape r = 1 lo-lane balance measured at 8 / 8 in [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) is exactly this hypothetical — kept in the table because it names the raw-primitive property, not because the output is exposed.

The composite bound is therefore: a wire attack on the fill output would require breaking Part 2, then holding a monolithic 128-bit consumption of `(lo, hi)` in which the Λ-set structure survives the divmod through C(48, 16) — the divmod is not known to preserve any such structure — with a residual 2⁵⁷·⁸ preimage ambiguity per triple even under a full mask read. The r = 1 standalone breaks in the section above are therefore raw-primitive properties; no exploitation path on the shipped wire is known through this fill regime, and the shape-13 fill-shape r = 1 lo-lane balance measured in [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) is preserved in that table as a raw-primitive property, not a wire attack.

**Empirical closure of the divmod-preservation caveat.** The "divmod is not known to preserve any Λ-set structure" clause in the bound above has been verified empirically at the shipped cascade depths. Order-4 idx cube {0,1,2,3} at shapes 20 / 36 / 68 at r = 4 (the shallowest shipped depth for `keyBits = 512`) is passed through the full fill chain — `ChainHash-4` → `(lo, hi)` split → `splitRank48` divmod → `rankToMaskTriple48` combinadic unrank — and the byte-level XOR-sum balance across the resulting mask triple is measured over the 2³² texts per set. At every shape the mask-triple bytes register **0 / 6 balanced on m0, 0 / 6 on m1, 0 / 6 on m2** (1 seed × 1 set × 2³² texts per shape, ≈ 295 s per set at 15 threads, `scripts/redteam/itb/theory/aesitb128/order4_unrank_go`), matching the h_r primary-observable floor from [§3.10.2](#3102-dissolution-mode--cost-versus-cascade-depth) at the same cells (0 / 8 raw h_r on shape 20 / 36 / 68 at r = 4). The Λ-set has been fully absorbed by the cascade before the divmod stage — the divmod + unrank composition sees uniform-band input and produces uniform-band mask-triple output. This closes the last measurable gap where a hypothetical modular structure through divmod-by-C(48, 16) or the combinadic unrank could have preserved a downstream signal; the composite bound reads as measured, not argued.

## 4. Primitive shelf

Provenance and the published SMHasher weakness each primitive is selected to stress. The per-axis measured results are in [§3](#3-results); the consolidated Axis C seed-recovery verdicts (with the rounds = 1 vs rounds ≥ 2 split) are in the [§3.4 table](#34-axis-c--sat-kpa-seed-recovery-resistance).

| # | Primitive | Published Axis A signature |
|--:|-----------|:---------------------------|
| 1 | **t1ha1_64le** (Yuriev) | Avalanche 3.77–3.95 % at 512–1024-bit keys |
| 2 | **SeaHash** (Ticki, 2016) | PerlinNoise 2.2 × 10¹² × |
| 3 | **mx3** (Maiga, 2022) | PerlinNoise AV 1.48 × 10¹² × |
| 4 | **SipHash-1-3** (reduced-round) | 0.9 % avalanche bias (reduced-round) |

Shelf verdict labels:

- **neutralized ✓** — Axis B passes (`|Δ50| < 1 %`); the published SMHasher weakness does not reach the attacker-observable ciphertext surface.
- **Resistant at tested budget** — Axis C SAT KPA timed out across all tested encodings × backends within the budget. The weakest positive label this shelf emits — always qualified with the measured budget.
- **Dangerous** — the bare or rounds = 1 chain is SAT-broken in commodity time; the deployment-depth (rounds ≥ 2) behaviour is recorded separately in the [§3.4 table](#34-axis-c--sat-kpa-seed-recovery-resistance).
- **Fully broken** — Axis C produced functionally-equivalent K at rounds = 1 AND the rounds ≥ 2 chain is breakable in the same regime.

## 5. Reproduction

Reproduction commands that invoke a `go test` step (directly or through a shell driver) require the `redteam` build tag: `go test -tags redteam ...`. The four Axis-B shell drivers below (one `harness_bias_audit.sh` per primitive under `scripts/redteam/itb/theory/<primitive>/`) already pass the tag internally. The self-parity tests in [§5.5](#55-self-parity-tests) and the pre-screen invocations in [§5.6](#56-sat-free-pre-screen-35) are Python-only and do not require the tag.

### 5.1. t1ha1_64le

```bash
# Axis A — avalanche on raw primitive
python3 scripts/redteam/itb/theory/t1ha1/lab_bias_t1ha1.py \
    --n-keys 65536 --key-sizes 32,64,128 \
    --json-report ~/scratch/redteam/t1ha1stress/axis_a_lab_bias.json

# Axis A' — structural-input bias (json + html × 4 KB / 64 KB)
python3 scripts/redteam/itb/theory/t1ha1/lab_struct_t1ha1.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report ~/scratch/redteam/t1ha1stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/itb/theory/t1ha1/lab_struct_t1ha1.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report ~/scratch/redteam/t1ha1stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/itb/theory/t1ha1/lab_struct_t1ha1.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report ~/scratch/redteam/t1ha1stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/itb/theory/t1ha1/lab_struct_t1ha1.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report ~/scratch/redteam/t1ha1stress/axis_a_struct_html_n4096_65536.json

# Axis B — ITB-wrapped raw-mode bias
bash scripts/redteam/itb/theory/t1ha1/harness_bias_audit.sh

# Axis C — raw chain SAT KPA (rounds = 1 obs = 8, 24 h budget)
python3 scripts/redteam/itb/theory/t1ha1/sat_calibration_raw_t1ha1.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver z3 \
    --json-report ~/scratch/redteam/t1ha1stress/axis_c_raw_z3.json
python3 scripts/redteam/itb/theory/t1ha1/sat_calibration_raw_t1ha1.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver bitwuzla \
    --json-report ~/scratch/redteam/t1ha1stress/axis_c_raw_bw.json
```

### 5.2. SeaHash

```bash
# Axis A
python3 scripts/redteam/itb/theory/seahash/lab_bias_seahash.py \
    --n-keys 65536 --key-sizes 32,64,128 \
    --json-report ~/scratch/redteam/seahashstress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/itb/theory/seahash/lab_struct_seahash.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report ~/scratch/redteam/seahashstress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/itb/theory/seahash/lab_struct_seahash.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report ~/scratch/redteam/seahashstress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/itb/theory/seahash/lab_struct_seahash.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report ~/scratch/redteam/seahashstress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/itb/theory/seahash/lab_struct_seahash.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report ~/scratch/redteam/seahashstress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/itb/theory/seahash/harness_bias_audit.sh

# Axis C — raw chain SAT KPA (4 encodings × 2 backends, 24 h budget)
for MUL in native explicit; do for VAR in native case-split; do for SOLVER in z3 bitwuzla; do
    python3 scripts/redteam/itb/theory/seahash/sat_calibration_raw_seahash.py \
        --rounds 1 --obs 8 --timeout-sec 86400 --solver "$SOLVER" \
        --mul-encoding "$MUL" --var-shift-encoding "$VAR" \
        --json-report "~/scratch/redteam/seahashstress/axis_c_raw_${SOLVER}_${MUL}_${VAR}.json"
done; done; done
```

### 5.3. mx3

```bash
# Axis A
python3 scripts/redteam/itb/theory/mx3/lab_bias_mx3.py \
    --n-keys 65536 --key-sizes 32,256,1024 \
    --json-report ~/scratch/redteam/mx3stress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/itb/theory/mx3/lab_struct_mx3.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report ~/scratch/redteam/mx3stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/itb/theory/mx3/lab_struct_mx3.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report ~/scratch/redteam/mx3stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/itb/theory/mx3/lab_struct_mx3.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report ~/scratch/redteam/mx3stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/itb/theory/mx3/lab_struct_mx3.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report ~/scratch/redteam/mx3stress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/itb/theory/mx3/harness_bias_audit.sh

# Axis C — Z3 reaches Tier 3 in ~5 s on rounds = 1 obs = 8
python3 scripts/redteam/itb/theory/mx3/sat_calibration_raw_mx3.py \
    --rounds 1 --obs 8 --timeout-sec 60 --solver z3 \
    --json-report ~/scratch/redteam/mx3stress/axis_c_raw_z3.json
# Axis C — Bitwuzla reaches Tier 3 in ~2 s on the same cell
python3 scripts/redteam/itb/theory/mx3/sat_calibration_raw_mx3.py \
    --rounds 1 --obs 8 --timeout-sec 60 --solver bitwuzla \
    --json-report ~/scratch/redteam/mx3stress/axis_c_raw_bw.json
```

### 5.4. SipHash-1-3

```bash
# Axis A
python3 scripts/redteam/itb/theory/siphash13/lab_bias_siphash13.py \
    --n-keys 65536 --key-sizes 32,256,1024 \
    --json-report ~/scratch/redteam/siphash13stress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/itb/theory/siphash13/lab_struct_siphash13.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report ~/scratch/redteam/siphash13stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/itb/theory/siphash13/lab_struct_siphash13.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report ~/scratch/redteam/siphash13stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/itb/theory/siphash13/lab_struct_siphash13.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report ~/scratch/redteam/siphash13stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/itb/theory/siphash13/lab_struct_siphash13.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report ~/scratch/redteam/siphash13stress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/itb/theory/siphash13/harness_bias_audit.sh

# Axis C — raw chain SAT KPA (rounds = 1 obs = 8, 24 h budget)
python3 scripts/redteam/itb/theory/siphash13/sat_calibration_raw_siphash13.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver z3 \
    --json-report ~/scratch/redteam/siphash13stress/axis_c_raw_z3.json
python3 scripts/redteam/itb/theory/siphash13/sat_calibration_raw_siphash13.py \
    --rounds 1 --obs 8 --timeout-sec 86400 --solver bitwuzla \
    --json-report ~/scratch/redteam/siphash13stress/axis_c_raw_bw.json
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

`chainhashes/aesitb128.py` is the shipped AES-ITB-128 sponge mirrored in Python (self-tested on import against the `aesitb/aesitb_test.go` generic vectors and against its own numpy batched evaluator; AES building blocks imported from `chainhashes/aes2r.py`). The scripts below are in `scripts/redteam/itb/theory/aesitb128/`; every cascade screen sweeps r ∈ {1, 2, 3, 4, 5, 6, 7, 8, 12, 16}. `--data-len 20` (or 36 / 68) switches any cascade screen to a shipped per-pixel shape. Attacker-model flags follow the `--model {lab, realistic}` convention: `realistic` = lo lane only, idx-only Λ-sets (active bytes ⊆ `LE32(idx)` bytes 0..3), random nonce per set; `lab` = full 128-bit output, chosen data across all input bytes. Every recovery script defaults to the lab grants of the cell it was written for and prints the realistic-model result when passed `--model realistic`.

```bash
cd scripts/redteam/itb/theory/aesitb128

# Raw AES-ITB-128: Λ-set integral (orders 1-3 × one-block and shipped shapes),
# lab-grant one-pair inversion (raw primitive, full state visible).
python3 integral_aesitb128.py

# Pre-screen the aesitb128 primitive — both batteries read clean; `inv` = Y (§3.5 style).
python3 ../_common/chainhashes/avalanche_screen.py    --primitive aesitb128 --rounds-max 4
python3 ../_common/chainhashes/differential_screen.py --primitive aesitb128 --rounds-max 4

# Integral survival through ChainHash (r-sweep × observables). The three
# observables reported per depth are: lo lane (shipped), full state raw (lab),
# full-state P^-1 column peel (lab). The lo-lane column peel `w = InvMixColumns(
# lo ^ RC[1][0:8])` is an accumulator-side distinguisher step (realistic
# observable, produces no key candidate on its own).
python3 distinguisher_chainhash.py      # 1st order, 256 texts/set, 8 seeds/cell
python3 higher_order_chainhash.py       # 2nd order, 2^16 texts/set, 8 seeds/cell
python3 order3_chainhash.py             # 3rd order, 2^24 texts/set, 1 set/cell (~10 min)
python3 order4_chainhash.py --data-len 20 --rounds 1 --workers 16                     # 4th order diagonal set at shipped 20 B shape (chosen-nonce lab grant; classic 4-round set, ~18 min)
python3 order4_chainhash.py --data-len 15 --rounds 2 --workers 16                     # 4th order diagonal set at one-block lab shape, r = 2 (~17 min)
python3 order4_chainhash.py --data-len 20 --rounds 1 --workers 16 --active 0,1,2,3    # shipped-observable order 4 idx cube {0,1,2,3} at 20 B: 3-round property only (negative control at the shipped shape)
python3 order4_chainhash.py --data-len 68 --rounds 2 --workers 16 --active 0,1,2,3    # shipped-observable order 4 idx cube at 68 B, r = 2 (~30 s / set)

# Larger-N distribution screens (§3.10.2 cost-versus-depth table).
python3 differential_chainhash.py --samples 1048576
python3 uniformity_chainhash.py --samples 1000000 --reps 1

# KEY-RECOVERY on the shipped observable (lo lane, idx-only Λ-sets, random
# nonce per set) at the shipped 20 / 36 / 68 B shapes, depths 1..16: no
# candidate (structural — the κ peel needs the hidden hi lane; residual 2^64
# hi-lane enumeration). The `--lab-control` default runs the lab-grant engine
# on the same seeds in the same invocation as the positive control.
cd keyrecover_kbyte_go && go build -o kbyte . && cd ..
./keyrecover_kbyte_go/kbyte --model realistic --rounds 2,3,4,8,16 --sets 8 --trials 5

# INTEGRAL through the full fill chain: order-4 idx cube {0,1,2,3} at the
# shipped 20 / 36 / 68 B shapes at r = 4, passed through cascade + splitRank48
# divmod-by-C(48,16) + rankToMaskTriple48 combinadic unrank, measures byte-
# level XOR balance across the resulting 16-of-48 mask triple (m0/m1/m2, 6
# bytes each) plus the lo/hi lane balance for reference. Closes the "divmod
# is not known to preserve any Λ-set structure" caveat of §3.10.3 empirically
# — the Λ-set has been fully absorbed by the cascade before the divmod stage.
cd order4_unrank_go && go build -o unrank . && cd ..
./order4_unrank_go/unrank --cells 20:4,36:4,68:4 --trials 1 --workers 16

# KEY-RECOVERY, lab reference: pair-constancy engine at the one-block lab
# shape (T = 3 primitive; r = 2 recovers both seed blocks from one Λ-set,
# ≈ 2^25 work; r >= 3 fails).
python3 keyrecover_r2.py

# KEY-RECOVERY, lab reference: classical 4-round Square κ-byte engine at the
# shipped 20 B shape (T = 4 primitive; r = 2 recovers both seed blocks from 3
# Λ-sets = 768 chosen texts under the lab discard-off grant); `--model
# realistic` reruns the same shape and cascade depths under the shipped
# observable (idx-only sets, random nonce) — floor at every depth.
python3 keyrecover_r2_20byte.py
python3 keyrecover_r2_20byte.py --model realistic

# Standalone lo-lane KEY-RECOVERY at r = 1 on the one-block lab shape: the
# ≈ 2^20 structured Square-style recovery of K = fixedKey ^ seed from 15 chosen
# Λ-sets over plaintext bytes 0..14 (5 / 5). Runs may be split via `--trials` /
# `--skip-negative` / `--only-negative`. `--shape-probe DATA_LEN --rounds R
# --positions P0,P1,...` runs the same engine on a shipped per-pixel shape at
# the idx-eligible positions only (reports the winning score margin; no key
# verification — the engine's model does not hold at the shipped shapes).
python3 keyrecover_r1_2p20.py
python3 keyrecover_r1_2p20.py --shape-probe 20 --rounds 1 --positions 0,1,2,3
python3 keyrecover_r1_2p20.py --shape-probe 20 --rounds 4 --positions 0,1,2,3

# Data-differential (N = 8192 bases/Δ) — no truncated differential at any r.
python3 differential_chainhash.py

# Output uniformity (byte χ², per-bit bias, N = 10^5) at r = 1 and every cascade depth.
python3 uniformity_chainhash.py

# aes2r full-master-key recovery on the raw primitive: the aes2r engine extended
# from a byte to the full 128-bit master key (15 Λ-sets over plaintext bytes
# 0..14 + 2^8 pad-byte brute force, discard on and off alike — the same lab
# engine that supports the §3.7 r = 1 row).
python3 ../aes2r/fullkey_aes2r.py

# aes2r at NR = 4 under the shipped observable: the partial resolution of the
# 8 visible last-round-key bytes with the master key behind the hidden hi lane
# (2^64), the §3.7 r = 1 shipped-observable row.
cd ../aes2r/square5_go && go build -o square5 . && cd -
../aes2r/square5_go/square5 --model realistic --nr 4 --rounds 1,2,4 --trials 3

# aes2r at NR = 2 on the shipped-observable order-4 idx cube {0,1,2,3}: the
# r = 2 lo-lane 8 / 8 distinguisher referenced from §3.7, plus r = 1 / 3 / 4.
cd ../aes2r/order5_aes2r_go && go build -o order5aes2r . && cd -
../aes2r/order5_aes2r_go/order5aes2r --active 0,1,2,3 --nr 2 --rounds 1,2,3,4 --seed 20260906

# Head-to-head statistical comparison against aes2r (raw primitives, one harness,
# byte-identical inputs). Full matrix at N = 10^5 (all configs × shapes; ~6 min);
# marginal confirmation at N = 10^6 (~15 min); half-cross + data-avalanche
# confirmation at M = 10^5 on the block shape (~10 min).
python3 ../_common/stats_comparison_a2r_a128.py --all --samples 100000 --bases 10000 --trials 3 --seed 1 --json ~/scratch/redteam/aesitb128/stats_comparison_1e5.jsonl
python3 ../_common/stats_comparison_a2r_a128.py --config marginal --samples 1000000 --trials 3 --seed 1 --json ~/scratch/redteam/aesitb128/stats_comparison_1e6.jsonl
python3 ../_common/stats_comparison_a2r_a128.py --primitive aesitb128 --shape block --config avalanche --bases 100000 --trials 3 --seed 1 --json ~/scratch/redteam/aesitb128/stats_comparison_aval1e5.jsonl
# (repeat with --primitive aes2r / urandom / fnv1a for the aes2r / urandom / fnv1a rows)
# Summary tables from any JSONL:
python3 ../_common/stats_comparison_a2r_a128.py --report ~/scratch/redteam/aesitb128/stats_comparison_1e6.jsonl
```
