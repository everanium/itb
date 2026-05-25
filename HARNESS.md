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

### 3.4. Axis C — SAT KPA resistance (raw + ChainHash-1)

| Primitive | Raw KPA | ChainHash-1 | shelf verdict |
|:----------|:--------|:------------|:--------------|
| **t1ha1_64le** | **Times out at the 24 h budget** on rounds = 1 obs = 8 across Z3 and Bitwuzla | — (rounds = 1 already in timeout regime) | **Resistant at tested budget** |
| **SeaHash**    | **Times out at the 24 h budget** across all 4 encodings (`{native, explicit}` × `{native, case-split}`) on Z3 and Bitwuzla (8 cells) | — (rounds = 1 already in timeout regime) | **Resistant at tested budget** |
| **mx3**        | **SAT-broken** — Tier 3 FUNCTIONAL-EQ at obs = 8 / rounds = 1 (Z3 native ≈ 5 s, Bitwuzla native ≈ 2 s, holdout = 32 / 32) | **SAT-broken** — same wall-clock as Raw KPA (at rounds = 1 ChainHash composition degenerates to a single `mx3_hash` call: hi-lane seed unconstrained, lo-lane seed recovered functionally-equivalent to ground truth) | **Dangerous** — Raw + ChainHash-1 broken in seconds on commodity |
| **SipHash-1-3** | **Times out at the 24 h budget** on rounds = 1 obs = 8 across Z3 and Bitwuzla | — (rounds = 1 already in timeout regime) | **Resistant at tested budget** |

mx3 is the lone `Dangerous` row: the parallel two-lane construction collapses at rounds = 1 (hi-lane seed never enters the chain output's symbolic expression, and the lo-lane seed is functionally recoverable in seconds). Higher-round chains push mx3 into the timeout regime even on commodity budgets. Bit Soup mode (Triple) and Lock Soup overlay (Triple `SetLockSoup(1)` or Single `SetBitSoup(1)`/`SetLockSoup(1)`) are expected to neutralise mx3 at the construction layer; that measurement is not yet on the shelf.

For **t1ha1, SeaHash, and SipHash-1-3** the SAT budget is not the meaningful axis: they carry no invertibility hook, so seed-recovery SAT is **structurally inapplicable** — it times out at the 24 h budget, not for want of compute. Their only surfaced weakness is differential (t1ha1, SeaHash) — see [§3.5](#35-sat-free-algebraic--differential-pre-screen); SipHash-1-3 is clean on every axis. A larger SAT budget does not change this verdict, which is why the figure is reported as a structural property, not a budget-bounded timeout.

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

**What the pre-screen concludes — which primitives a solver could ride.** The screen surfaces four independent solver hooks; a primitive flagged on any one is a candidate for SAT recovery, a primitive clean on all four with `inv = ?` is the only verdict that genuinely requires the Axis C calibration to settle:

1. **GF(2)-affine directions** (`lin_score` or `const8` > 0). SeaHash carries a small affine fraction on both the full-width and low-byte tests — partial linear leakage a solver anchors on.
2. **Biased differential** (`ddt8_max` above the uniform band). t1ha1 (persistent) and SeaHash (round-3 deterministic) expose differential characteristics. This is a hook for a **differential attack** — a different attack class from the seed-recovery the Axis C SAT calibration probes, which times out at the 24 h budget precisely because the weakness is differential, not invertibility. So "Resistant at tested budget" for these two is better read as "no SAT invertibility hook"; the differential hook lives in a separate class the SAT axis structurally cannot reach (and, per [Axis B](#33-axis-b--itb-wrapped-raw-mode-bias), ITB's encoding neutralises it before it reaches a ciphertext anyway).
3. **Low algebraic degree** (`deg@m < m`). None of the mixers are low-degree — all saturate to the sub-cube dimension (deg@16 = 16, deg@20 = 20) at round 1, so there is no cube / higher-order-differential shortcut. fnv1a lags by a single degree (15 / 19), consistent with its simpler carry structure.
4. **Cheap structural inverse** (`inv = Y`) — but this is only a ROUND-1 signal, and it splits in two under the ChainHash feedforward. The Monte-Carlo columns are blind to invertibility, but invertibility alone is NOT the SAT hook. At rounds = 1 (no feedforward) an invertible round map is peeled directly — splitmix64, visually identical to murmur3 / xxhash64 on every diffusion / avalanche / degree / differential column, inverts in seconds because its mix64 is a composition of word-level bijections. At rounds ≥ 2, however, the inter-round XOR `k = seed[r] ⊕ h_prev` masks each round's output, so the solver can no longer peel round-by-round — it must solve the seed through the whole composition, and THAT tractability needs a further property `inv` does not capture: a **triangular / carry-up T-function** structure. fnv1a HAS it (its ×0x13B lo-lane is carry-up-only — output bit t depends only on input bits 0..t → solvable plane-by-plane LSB→MSB, and the feedforward does not break the triangularity). splitmix64 LACKS it — mix64's right-shifts (`z ^ (z>>30 / >>27 / >>31)`) push high bits DOWN into low, destroying triangularity → full algebraic degree, no shortcut. So the two diverge sharply at rounds ≥ 2 (see the SAT figures below): fnv1a stays trivially solvable, splitmix64 becomes SAT-hard despite equal invertibility. High degree and perfect avalanche do not imply SAT-hardness — and neither does invertibility alone; the carry-up T-function structure (which right-shift mixers destroy) is the actual SAT hook.

SipHash-1-3, murmur3, and xxhash64 are clean on all four axes with `inv = ?` — the screen surfaces no hook and defers to the SAT calibration (SipHash-1-3 timed out at the tested budget; murmur3 resists even rounds = 1 via the internal 128→64 discard). mx3 is `inv = Y`, like splitmix64 and fnv1a: the flag correctly predicts its rounds = 1 break (the Axis C `Dangerous` label — a single-call bijection inverted in ≈ 2–5 s), and, being a right-shift mixer with no carry-up T-function, it then resists at rounds ≥ 2 once the feedforward removes the direct-inversion handle (24 h budget). In short, `inv = Y` predicts rounds-1 breakability; only fnv1a's triangular structure carries that break into rounds ≥ 2.

**Empirical confirmation — the round-1-vs-feedforward split (splitmix64 vs fnv1a).** A raw-chain SAT calibration ([`sat_calibration_raw_splitmix64.py`](scripts/redteam/phase2_theory_splitmix64/sat_calibration_raw_splitmix64.py), the same harness shape as the FNV-1a and mx3 Axis C runs) confirms the round-1 reading: at **rounds = 1** (no feedforward) the splitmix64 lo-lane seed is recovered **bit-exact** (Tier 4, holdout 32 / 32) in ≈ 20 s (Z3, obs = 8) / ≈ 25 s (Bitwuzla, obs = 4) — invertibility peels a single round directly. At **rounds = 2**, however, splitmix64 **resists at the 24 h budget on both solvers**: the single feedforward masks the intermediate output, and mix64's right-shifts leave no triangular shortcut for the resulting solve. Contrast the ISOLATED ChainHash inversion of fnv1a — whose ×0x13B lo-lane is a carry-up T-function — which falls even at **rounds = 4 in ≈ 146 s (Bitwuzla) / ≈ 0.16 s** (the structure-aware T-function solver, which exploits exactly the carry-up triangularity). So splitmix64-rounds-2 (24 h budget) is already orders of magnitude harder than fnv1a-rounds-4 (≈ 146 s) — at FEWER rounds and EQUAL invertibility. That is direct evidence that fnv1a's SAT-tractability comes from its triangular carry-up structure, not from invertibility or round count, and that the right-shifts in mix64 (and in mx3 / BLAKE / real mixers) are what deny the solver that structure. (The ≈ 8 h figure cited for fnv1a elsewhere is the FULL Phase 2g ITB break — ChainHash + the ~90-bit per-pixel noise_pos barrier + 4 public-schema cribs — not this isolated chain inversion.) The pre-screen is therefore **necessary, not sufficient**: `inv = Y` flags only the round-1 weakness; round ≥ 2 SAT-tractability additionally requires the triangular T-function structure, so a clean algebraic / differential row remains a "worth a SAT calibration" signal, never a security verdict.

**Barrier-isolation summary** — which mechanism walls each primitive (the two barriers are independent; real ITB stacks both + noise_pos / LockSoup on top):

| Primitive | round map | discard-hi (internal lo/hi mix) | r = 1 SAT | r ≥ 2 SAT |
|:----------|:----------|:--------------------------------|:----------|:----------|
| **fnv1a** | carry-up T-function (no right-shift) | off (lo independent of hi) | falls | **falls** — triangular structure survives the feedforward (isolated chain r = 4 ≈ 146 s Bitwuzla / ≈ 0.16 s T-solver) |
| **splitmix64** | right-shift bijection (no T-function) | off (lo self-contained) | falls ≈ 20 s | **resists at the 24 h budget** — feedforward masks the intermediate, no triangular shortcut |
| **mx3** | right-shift bijection (no T-function) | off (two-lane independent) | falls ≈ 2–5 s | **resists at the 24 h budget** — same mechanism as splitmix64 |
| **murmur3** | right-shift + internal h1 / h2 **mix** | **on at r = 1** (128→64 projection of mixed state) | **resists** (full 128-bit ≈ 2.1 s vs lo-only timeout) | resists (discard + feedforward stack) |

fnv1a is the only row solvable at r ≥ 2 — its carry-up triangularity is the SAT hook, and it survives the feedforward. The right-shift mixers (splitmix64, mx3) fall at r = 1 only by inverting a single bijection; one feedforward round then walls them. murmur3 is walled already at r = 1 by the internal discard, with no feedforward needed.

**The two screens are complementary.** SAT calibration targets seed recovery (invertibility / T-function) and so catches fnv1a (and mx3 / splitmix64 at rounds = 1), but TIMES OUT on t1ha1, SeaHash, and SipHash-1-3 — they carry no invertibility hook. The differential screen targets a different attack class and catches what SAT misses: **t1ha1** (a persistent biased low-byte differential, ddt8_max ≈ 0.10–0.22 across rounds) and **SeaHash** (a round-dependent differential up to 1.0 plus partial GF(2)-affinity, const8 = 0.031, lin_score = 0.021) are **differential-only** — SAT-resistant yet differentially flagged. **SipHash-1-3** is clean on both (only the Axis A reduced-round avalanche signature marks it). No differential attack is pursued: [Axis B](#33-axis-b--itb-wrapped-raw-mode-bias) already shows ITB's encoding (rotation + noise barrier + COBS) neutralises these raw-primitive differential biases on the attacker-observable ciphertext surface (`|Δ50| < 1 %`), so the hook does not reach a deployed ciphertext. The screen's value is cheap triage of the raw primitive, not an exploit path.

## 4. Primitive shelf

| # | Primitive | Axis A signature (published) | Axis A / A' / B | Axis C |
|--:|-----------|:-----------------------------|:----------------|:-------|
| 1 | **t1ha1_64le** (Yuriev) | Avalanche 3.77–3.95 % at 512–1024-bit keys | measured | **Resistant at tested budget** |
| 2 | **SeaHash** (Ticki, 2016) | PerlinNoise 2.2 × 10¹² × | measured | **Resistant at tested budget** |
| 3 | **mx3** (Maiga, 2022) | PerlinNoise AV 1.48 × 10¹² × | measured | **Dangerous** |
| 4 | **SipHash-1-3** (reduced-round) | 0.9 % avalanche bias (reduced-round) | measured | **Resistant at tested budget** |

Shelf verdict labels:

- **neutralized ✓** — Axis B passes (`|Δ50| < 1 %`) on Single Ouroboros; Triple modes redundant once Single absorption is established.
- **Resistant at tested budget** — Axis C SAT KPA timed out across all tested encodings × backends within the budget. The weakest positive label this shelf emits — always qualified with the measured budget.
- **Dangerous** — Raw chain or ChainHash-1 SAT-broken in commodity time; higher-round chain unmeasured or unreachable at the tested budget.
- **Fully broken** — Axis C Raw or ChainHash-1 produced functionally-equivalent K AND higher-round chain breakable in the same regime.

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
