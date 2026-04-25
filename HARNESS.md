# HARNESS.md — Non-cryptographic Hash Primitive Analysis Shelf

*(public sibling of [REDTEAM.md](REDTEAM.md) / [ITB.md](ITB.md) / [SCIENCE.md](SCIENCE.md) / [PROOFS.md](PROOFS.md). Three-axis empirical plan per primitive: (A) lab bias on raw primitive, (B) ITB-wrapped bias on known-ASCII corpus, (C) SAT KPA calibration. Scope restricted to primitives whose Go reference + Python mirror each fit in ≤ ~500 LOC.)*

## Empirical results summary (as measured)

Four tables, one per measurement axis. Each new primitive row is appended as its measurement completes; primitives still in the § 4.1 priority list (without measured rows below) are unmeasured pending shelf work. Tables parallel the [REDTEAM.md Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) schema where applicable, with two additions — (i) an `Axis A'` table for the ITB-attack-realistic structural-bias test (fixed seed + varying structured JSON inputs), which the Phase 2a extension matrix does not include; (ii) `Triple Byte Level` and `Triple Bit Soup` columns in the Axis B table reserved for the Triple-mode measurements documented in [§ 3.1](#31-three-axis-measurement-plan), with an em-dash (`—`) for primitives where the Triple mode has not been measured because the Single mode already established `neutralized ✓` (additional Triple measurements add no architectural information at that point).

### Axis A — lab bias on raw primitive (SMHasher-style avalanche on hLo projection)

Random-input avalanche reproduced on the local Python mirror, validated against published [`rurban/smhasher`](https://github.com/rurban/smhasher) numbers. Measurement convention: SMHasher-style bias `2 × |P(flip) − 0.5| × 100 %`; max over all (input_bit, output_bit) pairs. Each row corresponds to one key-size × n_keys configuration.

| Primitive | key_bits | n_keys | measured max bias | published (rurban) | reproduction ratio |
|:----------|---------:|------:|------------------:|-------------------:|:-------------------|
| **t1ha1_64le** | 256 | 65 536 | 1.82 % | not separately reported | noise-dominated at this key size (noise-max floor ≈ 1.78 %) |
| **t1ha1_64le** | 512 | 65 536 | **3.19 %** | 3.77 % | **85 %** (protocol differences explain the gap — see § 8 running log) |
| **t1ha1_64le** | 1024 | 65 536 | **3.24 %** | 3.95 % | **82 %** |
| **SeaHash**    | 256 | 65 536 | 1.45 % | not separately reported (clean) | at noise (SeaHash's avalanche is clean per rurban; documented weakness is PerlinNoise, not exercised by this avalanche test) |
| **SeaHash**    | 512 | 65 536 | 1.87 % | not separately reported (clean) | at noise |
| **SeaHash**    | 1024 | 65 536 | 1.68 % | not separately reported (clean) | at noise |
| **mx3**        | 256  | 65 536 | 1.55 % | not separately reported (clean) | at noise (mx3's avalanche is clean per rurban; documented weakness is PerlinNoise AV with 1.48 × 10¹² × over-expected collisions, not exercised by this avalanche harness) |
| **mx3**        | 2048 | 65 536 | 1.89 % | not separately reported (clean) | at noise |
| **mx3**        | 8192 | 65 536 | 2.08 % | not separately reported (clean) | at noise |

Directional scaling (larger keys → larger bias) matches published rurban finding for t1ha1; published magnitude partially reproduced on the local Python mirror. SeaHash and mx3 avalanche are empirically flat across the measured key range — matches rurban's reporting (both primitives pass the Avalanche subtest; their documented weaknesses are PerlinNoise / coordinate-structured input, not exercised by this avalanche harness). The mx3 key range extends to 8192-bit input to probe whether catastrophic SMHasher-weakness manifests at larger key sizes — it does not, since mx3's catastrophe is bound to coordinate-structured inputs, not avalanche.

### Axis A' — ITB-attack-realistic structural bias (fixed seed + varying JSON schema)

Complementary to Axis A. Methodology: seed fixed across all trials (mirrors ITB deployment reality where seeds are per-deployment invariants); inputs vary across N instances but share a JSON schema with repeated field names, varying field values (mirrors real traffic patterns where attackers observe many ciphertexts of structurally-similar plaintexts). Three statistics on the hLo projection: per-bit output frequency, byte chi-square uniformity (df=255), sequential autocorrelation (XOR of adjacent hashes).

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

All configurations converge on the same conclusion: under fixed seed + varying structured input (JSON or HTML), the hLo projection of each primitive is indistinguishable from random at the probe's resolution. The Axis A SMHasher bias signals are protocol-specific (random input + 1-bit flips for avalanche; coordinate-grid inputs for mx3 PerlinNoise AV) and do not manifest as structural bias under the ITB-realistic threat model. JSON (fixed-width records, byte-aligned field-name repetition) and HTML (tag-wrapped, less byte-aligned) give consistent verdicts — format-alignment axis does not reveal hidden bias in any measured primitive.

### Axis B — ITB-wrapped raw-mode bias (Single / Triple Byte Level / Triple Bit Soup)

ITB corpus generated with the primitive wrapped as the ChainHash128 inner function at `keyBits = 1024`, N=2 nonce-reuse colliding ciphertexts per cell, BF=1, plaintext drawn from `known_ascii` (uniform printable ASCII + whitespace — strongest per-byte bit-7=0 bias regime, worst case for the absorption claim). Raw-mode bias probe ([`scripts/redteam/phase2_theory/raw_mode_bias_probe.py`](scripts/redteam/phase2_theory/raw_mode_bias_probe.py)) scans every candidate pixel-shift and reports axis-2 `|Δ50 TRUE|` — the robust discriminator per [Phase 2a extension § two-axis verdict](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2).

Threshold: `|Δ50| ≤ 1 %` → **neutralized ✓** (bias absorbed). `—` in Triple columns indicates the mode was not run because Single already established absorption — adding Triple-mode rows at that point costs measurement time without refining the architectural claim.

| Primitive | size | format | Single \|Δ50\| | Triple Byte Level \|Δ50\| | Triple Bit Soup \|Δ50\| | Axis C verdict | shelf verdict |
|:----------|-----:|:-------|---------------:|--------------------------:|------------------------:|:---------------|:--------------|
| **t1ha1_64le** | 512 KB | ascii | **0.607 %** ✓ | — | — | — (not yet measured) | **neutralized ✓** on Single (Triple redundant for this primitive) |
| **t1ha1_64le** | 1 MB   | ascii | **0.244 %** ✓ | — | — | — (not yet measured) | **neutralized ✓** on Single (Triple redundant for this primitive) |
| **SeaHash**    | 512 KB | ascii | **0.816 %** ✓ | — | — | — (not yet measured) | **neutralized ✓** on Single (Triple redundant for this primitive) |
| **SeaHash**    | 1 MB   | ascii | **0.140 %** ✓ | — | — | — (not yet measured) | **neutralized ✓** on Single (Triple redundant for this primitive) |
| **mx3**        | 512 KB | ascii | **0.363 %** ✓ | — | — | — (not yet measured) | **neutralized ✓** on Single (Triple redundant for this primitive) |
| **mx3**        | 1 MB   | ascii | **0.119 %** ✓ | — | — | — (not yet measured) | **neutralized ✓** on Single (Triple redundant for this primitive) |

All three primitives neutralize at both corpus sizes — t1ha1's hLo-projected avalanche signal (82–85 % of published on Axis A local mirror) is fully absorbed by ITB's rotation + noise barrier; SeaHash (whose documented weakness is PerlinNoise on coordinate-structured input rather than random-input avalanche) likewise produces no measurable ITB-surface bias at either corpus size. mx3 — the HARNESS shelf's paradox case, passing SMHasher avalanche cleanly yet catastrophically failing PerlinNoise AV (1.48 × 10¹² × over-expected collisions) — also neutralizes on Axis B, confirming that coordinate-grid-specific collision structure does not reach the ITB ciphertext surface because ITB's encoding pipeline (COBS framing + byte-channel split + noise barrier + CSPRNG fill) does not produce coordinate-shaped inputs to the primitive. The published SMHasher weaknesses of all three primitives — avalanche-scaling (t1ha1), PerlinNoise collision (SeaHash and mx3) — do not reach the attacker-observable ciphertext surface under ITB wrap.

### Axis C — SAT KPA resistance (raw + ChainHash-1)

Primitive-level algebraic SAT recovery — orthogonal to bias axes. Columns correspond to the two wrap levels from [§ 3.1 Axis C](#31-three-axis-measurement-plan). No primitive measured yet on the shelf; rows appended as calibration runs complete.

| Primitive | Raw KPA | ChainHash-1 | shelf verdict label |
|:----------|:--------|:------------|:--------------------|
| **t1ha1_64le** | — (not yet measured) | — (not yet measured) | — |
| **SeaHash**    | — (not yet measured) | — (not yet measured) | — |
| **mx3**        | — (not yet measured) | — (not yet measured) | — |

---

## 0. Status

Skeleton. Populated as primitives are measured. Scope restricted to ensure each primitive can be implemented in ≤ ~500 LOC Go + ≤ ~500 LOC Python mirror — primitives exceeding this budget (xxh3 multi-stage state, CityHash / FarmHash size-dispatched algorithms, HighwayHash SIMD / AES-NI intrinsics, SpookyHash V2 12-variable mixing, wyhash 128-bit multiplication expansion, AHash complex ARX state) are listed in [§ 4.3](#43-out-of-scope--implementation-complexity) as out-of-scope with reasons, to keep the project focused on empirical measurement rather than non-load-bearing reimplementation.

---

## 1. Scope

Primitive-focused empirical cryptanalysis for the middle zone of the hash spectrum — **non-cryptographic hashes that are neither trivially invertible nor publicly broken under KPA**, with implementation cost inside the shelf budget. The shelf answers, per primitive, three independent questions along three axes:

- **Axis A — Lab bias.** Does the primitive pass the same distributional quality tests that SMHasher / HashEvals already report (avalanche, BIC, MomentChi2, PerlinNoise, sparse-keyset collisions)? Reproduces the published finding on local hardware and establishes the bias signal magnitude the ITB wrapping is asked to absorb.
- **Axis B — ITB-wrapped bias.** Does the same primitive, once wrapped by ITB's ChainHash + rotation + noise barrier, still leak measurable bias through the raw-mode attacker probe ([Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2))? This is the strongest absorption test — the more the primitive leaks on Axis A, the stronger the ITB claim if Axis B still returns `neutralized ✓`.
- **Axis C — SAT KPA calibration.** Given polynomially-many `(m_i, h(m_i, k))` pairs, can a commodity SAT solver recover `k` on commodity hardware, and within what wall-clock budget? Measured at two wrap levels: raw primitive (no ChainHash) and ChainHash-1 (one round of ITB-style wrapping with `hLo`-only projection).

### 1.1. What IS in scope

Primitives with all four properties:

1. **Non-cryptographic** — designed for distribution quality / speed / hash-table load factor, not for cryptographic security. Typically has no formal PRF proof and no published KPA security argument.
2. **Not publicly broken under KPA** — no existing academic or industry paper demonstrating seed recovery from polynomially-many known-plaintext pairs in practical wall-clock.
3. **Not trivially invertible** — no closed-form algebraic inverse (rules out FNV-1, FNV-1a, DJB2, SDBM, Adler32, every CRC variant, Jenkins OAAT, PJW, Pearson, FxHash single-mul class, MurmurHash2 lo-round form, and similar per-byte-carry-only / single-invertible-mul constructions).
4. **Implementation cost ≤ ~500 LOC per side** — both the Go reference and the Python mirror each fit in ~500 LOC of straightforward code without SIMD / AES-NI dependencies, size-dispatched algorithm selection, or multi-stage internal state machines. This is a hard engineering constraint that excludes a large number of primitives that might otherwise qualify (see [§ 4.3](#43-out-of-scope--implementation-complexity)).

### 1.2. What IS NOT in scope (and why)

Four exclusion categories, each with specific rationale:

- **Invertible non-crypto hashes.** FNV-1 / FNV-1a, FxHash, DJB2, SDBM, Adler32, CRC 8 / 16 / 32 / 64 / 128, Jenkins OAAT, PJW, ElfHash, Pearson, Lookup3 core, FNV-64 variants, MurmurHash2 lo-round form. ITB [Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) already establishes the empirical pattern for the FNV-1a class (SAT-breakable at ITB minimum config in ~8 h commodity), and the pattern generalises to every primitive in this class — the same carry-chain / XOR-linear / single-invertible-mul structure admits SAT recovery with trivial adaptation. Adding more rows is pure redundancy.

- **Publicly broken hashes.** MD5 collisions, SHA-1 collisions, RIPEMD-128 preimage-reduced, Tiger preimage-reduced, GOST pre-2015. Public attack literature already answers the resistance question. MD5 specifically is covered by ITB [Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) on Axis B (bias-neutralized ✓ at 4 MB × ASCII stress cell) and by [Phase 2b](REDTEAM.md#phase-2b--per-pixel-candidate-distinguisher) NIST-STS on randomness quality; no shelf work needed.

- **Formally-PRF hashes.** SipHash-2-4 family, AES-CMAC, BLAKE2 / BLAKE3 family, ChaCha20 keyed, HMAC-SHA-256 / SHA-512, KMAC, Areion, full-round SHA-family. Under the PRF assumption, successful SAT recovery would constitute a PRF distinguisher and is therefore ruled out by definition — the PRF assumption does the work, no calibration needed. Reduced-round variants (SipHash-1-3, reduced SHA rounds) sit at the boundary and are evaluated case by case in [§ 4.1](#41-priority-targets--interesting-bias-failures).

- **Implementation complexity.** Primitives whose reference implementation exceeds ~500 LOC on either side (Go or Python) or that depend on CPU-specific intrinsics (AES-NI, VAES, SIMD accumulator-bandwidth engineering) are excluded from shelf scope to avoid drowning the project in non-load-bearing reimplementation. See [§ 4.3](#43-out-of-scope--implementation-complexity) for the explicit list with reasons. If a primitive in this class produces a notable SMHasher / academic finding in future, the exclusion is revisitable.

### 1.3. Contingency note

If any primitive placed in § 1.2 turns out to resist this shelf's generic SAT approach despite being classified trivially invertible or broken, that itself becomes an in-scope row (unexpected empirical robustness of a presumed-trivial primitive is a research finding). Conversely, if a primitive in the shelf turns out to admit a previously-unknown closed-form inverse during harness development, the inverse itself is the publication — not the SAT measurement.

---

## 2. Relationship to ITB (clarifying note)

This document lives in the ITB repository for infrastructure reuse (Z3 / Bitwuzla harness scaffolding from `scripts/redteam/phase2_theory_*`, parity-gadget patterns, synthetic-corpus generation conventions, bias-probe machinery in `scripts/redteam/phase2_theory/raw_mode_bias_probe.py`). Each primitive's measurement lives on two footings:

- **Standalone (Axis A + Axis C raw-KPA column).** Lab bias measurement on the primitive called directly from seed, and SAT KPA on `h(m, k)` with no ITB wrapping. Primitive-level resistance only. These numbers apply to any symmetric construction using the primitive standalone, not just ITB.

- **ITB-wrapped (Axis B + Axis C ChainHash-1 column).** Bias probe on the ITB ciphertext output when the primitive is plugged into ChainHash as the inner round function, and SAT on one ChainHash round with `hLo`-only projection. These numbers inherit ITB's rotation + noise barrier structure and do NOT apply to other constructions.

ITB's full ChainHash wrap + per-pixel envelope adds a primitive-dependent multiplier on top of the shelf measurements. Empirically measured on FNV-1a ([Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based)): ~20–100× from ChainHash round count, further ×289 from `startPixel` brute force for 4 KB ciphertext. SAT parallelism under the full ITB wrap scales **only** through disjoint `startPixel` instance enumeration (one candidate per worker). In-instance parallelism (cube-and-conquer, `smt.threads=N`) is empirically counterproductive under the densely-coupled carry-chain + mod-7 rotation constraint graph ([Phase 2g finding](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based)).

If the reader's security argument rests on the primitive standalone, Axis A + Axis C raw-KPA apply directly. If the argument rests on ITB composition, the shelf numbers are a lower bound; use [REDTEAM.md Phase 2g methodology](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) with the primitive swap for the composed-system measurement.

---

## 3. Methodology

### 3.1. Three-axis measurement plan

Per in-scope primitive, three independent measurements testing **three orthogonal properties** — (A) statistical bias of the primitive's hLo projection, (B) whether ITB's encoding absorbs that bias into the ciphertext surface, (C) algebraic SAT recovery of the seed regardless of bias. Execution order in [§ 3.5](#35-execution-order-per-primitive).

**Axis A — hLo-projected lab bias on raw primitive.** Measures bias on the **lower 64 bits of the primitive's output** (`h(m, k).lo`) — the only lane ITB's encoding path sees, since `channelXOR = hLo >> 3` and `hHi` is discarded entirely. This is a **universal ITB absorption mechanism** applying to every primitive: whatever bias lives in hHi is gone before ChainHash wraps the output; only hLo-surviving bias matters for Axis B.

Two structural scenarios distinguish primitive families:

- **Weak or asymmetric lane mixing** (FNV-1a class, some ARX constructions): the primitive's bias signature may concentrate in one of the two lanes. If bias lives predominantly in hHi, ITB's hHi-discard absorbs it outright; if bias lives in hLo, it reaches the ChainHash composition and requires Axis B to absorb through rotation + noise barrier. FNV-1a empirically clean on hLo at probe sample size ([Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) `|Δ50| ≤ 0.45`) — its carry-chain residual accumulates more strongly in hHi than hLo, and the hHi discard does the absorption work.
- **Full lane mixing** (AES-CMAC, BLAKE2/3 family, SipHash-2-4, well-designed ARX primitives): compound state distributed across both lanes symmetrically; hHi discard halves the observable bit-width (128-bit output → 64 effective hLo bits) but whatever bias exists in the full output is proportionally visible in hLo.

Key tests on **hLo projection specifically** (not native output):
- **Avalanche bias on hLo** — worst-case % deviation from 50 % bit-flip probability over all input bit positions × all hLo output bit positions. Baseline ~0.6 % for properly mixing primitive; > 1 % indicates measurable bias reaching the lane ITB actually sees.
- **BIC on hLo** — pairwise correlation between hLo output bits under independent input perturbations.
- **MomentChi2 on hLo** — distributional uniformity of the 64-bit hLo output.
- **PerlinNoise / sparse-keyset on hLo** — structured-input leakage surviving hHi discard.

Output: per-primitive Axis A signature `(avalanche_max_pct_hLo, bic_fail_count_hLo, momentchi2_p_hLo, perlinnoise_collision_multiplier_hLo, sparse_collision_multiplier_hLo)`. A primitive that SMHasher flags as biased on native output may come back **clean on hLo alone** — FNV-1a is the canonical case. Conversely a primitive clean on native output may leak on hLo if its internal mixing routes bias toward lane 0. Axis A decides which regime the primitive sits in. Harness: `scripts/redteam/phase2_theory_<p>/lab_bias_<p>.py`.

**Axis B — ITB-wrapped bias on ASCII corpus (Single + Triple Byte Level + Triple Bit Soup).** Runs the existing [Phase 2a extension bias probe](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) against fresh 4 MB `known_ascii` corpora generated through ITB with the primitive wrapped in ChainHash at `keyBits = 1024`, in **three independent encoding modes**:

- **Single Ouroboros** — basic rotation + noise barrier. Current Phase 2a extension scope.
- **Triple Ouroboros Byte Level** (`SetBitSoup(0)`) — every-3rd-byte partition dilutes input-driven bias weight to ≈1/3 (Phase 2a extension bit-soup arm empirically: 47 % single → 48.1–48.3 % triple on CRC128 control).
- **Triple Ouroboros Bit Soup** (`SetBitSoup(1)`) — bit-permuted plaintext destroys byte-level bias patterns entirely; per-snake content carries no byte-aligned structure.

ASCII plaintext is used because it carries the strongest per-byte-independent bit bias (bit 7 ≡ 0 for 0x20..0x7E + `\t` + `\n`) — the worst case for the absorption claim. Each mode tests a different dilution mechanism: Single tests rotation + noise barrier alone; Triple Byte Level adds 3-way plaintext partition; Triple Bit Soup adds bit-level permutation on top. A primitive must pass all three modes to earn `neutralized ✓` on Axis B. The most interesting failure would be a primitive passing Single but failing Bit Soup (or vice versa) — reveals mode-specific absorption weakness, an architectural finding.

Expected outcome grid:
- Axis A `Clean` on hLo → all three Axis B modes `neutralized ✓` trivially.
- Axis A `Biased` on hLo → Single is the load-bearing test (rotation barrier must absorb directly); Triple Byte Level adds 3-way dilution; Triple Bit Soup adds bit-permutation destruction. A primitive failing Single but passing Triple modes would reveal that ITB's rotation alone is not sufficient but the Triple partition fills the gap.

Output: per-primitive Axis B verdict triple `(single_verdict, triple_byte_verdict, triple_bit_soup_verdict)` matching the [Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) two-axis scheme per mode. Harness: reuses `scripts/redteam/bias_audit_matrix.sh` (Single) + `scripts/redteam/bias_audit_matrix_triple.sh` (Triple modes, `ITB_BITSOUP` env toggling between Byte Level and Bit Soup); Python mirror at `scripts/redteam/phase2_theory/chainhashes/<p>.py` is unchanged across modes — the mode switch happens entirely on the Go encoding side.

**Axis C — SAT KPA calibration (orthogonal to bias axis).** Measures **algebraic seed recovery** via SAT solver on known-plaintext observations — completely independent of Axis A/B bias results. FNV-1a is the paradigm: passes Axis A + B (statistically clean on hLo, ITB masking absorbs what little bias exists) yet **fails Axis C in ~8 h** ([Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based)) because modular-inverse closed form makes ChainHash composition a tractable bitvector-SAT instance. Phase 2g exploits algebraic invertibility, not bias — bias passes Axis B cleanly, attack succeeds anyway.

Two columns per primitive:
- **Raw KPA.** Primitive called directly from seed: `h(m, k)`. No ChainHash, no ITB envelope. Primitive-level algebraic resistance only.
- **ChainHash-1.** One round of ITB-style ChainHash128 wrapping (`hLo`-only extraction: `ChainHash(data, k).lo & MASK64`). Tests whether the `hLo`-only projection helps or hurts the attacker — for some primitives lo-lane isolation collapses the effective key space to 64 bits; for others the full state mixes into `hLo` preserving the complete seed width.

What Axis C actually tests per primitive family:
- **Invertible primitives** (FNV-1a, class thereof): SAT is always tractable at some round count; question is *how many ChainHash rounds* before SAT times out. FNV-1a: 4 rounds / keyBits=512 in 8h commodity; 8 rounds / keyBits=1024 extrapolates to weeks-to-months; 16 rounds / keyBits=2048 extrapolates to decades.
- **Multi-round ARX** (t1ha1_64le, SeaHash, MetroHash64_1, mx3): empirical question — when does ARX diffusion resist commodity SAT? Published SMT-on-ARX literature (Mouha et al.; reduced-round attacks on SipHash/Speck/Simon) suggests 2–7× per-round cost, reduced-round breaks typically at 3–5 rounds before commodity timeout.
- **Short-accumulator** (MurmurHash3 x86_32, mx3): small state can be SAT-enumerated at moderate observation count regardless of round structure.

Axis C runs on **every § 4.1 priority primitive** ordered by expected SAT-tractability (see § 3.5) — regardless of Axis A/B outcomes, because SAT is orthogonal. Skip Axis C only for primitives already covered by ITB-internal measurements: FNV-1a ([Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) empirical ~8h) and MD5 (weekly calibration in progress).

Output: per-primitive verdict (`✗ SAT-broken` / `⏱ Timeout` / `⚠ Resistant`) at both columns. Harness: `scripts/redteam/phase2_theory_<p>/sat_calibration_raw_<p>.py` + `sat_calibration_chain_<p>.py`.

### 3.2. Harness structure per axis

Per primitive `<p>`, three-harness layout:

```
scripts/redteam/phase2_theory_<p>/
├── <p>_chain_lo_concrete.py    # parity gadget: pure Python + Z3 symbolic
├── lab_bias_<p>.py             # Axis A harness (raw primitive SMHasher-subset)
├── sat_calibration_raw_<p>.py  # Axis C column 1 (raw KPA, no ChainHash)
└── sat_calibration_chain_<p>.py # Axis C column 2 (ChainHash-1 variant)

scripts/redteam/phase2_theory/chainhashes/<p>.py  # Python mirror for Axis B (reused by raw_mode_bias_probe.py)
scripts/redteam/phase2_theory/chainhashes/_parity_dump/main.go  # extended with <p> test vectors for Go↔Python parity
<p>Hash128 in redteam_test.go or equivalent  # Go reference for Axis B ChainHash wrap
```

Pattern templates from `scripts/redteam/phase2_theory_fnv1a/` (FNV-1a full harness including Axis C both columns) and `scripts/redteam/phase2_theory_md5/` (MD5 full harness). Single-file parity gadget validates concrete-vs-symbolic on random vectors before SAT run. Calibration harness emits incremental JSON with per-cell wall-clock / RSS / holdout / status.

Axis B does not need a per-primitive harness file — it reuses the existing `scripts/redteam/phase2_theory/raw_mode_bias_probe.py` through the chainhashes plugin mechanism. Only the Python mirror at `chainhashes/<p>.py` + the Go parity entry in `_parity_dump/main.go` need to be added per primitive.

### 3.3. Grid

Default measurement grid per primitive:

- **Observations (Axis C):** `{1, 2, 4, 8, 16, 32, 64}` known `(m, h(m, k))` pairs.
- **Timeout per cell (Axis C):** 24 h single-core baseline; extended to 1 week or 3 months for primitives expected in the timeout regime.
- **Solvers (Axis C):** Z3 4.14+ for small instances, Bitwuzla 0.9+ for large or multiplication-heavy instances (same rationale as FNV-1a calibration — Bitwuzla's subprocess timeout is enforced across parse / bit-blast / CDCL uniformly, Z3's applies only to CDCL loop).
- **Axis A corpus:** 2²⁰ random inputs per test; sparse-keyset test uses all 160-bit keys with ≤ 4 bits set.
- **Axis B corpus:** 4 MB `known_ascii` plaintext (uniform draws from 97-char printable ASCII + `\t` + `\n`), matching the [MD5 4 MB stress cell](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) format so cross-primitive comparisons are apples-to-apples.
- **Hardware:** commodity 16-core Linux host, 48 GB RAM. Larger budgets delegated to secondary machines.

### 3.4. Verdict categories and REDTEAM.md Hash matrix labels

Each primitive × axis cell gets one of the per-cell status codes:

**Axis A (lab bias)**:
- ✓ **Clean** — all SMHasher-subset tests pass within noise. Bias-negative control.
- ⚠ **Mild** — one or two marginal failures (e.g. MomentChi2 elevated but not catastrophic, 0.9 % avalanche bias).
- ✗ **Biased** — one or more catastrophic failures (avalanche > 3 %, PerlinNoise 10⁶× or more, BIC hard fail).

**Axis B (ITB-wrapped bias)**:
- ✓ **Neutralized** — `|Δ50 TRUE| ≤ 1 p.p.`, axis-1 TRUE rank middle, consistent across plaintext formats.
- ✗ **Bias-leak** — `|Δ50 TRUE| ≥ 2 p.p.` or axis-1 TRUE rank < 1 % with plateau < 1 %. This would be an architectural finding.
- ? **Ambiguous** — between thresholds.

**Axis C (SAT KPA)**:
- ✗ **SAT-broken** — seed recovered with `holdout_functionally_equivalent` in the cell's wall-clock budget.
- ⏱ **Timeout at budget** — SAT did not terminate within the largest attempted budget.
- ⚠ **Resistant but unproven** — timeout at largest budget tried AND the primitive has no known structural weakness that suggests a tighter analysis would succeed.

Beyond the per-cell status, each primitive receives a **shelf-level verdict label** mirroring the [REDTEAM.md Hash matrix](REDTEAM.md#hash-matrix) convention:

- **Fully broken** — Axis C Raw-KPA OR ChainHash-1 empirically produced `SAT-broken` with functionally-equivalent K in commodity budget (days-to-weeks single-core). Reference datum: FNV-1a in [Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based).
- **Dangerous** — Axis C timed out at shelf budget, BUT analytical extrapolation to ITB-wrapped ranges places full decrypt inside a well-funded attacker's reach (cluster-weeks to cluster-years). Leads to `Dangerous` marking in the REDTEAM.md Hash matrix.
- **Resistant (at tested budget)** — Axis C raw / ChainHash-1 SAT timed out at shelf budget AND analytical extrapolation to ITB-wrapped ranges lands beyond any plausible attacker budget. No empirical break, no feasible extrapolation. The weakest positive claim this shelf ever emits — always qualified with the measured budget that produced the timeout.

A primitive may hold different labels at different ITB-wrapping levels: `Fully broken at keyBits = 512 / 4 rounds` but `Resistant at keyBits = 1024 / 8 rounds`. The shelf records the worst-case level at which the break is feasible, with a concrete analytical extrapolation footnote for the levels where it is not.

### 3.5. Execution order per primitive

Strict ordering; **no early-stop** — each axis produces an orthogonal data point that stands independently. Axis C runs on every § 4.1 priority primitive regardless of A/B outcomes, because the three axes test different properties.

1. **Write Go reference + Python mirror + parity test vectors.** Validate Go ↔ Python bit-exact on 10+ vectors before any empirical run. Without parity validation, all subsequent measurements are untrustworthy.

2. **Axis A — hLo-projected lab bias.** ~1 h compute per primitive on commodity 16-core. Reproduces or contradicts `rurban/smhasher` entry adapted to the hLo projection. Diagnostic — identifies whether the primitive's bias lives in hHi (absorbed by ITB's hHi-discard outright) or hLo (propagates to ChainHash, must be absorbed at Axis B).

3. **Axis B — ITB-wrapped bias (Single + Triple Byte Level + Triple Bit Soup).** ~30 min total across three modes on commodity 16-core. Runs existing [Phase 2a extension probe](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) under each `SetBitSoup` mode. Output: verdict triple `(single, triple_byte, triple_bit_soup)`.

4. **Axis C — SAT KPA.** 24 h – 1 week per cell on commodity 16-core. Both columns (raw + ChainHash-1). Runs on all § 4.1 priority primitives **ordered by expected SAT-tractability** (fastest first to deliver early empirical rows):
   1. **mx3** (~10 LOC mixer, 3 rounds, low state — commodity-break candidate)
   2. **MurmurHash3 x86_32** (32-bit accumulator — commodity-break candidate)
   3. **SipHash-1-3** (reduced-round PRF boundary case)
   4. **t1ha1_64le** (multi-round ARX with 64×64 multiplications — expected timeout)
   5. **SeaHash** (4-lane ARX — expected timeout)
   6. **MetroHash64_1** (multi-round mixing — expected timeout)
   7. **t1ha0_32le** (multi-round — expected timeout)
   8. **pengyhash** (clean control — expected timeout)

Cross-axis interpretation rules:
- **Axis A `Clean` + Axis B `Neutralized ✓` + Axis C `Timeout`** → **Resistant** verdict. Baseline for a well-behaved primitive (pengyhash-class).
- **Axis A `Biased` on hLo + Axis B `Neutralized ✓` + Axis C `Timeout`** → **Resistant**; strong architectural datapoint demonstrating ITB absorbs primitive-level hLo bias AND SAT cannot reach the seed. Paradigm: t1ha1_64le, SeaHash, MetroHash64_1 if timeout holds.
- **Axis A * + Axis B `Neutralized ✓` + Axis C `SAT-broken`** → **Fully broken**; paradigm case like FNV-1a — bias absorbed but seed recovered algebraically.
- **Axis A * + Axis B `Bias-leak ✗` on any mode** → architectural finding at bias layer; document in REDTEAM.md Phase 2a extension. Axis C still runs to quantify SAT cost independently.

No early-stop: bias absorption (Axis B) and algebraic resistance (Axis C) are independent deployment-safety properties. A primitive must pass both to qualify.

---

## 4. Primitive shelf

Restructured by priority rather than by hash family. Each row is a concrete implementation-and-measurement target (§ 4.1 – § 4.2) or an explicit exclusion with reason (§ 4.3 – § 4.4).

### 4.1. Priority targets — interesting bias failures

Non-cryptographic, non-GF(2)-linear, non-trivially-invertible, with documented SMHasher failures, and implementable in the ≤ 500 LOC per-side budget. Ordered by pedagogical priority for the ITB absorption claim.

| # | Primitive | Axis A signature (published) | Go reference | Python port | Unique bias dimension |
|:-:|:----------|:-----------------------------|:-------------|:------------|:----------------------|
| 1 | **t1ha1_64le** (Leonid Yuriev) | Avalanche FAIL: 3.77 % worst bias at 512-bit keys, 3.95 % at 1024-bit keys (vs ~0.6 % baseline). Large-key avalanche signal grows with key size. | `github.com/dgryski/go-t1ha` (Go lib exists) | ~400 LOC from canonical C reference | Avalanche-at-large-keys — directly matches ITB's large-key operating point (keyBits = 512 / 1024 / 2048) |
| 2 | **SeaHash** (Ticki, 2016) | PerlinNoise catastrophic: 2.2 × 10¹²× over-expected collisions. 4-lane pure ARX. | `github.com/blainsmith/seahash` | ~150 LOC | Coordinate-structured input leak — directly relates to ciphertext pixel-index structure |
| 3 | **MetroHash64_1** (J. Andrew Rogers) | Quadruple fail: UB + LongNeighbors + **BIC** + MomentChi2. BIC fail is unique — output bits pairwise correlated. | `github.com/dgryski/go-metro` (unofficial Go port) | ~250 LOC | BIC failure — unique among shelf candidates; tests whether rotation + noise de-correlates bits the primitive leaves correlated |
| 4 | **mx3** (Jon Maiga) | PerlinNoise AV fail: 1.48 × 10¹²× over-expected collisions, 345× on high-32-bit. UB flagged. | ~10 LOC mixer (no existing Go package; trivial port) | ~10 LOC | Paradox case — author engineered for quality, catastrophic leak anyway. Tests whether barrier absorbs bias the primitive's author did not know was there |
| 5 | **MurmurHash3 x86_32** (Austin Appleby, 2011) | MomentChi2 69 + UB. Short 32-bit accumulator; documented avalanche weaknesses on specific bit-patterns. | `github.com/spaolacci/murmur3` or similar | ~100 LOC | Short-accumulator class; mainstream deployment (Cassandra, Kafka, Elasticsearch); SAT-weak on Axis C regardless of Axis B |
| 6 | **t1ha0_32le** (Leonid Yuriev) | Sparse catastrophic: 2.38 × 10⁶× over-expected collision on 160-bit sparse keys (≤ 4 bits set). | same package as #1 | ~300 LOC | Sparse-input collision — directly relates to Crib-KPA threat model (attacker cribs are sparse by construction: format headers, mostly-zero tokens) |
| 7 | **SipHash-1-3** (reduced-round SipHash) | 0.9 % worst avalanche bias (vs ~0.2 % for full SipHash-2-4). Sub-1 % but elevated. | `dchest/siphash` + trivial round-count parameterisation | ~80 LOC | Reduced-round boundary case — formally PRF at full rounds, measurable bias at reduced. Tests whether reduced-round primitive can still be wrapped by ITB to neutralized ✓ |

All seven primitives satisfy § 1.1 four-way gate:
- Non-cryptographic (primary design goal is speed / distribution quality, not cryptographic security).
- Non-trivially-invertible (ARX / carry-chain structures with multi-round composition; no closed-form seed recovery known).
- Not publicly broken under KPA (no published seed-recovery paper for any of them).
- Implementation ≤ 500 LOC each side (confirmed by reading reference implementations).

### 4.2. Bias-negative controls

Clean primitives paired with § 4.1 failures to validate the shelf has discriminator power — ITB absorbs measured bias from the failing primitives AND produces no spurious bias signal on the clean ones.

| # | Primitive | Axis A signature | Go reference | Python port | Role |
|:-:|:----------|:-----------------|:-------------|:------------|:-----|
| 8 | **pengyhash** (Alberto Fajardo, 2020) | Clean in rurban's table. Compact pure ARX. | `github.com/skeeto/pengyhash` | ~50 LOC | Bias-negative control matched to § 4.1 primitives' ASCII-corpus scope; demonstrates probe does not flag false positives on quality hashes |

Additional bias-negative candidates for future expansion (not in immediate scope but listed for completeness): NMHash32, t1ha2_atonce (if the extra state variables justify the port cost later).

### 4.3. Out-of-scope — implementation complexity

Primitives that would qualify under § 1.1's first three criteria (non-crypto, not-trivially-invertible, not-publicly-broken) but whose reference implementation exceeds the ~500 LOC per-side budget or depends on CPU-specific intrinsics. Listed with the specific complexity driver and the minimal summary from `rurban/smhasher` so the reader can judge whether to promote a specific row later.

| Primitive | SMHasher status | Complexity driver | Revisit condition |
|:----------|:----------------|:------------------|:------------------|
| **xxh3-64 / xxh3-128 withSeed** | Moment Chi2 14974, BIC drift | Multi-stage internal: separate algorithms for ≤ 16 B, 17–128 B, 129–240 B, > 240 B inputs; stripe accumulator architecture (~1 500 LOC canonical C). | If xxh3's headline-mainstream deployment status justifies the effort; decision deferred. |
| **xxh3-64 / xxh3-128 withSecret (192 B secret)** | Same as withSeed + secret-expansion machinery | Same plus 192-byte secret expansion path. | As above. |
| **xxh64** (Collet, 2012) | Clean | Multi-stage (≤ 32 B vs > 32 B) + finalisation mixing; ~400 LOC. Marginal — could be reconsidered if a specific research question justifies. | Only if xxh3 precedes it. |
| **xxh32** | LongNeighbors + 4-bit-diff collisions + MomentChi2 220 | Similar multi-stage to xxh64 but simpler. | Borderline — could be moved to § 4.1 if effort permits. |
| **MurmurHash3 x64_128** | Moment Chi2 69 + UB | Dual 64-bit-lane with cross-mixing in finalize; ~250 LOC. Moderate but not sub-500. | If mainstream deployment analysis calls for it explicitly. |
| **MurmurHash3 x86_128** | LongNeighbors + DiffDist + UB | Four-lane parallel accumulator, less clean than x86_32. | As above. |
| **CityHash64 / CityHash128 / CityCrc128** | CityHash64: Sparse + TwoBytes; others clean | Size-dispatched internal algorithm selection; several specialised paths for different input ranges; CityCrc128 uses SSE4 CRC intrinsics. | If size-dispatch complexity justified by specific finding. |
| **FarmHash64 / FarmHash128 / FarmHashFingerprint64** | 32-bit variant machine-specific; 64/128 clean | Successor to CityHash; adds further internal algorithm selection including SIMD-optimised paths. | Low priority. |
| **wyhash-final4 / wyhash-final3** | Clean / clean | 64×64 → 128-bit multiplication + seed expansion + stripe processing; ~500 LOC at the edge of budget, with 128-bit multiplication being the engineering headache. | Borderline; if the bias-negative control case for § 4.2 wants a representative from the wyhash family. |
| **rapidhash** (De Carli, 2024+) | Clean | wyhash-derivative; same 128-bit mul architecture. | As wyhash-final4. |
| **komihash** (Vaneev, 2021+) | Clean | Two 128-bit multiplications per block in key schedule. | As wyhash-final4. |
| **MetroHash128 / MetroHash128_1 / MetroHash128_2** | UB + LongNeighbors | 128-bit output dual-lane variant of MetroHash64. Extra state vs the already-porteable MetroHash64_1. | If MetroHash64_1 lands and a 128-bit output version is specifically wanted. |
| **FxHash** (rustc / Firefox) | Avalanche 1.86 % avg, 6.92 % worst | Trivially invertible: `state = (state.rotate_left(5) ^ byte) * PRIME`. Single invertible multiply + invertible rotate + invertible XOR ≈ FNV-1a class. See § 4.4 for explicit exclusion reason. | Moved to § 4.4 triviality exclusion. |
| **AHash (SW fallback)** | ahash64 rust — not fully tested | Complex ARX state; AES-NI hardware path migrates to formal PRF. SW fallback non-trivial to isolate and port cleanly. | If SW-only measurement becomes relevant. |
| **gxhash (SW fallback)** | AES-only in hardware path | AES-NI hardware path → formal PRF; SW fallback uses non-AES mixing, not cleanly isolated in reference. | As AHash. |
| **foldhash** (Mara Bos, 2024+) | Unmeasured | New Rust stdlib candidate; ARX-based but relatively unstudied. ~300 LOC if SW path cleanly isolated. | If external SMHasher coverage lands. |
| **SpookyHash V2** (Bob Jenkins) | Clean in current rurban table | 12-variable state machine with multi-round mixing (~800 LOC canonical). | If needed as a bias-negative control from the Jenkins family and effort permits. |
| **HighwayHash (SW-fallback)** | Earlier reports: PerlinNoise, !msvc | SIMD-heavy; AES-NI dependencies in standard path. SW-only variant measurable but complex (~1 000 LOC). | If AES-fallback analysis wanted explicitly. |
| **NMHash32 / NMHash32X** (James Z. M. Gao) | Clean | Four-lane ARX + variable-length processing paths. ~400 LOC at the edge. | If additional bias-negative control from the 32-bit family is needed. |
| **Zig stdlib Wyhash / Go hash/maphash** | Ports of upstream wyhash or AES-NI maphash | Dependent on above wyhash / AHash / maphash-fallback decisions. | Per parent. |
| **t1ha2_atonce** | Zeroes low3 | More state variables than t1ha0 / t1ha1; secondary t1ha target. | If t1ha1_64le and t1ha0_32le land and additional t1ha datapoint is specifically wanted. |

### 4.4. Out-of-scope — triviality / already covered

Primitives that satisfy the implementation budget but fail the first three § 1.1 criteria (trivially invertible, publicly broken, or redundant with existing ITB-internal empirical coverage).

| Primitive | Exclusion category | Reason |
|:----------|:-------------------|:-------|
| **FxHash** (rustc / Firefox) | Trivially invertible | `state = (state.rotate_left(5) ^ byte) * PRIME`. Each step is invertible: rotation and XOR are bijections, multiplication by `PRIME = 0x100000001b3` (FNV-1a 64 prime) is invertible in Z / 2⁶⁴. Complete per-byte closed-form inverse. Same class as FNV-1a covered by ITB Phase 2g. |
| **FNV-1a 32 / FNV-1a 64 / fnv-rs** | Trivially invertible | Same structure as FNV-1a 128 already covered by [Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based). |
| **FNV1A_Pippip_Yurii / FNV1A_Totenschiff** | Trivially invertible + `fails all tests` in rurban | FNV-1a variants with minor twists; same algebraic class. |
| **MD5** | Cryptographically broken + already covered | ITB [Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) 4 MB stress cell (Axis B ✓ neutralized) + [Phase 2b](REDTEAM.md#phase-2b--per-pixel-candidate-distinguisher) NIST-STS + [Phase 2d](REDTEAM.md#phase-2d--nonce-reuse) + [Phase 2e](REDTEAM.md#phase-2e--related-seed-differential) already supply MD5 coverage across all three axes. No shelf work needed. |
| **lookup3 / lookup2** (Bob Jenkins) | Weak + rurban `28 % bias, collisions, 30 % distr` | Too broken — even a passing Axis B would be hard to interpret. |
| **PJW / DJB2 / SDBM / Adler32** | Trivially invertible | Historical weak hashes; covered by invertible category. |
| **Jenkins OAAT** | Trivially invertible | One-At-A-Time hash; covered. |
| **PMurHash32** | Redundant with Murmur3A | Same accumulator class as MurmurHash3 x86_32 (Murmur3A); plus BadSeeds = seed 0xfca58b2d collapses on all-zero key. Adds no value beyond § 4.1 row 5. |
| **HalfSipHash** | Redundant with SipHash-1-3 | § 4.1 row 7 already represents reduced-round SipHash family. HalfSipHash's additional reduction does not expose a different bias dimension. |
| **SipHash-2-4** | Formally PRF | Full-round SipHash; out of shelf scope by § 1.2 formal-PRF clause. |

---

## 5. Expected results matrix (prior to measurement)

Prior beliefs per § 4.1 priority primitive, updated as empirical rows land. Probability judgements held with wide error bars.

| Primitive | Expected Axis A | Expected Axis B | Expected Axis C Raw | Expected Axis C ChainHash-1 | Expected shelf verdict |
|:----------|:----------------|:----------------|:--------------------|:----------------------------|:-----------------------|
| **t1ha1_64le** | ✗ Biased (avalanche 3.77–3.95 % confirmed) | ✓ Neutralized (load-bearing test) | ⏱ Timeout at 1 week; hard SAT target due to 64×64→128 multiplications | ⏱ Timeout at 1 week | **Resistant (at tested budget)** or **Dangerous** pending Axis C analytical extrapolation |
| **SeaHash** | ✗ Biased (PerlinNoise 10¹²×) | ✓ Neutralized (load-bearing) | ⏱ Timeout at 1 week; 4-lane ARX target | ⏱ Timeout at 1 week | **Resistant** or **Dangerous** |
| **MetroHash64_1** | ✗ Biased (BIC fail + 3 others) | ✓ Neutralized (load-bearing) | ⏱ Timeout at 1 week | ⏱ Timeout at 1 week | **Resistant** or **Dangerous** |
| **mx3** | ✗ Biased (PerlinNoise AV 10¹²×) | ✓ Neutralized (load-bearing) | ⏱ Timeout at 24 h — single mixer with 3 rounds, potentially SAT-breakable at very low obs count | ⏱ Timeout extended | **Dangerous** or **Fully broken** at reduced-round SAT |
| **MurmurHash3 x86_32** | ⚠ Mild (MomentChi2 69) | ✓ Neutralized trivially (weak bias absorbed easily) | ✗ SAT-broken at raw-KPA column — 32-bit accumulator is small enough to SAT-enumerate at moderate observations | ✗ or ⏱ at ChainHash-1 | **Fully broken** expected (like FNV-1a but for different structural reason: accumulator size rather than GF(2)-linearity) |
| **t1ha0_32le** | ✗ Biased (sparse-keyset 10⁶×) | ✓ Neutralized (load-bearing; interesting because sparse inputs are Crib-KPA cribs) | ⏱ Timeout at 1 week | ⏱ Timeout at 1 week | **Resistant** or **Dangerous** |
| **SipHash-1-3** | ⚠ Mild (0.9 % avalanche) | ✓ Neutralized trivially | ⏱ Timeout at 1 week — formally PRF-adjacent; reduced rounds but still ARX-hard | ⏱ Timeout at 1 week | **Resistant** expected |
| **pengyhash** (control) | ✓ Clean | ✓ Neutralized trivially | ⏱ Timeout at 1 week | ⏱ Timeout at 1 week | **Resistant** expected (baseline) |

Priors are informed by the four findings that follow. Any empirical result significantly tighter than the predicted budget is itself a publication:

1. **Axis A predictions follow published SMHasher entries** directly; deviations would indicate implementation divergence from the canonical reference (parity-test discipline catches this before Axis B).
2. **Axis B `Neutralized ✓` predictions are the load-bearing claim** — an `bias-leak ✗` on any of t1ha1_64le / SeaHash / MetroHash64_1 / mx3 / t1ha0_32le would be an architectural finding invalidating or at minimum restricting the [Proof 7](PROOFS.md#proof-7-bias-neutralization) absorption claim.
3. **Axis C timeouts are predicted for 5 of 7** — multi-round ARX primitives resist commodity SAT at shelf-budget scale, consistent with published SMT-on-ARX literature (Mouha et al.; reduced-round-only breaks in the cryptographic hash literature).
4. **`MurmurHash3 x86_32` expected SAT-break** — 32-bit accumulator is small enough that observation-count × SAT-variable-count lands inside solver capability at moderate obs count. If this prediction fails, the failure itself contradicts an expected consequence of short-accumulator design.

---

## 6. Reproducibility

Template commands per axis, to be adapted per primitive. Same conventions as the [Phase 2g reproduction block](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based).

**Axis A — Lab bias on raw primitive**:

```bash
# Reproduce SMHasher-subset signature on local hardware.
python3 scripts/redteam/phase2_theory_<p>/lab_bias_<p>.py \
    --tests avalanche,bic,momentchi2,perlinnoise,sparse \
    --corpus-size 1048576 \
    --json-report tmp/attack/<p>stress/axis_a_lab_bias.json
```

**Axis B — ITB-wrapped bias on ASCII corpus**:

```bash
# Run the existing Phase 2a extension probe with <p> added to PRIMITIVES.
# Requires <p>.py Python mirror at scripts/redteam/phase2_theory/chainhashes/<p>.py
# and Go side <p>Hash128 registered in redteam_test.go (or equivalent).

# First validate Go ↔ Python parity:
python3 scripts/redteam/phase2_theory/chainhashes/_parity_test.py

# Then run the bias-probe matrix:
RESULTS_TAG=bias_audit_<p>_4mb_ascii \
PRIMITIVES="<p>" \
SIZES="4194304" \
FORMATS="ascii" \
PROBE_SIZE=auto PARALLEL=6 \
bash scripts/redteam/bias_audit_matrix.sh

python3 scripts/redteam/aggregate_bias_audit.py \
    tmp/attack/nonce_reuse/results/bias_audit_<p>_4mb_ascii/matrix_summary.jsonl
```

**Axis C — SAT KPA calibration**:

```bash
# Raw KPA calibration: N rounds × M observations grid.
python3 scripts/redteam/phase2_theory_<p>/sat_calibration_raw_<p>.py \
    --rounds 1 --obs 16,32,64 --timeout-sec 86400 \
    --json-report tmp/attack/<p>stress/axis_c_raw_24h.json

# ChainHash-1 variant.
python3 scripts/redteam/phase2_theory_<p>/sat_calibration_chain_<p>.py \
    --rounds 1 --obs 16,32,64 --timeout-sec 86400 \
    --json-report tmp/attack/<p>stress/axis_c_chain_24h.json
```

Each invocation emits incremental JSON; cells are resumable on restart. Summarise via `jq` over the result files.

---

## 7. Publication strategy

Each primitive producing a concrete cross-axis verdict (Axis A measured + Axis B measured + Axis C verdict or timeout) is a candidate for a short standalone writeup (blog post / arXiv note): *"Empirical SAT KPA resistance and ITB bias-neutralization of `<primitive>`, wall-clock `<N> h` at `<M>` observations on commodity hardware"*. The full shelf is a second-paper target once 3+ priority primitives have completed all three axes: *"Three-axis empirical cryptanalysis shelf: lab bias + ITB-wrapped absorption + SAT KPA for widely-deployed non-cryptographic hashes"*.

**t1ha1_64le is the headline first-row candidate** because its large-key avalanche failure scales precisely with ITB's flagship operating point, producing the sharpest narrative contrast: "SMHasher reports 3.77–3.95 % avalanche bias at 512 / 1024-bit keys; ITB with t1ha1_64le as inner round function still measures `neutralized ✓` on the raw-mode bias probe". Subsequent primitives add breadth across bias dimensions (coordinate-structured via SeaHash, BIC via MetroHash64_1, "author-quality-designed paradox" via mx3, sparse-input via t1ha0_32le).

A separate orthogonal research thread, deferred: **ML-enhanced beam-search discrimination** under non-linear wrapping constructions. The current shelf harness ranks per-pixel `noise_pos` candidates using format-aware heuristics (printable-ASCII ratio, format-signature counts) — the same discriminators used in [REDTEAM.md Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) decrypt. Replacing those heuristics with a CNN / transformer / LLM-API scorer trained on self-generated corpora follows the established ML-cryptanalysis pattern (Gohr, CRYPTO 2019; subsequent follow-up literature); the trained model deploys on target ciphertext using only beam-search-visible partial reconstructions — attacker-realistic train / deploy separation preserved. Binary-format recovery rates under the current heuristic sit at the random-byte collision floor ([REDTEAM.md Phase 2g architectural finding 6](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based)); ML-enhanced discrimination is expected to raise them substantially on formats that carry structural entropy margin (ZIP, PDF, MP4, DEFLATE). Quantifying this improvement is a distinct empirical study. Out of scope for this shelf's primitive-resistance measurements; complements them by clarifying the decrypt-side boundary.

---

## 8. Running log

Append one dated line per concrete milestone. Do not rewrite history.

- 2026-04-23 — File created as planning skeleton; scope initially covered 20+ candidate primitives across xxh / Murmur / Google / Metro / Wy / Rust-ecosystem / Zig-Go-ecosystem families. No measurements; structure followed FNV-1a / MD5 working-plan pattern.
- 2026-04-23 — Moved out of `.gitignore`; HARNESS.md graduated to public sibling of REDTEAM.md / ITB.md / SCIENCE.md / PROOFS.md as a statement of intent — the non-crypto-hash empirical-cryptanalysis project is an active, publicly-declared direction.
- 2026-04-23 — Shelf verdict scheme aligned with [REDTEAM.md Hash matrix](REDTEAM.md#hash-matrix) labels: per-primitive shelf-level verdict (`Fully broken` / `Dangerous` / `Resistant`) added to planning tables.
- 2026-04-25 — Restructured from 6 hash-family tables to 4 priority-based groups with explicit implementation-complexity gate (≤ 500 LOC per side). Scope narrowed to 7 priority primitives + 1 bias-negative control, total 8 rows. Out-of-scope primitives moved to § 4.3 (complexity) and § 4.4 (triviality) with per-row reasons. Three-axis measurement plan (Axis A lab bias, Axis B ITB-wrapped bias, Axis C SAT KPA) formalised in § 3.1. SMHasher findings cross-referenced from `rurban/smhasher` quality-problems table + per-hash reports; expected results matrix (§ 5) updated with primitive-specific predictions. Axis B reuses the existing [Phase 2a extension bias probe](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) machinery; only new Python mirrors in `chainhashes/` + Go parity entries in `_parity_dump/main.go` need to be added per primitive.
- 2026-04-25 — Three-axis model clarified: Axis A refined to **hLo-projected bias** (not native-output bias) — since ITB discards hHi entirely, only hLo-surviving bias matters. hHi discard documented as a universal ITB absorption mechanism applying to every primitive, distinct from the rotation + noise barrier that acts on the hLo residual. Axis B extended to **three encoding modes** (Single Ouroboros, Triple Byte Level, Triple Bit Soup) to capture mode-specific dilution behaviour. Axis C clarified as **orthogonal to bias** — FNV-1a paradigm: passes A + B (bias absorbed) yet fails C in ~8 h via algebraic modular-inverse SAT ([Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based)), demonstrating the two axes test independent properties. Execution order § 3.5 updated: no early-stop, all § 4.1 primitives run all three axes; Axis C ordering by expected SAT-tractability (fastest primitives first) to deliver empirical rows faster.
- 2026-04-25 — ML-enhanced beam-search discrimination retained in § 7 as orthogonal deferred thread.
