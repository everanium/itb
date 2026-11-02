## ITB Lean 4 Formal Verification Suite

Machine-checked formal verification of the mathematical, combinatorial, bit-vector, and structural theorems of the ITB symmetric cipher construction in **Lean 4** (`leanprover/lean4:v4.35.0`).

Every theorem in this package is verified from first principles by the Lean 4 kernel using only the standard library (`Init`), with **zero `sorry` placeholders**, **zero user-defined `axiom` declarations**, and **zero external package dependencies**.

---

## Module Architecture

| Module | Scope | Proofs & Sections Verified |
|---|---|---|
| [`ITB/Thresholds.lean`](ITB/Thresholds.lean) | Exact integer exponent bounds, ambiguity dominance thresholds, noise barrier margins, container `side + 1` DRBG residue guarantees, square container third partition (`side^2 mod 3 ∈ {0, 1}`), and `gcd(7, 8) = 1` byte-splitting non-alignment | [PROOFS.md § Proof 4](../PROOFS.md#proof-4-rotation-barrier), [§ Proof 5](../PROOFS.md#proof-5-noise-barrier-bound), [§ Proof 9](../PROOFS.md#proof-9-ambiguity-dominance-threshold), [§ Proof 10](../PROOFS.md#proof-10-guaranteed-drbg-residue-no-perfect-fill), [SCIENCE.md § 2.10](../SCIENCE.md#210-byte-splitting-property) |
| [`ITB/RankBarrier.lean`](ITB/RankBarrier.lean) | Verified Pascal triangle binomial coefficients `C(n, k)`, 48-bit and 168-bit **Rank Barrier** mask space cardinalities, preimage bounds, two-step unrank surjectivity and preimage witness injectivity, `gcd(A, B)` anti-collapse theorems, and Horner `qmod` reduction | [PROOFS.md § Proof 11](../PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier), [§ Proof 12](../PROOFS.md#proof-12-gcda-b-anti-collapse-trap), [SCIENCE.md § 1.2.1](../SCIENCE.md#121-rank-barrier-48-bit-and-168-bit-combinadic-chunk-permutations), [§ 2.15](../SCIENCE.md#215-48-bit-and-168-bit-rank-barrier-mask-spaces-theorem-11), [§ 2.16](../SCIENCE.md#216-gcda-b-anti-collapse-trap-theorem-12) |
| [`ITB/PixelBarrier.lean`](ITB/PixelBarrier.lean) | Bit-accurate `BitVec 7` / `BitVec 8` channel operations (`rotate7`, `unrotate7`, `insertBit`, `extractBits`, `encodeChannel`, `decodeChannel`), `noiseFold3` GF(2)-linearity and full 64-bit single-bit flip sensitivity, `dataHash % 7` vs `dataHash >> 3` full `(rot, mask56)` realizability, round-trip bijections, COA equiprobability bijection, KPA unique mask existence, `startPixel` indistinguishability under CCA, CCA single-bit flip invariance, early-stop query expectation (`35 / 8 = 4.375`), and bias neutralization | [PROOFS.md § Proof 1](../PROOFS.md#proof-1-information-theoretic-barrier), [§ Proof 2](../PROOFS.md#proof-2-per-bit-xor-kpa-resistance), [§ Proof 6](../PROOFS.md#proof-6-cca-leak-upper-bound), [§ Proof 7](../PROOFS.md#proof-7-bias-neutralization) |
| [`ITB/SplitRank168.lean`](ITB/SplitRank168.lean) | 48-bit (`interlockB48Recip = ⌊2^93 / B₄₈⌋`, `interlockA48Recip = ⌊2^105 / A₄₈⌋`) and multi-limb 168-bit (`interlockMuB168 = ⌊2^236 / B₁₆₈⌋`, `interlockMuA168 = ⌊2^342 / A₁₆₈⌋`) reciprocal constants, truncation error envelopes, and single-correction Euclidean exactness for `divB`, `modA`, `divmodStepB168`, `modStepA168`, `splitRank48Recip`, and `splitRank168` in [`interlock48_rank_split.go`](../interlock48_rank_split.go) and [`interlock168_rank_split.go`](../interlock168_rank_split.go) | [PROOFS.md § Proof 11](../PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier), [§ Proof 12](../PROOFS.md#proof-12-gcda-b-anti-collapse-trap), [SCIENCE.md § 1.2.1](../SCIENCE.md#121-rank-barrier-48-bit-and-168-bit-combinadic-chunk-permutations) |
| [`ITB/SeedIsolation.lean`](ITB/SeedIsolation.lean) | 8-seed isolation and pigeonhole minimality across 8 domains, 28-pair cross-domain leakage partition, per-region noise counter disjointness, asymmetric `nonceSplit` (`16`, `32`, `64` B) and 32-bit `xorFold32` bijection on `interlock_nonce`, `ChainHash` full component utilization and two-stage cascade round counts, Full KPA work factor bounds, oracle-free deniability surjection, `Verify-before-COBS` state machine, `Streaming AEAD` cumulative pixel offset monotonicity (`StreamMACInput`), 4-way wire-shape parity (`nomacTagStubSizeCfg`), and dual-nonce axis independence | [PROOFS.md § Proof 3](../PROOFS.md#proof-3-8-seed-isolation), [§ Proof 3a](../PROOFS.md#proof-3a-8-seed-isolation-minimality), [§ Proof 3b](../PROOFS.md#proof-3b-chainhash-full-component-utilization), [§ Proof 4a](../PROOFS.md#proof-4a-multi-factor-full-kpa-resistance), [§ Proof 8](../PROOFS.md#proof-8-oracle-free-deniability), [§ MAC-Inside-Encrypt Composition](../PROOFS.md#mac-inside-encrypt-composition), [§ Nonce Uniqueness](../PROOFS.md#nonce-uniqueness) |
| [`ITB.lean`](ITB.lean) | Top-level library root importing all five verification modules | All theorems |

---

## Correspondence to `PROOFS.md` and `SCIENCE.md`

| Proof / Section | Mathematical Statement | Lean 4 Theorem(s) | Module |
|---|---|---|---|
| **Proof 1**: Information-Theoretic Barrier | For every fixed configuration `(m, r, np)`, `(d, noiseBit) ↦ encodeChannel d m r np noiseBit` is a bijection `BitVec 7 × Bool ↔ BitVec 8` (`256 ↔ 256`), and every observed byte `v` admits a unique plaintext `d` for container noise bit `v.getLsbD np.val`; `noiseFold3` is GF(2)-linear (`32, 16, 16` input bits per output bit) and flips output on every single bit flip in `noiseMix` (`noisepos.go:9-16`) | `proof1_encode_bijection_left_inv`, `proof1_encode_bijection_right_inv`, `proof1_unique_plaintext_for_observation`, `proof1_fixed_plaintext_two_outcomes`, `noiseFold3_xor_hom`, `noiseFold3_basis_nonzero`, `noiseFold3_single_bit_flip` | `ITB.PixelBarrier` |
| **Proof 2**: Per-Bit XOR KPA Resistance | For every `d ∈ BitVec 7`, `v ∈ BitVec 8`, `np ∈ Fin 8`, and `r ∈ Fin 7`, there exists a unique 7-bit mask `m = unrotate7 (extractBits v np) r ^^^ d` consistent with `v` (`56` pairs without CCA, `7` with CCA); semantic per-pixel configurations `8 · 7 · 2^56 = 56 · 2^56 ≈ 2^61.81` (`2^61 < pixelSemanticConfigs < 2^62`) and post-CCA `7 · 2^56 ≈ 2^58.81` (`2^58 < pixelPostCCAConfigs < 2^59`); every `(rot, mask56) ∈ Fin 7 × BitVec 56` has `36` or `37` preimages over the 8 non-mask bits of `dataHash` (`process_generic.go:69-70`) | `candidateMask_consistent`, `candidateMask_unique`, `proof2_exists_unique_mask`, `proof2_candidate_counts`, `pixel_semantic_config_bounds`, `dataHash_mod7_decomp`, `dataHash_rot_mask_realizable` | `ITB.PixelBarrier` |
| **Proof 2 Corollary**: `startPixel` Indistinguishability | Under KPA and even with CCA-revealed `noisePos`, every candidate offset `(startPixel + p) % totalPixels` and rotation `r ∈ Fin 7` admits a unique valid mask `m`, yielding zero elimination predicate on `startPixel_i` | `proof2_corollary_startPixel_indistinguishable` | `ITB.PixelBarrier` |
| **Proof 3**: 8-Seed Isolation & Disjoint Noise Counters | Bijection of the 8 **Triple Ouroboros** domains (`N, L, D₁..D₃, S₁..S₃`) onto `Fin 8`; strict disjointness of per-region noise counter ranges `r.val * regionPixels + p` across `r ∈ Fin 3`; 13-byte `[0x03 ‖ LE64(groupIdx) ‖ v]` evaluation block injectivity and 32-bit `xorFold32` bijection | `domainToFin8_injective`, `noiseCounter_injective`, `xorFold32_bijection`, `rankEvalBlock_injective` | `ITB.SeedIsolation` |
| **Proof 3a**: 8-Seed Isolation Minimality | For every `k ≤ 7` and `f : Domain8 → Fin k`, there exist `d1 ≠ d2` with `f d1 = f d2`; all `28` unordered domain pairs (`56` ordered pairs) partition into `16` Observable+Unobservable, `6` Observable+Observable, and `6` Unobservable+Unobservable merges | `eight_seed_minimality`, `proof3a_leakage_partition_counts` | `ITB.SeedIsolation` |
| **Proof 3b**: `ChainHash` Full Component Utilization & Two-Stage Cascade Fill | For any injective per-round keyed map `H d : BitVec w → BitVec w`, modifying `s_0` or any interior component `s_k` in `s_0 :: (pre ++ s_k :: suf)` strictly changes `chainHash H d`; conversely, `H(d, k) = k ⊕ f(d)` cancels `f(d)` after 2 rounds (`s_1 ⊕ s_0`); **Rank Barrier** cascade depth `1 + keyBits / width` (`5 / 9 / 17` at width 128, `3 / 5 / 9` at width 256, `2 / 3 / 5` at width 512) is 1 round deeper than **Pixel Barrier** (`4 / 8 / 16`) and utilizes both primer key `K` and all session components | `chainHashSteps_injective_of_injective`, `proof3b_head_component_utilization`, `proof3b_interior_component_utilization`, `proof3b_xor_cancelling_two_rounds`, `interlockCascadeRounds_eq_succ`, `cascade_round_counts_shipped`, `interlockCascade_primer_and_session_utilization` | `ITB.SeedIsolation` |
| **Proof 4**: Rotation Barrier | Exact integer brackets: `2^1238 < 7^441 < 2^1239` (Mode 2), `2^3439 < 7^1225 < 2^3440` (Mode 1), `2^1122 < 7^400 < 2^1123` (single-region floor), `7^441 > 2^1024`, `7^1225 > 2^1024`, and `7^441 > 2^306` (Landauer bound) | `rotation_barrier_mode2_lower`, `rotation_barrier_mode2_upper`, `rotation_barrier_mode1_lower`, `rotation_barrier_mode1_upper`, `rotation_barrier_single_lower`, `rotation_barrier_single_upper`, `rotation_barrier_mode2_exceeds_landauer` | `ITB.Thresholds` |
| **Proof 4a**: Multi-Factor Full KPA Resistance | Exact Full KPA brute-force work factor brackets at 1024-bit keys for Mode 1 (`P = 1225`: `2^2058 < P · 2^2048 < 2^2059` Core ITB, `2^1034 < P · 2^1024 < 2^1035` MAC + Reveal) and Mode 2 (`P = 441`: `2^2056 < P · 2^2048 < 2^2057`, `2^1032 < P · 2^1024 < 2^1033`) | `proof4a_full_kpa_work_factors_1024` | `ITB.SeedIsolation` |
| **Proof 5**: Noise Barrier Bound | `2^(8 · 1225) = 2^1024 · 2^8776 > 2^1024` (Mode 1), `2^(8 · 441) = 2^1024 · 2^2504 > 2^1024` (Mode 2), `8 · 400 = 3200 > 1024`, 512/2048-bit bounds, and general theorem `k > 0 → 7^P ≥ 2^k → 2^(8 · P) > 2^k` | `noise_barrier_mode1_factor`, `noise_barrier_mode2_factor`, `noise_barrier_dominates_of_rotation_threshold` | `ITB.Thresholds` |
| **Proof 6**: CCA Leak Upper Bound | Flipping bit `b ∈ Fin 8` preserves `extractBits` and `decodeChannel` iff `b = np`; early-stop sequential search consumes `1 + 2 + 3 + 4 + 5 + 6 + 7 + 7 = 35` queries across 8 outcomes (`35 / 8 = 4.375` queries/pixel; `42,875 / 8 = 5,359.375` vs `9,800` across `1,225` pixels) | `flipBit8_extractBits_eq_iff`, `flipBit8_decodeChannel_eq_iff`, `earlyStopQueries_sum_eq_35`, `earlyStopQueries_mode1_budget` | `ITB.PixelBarrier` |
| **Proof 7**: Bias Neutralization | For every plaintext `d`, rotation `r`, and pre-insertion 7-bit word `y`, `m = unrotate7 y r ^^^ d` is the unique mask satisfying `rotate7 (d ^^^ m) r = y` | `proof7_rotation_mask_bijection` | `ITB.PixelBarrier` |
| **Proof 8**: Oracle-Free Deniability | Under any candidate configuration `(m', r', np')`, `decodeChannel · m' r' np'` is an exact 2-to-1 surjection `BitVec 8 → BitVec 7` mapping uniform container bytes onto uniform 7-bit outputs | `proof8_deniability_channel_surjection` | `ITB.SeedIsolation` |
| **Proof 9**: Ambiguity Dominance Threshold | Tight upper and lower integer bounds on `MinPixels` at 512-bit (`183` CCA / `89` No-CCA), 1024-bit (`365` CCA / `177` No-CCA), and 2048-bit (`730` CCA / `353` No-CCA) keys, plus Mode 1/2/64 KB `56^P` and `7^P` brackets | `threshold_512_cca_above`, `threshold_512_cca_below`, `threshold_1024_cca_above`, `threshold_1024_cca_below`, `threshold_2048_cca_above`, `threshold_2048_cca_below`, `ambiguity_dominates_of_ge` | `ITB.Thresholds` |
| **Proof 10**: Guaranteed DRBG Residue | General identity `((s + 1)^2 - s^2) · 7 = (2s + 1) · 7 ≥ 21` for all `s ≥ 1`, square container third partition `s^2 mod 3 ∈ {0, 1}` (`thirdPixels2 ∈ {third, third + 1}`, `triplepayload.go:144-153`), and exact table values for Mode 2 (`287` B / `532` B), Mode 1 (`483` B / `910` B), single-region (`273` B / `245` B), 16 KB (`693` B), 1 MB (`5,439` B), and 64 MB (`43,449` B) | `drbg_gap_identity`, `drbg_no_perfect_fill`, `square_mod3_ne_two`, `tripleThirdCaps_square_gap`, `drbg_residue_mode2`, `drbg_residue_mode1`, `drbg_residue_single_region`, `drbg_residue_16kb`, `drbg_residue_1mb`, `drbg_residue_64mb` | `ITB.Thresholds` |
| **Proof 11**: 48-bit & 168-bit Rank Barrier Mask Spaces | Exact values and bit-brackets for `A48 = C(48, 16)`, `B48 = C(32, 16)`, `Omega48`, `Omega48WithFold = Omega48 · 2^32` (`2^102 < Omega48WithFold < 2^103`), `Preimages48 = ⌊2^128 / Omega48⌋`, `A168 = C(168, 56)`, `B168 = C(112, 56)`, `Omega168`, `Omega168WithFold = Omega168 · 2^32` (`2^290 < Omega168WithFold < 2^291`), `Preimages168 = ⌊2^512 / Omega168⌋`, multi-chunk dominance (`Omega168^2 > 2^512`, `Omega168^4 > 2^1024`, `Omega168^8 > 2^2048`), and general two-step unrank surjectivity/preimage theorems | `A48_eq`, `B48_eq`, `Omega48_eq`, `Omega48WithFold_bounds`, `Preimages48_eq`, `A168_eq`, `B168_eq`, `Omega168_eq`, `Omega168WithFold_bounds`, `Preimages168_eq`, `twoStepUnrank_witness`, `twoStepWitness_injective`, `twoStepWitness_lt` | `ITB.RankBarrier` |
| **Proof 12**: `gcd(A, B)` Anti-Collapse Trap & Reciprocal Unranking | `gcd(A48, B48) = 66,861 = 3^2 · 17 · 19 · 23`; `gcd(A168, B168) = 10,078,335,949,946,663,736`; naive double-modulo `r ↦ (r mod A, r mod B)` excludes all `(a, b)` with `a mod d ≠ b mod d`; Horner `qmod` identity; exact reciprocal constants and single-correction Euclidean exactness for 48-bit `divB` (`⌊2^93 / B₄₈⌋`) and `modA` (`⌊2^105 / A₄₈⌋`) and 168-bit `divmodStepB168` (`⌊2^236 / B₁₆₈⌋`) and `modStepA168` (`⌊2^342 / A₁₆₈⌋`) | `gcd_A48_B48`, `gcd_A168_B168`, `naiveDoubleMod_unreachable_of_mod_ne`, `anti_collapse_48_separation`, `anti_collapse_168_separation`, `horner_qmod_step`, `interlockB48Recip_eq_floor_div`, `interlockA48Recip_eq_floor_div`, `divB48_single_correction_exact`, `modA48_single_correction_exact`, `B168_limbs_eq_binom`, `A168_limbs_eq_binom`, `muB168_eq_floor_div`, `muA168_eq_floor_div`, `divmodStepB168_error_envelope`, `modStepA168_error_envelope`, `single_correction_exact` | `ITB.RankBarrier`, `ITB.SplitRank168` |
| **SCIENCE.md § 2.10**: Byte-Splitting Property | `gcd(7, 8) = 1`; no interior byte boundary `8b` (`1 ≤ b ≤ 6`) aligns with any interior channel boundary `7c` (`1 ≤ c ≤ 7`); every byte `b ∈ Fin 7` spans adjacent channels `b` and `b + 1`; under `Interlock = "48"`, `gcd(2, 7) = 1` cycles `2`-byte lane fragments across all 7 pixel offsets and spans 3–4 channels per fragment (`16 > 2 · 7`); under `Interlock = "168"`, `interlock_nonce` (`22, 21, 21` B) + COBS framing (`+1` B header, `255 mod 7 = 3`) forces every `7`-byte lane fragment to straddle two consecutive pixels (`(22 + 1) mod 7 = 2 ≠ 0`, `(21 + 1) mod 7 = 1 ≠ 0`) | `gcd_7_8_eq_1`, `byte_channel_no_interior_alignment`, `every_byte_spans_two_adjacent_channels`, `interlock48_pixel_channel_nonalignment`, `interlock168_cobs_pixel_straddling` | `ITB.Thresholds`, `ITB.SeedIsolation` |
| **Additional Theorem**: MAC-Inside-Encrypt Composition & 4-Way Wire-Shape Parity | Asymmetric `nonceSplit` (`(6, 5, 5)` at 16 B, `(11, 11, 10)` at 32 B, `(22, 21, 21)` at 64 B) and lane/pixel alignment shifts (`22 mod 2 = 0 ≠ 21 mod 2 = 1`, `22 mod 7 = 1 ≠ 21 mod 7 = 0`); uniform `1/8` accept vs `7/8` reject bit-flip classification; `Verify-before-COBS` state machine unreachable on MAC failure; strict cumulative pixel offset monotonicity (`StreamMACInput` anti-reorder, anti-truncation, and cross-stream anti-splice); 4-way capacity and wire-length parity across `No MAC` / `MAC` × `Single Message` / `Streaming` (`nomacTagStubSizeCfg = tagSize + 1 ∈ {17, 33, 65}`) | `nonceSplit_sum_and_balance`, `nonceSplit_shipped_widths`, `nonceSplit_64_lane_alignment_asymmetry`, `mac_inside_encrypt_verify_before_cobs`, `mac_inside_encrypt_uniform_bitflip_classification`, `stream_offset_strict_mono`, `stream_reorder_distinguishes`, `stream_finalFlag_distinguishes`, `stream_id_distinguishes`, `nomacTagStubSize_shipped_widths`, `four_way_wire_shape_parity` | `ITB.SeedIsolation` |
| **Additional Theorem**: Nonce Uniqueness | Birthday exponents (`2^256` single-axis / `2^512` dual-axis at 512-bit default; `2^64` / `2^128` at 128-bit) and fresh un-collided axis preservation under any single-slot collision | `nonce_birthday_exponents`, `dual_nonce_fresh_axis_of_ne` | `ITB.SeedIsolation` |

---

## Verified Numerical Constants Summary

All constants below are certified by the Lean 4 kernel (`by decide` / `rfl` over arbitrary-precision `Nat` and fixed-width `BitVec`):

- **Ambiguity Dominance Thresholds (`MinPixels`)**:
  - `512`-bit key: `7^182 < 2^512 < 7^183` (CCA `P_threshold = 183`) and `56^88 < 2^512 < 56^89` (No-CCA `P_threshold = 89`).
  - `1024`-bit key: `7^364 < 2^1024 < 7^365` (CCA `P_threshold = 365`) and `56^176 < 2^1024 < 56^177` (No-CCA `P_threshold = 177`).
  - `2048`-bit key: `7^729 < 2^2048 < 7^730` (CCA `P_threshold = 730`) and `56^352 < 2^2048 < 56^353` (No-CCA `P_threshold = 353`).
- **Container Ambiguity Brackets (1024-bit key)**:
  - Mode 2 (`21 × 21 = 441` px): `2^1238 < 7^441 < 2^1239` and `2^2561 < 56^441 < 2^2562`.
  - Mode 1 (`35 × 35 = 1,225` px): `2^3439 < 7^1225 < 2^3440` and `2^7114 < 56^1225 < 2^7115`.
  - Single-region baseline (`20 × 20 = 400` px): `2^1122 < 7^400 < 2^1123` and `2^2322 < 56^400 < 2^2323`.
  - 64 KB (`99 × 99 = 9,801` px): `2^27514 < 7^9801 < 2^27515` and `2^56917 < 56^9801 < 2^56918`.
- **Rank Barrier (`Interlock = "48"`)**:
  - `A48 = C(48, 16) = 2,254,848,913,647` (`2^41 < A48 < 2^42`).
  - `B48 = C(32, 16) = 601,080,390` (`2^29 < B48 < 2^30`).
  - `Omega48 = A48 · B48 = 1,355,345,464,406,015,082,330` (`2^70 < Omega48 < 2^71`).
  - `Omega48WithFold = Omega48 · 2^32 = 5,821,164,444,405,766,844,290,097,479,680` (`2^102 < Omega48WithFold < 2^103`).
  - `Preimages48 = ⌊2^128 / Omega48⌋ = 251,066,887,267,792,206` (`2^57 < Preimages48 < 2^58`).
  - `gcd(A48, B48) = 66,861 = 3^2 · 17 · 19 · 23` (`2^16 < 66,861 < 2^17`).
  - `interlockB48Recip = ⌊2^93 / B48⌋ = 0xe4a737fd2603cba7` (`16,476,199,322,162,285,479`).
  - `interlockA48Recip = ⌊2^105 / A48⌋ = 0xf9a974e0a78bad8f` (`17,990,038,694,740,602,255`).
- **Rank Barrier (`Interlock = "168"`)**:
  - `A168 = C(168, 56) = 1,799,363,822,299,435,101,766,134,108,620,363,111,079,750,360` (`2^150 < A168 < 2^151`).
  - `B168 = C(112, 56) = 390,590,044,887,157,789,360,330,532,465,784` (`2^108 < B168 < 2^109`).
  - `Omega168 = A168 · B168 = 702,813,596,120,264,168,420,100,264,216,585,729,858,529,081,007,646,807,547,722,792,977,161,961,682,240` (`2^258 < Omega168 < 2^259`).
  - `Omega168WithFold = Omega168 · 2^32` (`2^290 < Omega168WithFold < 2^291`).
  - `Preimages168 = ⌊2^512 / Omega168⌋ = 19,077,331,463,075,847,632,709,418,264,551,801,233,111,994,340,630,406,080,247,337,248,653,165,811,287` (`2^253 < Preimages168 < 2^254`).
  - `gcd(A168, B168) = 10,078,335,949,946,663,736 = 2^3 · 3^2 · 19 · 29 · 31 · 59 · 61 · 67 · 71 · 73 · 79 · 83` (`2^63 < gcd < 2^64`).
  - `muB168 = ⌊2^236 / B168⌋ = 0xd4b20d19ce585c96_4508f9134af46c6b`.
  - `muA168 = ⌊2^342 / A168⌋ = 0xcb0ee004eb554b2b_660063d3f1f72561_e2ea7578684213e8`.
- **Pixel Barrier Semantic Configuration Spaces**:
  - Pre-CCA: `pixelSemanticConfigs = 8 · 7 · 2^56 = 4,035,225,266,123,964,416` (`2^61 < pixelSemanticConfigs < 2^62`).
  - Post-CCA: `pixelPostCCAConfigs = 7 · 2^56 = 504,403,158,265,495,552` (`2^58 < pixelPostCCAConfigs < 2^59`).
  - Cascade rounds (`512 / 1024 / 2048`-bit keys): `(4, 8, 16)` **Pixel Barrier** vs `(5, 9, 17)` **Rank Barrier** at width 128; `(2, 4, 8)` vs `(3, 5, 9)` at width 256; `(1, 2, 4)` vs `(2, 3, 5)` at width 512.

---

## Reproducing the Verification

Install [`elan`](https://github.com/leanprover/elan) (the Lean 4 toolchain manager) and run `lake build` inside `lean/`:

```sh
cd lean
lake build
```

`lake build` reads [`lean-toolchain`](lean-toolchain) (`leanprover/lean4:v4.35.0`) and checks all five modules in a few seconds with zero network dependencies and zero warnings.

## See also

- [PROOFS.md](../PROOFS.md) — Formal security proofs narrative.
- [SCIENCE.md](../SCIENCE.md) — Scientific analysis and architectural security arguments.
- [SECURITY.md](../SECURITY.md) — Threat model and composition modes reference.
- [ITB.md](../ITB.md) — Accessible explanation of the barrier architecture.
- [README.md](../README.md) — Main project overview and API documentation.
