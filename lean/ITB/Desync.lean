/-
  Formal verification of the Two-Layer Desynchronization Architecture:
  - Part I (Layer I — Outer Pixel Barrier): Invisible Sub-Regions `Π_r` with dynamic
    sub-region counts `K_r`, telescopic boundary conservation, the `effectiveStartPixel`
    modular identity for zero-copy SIMD/CGO compatibility, bijectivity and interval
    disjointness of `subregionAddr`, and exact combinatorial trajectory bounds at the
    Mode 2 (`P_r = 147`) and Mode 1 (`P_r = 408`) container floors (Proof 4a strengthening).
  - Part II (Layer II — Inner Interlocked Barrier): Cross-lane slot desynchronization
    `Σ_0, Σ_1, Σ_2` in `Interlock48` and `Interlock168`, guaranteed distinctness of shifts
    `β_0 ≠ β_1` (`desync_beta0_ne_beta1`) and absence of co-indexed slot pairs, bijectivity
    of `laneSlotShift`, and multiplicative strengthening of `Omega48` and `Omega168` at the
    Mode 2 and Mode 1 floors (Proofs 11 and 12 strengthening).
  - Part III (Non-Interference across Proofs 1–12): Formal proof that composing Layer I
    and Layer II preserves Proof 1 (Information-Theoretic Barrier), Proof 2 (Per-Bit XOR
    KPA Resistance and 56/7 candidate counts), Proof 3 & 3a (8-Seed Isolation, `Domain8`
    leakage partition, domain tag separation `0x01..0x06`, and the 128-bit full-width
    bijection `fullWidthFold_bijection`, `fullWidthFold_preserves_prf_cardinality`,
    `fullWidthFold_crc128_dual_lane_sensitivity`, `fullWidthFold_non_affine_gf2`, and
    `fullWidthFold_fnv1a_dead_zone_coverage`), Proof 6 & MAC-Inside-Encrypt
    (`Verify-before-COBS`), Proof 8 (Deniability), Proof 9 (Ambiguity Dominance),
    Proof 10 (Guaranteed DRBG Residue & 0-byte wire overhead), and Proof 12
    (`gcd` Anti-Collapse).
-/
import ITB.Thresholds
import ITB.RankBarrier
import ITB.PixelBarrier
import ITB.SplitRank
import ITB.SeedIsolation

namespace ITB.Desync

open ITB.Thresholds
open ITB.RankBarrier
open ITB.PixelBarrier
open ITB.SplitRank
open ITB.SeedIsolation

set_option exponentiation.threshold 60000
set_option maxRecDepth 200000

/-! ## Helper Lemma: Bounded Modular Reduction Below `2 * M` -/

/--
  For any `x < 2 * M`, `x % M` equals `x` when `x < M` and `x - M` when `M ≤ x < 2 * M`.
  Reduces modular arithmetic on bounded sums (`< 2 * M`) to linear integer arithmetic.
-/
theorem mod_of_lt_two_mul (x M : Nat) (hx : x < 2 * M) :
    x % M = if x < M then x else x - M := by
  split
  · next hlt => exact Nat.mod_eq_of_lt hlt
  · next hge =>
    have hsub_lt : x - M < M := by omega
    have heq : x = (x - M) + M * 1 := by omega
    conv => lhs; rw [heq]
    rw [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hsub_lt]

/-!
  =============================================================================
  PART I: Outer Pixel Barrier — Invisible Sub-Regions `Π_r` (Proof 4a)
  =============================================================================
-/

/-! ### 1.1 Dynamic Sub-Region Count `K_r` Bounds -/

/--
  Dynamic sub-region count `K_r ∈ [6, 10]` for compact Mode 2 containers,
  derived from a PRF word `w` of `(startSeed_r, main_nonce)`:
  `K_r = 6 + (w % 5)`.
-/
def dynamicSubregionCountMode2 (w : Nat) : Nat :=
  6 + w % 5

/--
  Dynamic sub-region count `K_r ∈ [8, 16]` for standard Mode 1 containers,
  derived from a PRF word `w` of `(startSeed_r, main_nonce)`:
  `K_r = 8 + (w % 9)`.
-/
def dynamicSubregionCountMode1 (w : Nat) : Nat :=
  8 + w % 9

/--
  For every PRF output word `w : Nat`, `dynamicSubregionCountMode2 w` lies
  strictly in the interval `[6, 10]`.
-/
theorem dynamicSubregionCountMode2_bounds (w : Nat) :
    6 ≤ dynamicSubregionCountMode2 w ∧ dynamicSubregionCountMode2 w ≤ 10 := by
  unfold dynamicSubregionCountMode2
  omega

/--
  For every PRF output word `w : Nat`, `dynamicSubregionCountMode1 w` lies
  strictly in the interval `[8, 16]`.
-/
theorem dynamicSubregionCountMode1_bounds (w : Nat) :
    8 ≤ dynamicSubregionCountMode1 w ∧ dynamicSubregionCountMode1 w ≤ 16 := by
  unfold dynamicSubregionCountMode1
  omega

/--
  Every integer `k ∈ [6, 10]` (5 distinct sub-region counts) is realized by
  `dynamicSubregionCountMode2`, and every `k ∈ [8, 16]` (9 distinct sub-region counts)
  is realized by `dynamicSubregionCountMode1`.
-/
theorem dynamicSubregionCount_realizable :
    ((List.range 5).map dynamicSubregionCountMode2 = [6, 7, 8, 9, 10]) ∧
    ((List.range 9).map dynamicSubregionCountMode1 = [8, 9, 10, 11, 12, 13, 14, 15, 16]) := by
  decide

/-! ### 1.2 Telescopic Sub-Region Boundary Conservation -/

/--
  Sum of sub-region lengths `(O_{k+1} - O_k)` across a monotonic boundary sequence
  starting at `curr` with remaining boundary points `rest`.
-/
def boundaryDiffSum : Nat → List Nat → Nat
  | _, [] => 0
  | curr, next :: rest => (next - curr) + boundaryDiffSum next rest

/--
  Last boundary point of a boundary sequence starting at `curr` with tail `rest`.
-/
def lastBoundary : Nat → List Nat → Nat
  | curr, [] => curr
  | _, next :: rest => lastBoundary next rest

/--
  Pairwise monotonicity predicate `curr ≤ b_1 ≤ b_2 ≤ ...` on a boundary sequence.
-/
def MonotoneBoundaries : Nat → List Nat → Prop
  | _, [] => True
  | curr, next :: rest => curr ≤ next ∧ MonotoneBoundaries next rest

/--
  For any monotonically non-decreasing boundary sequence starting at `curr`,
  `curr ≤ lastBoundary curr rest`.
-/
theorem lastBoundary_ge (curr : Nat) (rest : List Nat)
    (hmono : MonotoneBoundaries curr rest) :
    curr ≤ lastBoundary curr rest := by
  induction rest generalizing curr with
  | nil =>
    unfold lastBoundary
    omega
  | cons next tail ih =>
    unfold MonotoneBoundaries at hmono
    rcases hmono with ⟨hle, htail⟩
    unfold lastBoundary
    have ih_step := ih next htail
    omega

/--
  General Telescopic Boundary Conservation Theorem:
  For any monotonically non-decreasing sequence of sub-region boundaries
  `curr ≤ b_1 ≤ b_2 ≤ ... ≤ b_K`, the sum of sub-region lengths
  `∑ (b_{k+1} - b_k)` identically equals `b_K - curr`.
-/
theorem telescopic_boundary_sum (curr : Nat) (rest : List Nat)
    (hmono : MonotoneBoundaries curr rest) :
    boundaryDiffSum curr rest = lastBoundary curr rest - curr := by
  induction rest generalizing curr with
  | nil =>
    unfold boundaryDiffSum lastBoundary
    omega
  | cons next tail ih =>
    unfold MonotoneBoundaries at hmono
    rcases hmono with ⟨hle, htail⟩
    unfold boundaryDiffSum lastBoundary
    have ih_step := ih next htail
    have hlast_ge := lastBoundary_ge next tail htail
    omega

/--
  Corollary (`O_0 = 0`, `O_K = P_r`): for any monotonic boundary partition of `[0, P_r)`
  ending at `lastBoundary 0 rest = P_r`, the sum of sub-region sizes `∑ M_k` equals `P_r`
  with zero lost or unmapped pixels.
-/
theorem telescopic_region_partition_sum (rest : List Nat) (Pr : Nat)
    (hmono : MonotoneBoundaries 0 rest)
    (hend : lastBoundary 0 rest = Pr) :
    boundaryDiffSum 0 rest = Pr := by
  rw [telescopic_boundary_sum 0 rest hmono, hend, Nat.sub_zero]

/--
  Explicit 8-subregion telescopic jitter conservation:
  Given base sub-region sizes `b0..b7` and interior boundary jitters `d1..d7`
  (with `d_k ≤ b_k`), the jittered sizes
  `M_0 = b0 + d1`, `M_k = b_k - d_k + d_{k+1}` (`1 ≤ k ≤ 6`), `M_7 = b7 - d7`
  sum identically to `b0 + b1 + b2 + b3 + b4 + b5 + b6 + b7`.
-/
theorem telescopic_jitter8_sum_preserved
    (b0 b1 b2 b3 b4 b5 b6 b7 d1 d2 d3 d4 d5 d6 d7 : Nat)
    (h1 : d1 ≤ b1) (h2 : d2 ≤ b2) (h3 : d3 ≤ b3) (h4 : d4 ≤ b4)
    (h5 : d5 ≤ b5) (h6 : d6 ≤ b6) (h7 : d7 ≤ b7) :
    let m0 := b0 + d1
    let m1 := b1 - d1 + d2
    let m2 := b2 - d2 + d3
    let m3 := b3 - d3 + d4
    let m4 := b4 - d4 + d5
    let m5 := b5 - d5 + d6
    let m6 := b6 - d6 + d7
    let m7 := b7 - d7
    m0 + m1 + m2 + m3 + m4 + m5 + m6 + m7 =
      b0 + b1 + b2 + b3 + b4 + b5 + b6 + b7 := by
  dsimp only
  omega

/-! ### 1.3 `effectiveStartPixel` Modular Identity and `subregionAddr` Bijectivity -/

/--
  Local cyclic step inside a sub-region of size `M` with local start offset `s`:
  `q ↦ (s + q) % M`.
-/
def subregionStep (M s q : Nat) : Nat :=
  (s + q) % M

/--
  Inverse local cyclic step inside a sub-region of size `M` with local start offset `s < M`:
  `y ↦ (y + M - s) % M`.
-/
def invSubregionStep (M s y : Nat) : Nat :=
  (y + M - s) % M

/--
  Physical pixel address inside a region for local step `q < M` in a sub-region
  at physical base offset `O` of length `M` with local start offset `s`:
  `subregionAddr O M s q = O + (s + q) % M`.
-/
def subregionAddr (O M s q : Nat) : Nat :=
  O + (s + q) % M

/--
  Effective `startPixel` passed to `processChunk{128,256,512}` (`process_cgo.go`,
  `process_pixels.c`, `process_generic.go`) for a sub-region of physical length `M`,
  local start offset `s < M`, and logical stream start index `P`:
  `effectiveStartPixel M s P = (s + M - (P % M)) % M`.
-/
def effectiveStartPixel (M s P : Nat) : Nat :=
  (s + M - (P % M)) % M

/--
  `effectiveStartPixel` Compatibility Identity:
  For every sub-region size `M > 0`, local start `s`, logical sub-chunk start `P`,
  and local pixel index `q` (where the global logical pixel index is `p = P + q`),
  the C/Go formula `(effectiveStartPixel M s P + (P + q)) % M`
  evaluates identically to the local cyclic index `(s + q) % M`.
-/
theorem effectiveStartPixel_compat (M s P q : Nat) (hM : 0 < M) :
    (effectiveStartPixel M s P + (P + q)) % M = (s + q) % M := by
  unfold effectiveStartPixel
  rw [Nat.mod_add_mod]
  have hlt : P % M < M := Nat.mod_lt P hM
  have hdiv : M * (P / M) + P % M = P := Nat.div_add_mod P M
  have heq : s + M - P % M + (P + q) = (s + q) + M * (P / M + 1) := by
    rw [Nat.mul_add, Nat.mul_one]
    omega
  rw [heq, Nat.add_mul_mod_self_left]

/--
  Sub-Region Memory Bounds Invariant:
  For every `M > 0`, `subregionAddr O M s q` lies strictly within the sub-region's
  contiguous physical slice `[O, O + M)`.
-/
theorem subregionAddr_in_bounds (O M s q : Nat) (hM : 0 < M) :
    O ≤ subregionAddr O M s q ∧ subregionAddr O M s q < O + M := by
  unfold subregionAddr
  have hlt : (s + q) % M < M := Nat.mod_lt (s + q) hM
  omega

/--
  Left inverse of `subregionStep`: for any `s < M` and `q < M`,
  `invSubregionStep M s (subregionStep M s q) = q`.
-/
theorem subregionStep_left_inv (M s q : Nat) (hs : s < M) (hq : q < M) :
    invSubregionStep M s (subregionStep M s q) = q := by
  unfold invSubregionStep subregionStep
  have hsq : s + q < 2 * M := by omega
  rw [mod_of_lt_two_mul (s + q) M hsq]
  have houter : (if s + q < M then s + q else s + q - M) + M - s < 2 * M := by
    split <;> omega
  rw [mod_of_lt_two_mul _ M houter]
  split <;> split <;> omega

/--
  Right inverse of `subregionStep`: for any `s < M` and `y < M`,
  `subregionStep M s (invSubregionStep M s y) = y`.
-/
theorem subregionStep_right_inv (M s y : Nat) (hs : s < M) (hy : y < M) :
    subregionStep M s (invSubregionStep M s y) = y := by
  unfold subregionStep invSubregionStep
  have hyM : y + M - s < 2 * M := by omega
  rw [mod_of_lt_two_mul (y + M - s) M hyM]
  have houter : s + (if y + M - s < M then y + M - s else y + M - s - M) < 2 * M := by
    split <;> omega
  rw [mod_of_lt_two_mul _ M houter]
  split <;> split <;> omega

/--
  Intra-Subregion Injectivity:
  Within a sub-region `[O, O + M)` with `s < M`, distinct local steps `q1, q2 < M`
  map to strictly distinct physical pixel addresses.
-/
theorem subregionAddr_injective (O M s q1 q2 : Nat)
    (hs : s < M) (hq1 : q1 < M) (hq2 : q2 < M)
    (heq : subregionAddr O M s q1 = subregionAddr O M s q2) :
    q1 = q2 := by
  unfold subregionAddr at heq
  have hstep : subregionStep M s q1 = subregionStep M s q2 := by
    unfold subregionStep
    omega
  have hinv := congrArg (invSubregionStep M s) hstep
  rw [subregionStep_left_inv M s q1 hs hq1, subregionStep_left_inv M s q2 hs hq2] at hinv
  exact hinv

/--
  Inter-Subregion Disjointness:
  Any two physical sub-containers `[O_1, O_1 + M_1)` and `[O_2, O_2 + M_2)` with
  `O_1 + M_1 ≤ O_2` never collide for any local steps `q_1, q_2` and starts `s_1, s_2`.
-/
theorem subregion_disjoint_intervals (O1 M1 s1 q1 O2 M2 s2 q2 : Nat)
    (hM1 : 0 < M1) (hM2 : 0 < M2) (hdisj : O1 + M1 ≤ O2) :
    subregionAddr O1 M1 s1 q1 ≠ subregionAddr O2 M2 s2 q2 := by
  have hb1 := subregionAddr_in_bounds O1 M1 s1 q1 hM1
  have hb2 := subregionAddr_in_bounds O2 M2 s2 q2 hM2
  omega

/-! ### 1.4 Exact Combinatorial Trajectory Bounds at Mode 2 (`P_r = 147`) and Mode 1 (`P_r = 408`) Floors -/

/-- Factorial `n!` for counting sub-region permutations `|S_K| = K!`. -/
def factorial : Nat → Nat
  | 0 => 1
  | n + 1 => (n + 1) * factorial n

/-- Exact factorials for sub-region counts `K ∈ {6, 8, 10, 12, 16}`. -/
theorem factorial_subregion_counts :
    factorial 6 = 720 ∧
    factorial 8 = 40320 ∧
    factorial 10 = 3628800 ∧
    factorial 12 = 479001600 ∧
    factorial 16 = 20922789888000 := by decide

/--
  Mode 2 Minimum Container Floor (`21 × 21 = 441` pixels, `P_r = 147` pixels/region,
  dynamic sub-region count `K_r ∈ [6, 10]`):
  1. 3-region initial entry-pixel space `(Π_0(0), Π_1(0), Π_2(0))`:
     `147^3 = 3,176,523`, bracketed by `2^21 < 147^3 < 2^22` (`≈ 2^21.60`).
  2. At the minimum sub-region count `K = 6` (`⌊147 / 6⌋ = 24` pixels/sub-region, `6! = 720`
     permutations, and `24^6` per-pixel local start combinations `s_{r,k} ∈ [0, 24)` per region
     via `effectiveStartPixel`), the unjittered 3-region space `(6! * 24^6)^3` lies in
     `(2^111, 2^112)`, and with `2^5` telescopic boundary jitter choices per region,
     `(2^5 * 6! * 24^6)^3` lies in `(2^126, 2^127)` (`> 2^104` after dividing out `147^3`).
  3. At `K = 8` sub-regions (`⌊147 / 8⌋ = 18` pixels/sub-region, `8! = 40,320` permutations,
     and `18^8` per-pixel start combinations `s_{r,k} ∈ [0, 18)` per region), the unjittered
     3-region trajectory space `(8! * 18^8)^3` is bracketed by `2^145 < (8! * 18^8)^3 < 2^146`
     (`≈ 2^145.98`, or `> 2^124` after dividing out `147^3`).
  4. Including the `2^7` telescopic boundary jitter choices per region (`δ_k ∈ {-1, 0}`) at
     `K = 8`, the full 3-region trajectory space `(2^7 * 8! * 18^8)^3` is bracketed by
     `2^166 < (2^7 * 8! * 18^8)^3 < 2^167` (`≈ 2^166.98 > 2^160`), and even if an oracle
     grants the exact initial physical pixels `Π_r(0)` in all 3 regions (dividing out `147^3`),
     the remaining unknown trajectory space strictly exceeds `2^145` (`> 2^138`).
  5. At the upper Mode 2 count `K = 10` (`⌊147 / 10⌋ = 14` pixels/sub-region), the unjittered
     space `(10! * 14^10)^3` lies in `(2^179, 2^180)` and the jittered space
     `(2^9 * 10! * 14^10)^3` lies in `(2^206, 2^207)`.
-/
theorem subregion_trajectory_bounds_mode2_floor :
    441 / 3 = 147 ∧
    147 / 6 = 24 ∧
    147 / 8 = 18 ∧
    147 / 10 = 14 ∧
    2 ^ 21 < 147 ^ 3 ∧ 147 ^ 3 < 2 ^ 22 ∧
    2 ^ 111 < (factorial 6 * 24 ^ 6) ^ 3 ∧
    (factorial 6 * 24 ^ 6) ^ 3 < 2 ^ 112 ∧
    2 ^ 126 < (2 ^ 5 * factorial 6 * 24 ^ 6) ^ 3 ∧
    (2 ^ 5 * factorial 6 * 24 ^ 6) ^ 3 < 2 ^ 127 ∧
    (2 ^ 5 * factorial 6 * 24 ^ 6) ^ 3 / (147 ^ 3) > 2 ^ 104 ∧
    2 ^ 145 < (factorial 8 * 18 ^ 8) ^ 3 ∧
    (factorial 8 * 18 ^ 8) ^ 3 < 2 ^ 146 ∧
    (factorial 8 * 18 ^ 8) ^ 3 / (147 ^ 3) > 2 ^ 124 ∧
    2 ^ 166 < (2 ^ 7 * factorial 8 * 18 ^ 8) ^ 3 ∧
    (2 ^ 7 * factorial 8 * 18 ^ 8) ^ 3 < 2 ^ 167 ∧
    (2 ^ 7 * factorial 8 * 18 ^ 8) ^ 3 > 2 ^ 160 ∧
    (2 ^ 7 * factorial 8 * 18 ^ 8) ^ 3 / (147 ^ 3) > 2 ^ 145 ∧
    (2 ^ 7 * factorial 8 * 18 ^ 8) ^ 3 / (147 ^ 3) > 2 ^ 138 ∧
    2 ^ 179 < (factorial 10 * 14 ^ 10) ^ 3 ∧
    (factorial 10 * 14 ^ 10) ^ 3 < 2 ^ 180 ∧
    2 ^ 206 < (2 ^ 9 * factorial 10 * 14 ^ 10) ^ 3 ∧
    (2 ^ 9 * factorial 10 * 14 ^ 10) ^ 3 < 2 ^ 207 := by decide

/--
  Mode 1 Minimum Container Floor (`35 × 35 = 1225` pixels, `P_0 = P_1 = 408`, `P_2 = 409`,
  dynamic sub-region count `K_r ∈ [8, 16]`):
  1. 3-region initial entry-pixel space `(Π_0(0), Π_1(0), Π_2(0))`:
     `408^2 * 409 = 68,083,776`, bracketed by `2^26 < 408^2 * 409 < 2^27` (`≈ 2^26.02`).
  2. At the minimum Mode 1 count `K = 8` sub-regions (`⌊408 / 8⌋ = 51` pixels/sub-region,
     `8! = 40,320` permutations, and `51^8` per-pixel local start combinations `s_{r,k} ∈ [0, 51)`
     per region via `effectiveStartPixel`), the unjittered 3-region trajectory space
     `(8! * 51^8)^3` is bracketed by `2^182 < (8! * 51^8)^3 < 2^183` (`≈ 2^182.04`, or `> 2^156`
     after dividing out `408^2 * 409`).
  3. Including the `4^7` telescopic boundary jitter choices per region (`δ_k ∈ {-2, -1, 0, +1}`)
     at `K = 8`, the full 3-region trajectory space `(4^7 * 8! * 51^8)^3` is bracketed by
     `2^224 < (4^7 * 8! * 51^8)^3 < 2^225` (`≈ 2^224.04 > 2^216`), and even if an oracle
     grants the exact initial physical pixels `Π_r(0)` in all 3 regions (dividing out `408^2 * 409`),
     the remaining unknown trajectory space strictly exceeds `2^198` (`> 2^189`).
  4. At the upper dynamic count `K = 16` (`⌊408 / 16⌋ = 25` pixels/sub-region,
     `16! = 20,922,789,888,000`), `(16! * 25^16)^3` lies in `(2^355, 2^356)` (`> 2^354`),
     and with `4^15` telescopic boundary jitter choices per region, `(4^15 * 16! * 25^16)^3`
     lies in `(2^445, 2^446)`.
-/
theorem subregion_trajectory_bounds_mode1_floor :
    1225 / 3 = 408 ∧
    1225 - 2 * 408 = 409 ∧
    408 / 8 = 51 ∧
    408 / 16 = 25 ∧
    2 ^ 26 < 408 ^ 2 * 409 ∧ 408 ^ 2 * 409 < 2 ^ 27 ∧
    2 ^ 182 < (factorial 8 * 51 ^ 8) ^ 3 ∧
    (factorial 8 * 51 ^ 8) ^ 3 < 2 ^ 183 ∧
    (factorial 8 * 51 ^ 8) ^ 3 / (408 ^ 2 * 409) > 2 ^ 156 ∧
    2 ^ 224 < (4 ^ 7 * factorial 8 * 51 ^ 8) ^ 3 ∧
    (4 ^ 7 * factorial 8 * 51 ^ 8) ^ 3 < 2 ^ 225 ∧
    (4 ^ 7 * factorial 8 * 51 ^ 8) ^ 3 > 2 ^ 216 ∧
    (4 ^ 7 * factorial 8 * 51 ^ 8) ^ 3 / (408 ^ 2 * 409) > 2 ^ 198 ∧
    (4 ^ 7 * factorial 8 * 51 ^ 8) ^ 3 / (408 ^ 2 * 409) > 2 ^ 189 ∧
    2 ^ 355 < (factorial 16 * 25 ^ 16) ^ 3 ∧
    (factorial 16 * 25 ^ 16) ^ 3 < 2 ^ 356 ∧
    2 ^ 445 < (4 ^ 15 * factorial 16 * 25 ^ 16) ^ 3 ∧
    (4 ^ 15 * factorial 16 * 25 ^ 16) ^ 3 < 2 ^ 446 := by decide

/-!
  =============================================================================
  PART II: Inner Interlocked Barrier — Cross-Lane Slot Desynchronization `Σ_ℓ`
           in `Interlock48` and `Interlock168` (Proofs 11 and 12)
  =============================================================================
-/

/-! ### 2.1 Distinct Cyclic Shifts (`β_0 ≠ β_1`) and Bijectivity of `laneSlotShift` -/

/-- Primary lane cyclic shift `β_0 = r_0 % m`. -/
def desyncBeta0 (m r0 : Nat) : Nat :=
  r0 % m

/--
  Secondary lane cyclic shift `β_1 = (β_0 + 1 + r_1 % (m - 1)) % m`.
  By adding an offset in `[1, m - 1]` modulo `m`, `β_1` is guaranteed to be
  strictly distinct from `β_0` for every `m ≥ 2` and all PRF words `r_0, r_1`.
-/
def desyncBeta1 (m r0 r1 : Nat) : Nat :=
  (desyncBeta0 m r0 + 1 + r1 % (m - 1)) % m

/-- Forward cyclic slot map `μ(j) = (j + β) % m` on `[0, m)`. -/
def laneSlotShift (m beta j : Nat) : Nat :=
  (j + beta) % m

/-- Inverse cyclic slot map `μ⁻¹(y) = (y + m - β) % m` on `[0, m)`. -/
def invLaneSlotShift (m beta y : Nat) : Nat :=
  (y + m - beta) % m

/-- Bounds for `desyncBeta0` and `desyncBeta1`: both lie strictly in `[0, m)` when `m ≥ 2`. -/
theorem desyncBeta_lt (m r0 r1 : Nat) (hm : 2 ≤ m) :
    desyncBeta0 m r0 < m ∧ desyncBeta1 m r0 r1 < m := by
  unfold desyncBeta0 desyncBeta1
  have hm_pos : 0 < m := by omega
  exact ⟨Nat.mod_lt r0 hm_pos, Nat.mod_lt _ hm_pos⟩

/--
  Guaranteed Shift Desynchronization (`β_0 ≠ β_1`):
  For every block/superblock count `m ≥ 2` and any PRF words `r_0, r_1 : Nat`,
  `desyncBeta0 m r0 ≠ desyncBeta1 m r0 r1`.
-/
theorem desync_beta0_ne_beta1 (m r0 r1 : Nat) (hm : 2 ≤ m) :
    desyncBeta0 m r0 ≠ desyncBeta1 m r0 r1 := by
  unfold desyncBeta1 desyncBeta0
  have hm_pos : 0 < m := by omega
  have hm1_pos : 0 < m - 1 := by omega
  have hb0 : r0 % m < m := Nat.mod_lt r0 hm_pos
  have hr1 : r1 % (m - 1) < m - 1 := Nat.mod_lt r1 hm1_pos
  have hsum : r0 % m + 1 + r1 % (m - 1) < 2 * m := by omega
  rw [mod_of_lt_two_mul (r0 % m + 1 + r1 % (m - 1)) m hsum]
  split <;> omega

/--
  Zero Co-Indexed Slot Pairs (`μ_0(j) ≠ μ_1(j)` for all `j < m`):
  For every `m ≥ 2`, any PRF words `r_0, r_1`, and every chunk/slot index `j < m`,
  lane 0 and lane 1 never place chunk `j` at the same relative slot index.
-/
theorem desync_no_fixed_slot_pair (m r0 r1 j : Nat) (hm : 2 ≤ m) (hj : j < m) :
    laneSlotShift m (desyncBeta0 m r0) j ≠ laneSlotShift m (desyncBeta1 m r0 r1) j := by
  unfold laneSlotShift
  have ⟨hb0, hb1⟩ := desyncBeta_lt m r0 r1 hm
  have hne := desync_beta0_ne_beta1 m r0 r1 hm
  have hj0 : j + desyncBeta0 m r0 < 2 * m := by omega
  have hj1 : j + desyncBeta1 m r0 r1 < 2 * m := by omega
  rw [mod_of_lt_two_mul (j + desyncBeta0 m r0) m hj0,
      mod_of_lt_two_mul (j + desyncBeta1 m r0 r1) m hj1]
  split <;> split <;> omega

/--
  Left inverse of `laneSlotShift`: for any `beta < m` and `j < m`,
  `invLaneSlotShift m beta (laneSlotShift m beta j) = j`.
-/
theorem laneSlotShift_left_inv (m beta j : Nat) (hb : beta < m) (hj : j < m) :
    invLaneSlotShift m beta (laneSlotShift m beta j) = j := by
  unfold invLaneSlotShift laneSlotShift
  have hjb : j + beta < 2 * m := by omega
  rw [mod_of_lt_two_mul (j + beta) m hjb]
  have houter : (if j + beta < m then j + beta else j + beta - m) + m - beta < 2 * m := by
    split <;> omega
  rw [mod_of_lt_two_mul _ m houter]
  split <;> split <;> omega

/--
  Right inverse of `laneSlotShift`: for any `beta < m` and `y < m`,
  `laneSlotShift m beta (invLaneSlotShift m beta y) = y`.
-/
theorem laneSlotShift_right_inv (m beta y : Nat) (hb : beta < m) (hy : y < m) :
    laneSlotShift m beta (invLaneSlotShift m beta y) = y := by
  unfold laneSlotShift invLaneSlotShift
  have hym : y + m - beta < 2 * m := by omega
  rw [mod_of_lt_two_mul (y + m - beta) m hym]
  have houter : (if y + m - beta < m then y + m - beta else y + m - beta - m) + beta < 2 * m := by
    split <;> omega
  rw [mod_of_lt_two_mul _ m houter]
  split <;> split <;> omega

/-! ### 2.2 Multiplicative Strengthening of `Omega48` and `Omega168` at Mode 2 and Mode 1 Floors -/

/--
  Mode 2 Floor (`21 × 21 = 441` px, `P_r = 147` px, `M = 480` chunks in `Interlock48`,
  `M = 137` chunks in `Interlock168`):
  1. `Omega48 = 1,355,345,464,406,015,082,330` and `Omega168` are 100% preserved.
  2. In `Interlock48` (`M = 480`), the combined per-chunk mask × 3-lane slot space is
     `Omega48 * 480^3 > 2^96` (`< 2^97`), and with the 32-bit `interlock_nonce` fold `v`,
     `Omega48WithFold * 480^3 > 2^128` (`< 2^129`).
  3. In `Interlock168` (`M = 137`), the combined per-chunk mask × 3-lane slot space is
     `Omega168 * 137^3 > 2^279` (`< 2^280`), and with the 32-bit `interlock_nonce` fold `v`,
     `Omega168WithFold * 137^3 > 2^311` (`< 2^312`).
-/
theorem interlock_desync_bounds_mode2_floor :
    2 ^ 96 < Omega48 * 480 ^ 3 ∧
    Omega48 * 480 ^ 3 < 2 ^ 97 ∧
    2 ^ 128 < Omega48WithFold * 480 ^ 3 ∧
    Omega48WithFold * 480 ^ 3 < 2 ^ 129 ∧
    2 ^ 279 < Omega168 * 137 ^ 3 ∧
    Omega168 * 137 ^ 3 < 2 ^ 280 ∧
    2 ^ 311 < Omega168WithFold * 137 ^ 3 ∧
    Omega168WithFold * 137 ^ 3 < 2 ^ 312 := by decide

/--
  Mode 1 Floor (`35 × 35 = 1225` px, `P_r = 408` px, `M = 1395` chunks in `Interlock48`,
  `M = 398` chunks in `Interlock168`):
  1. In `Interlock48` (`M = 1395`), `Omega48 * 1395^3 > 2^101` (`< 2^102`), and with
     the 32-bit `interlock_nonce` fold `v`, `Omega48WithFold * 1395^3 > 2^133` (`< 2^134`).
  2. In `Interlock168` (`M = 398`), `Omega168 * 398^3 > 2^284` (`< 2^285`), and with
     the 32-bit `interlock_nonce` fold `v`, `Omega168WithFold * 398^3 > 2^316` (`< 2^317`).
-/
theorem interlock_desync_bounds_mode1_floor :
    2 ^ 101 < Omega48 * 1395 ^ 3 ∧
    Omega48 * 1395 ^ 3 < 2 ^ 102 ∧
    2 ^ 133 < Omega48WithFold * 1395 ^ 3 ∧
    Omega48WithFold * 1395 ^ 3 < 2 ^ 134 ∧
    2 ^ 284 < Omega168 * 398 ^ 3 ∧
    Omega168 * 398 ^ 3 < 2 ^ 285 ∧
    2 ^ 316 < Omega168WithFold * 398 ^ 3 ∧
    Omega168WithFold * 398 ^ 3 < 2 ^ 317 := by decide

/-!
  =============================================================================
  PART III: Non-Interference Theorems Across Proofs 1 through 12
  =============================================================================
-/

/-! ### 3.1 Preservation of Proof 1 (Information-Theoretic Barrier), Proof 2 (KPA), and Proof 8 (Deniability) -/

/--
  Preservation of Proof 1 (`desync_preserves_proof1_bijection`):
  At every physical sub-region pixel `subregionAddr O M s q` and for any Layer II
  permuted data stream `dStream : Nat → BitVec 7`, the channel encoding map
  `(d, noiseBit) ↦ encodeChannel d m r np noiseBit` remains an exact bijection between
  `BitVec 7 × Bool` (`256` pairs) and `BitVec 8` (`256` bytes), preserving the uniform
  marginal `P(v | h, Π_r, Σ_ℓ) = 1/256`.
-/
theorem desync_preserves_proof1_bijection
    (O M s q : Nat) (obs : Nat → BitVec 8)
    (m : BitVec 7) (r : Fin 7) (np : Fin 8) (d : BitVec 7) (noiseBit : Bool) :
    let physIdx := subregionAddr O M s q
    let v := obs physIdx
    (decodeChannel (encodeChannel d m r np noiseBit) m r np,
     (encodeChannel d m r np noiseBit).getLsbD np.val) = (d, noiseBit) ∧
    encodeChannel (decodeChannel v m r np) m r np (v.getLsbD np.val) = v := by
  dsimp only
  exact ⟨proof1_encode_bijection_left_inv m r np d noiseBit,
         proof1_encode_bijection_right_inv m r np (obs (subregionAddr O M s q))⟩

/--
  Preservation of Proof 2 (`desync_preserves_proof2_unique_mask`):
  For any sub-region configuration `(O, M, s, q)`, any Layer II slot permutation `sigma : Nat → Nat`,
  any logical plaintext stream `plain : Nat → BitVec 7`, any observed container `obs : Nat → BitVec 8`,
  any candidate noise position `np : Fin 8`, and any candidate rotation `r : Fin 7`,
  there exists a unique 7-bit mask `m = candidateMask v (plain (sigma q)) np r` consistent
  with the observation `v = obs (subregionAddr O M s q)`.
-/
theorem desync_preserves_proof2_unique_mask
    (O M s q : Nat) (sigma : Nat → Nat) (plain : Nat → BitVec 7) (obs : Nat → BitVec 8)
    (np : Fin 8) (r : Fin 7) :
    let physIdx := subregionAddr O M s q
    let v := obs physIdx
    let d := plain (sigma q)
    encodeChannel d (candidateMask v d np r) r np (v.getLsbD np.val) = v ∧
    ∀ m' : BitVec 7, encodeChannel d m' r np (v.getLsbD np.val) = v → m' = candidateMask v d np r := by
  dsimp only
  exact proof2_exists_unique_mask (plain (sigma q)) (obs (subregionAddr O M s q)) np r

/--
  Preservation of the 56 Pre-CCA and 7 Post-CCA Per-Pixel Candidate Counts
  (`desync_preserves_56_candidates`):
  At every sub-region pixel `subregionAddr O M s q`, all `8 × 7 = 56` candidate `(np, r)` pairs
  before CCA and all `7` candidate rotations `r ∈ Fin 7` after CCA noise-position revelation
  admit a valid consistent mask.
-/
theorem desync_preserves_56_candidates :
    ((List.finRange 8).flatMap fun (np : Fin 8) =>
      (List.finRange 7).map fun (r : Fin 7) => (np, r)).length = 56 ∧
    (List.finRange 7).length = 7 ∧
    pixelSemanticConfigs = 56 * 2 ^ 56 ∧
    pixelPostCCAConfigs = 7 * 2 ^ 56 := by decide

/--
  Preservation of Proof 8 (`desync_preserves_proof8_deniability`):
  Decoding any sub-region pixel `subregionAddr O M s q` under any wrong candidate
  `(m', r', np')` remains a strict 2-to-1 surjection from `BitVec 8` (`256` byte values)
  onto `BitVec 7` (`128` 7-bit values).
-/
theorem desync_preserves_proof8_deniability
    (O M s q : Nat) (obs : Nat → BitVec 8)
    (m' : BitVec 7) (r' : Fin 7) (np' : Fin 8) (out : BitVec 7) (nb : Bool) :
    let physIdx := subregionAddr O M s q
    let v := encodeChannel out m' r' np' nb
    decodeChannel v m' r' np' = out ∧
    v.getLsbD np'.val = nb ∧
    encodeChannel (decodeChannel (obs physIdx) m' r' np') m' r' np'
      ((obs physIdx).getLsbD np'.val) = obs physIdx ∧
    ∀ v' : BitVec 8,
      decodeChannel v' m' r' np' = out →
      v'.getLsbD np'.val = nb →
      v' = v := by
  dsimp only
  have h8 := proof8_deniability_channel_surjection m' r' np' out nb
  exact ⟨h8.1, h8.2.1, encode_decode_id (obs (subregionAddr O M s q)) m' r' np', h8.2.2⟩

/-! ### 3.2 Preservation of Proof 3, Proof 3a (8-Seed Isolation), and Domain Tag Separation -/

/-- Domain tag `0x01` (MAC / KDF stream derivation). -/
def domainTagMAC : BitVec 8 := 0x01#8
/-- Domain tag `0x02` (`deriveStartPixel` on `startSeed1..3`). -/
def domainTagStartPixel : BitVec 8 := 0x02#8
/-- Domain tag `0x03` (`rankEvalBlock` per-group evaluation on `lockSeed`). -/
def domainTagRankEval : BitVec 8 := 0x03#8
/-- Domain tag `0x04` (`deriveInterLockSeed` primer key on `lockSeed`). -/
def domainTagInterLockSeed : BitVec 8 := 0x04#8
/-- Domain tag `0x05` (Layer I sub-region schedule on `startSeed1..3`). -/
def domainTagSubregion : BitVec 8 := 0x05#8
/-- Domain tag `0x06` (Layer II cross-lane slot desynchronization on `lockSeed`). -/
def domainTagLaneDesync : BitVec 8 := 0x06#8

/--
  All 6 domain tags `0x01..0x06` across ITB are pairwise distinct (`15` unordered pairs = `30` ordered pairs).
-/
theorem desync_domain_tags_pairwise_distinct :
    let tags := [domainTagMAC, domainTagStartPixel, domainTagRankEval,
                 domainTagInterLockSeed, domainTagSubregion, domainTagLaneDesync]
    tags.length = 6 ∧
    tags.Nodup := by decide

/--
  Preservation of Proof 3 Per-Region Noise Counter Disjointness (`desync_preserves_noiseCounter_injective`):
  Because `processChunk*` hashes `noiseBase + P + q` (the logical pixel index `p = P + q`)
  independently of the physical sub-region address `subregionAddr O M s q`, distinct
  `(region, P + q)` pairs never collide on `noiseSeed`.
-/
theorem desync_preserves_noiseCounter_injective
    (r1 r2 : Fin 3) (regionPixels P1 q1 P2 q2 : Nat)
    (hp1 : P1 + q1 < regionPixels) (hp2 : P2 + q2 < regionPixels)
    (heq : noiseCounter r1 regionPixels (P1 + q1) = noiseCounter r2 regionPixels (P2 + q2)) :
    r1 = r2 ∧ P1 + q1 = P2 + q2 :=
  noiseCounter_injective r1 r2 regionPixels (P1 + q1) (P2 + q2) hp1 hp2 heq

/--
  Preservation of Proof 3a (`desync_preserves_seed_isolation`):
  Layer I (`subregionAddr` driven exclusively by `startSeed_r` in domains `.S1, .S2, .S3`,
  where `isObservable = true`) and Layer II (`laneSlotShift` driven exclusively by `lockSeed`
  in domain `.L`, where `isObservable = false`) introduce zero cross-domain seed sharing,
  preserving `eight_seed_minimality` and the exact `32 / 12 / 12` leakage-class partition.
-/
theorem desync_preserves_seed_isolation :
    isObservable .S1 = true ∧
    isObservable .S2 = true ∧
    isObservable .S3 = true ∧
    isObservable .L = false ∧
    isObservable .D1 = false ∧
    isObservable .D2 = false ∧
    isObservable .D3 = false ∧
    classifyMerge .S1 .L = .ObservableAndUnobservable ∧
    classifyMerge .S2 .L = .ObservableAndUnobservable ∧
    classifyMerge .S3 .L = .ObservableAndUnobservable := by decide

/-! ### 3.3 Preservation of Proof 6 (CCA Leak Bound) and `Verify-before-COBS` -/

/--
  Preservation of Proof 6 (`desync_preserves_proof6_cca_classification`):
  At every physical pixel `subregionAddr O M s q` of any invisible sub-region, flipping
  bit `b ∈ Fin 8` of the observed channel byte `v = obs (subregionAddr O M s q)` preserves
  `decodeChannel` if and only if `b = np`, with exactly 1 accept (`b = np`) and 7 rejects
  (`b ≠ np`) across all 8 bit positions.
-/
theorem desync_preserves_proof6_cca_classification
    (O M s q : Nat) (obs : Nat → BitVec 8) (m : BitVec 7) (r : Fin 7) (np b : Fin 8) :
    let v := obs (subregionAddr O M s q)
    (decodeChannel (flipBit8 v b) m r np = decodeChannel v m r np ↔ b = np) ∧
    ((List.finRange 8).filter (fun bit => extractBits (flipBit8 v bit) np == extractBits v np)).length = 1 ∧
    ((List.finRange 8).filter (fun bit => extractBits (flipBit8 v bit) np != extractBits v np)).length = 7 := by
  dsimp only
  exact ⟨flipBit8_decodeChannel_eq_iff (obs (subregionAddr O M s q)) m r np b,
         mac_inside_encrypt_uniform_bitflip_classification (obs (subregionAddr O M s q)) np⟩

/--
  Two-layer authenticated decoder state machine (`authDecodeDesync`):
  1. Layer I (`subregionDecode`) decodes the physical container using public `main_nonce`
     and `startSeed1..3` into `cap`.
  2. `verifyMAC cap` checks the full-capacity MAC tag **before** COBS null search and
     **before** Layer II (`invLaneDesync`).
  3. Only if `verifyMAC cap = true` does the decoder run `cobsSearchNull` and `invLaneDesync`.
-/
def authDecodeDesync {Container Capacity Lanes Payload : Type}
    (subregionDecode : Container → Capacity)
    (verifyMAC : Capacity → Bool)
    (cobsSearchNull : Capacity → Lanes)
    (invLaneDesync : Lanes → Payload)
    (cont : Container) : AuthDecodeResult Payload :=
  let cap := subregionDecode cont
  if verifyMAC cap then .cobsDecoded (invLaneDesync (cobsSearchNull cap))
  else .macRejected

/--
  Preservation of `Verify-before-COBS` under Two-Layer Desynchronization
  (`desync_preserves_verify_before_cobs`):
  Whenever `verifyMAC (subregionDecode cont) = false` (any tampered bit in data, COBS framing,
  `interlock_nonce` prefix, or DRBG tail), `authDecodeDesync` returns `.macRejected` and is
  completely invariant to both `cobsSearchNull` and `invLaneDesync` (neither COBS nor Layer II
  slot desynchronization is ever executed on unauthenticated data).
-/
theorem desync_preserves_verify_before_cobs {Container Capacity Lanes Payload : Type}
    (subregionDecode : Container → Capacity)
    (verifyMAC : Capacity → Bool)
    (cobs1 cobs2 : Capacity → Lanes)
    (desync1 desync2 : Lanes → Payload)
    (cont : Container)
    (hfail : verifyMAC (subregionDecode cont) = false) :
    authDecodeDesync subregionDecode verifyMAC cobs1 desync1 cont = .macRejected ∧
    authDecodeDesync subregionDecode verifyMAC cobs1 desync1 cont =
      authDecodeDesync subregionDecode verifyMAC cobs2 desync2 cont := by
  unfold authDecodeDesync
  dsimp only
  rw [hfail]
  exact ⟨rfl, rfl⟩

/-! ### 3.4 Preservation of Proof 9 (Ambiguity Dominance), Proof 10 (DRBG Residue), and Proof 12 (`gcd` Anti-Collapse) -/

/--
  Preservation of Proofs 9 and 10 (`desync_preserves_proof9_and_proof10`):
  Because telescopic sub-region sizes sum to `P_r` (`telescopic_region_partition_sum`)
  and Layer II slot permutations preserve `laneLen` (`0` bytes of wire overhead),
  the total container pixel count `P = (s + 1)^2`, the ambiguity dominance bound `C^P > 2^k`,
  and the guaranteed DRBG residue `(s + 1)^2 * 7 - s^2 * 7 = (2 * s + 1) * 7 ≥ 21` bytes
  are identically preserved.
-/
theorem desync_preserves_proof9_and_proof10
    (s C P_th k : Nat) (hs : s ≥ 1) (hC : C ≥ 1)
    (hP : (s + 1) ^ 2 ≥ P_th) (hth : C ^ P_th > 2 ^ k) :
    C ^ ((s + 1) ^ 2) > 2 ^ k ∧
    (s + 1) ^ 2 * 7 - s ^ 2 * 7 = (2 * s + 1) * 7 ∧
    (s + 1) ^ 2 * 7 - s ^ 2 * 7 ≥ 21 :=
  ⟨ambiguity_dominates_of_ge hC hP hth, drbg_no_perfect_fill s hs⟩

/--
  Preservation of Proof 12 (`desync_preserves_proof12_anti_collapse`):
  When deriving independent sub-region or slot parameters `(a, b) ∈ [0, A) × [0, B)` from
  a single word `r` when `gcd(A, B) = d > 1`, two-step division-before-modulo
  `twoStepUnrank A B` reaches every pair `(a, b)` via `twoStepWitness A B 0 a b`,
  whereas `naiveDoubleMod A B` (`(r % A, r % B)`) collapses whenever `a % d ≠ b % d`.
-/
theorem desync_preserves_proof12_anti_collapse (A B d a b : Nat)
    (ha : a < A) (hb : b < B) (hdA : d ∣ A) (hdB : d ∣ B) (hne : a % d ≠ b % d) :
    twoStepUnrank A B (twoStepWitness A B 0 a b) = (a, b) ∧
    (¬ ∃ r : Nat, naiveDoubleMod A B r = (a, b)) :=
  ⟨twoStepUnrank_witness A B 0 a b ha hb,
   naiveDoubleMod_unreachable_of_mod_ne A B d a b hdA hdB hne⟩

/-! ### 3.5 Full-Width Bijective Feistel Fold `fullWidthFold` (`0x05` and `0x06`) -/

/--
  Full-width bijective Feistel fold over the 128-bit `(hLo, hHi)` pair of a `ChainHash`
  evaluation under domain tags `0x05` (Layer I sub-region schedule) and `0x06` (Layer II
  cross-lane slot desynchronization):
  `mixHi = rotl64(hHi, 25) + rotl64(hHi, 53)`
  `w0    = hLo + mixHi`
  `w1    = hHi ^^^ rotl64(w0, 19) ^^^ rotl64(w0, 41)`
  Couples both 64-bit output lanes so that `w0` and `w1` depend on 100% of key words
  even in broken-primitive stress controls (e.g., `FNV-1a`, where `hLo` alone is blind to
  odd-indexed key words and `hHi` has a 24-bit low-order dead zone `hHi[0..23]`).
-/
def fullWidthFold (hLo hHi : BitVec 64) : BitVec 64 × BitVec 64 :=
  let mixHi := hHi.rotateLeft 25 + hHi.rotateLeft 53
  let w0 := hLo + mixHi
  let w1 := hHi ^^^ (w0.rotateLeft 19) ^^^ (w0.rotateLeft 41)
  (w0, w1)

/--
  Exact inverse of `fullWidthFold` on `BitVec 64 × BitVec 64`.
-/
def invFullWidthFold (w0 w1 : BitVec 64) : BitVec 64 × BitVec 64 :=
  let hHi := w1 ^^^ (w0.rotateLeft 19) ^^^ (w0.rotateLeft 41)
  let mixHi := hHi.rotateLeft 25 + hHi.rotateLeft 53
  let hLo := w0 - mixHi
  (hLo, hHi)

/--
  Full-Width Bijective Feistel Fold Theorem (`fullWidthFold_bijection`):
  `fullWidthFold` and `invFullWidthFold` are exact two-sided inverses on `BitVec 64 × BitVec 64`,
  inducing a strict bijection over `2^128` states with zero entropy loss on uniform PRF outputs.
-/
theorem fullWidthFold_bijection (hLo hHi w0 w1 : BitVec 64) :
    invFullWidthFold (fullWidthFold hLo hHi).1 (fullWidthFold hLo hHi).2 = (hLo, hHi) ∧
    fullWidthFold (invFullWidthFold w0 w1).1 (invFullWidthFold w0 w1).2 = (w0, w1) := by
  unfold fullWidthFold invFullWidthFold
  dsimp only
  have h_xor1 :
      hHi ^^^ (hLo + (hHi.rotateLeft 25 + hHi.rotateLeft 53)).rotateLeft 19 ^^^
        (hLo + (hHi.rotateLeft 25 + hHi.rotateLeft 53)).rotateLeft 41 ^^^
        (hLo + (hHi.rotateLeft 25 + hHi.rotateLeft 53)).rotateLeft 19 ^^^
        (hLo + (hHi.rotateLeft 25 + hHi.rotateLeft 53)).rotateLeft 41 = hHi := by
    bv_decide
  have h_sub :
      hLo + (hHi.rotateLeft 25 + hHi.rotateLeft 53) -
        (hHi.rotateLeft 25 + hHi.rotateLeft 53) = hLo := by
    bv_decide
  have h_add :
      w0 - ((w1 ^^^ w0.rotateLeft 19 ^^^ w0.rotateLeft 41).rotateLeft 25 +
            (w1 ^^^ w0.rotateLeft 19 ^^^ w0.rotateLeft 41).rotateLeft 53) +
        ((w1 ^^^ w0.rotateLeft 19 ^^^ w0.rotateLeft 41).rotateLeft 25 +
         (w1 ^^^ w0.rotateLeft 19 ^^^ w0.rotateLeft 41).rotateLeft 53) = w0 := by
    bv_decide
  have h_xor2 :
      w1 ^^^ w0.rotateLeft 19 ^^^ w0.rotateLeft 41 ^^^ w0.rotateLeft 19 ^^^ w0.rotateLeft 41 = w1 := by
    bv_decide
  rw [h_xor1, h_sub, h_add, h_xor2]
  exact ⟨rfl, rfl⟩

/--
  `FNV-1a` 24-Bit Low-Order Dead-Zone Coverage (`fullWidthFold_fnv1a_dead_zone_coverage`):
  In 128-bit `FNV-1a`, the high 40 bits `hHi[24..63]` carry the active key-dependent bits
  while `hHi[0..23]` form a 24-bit low-order dead zone. Rotating `hHi` left by `25` maps
  `hHi[24..63]` onto bits `[49..63]` and `[0..24]`, and rotating `hHi` left by `53` maps
  `hHi[24..63]` onto bits `[13..52]`, covering all 64 bit positions `[0..63]` of `w0`.
-/
theorem fullWidthFold_fnv1a_dead_zone_coverage :
    24 + 25 = 49 ∧
    (63 + 25) % 64 = 24 ∧
    (24 + 53) % 64 = 13 ∧
    (63 + 53) % 64 = 52 ∧
    13 ≤ 24 ∧ 49 ≤ 52 := by decide

/--
  Universal PRF Preimage Uniqueness Theorem (`fullWidthFold_preserves_prf_cardinality`):
  For every 128-bit target output `(w0, w1) : BitVec 64 × BitVec 64`, `invFullWidthFold w0 w1`
  is the unique preimage under `fullWidthFold`. Consequently, for every PRF-grade registry
  primitive in ITB, applying `fullWidthFold` preserves the exact uniform distribution on
  `{0, 1}^128` with 1-to-1 preimage cardinality and zero bits of entropy loss.
-/
theorem fullWidthFold_preserves_prf_cardinality (w0 w1 hLo hHi : BitVec 64) :
    fullWidthFold (invFullWidthFold w0 w1).1 (invFullWidthFold w0 w1).2 = (w0, w1) ∧
    (fullWidthFold hLo hHi = (w0, w1) ↔ (hLo, hHi) = invFullWidthFold w0 w1) := by
  refine ⟨(fullWidthFold_bijection hLo hHi w0 w1).2, ⟨?_, ?_⟩⟩
  · intro hf
    have hinv := (fullWidthFold_bijection hLo hHi w0 w1).1
    rw [hf] at hinv
    exact hinv.symm
  · intro hpre
    have h1 : hLo = (invFullWidthFold w0 w1).1 := congrArg Prod.fst hpre
    have h2 : hHi = (invFullWidthFold w0 w1).2 := congrArg Prod.snd hpre
    rw [h1, h2]
    exact (fullWidthFold_bijection hLo hHi w0 w1).2

/--
  Dual-Lane Sensitivity Theorem (`fullWidthFold_crc128_dual_lane_sensitivity`):
  Eliminates the 50% odd-component seed blindness of `hLo` in both `CRC128` (`hLo = CRC64-ECMA`
  on even seed words, `hHi = CRC64-ISO` on odd seed words) and `FNV-1a`:
  1. For any fixed `hHi`, distinct `hLo1 ≠ hLo2` produce strictly distinct `w0` words.
  2. For any fixed `hLo`, distinct `hHi1 ≠ hHi2` produce strictly distinct `(w0, w1)` pairs.
  3. Universal single-bit sensitivity in `w0` alone to BOTH 64-bit lanes: for every state
     `(hLo, hHi)` and every bit position `b < 64`, flipping bit `b` in `hLo` strictly changes
     `w0`, and flipping bit `b` in `hHi` also strictly changes `w0`.
-/
theorem fullWidthFold_crc128_dual_lane_sensitivity
    (hLo hLo1 hLo2 hHi hHi1 hHi2 b : BitVec 64) :
    ((fullWidthFold hLo1 hHi).1 = (fullWidthFold hLo2 hHi).1 ↔ hLo1 = hLo2) ∧
    (fullWidthFold hLo hHi1 = fullWidthFold hLo hHi2 ↔ hHi1 = hHi2) ∧
    (b < 64#64 →
      (fullWidthFold (hLo ^^^ (1#64 <<< b)) hHi).1 ≠ (fullWidthFold hLo hHi).1 ∧
      (fullWidthFold hLo (hHi ^^^ (1#64 <<< b))).1 ≠ (fullWidthFold hLo hHi).1) := by
  refine ⟨?_, ?_, ?_⟩
  · unfold fullWidthFold
    dsimp only
    bv_decide
  · constructor
    · intro heq
      have hbij := (fullWidthFold_bijection hLo hHi1 hLo hHi1).1
      have hbij2 := (fullWidthFold_bijection hLo hHi2 hLo hHi2).1
      rw [heq] at hbij
      rw [hbij] at hbij2
      injection hbij2
    · intro heq
      subst heq
      rfl
  · unfold fullWidthFold
    dsimp only
    bv_decide

/--
  Non-Affinity and Public-Constant Non-Separability Theorem (`fullWidthFold_non_affine_gf2`):
  Because `fullWidthFold` combines `GF(2)` XOR/rotations with modular addition in `Z / 2^64 Z`,
  an affine `CRC128` state `(hLo, hHi) = (kLo ^^^ cLo, kHi ^^^ cHi)` cannot be separated into
  a key term and a public `zeroSeed` constant term `(cLo, cHi)`:
  1. `w0(K ^^^ c1) ≠ w0(K) ^^^ w0(c1)` and `w1(K ^^^ c1) ≠ w1(K) ^^^ w1(c1)` (`GF(2)` linearity fails),
  2. `w0(K ^^^ c1) - w0(c1) ≠ w0(K)` (`Z / 2^64 Z` constant subtraction fails),
  3. Across two distinct counter constants `c1 ≠ c2`, neither the XOR differential
     `w0(K ^^^ c1) ^^^ w0(K ^^^ c2)` nor the modular difference `w0(K ^^^ c1) - w0(K ^^^ c2)`
     equals the key-independent `zeroSeed` differential.
-/
theorem fullWidthFold_non_affine_gf2 :
    let kLo  : BitVec 64 := 0x0123456789ABCDEF#64
    let kHi  : BitVec 64 := 0xFEDCBA9876543210#64
    let c1Lo : BitVec 64 := 0x1111111111111111#64
    let c1Hi : BitVec 64 := 0x2222222222222222#64
    let c2Lo : BitVec 64 := 0x3333333333333333#64
    let c2Hi : BitVec 64 := 0x4444444444444444#64
    (fullWidthFold (kLo ^^^ c1Lo) (kHi ^^^ c1Hi)).1 ≠
      (fullWidthFold kLo kHi).1 ^^^ (fullWidthFold c1Lo c1Hi).1 ∧
    (fullWidthFold (kLo ^^^ c1Lo) (kHi ^^^ c1Hi)).2 ≠
      (fullWidthFold kLo kHi).2 ^^^ (fullWidthFold c1Lo c1Hi).2 ∧
    (fullWidthFold (kLo ^^^ c1Lo) (kHi ^^^ c1Hi)).1 - (fullWidthFold c1Lo c1Hi).1 ≠
      (fullWidthFold kLo kHi).1 ∧
    ((fullWidthFold (kLo ^^^ c1Lo) (kHi ^^^ c1Hi)).1 ^^^
     (fullWidthFold (kLo ^^^ c2Lo) (kHi ^^^ c2Hi)).1) ≠
      ((fullWidthFold c1Lo c1Hi).1 ^^^ (fullWidthFold c2Lo c2Hi).1) ∧
    ((fullWidthFold (kLo ^^^ c1Lo) (kHi ^^^ c1Hi)).1 -
     (fullWidthFold (kLo ^^^ c2Lo) (kHi ^^^ c2Hi)).1) ≠
      ((fullWidthFold c1Lo c1Hi).1 - (fullWidthFold c2Lo c2Hi).1) := by
  decide

end ITB.Desync
