/-
  Formal verification of the 48-bit and 168-bit Rank Barrier reciprocal division
  constants and single-correction exactness theorems for `divB`, `modA`,
  `splitRank48Recip`, `divmodStepB168`, `modStepA168`, and `splitRank168` in
  `interlock48_rank_split.go` and `interlock168_rank_split.go` (Proofs 11 and 12).
-/
import ITB.RankBarrier

namespace ITB.SplitRank

open ITB.RankBarrier

set_option exponentiation.threshold 10000
set_option maxRecDepth 200000

/-! ## Exact 64-Bit Limb Constants from `interlock168_rank_split.go` -/

/-- Low 64-bit limb of `A168 = C(168, 56)`. -/
def interlockA168_0 : Nat := 0xb93f03fb9f9a2ad8
/-- Middle 64-bit limb of `A168 = C(168, 56)`. -/
def interlockA168_1 : Nat := 0x053d5b033cbb2e27
/-- High 64-bit limb of `A168 = C(168, 56)`. -/
def interlockA168_2 : Nat := 0x000000000050afaf

/-- Low 64-bit limb of `B168 = C(112, 56)`. -/
def interlockB168_0 : Nat := 0x5bc2bbe1b5e02c78
/-- High 64-bit limb of `B168 = C(112, 56)`. -/
def interlockB168_1 : Nat := 0x00001341f080963d

/-- Low 64-bit limb of `muB168 = floor(2^236 / B168)`. -/
def interlockMuB168_0 : Nat := 0x4508f9134af46c6b
/-- High 64-bit limb of `muB168 = floor(2^236 / B168)`. -/
def interlockMuB168_1 : Nat := 0xd4b20d19ce585c96

/-- Low 64-bit limb of `muA168 = floor(2^342 / A168)`. -/
def interlockMuA168_0 : Nat := 0xe2ea7578684213e8
/-- Middle 64-bit limb of `muA168 = floor(2^342 / A168)`. -/
def interlockMuA168_1 : Nat := 0x660063d3f1f72561
/-- High 64-bit limb of `muA168 = floor(2^342 / A168)`. -/
def interlockMuA168_2 : Nat := 0xcb0ee004eb554b2b

/-- Multi-limb value of `A168` assembled from its 3 little-endian 64-bit limbs. -/
def A168_limbs : Nat :=
  interlockA168_2 * 2 ^ 128 + interlockA168_1 * 2 ^ 64 + interlockA168_0

/-- Multi-limb value of `B168` assembled from its 2 little-endian 64-bit limbs. -/
def B168_limbs : Nat :=
  interlockB168_1 * 2 ^ 64 + interlockB168_0

/-- Multi-limb value of `muB168` assembled from its 2 little-endian 64-bit limbs. -/
def muB168 : Nat :=
  interlockMuB168_1 * 2 ^ 64 + interlockMuB168_0

/-- Multi-limb value of `muA168` assembled from its 3 little-endian 64-bit limbs. -/
def muA168 : Nat :=
  interlockMuA168_2 * 2 ^ 128 + interlockMuA168_1 * 2 ^ 64 + interlockMuA168_0

/-! ## Verification of Limb Constants Against Binomial Coefficients and Reciprocals -/

/-- Exact match between the 2-limb constant `B168_limbs` in `interlock168_rank_split.go` and `C(112, 56)`. -/
theorem B168_limbs_eq_binom : B168_limbs = binom 112 56 := by decide

/-- Exact match between the 3-limb constant `A168_limbs` in `interlock168_rank_split.go` and `C(168, 56)`. -/
theorem A168_limbs_eq_binom : A168_limbs = binom 168 56 := by decide

/-- `muB168` is the exact floor reciprocal `⌊2^236 / B168⌋`. -/
theorem muB168_eq_floor_div : muB168 = 2 ^ 236 / B168_limbs := by decide

/-- Remainder `r_muB = 2^236 - muB168 * B168` satisfies `0 < r_muB < B168`. -/
theorem muB168_remainder_bounds :
    0 < 2 ^ 236 - muB168 * B168_limbs ∧
    2 ^ 236 - muB168 * B168_limbs < B168_limbs := by decide

/-- `muA168` is the exact floor reciprocal `⌊2^342 / A168⌋`. -/
theorem muA168_eq_floor_div : muA168 = 2 ^ 342 / A168_limbs := by decide

/-- Remainder `r_muA = 2^342 - muA168 * A168` satisfies `0 < r_muA < A168`. -/
theorem muA168_remainder_bounds :
    0 < 2 ^ 342 - muA168 * A168_limbs ∧
    2 ^ 342 - muA168 * A168_limbs < A168_limbs := by decide

/-! ## Error-Envelope and Single-Correction Exactness Theorems -/

/--
  Key slack inequality for `divmodStepB168`:
  The maximum reciprocal approximation error plus low-limb truncation error `(dropped < 2 * 2^192)`
  satisfies `(B168 * 2^64) * (2^236 - muB168 * B168) + (2 * 2^192) * B168 < 2^236 * B168`.
  This guarantees `qHat` never under-approximates `X / B168` by 2 or more (`X / B168 - qHat ≤ 1`).
-/
theorem divmodStepB168_error_envelope :
    (B168_limbs * 2 ^ 64) * (2 ^ 236 - muB168 * B168_limbs) + (2 * 2 ^ 192) * B168_limbs
      < 2 ^ 236 * B168_limbs := by decide

/--
  Key slack inequality for `modStepA168`:
  The maximum reciprocal approximation error plus low-limb truncation error `(dropped < 4 * 2^256)`
  satisfies `(A168 * 2^64) * (2^342 - muA168 * A168) + (4 * 2^256) * A168 < 2^342 * A168`.
  This guarantees `qHat` never under-approximates `X / A168` by 2 or more (`X / A168 - qHat ≤ 1`).
-/
theorem modStepA168_error_envelope :
    (A168_limbs * 2 ^ 64) * (2 ^ 342 - muA168 * A168_limbs) + (4 * 2 ^ 256) * A168_limbs
      < 2 ^ 342 * A168_limbs := by decide

/--
  General Barrett Under-Approximation and Single-Correction Exactness Theorem:
  Let divisor `D > 0`, shift `S > 0`, reciprocal `mu = S / D` (`mu * D ≤ S`), and dividend `X`.
  For any truncated product `P ≤ X * mu` with `qHat = P / S`:
  1. `qHat * D ≤ X` (`qHat` never overestimates `X / D`).
  2. If `X - qHat * D < 2 * D`, then the single branchless correction
     `q = if X - qHat * D ≥ D then qHat + 1 else qHat` and
     `r = if X - qHat * D ≥ D then X - (qHat + 1) * D else X - qHat * D`
     produces the exact Euclidean quotient and remainder: `X = q * D + r` and `r < D`.
-/
theorem single_correction_exact (D S mu X P : Nat)
    (hmu : mu * D ≤ S)
    (hP : P ≤ X * mu)
    (h_under : X < (P / S + 2) * D) :
    let qHat := P / S
    let rem := X - qHat * D
    let q := if rem ≥ D then qHat + 1 else qHat
    let r := if rem ≥ D then rem - D else rem
    qHat * D ≤ X ∧ X = q * D + r ∧ r < D := by
  dsimp only
  have h1 : (P / S) * S ≤ P := Nat.div_mul_le_self P S
  have h2 : (P / S) * (mu * D) ≤ (P / S) * S := Nat.mul_le_mul_left (P / S) hmu
  have h3 : (P / S) * mu * D ≤ X * mu := by
    rw [Nat.mul_assoc]
    omega
  have hqHat_le : (P / S) * D ≤ X := by
    by_cases hmu0 : mu = 0
    · subst hmu0
      have hP0 : P = 0 := by omega
      subst hP0
      simp
    · have hmu_pos : 0 < mu := Nat.pos_of_ne_zero hmu0
      have h4 : ((P / S) * D) * mu ≤ X * mu := by
        calc
          ((P / S) * D) * mu = (P / S) * (D * mu) := by rw [Nat.mul_assoc]
          _ = (P / S) * (mu * D) := by rw [Nat.mul_comm D mu]
          _ ≤ X * mu := by omega
      exact Nat.le_of_mul_le_mul_right h4 hmu_pos
  have h_add2 : (P / S + 2) * D = (P / S) * D + D + D := by
    rw [Nat.add_mul]
    omega
  have h_add1 : (P / S + 1) * D = (P / S) * D + D := by
    rw [Nat.add_mul, Nat.one_mul]
  refine ⟨hqHat_le, ?_, ?_⟩
  · split <;> omega
  · split <;> omega

/--
  Inductive correctness of multi-limb schoolbook division (`splitRank168` Step 1):
  If a step function replaces `(rem, w)` by `(q, rem')` satisfying `rem * 2^64 + w = q * B + rem'`
  with `rem' < B`, then combining a high quotient `Q_hi` (`N_hi = Q_hi * B + rem`) with limb `w`
  yields `N_hi * 2^64 + w = (Q_hi * 2^64 + q) * B + rem'` with `rem' < B`.
-/
theorem multi_limb_divmod_step (B N_hi Q_hi rem w q rem' : Nat)
    (h_hi : N_hi = Q_hi * B + rem)
    (h_step : rem * 2 ^ 64 + w = q * B + rem')
    (h_rem : rem' < B) :
    N_hi * 2 ^ 64 + w = (Q_hi * 2 ^ 64 + q) * B + rem' ∧ rem' < B := by
  refine ⟨?_, h_rem⟩
  calc
    N_hi * 2 ^ 64 + w = (Q_hi * B + rem) * 2 ^ 64 + w := by rw [h_hi]
    _ = Q_hi * B * 2 ^ 64 + (rem * 2 ^ 64 + w) := by rw [Nat.add_mul, Nat.add_assoc]
    _ = Q_hi * 2 ^ 64 * B + (q * B + rem') := by
      rw [h_step, Nat.mul_right_comm Q_hi B (2 ^ 64)]
    _ = (Q_hi * 2 ^ 64 + q) * B + rem' := by
      rw [Nat.add_mul, Nat.add_assoc]

/-! ## 48-Bit Reciprocal Division Constants (`splitRank48Recip`, `interlock48_rank_split.go:50-76`) -/

/-- 30-bit divisor `B = C(32, 16) = 601,080,390` in `interlock48_rank_split.go`. -/
def interlockB48 : Nat := 601080390

/-- 42-bit divisor `A = C(48, 16) = 2,254,848,913,647` in `interlock48_rank_split.go`. -/
def interlockA48 : Nat := 2254848913647

/-- Post-`mulhi` right-shift `interlockB48Shift = 29` (`2^29 < B < 2^30`). -/
def interlockB48Shift : Nat := 29

/-- Post-`mulhi` right-shift `interlockA48Shift = 41` (`2^41 < A < 2^42`). -/
def interlockA48Shift : Nat := 41

/-- 64-bit reciprocal `interlockB48Recip = ⌊2^93 / B⌋ = 0xe4a737fd2603cba7`. -/
def interlockB48Recip : Nat := 0xe4a737fd2603cba7

/-- 64-bit reciprocal `interlockA48Recip = ⌊2^105 / A⌋ = 0xf9a974e0a78bad8f`. -/
def interlockA48Recip : Nat := 0xf9a974e0a78bad8f

/--
  Certification of `interlockB48` and `interlockB48Recip` (`interlock48_rank_split.go:51-54`):
  `interlockB48 = B48 = C(32, 16)`, `interlockB48Recip = 16476199322162285479 = ⌊2^93 / B48⌋`,
  and the reciprocal approximation error `remB = 2^93 - interlockB48Recip * B48` satisfies
  `2^64 * remB < 2^93`.
-/
theorem interlockB48Recip_eq_floor_div :
    interlockB48 = B48 ∧
    interlockB48Recip = 16476199322162285479 ∧
    interlockB48Recip = (2 ^ (64 + interlockB48Shift)) / interlockB48 ∧
    interlockB48Recip * interlockB48 ≤ 2 ^ 93 ∧
    (interlockB48Recip + 1) * interlockB48 > 2 ^ 93 ∧
    (2 ^ 64) * (2 ^ 93 - interlockB48Recip * interlockB48) < 2 ^ 93 := by decide

/--
  Certification of `interlockA48` and `interlockA48Recip` (`interlock48_rank_split.go:52-55`):
  `interlockA48 = A48 = C(48, 16)`, `interlockA48Recip = 17990038694740602255 = ⌊2^105 / A48⌋`,
  and the reciprocal approximation error `remA = 2^105 - interlockA48Recip * A48` satisfies
  `2^64 * remA < 2^105`.
-/
theorem interlockA48Recip_eq_floor_div :
    interlockA48 = A48 ∧
    interlockA48Recip = 17990038694740602255 ∧
    interlockA48Recip = (2 ^ (64 + interlockA48Shift)) / interlockA48 ∧
    interlockA48Recip * interlockA48 ≤ 2 ^ 105 ∧
    (interlockA48Recip + 1) * interlockA48 > 2 ^ 105 ∧
    (2 ^ 64) * (2 ^ 105 - interlockA48Recip * interlockA48) < 2 ^ 105 := by decide

/-- Equivalence of `mulhi(X, mu) >> s` and `(X * mu) / 2^(64 + s)`. -/
theorem mulhi_shr_eq_div (X mu s : Nat) :
    ((X * mu) / 2 ^ 64) / 2 ^ s = (X * mu) / 2 ^ (64 + s) := by
  rw [Nat.div_div_eq_div_mul, ← Nat.pow_add]

/--
  For every 64-bit input `X < 2^64`, `divB` (`interlock48_rank_split.go:59-68`)
  under-approximates `X / B48` by at most 1 (`X < (qHat + 2) * B48`), and the single
  branchless correction produces the exact Euclidean quotient and remainder.
-/
theorem divB48_single_correction_exact (X : Nat) (hX : X < 2 ^ 64) :
    let qHat := (X * interlockB48Recip) / 2 ^ 93
    let rem := X - qHat * interlockB48
    let q := if rem ≥ interlockB48 then qHat + 1 else qHat
    let r := if rem ≥ interlockB48 then rem - interlockB48 else rem
    qHat * interlockB48 ≤ X ∧ X = q * interlockB48 + r ∧ r < interlockB48 := by
  have hmu : interlockB48Recip * interlockB48 ≤ 2 ^ 93 := by decide
  have h_under : X < ((X * interlockB48Recip) / 2 ^ 93 + 2) * interlockB48 := by
    unfold interlockB48 interlockB48Recip
    omega
  exact single_correction_exact interlockB48 (2 ^ 93) interlockB48Recip X (X * interlockB48Recip)
    hmu (Nat.le_refl _) h_under

/--
  For every 64-bit input `X < 2^64`, `modA` (`interlock48_rank_split.go:71-76`)
  under-approximates `X / A48` by at most 1 (`X < (qHat + 2) * A48`), and the single
  branchless correction produces the exact Euclidean remainder `r < A48`.
-/
theorem modA48_single_correction_exact (X : Nat) (hX : X < 2 ^ 64) :
    let qHat := (X * interlockA48Recip) / 2 ^ 105
    let rem := X - qHat * interlockA48
    let q := if rem ≥ interlockA48 then qHat + 1 else qHat
    let r := if rem ≥ interlockA48 then rem - interlockA48 else rem
    qHat * interlockA48 ≤ X ∧ X = q * interlockA48 + r ∧ r < interlockA48 := by
  have hmu : interlockA48Recip * interlockA48 ≤ 2 ^ 105 := by decide
  have h_under : X < ((X * interlockA48Recip) / 2 ^ 105 + 2) * interlockA48 := by
    unfold interlockA48 interlockA48Recip
    omega
  exact single_correction_exact interlockA48 (2 ^ 105) interlockA48Recip X (X * interlockA48Recip)
    hmu (Nat.le_refl _) h_under

end ITB.SplitRank
