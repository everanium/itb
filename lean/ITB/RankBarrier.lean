/-
  Formal verification of the 48-bit and 168-bit Rank Barrier combinadic mask spaces,
  preimage bounds, two-step unrank surjectivity, gcd(A, B) anti-collapse theorems,
  and Horner modular reduction identities (Proofs 11 and 12).
-/

namespace ITB.RankBarrier

set_option exponentiation.threshold 10000
set_option maxRecDepth 200000

/-! ## Binomial Coefficient via Verified Pascal Recurrence -/

/-- Advance one row of Pascal's triangle given the previous element `prev`. -/
def nextPascalRow : List Nat → Nat → List Nat
  | [], prev => [prev]
  | x :: xs, prev => (prev + x) :: nextPascalRow xs x

/-- Row `n` of Pascal's triangle: `[C(n, 0), C(n, 1), ..., C(n, n)]`. -/
def pascalRow : Nat → List Nat
  | 0 => [1]
  | n + 1 => nextPascalRow (pascalRow n) 0

/-- Retrieve element at index `k` of a list of naturals, defaulting to `0`. -/
def getAt : List Nat → Nat → Nat
  | [], _ => 0
  | x :: _, 0 => x
  | _ :: xs, k + 1 => getAt xs k

/-- Binomial coefficient `C(n, k)` evaluated via Pascal's triangle row `n`. -/
def binom (n k : Nat) : Nat :=
  getAt (pascalRow n) k

theorem nextPascalRow_getAt_zero (l : List Nat) (prev : Nat) :
    getAt (nextPascalRow l prev) 0 = prev + getAt l 0 := by
  cases l <;> rfl

theorem nextPascalRow_getAt_succ (l : List Nat) (prev k : Nat) :
    getAt (nextPascalRow l prev) (k + 1) = getAt l k + getAt l (k + 1) := by
  induction l generalizing prev k with
  | nil =>
    cases k <;> rfl
  | cons x xs ih =>
    cases k with
    | zero =>
      exact nextPascalRow_getAt_zero xs x
    | succ m =>
      exact ih x m

/-- Base case: `C(n, 0) = 1` for all `n`. -/
theorem binom_zero_right (n : Nat) : binom n 0 = 1 := by
  induction n with
  | zero => rfl
  | succ m ih =>
    unfold binom at ih ⊢
    change getAt (nextPascalRow (pascalRow m) 0) 0 = 1
    rw [nextPascalRow_getAt_zero, Nat.zero_add, ih]

/-- Base case: `C(0, k + 1) = 0` for all `k`. -/
theorem binom_zero_left (k : Nat) : binom 0 (k + 1) = 0 := rfl

/-- Pascal's identity: `C(n + 1, k + 1) = C(n, k) + C(n, k + 1)`. -/
theorem binom_succ_succ (n k : Nat) :
    binom (n + 1) (k + 1) = binom n k + binom n (k + 1) :=
  nextPascalRow_getAt_succ (pascalRow n) 0 k

/--
  Uniqueness of the binomial coefficient: any function `C : Nat → Nat → Nat`
  satisfying `C n 0 = 1`, `C 0 (k + 1) = 0`, and Pascal's recurrence
  `C (n + 1) (k + 1) = C n k + C n (k + 1)` equals `binom n k` for all `n, k`.
-/
theorem binom_unique (C : Nat → Nat → Nat)
    (hzr : ∀ n, C n 0 = 1)
    (hzl : ∀ k, C 0 (k + 1) = 0)
    (hrec : ∀ n k, C (n + 1) (k + 1) = C n k + C n (k + 1)) :
    ∀ n k, C n k = binom n k := by
  intro n
  induction n with
  | zero =>
    intro k
    cases k with
    | zero => rw [hzr, binom_zero_right]
    | succ m => rw [hzl, binom_zero_left]
  | succ m ih =>
    intro k
    cases k with
    | zero => rw [hzr, binom_zero_right]
    | succ j => rw [hrec, binom_succ_succ, ih j, ih (j + 1)]

/-! ## Proof 11: 48-bit and 168-bit Rank Barrier Mask Spaces -/

/-- Choices for lane 0 mask `m_0` in 48-bit mode: `A = C(48, 16)`. -/
def A48 : Nat := binom 48 16

/-- Choices for lane 1 mask `m_1` in 48-bit mode: `B = C(32, 16)`. -/
def B48 : Nat := binom 32 16

/-- Total 48-bit balanced partition space cardinality: `|Omega_chunk| = A * B`. -/
def Omega48 : Nat := A48 * B48

/-- Floor preimage count per 48-bit mask triple in `[0, 2^128)`. -/
def Preimages48 : Nat := 2 ^ 128 / Omega48

/-- Choices for lane 0 mask `m_0` in 168-bit mode: `A_168 = C(168, 56)`. -/
def A168 : Nat := binom 168 56

/-- Choices for lane 1 mask `m_1` in 168-bit mode: `B_168 = C(112, 56)`. -/
def B168 : Nat := binom 112 56

/-- Total 168-bit balanced partition space cardinality: `|Omega_chunk,168| = A_168 * B_168`. -/
def Omega168 : Nat := A168 * B168

/-- Floor preimage count per 168-bit mask triple in `[0, 2^512)`. -/
def Preimages168 : Nat := 2 ^ 512 / Omega168

/-- Exact evaluation: `A48 = C(48, 16) = 2254848913647`. -/
theorem A48_eq : A48 = 2254848913647 := by decide

/-- Bit-width bracket for `A48`: `2^41 < A48 < 2^42`. -/
theorem A48_bounds : 2 ^ 41 < A48 ∧ A48 < 2 ^ 42 := by decide

/-- Exact evaluation: `B48 = C(32, 16) = 601080390`. -/
theorem B48_eq : B48 = 601080390 := by decide

/-- Bit-width bracket for `B48`: `2^29 < B48 < 2^30`. -/
theorem B48_bounds : 2 ^ 29 < B48 ∧ B48 < 2 ^ 30 := by decide

/-- Exact evaluation: `Omega48 = A48 * B48 = 1355345464406015082330`. -/
theorem Omega48_eq : Omega48 = 1355345464406015082330 := by decide

/-- Bit-width bracket for `Omega48`: `2^70 < Omega48 < 2^71`. -/
theorem Omega48_bounds : 2 ^ 70 < Omega48 ∧ Omega48 < 2 ^ 71 := by decide

/-- Exact evaluation: `Preimages48 = 2^128 / Omega48 = 251066887267792206`. -/
theorem Preimages48_eq : Preimages48 = 251066887267792206 := by decide

/-- Bit-width bracket for `Preimages48`: `2^57 < Preimages48 < 2^58`. -/
theorem Preimages48_bounds : 2 ^ 57 < Preimages48 ∧ Preimages48 < 2 ^ 58 := by decide

/-- Exact evaluation: `A168 = C(168, 56) = 1799363822299435101766134108620363111079750360`. -/
theorem A168_eq : A168 = 1799363822299435101766134108620363111079750360 := by decide

/-- Bit-width bracket for `A168`: `2^150 < A168 < 2^151`. -/
theorem A168_bounds : 2 ^ 150 < A168 ∧ A168 < 2 ^ 151 := by decide

/-- Exact evaluation: `B168 = C(112, 56) = 390590044887157789360330532465784`. -/
theorem B168_eq : B168 = 390590044887157789360330532465784 := by decide

/-- Bit-width bracket for `B168`: `2^108 < B168 < 2^109`. -/
theorem B168_bounds : 2 ^ 108 < B168 ∧ B168 < 2 ^ 109 := by decide

/-- Exact evaluation: `Omega168 = A168 * B168 = 702813596120264168420100264216585729858529081007646807547722792977161961682240`. -/
theorem Omega168_eq :
    Omega168 = 702813596120264168420100264216585729858529081007646807547722792977161961682240 := by decide

/-- Bit-width bracket for `Omega168`: `2^258 < Omega168 < 2^259`. -/
theorem Omega168_bounds : 2 ^ 258 < Omega168 ∧ Omega168 < 2 ^ 259 := by decide

/-- Exact evaluation: `Preimages168 = 2^512 / Omega168 = 19077331463075847632709418264551801233111994340630406080247337248653165811287`. -/
theorem Preimages168_eq :
    Preimages168 = 19077331463075847632709418264551801233111994340630406080247337248653165811287 := by decide

/-- Bit-width bracket for `Preimages168`: `2^253 < Preimages168 < 2^254`. -/
theorem Preimages168_bounds : 2 ^ 253 < Preimages168 ∧ Preimages168 < 2 ^ 254 := by decide

/-- Multi-chunk dominance in 168-bit mode: 2 chunks (`42` B) exceed `2^517 > 2^512`. -/
theorem Omega168_two_chunks_dominates_512 : Omega168 ^ 2 > 2 ^ 517 ∧ Omega168 ^ 2 > 2 ^ 512 := by decide

/-- Multi-chunk dominance in 168-bit mode: 4 chunks (`84` B) exceed `2^1034 > 2^1024`. -/
theorem Omega168_four_chunks_dominates_1024 : Omega168 ^ 4 > 2 ^ 1034 ∧ Omega168 ^ 4 > 2 ^ 1024 := by decide

/-- Multi-chunk dominance in 168-bit mode: 8 chunks (`168` B) exceed `2^2068 > 2^2048`. -/
theorem Omega168_eight_chunks_dominates_2048 : Omega168 ^ 8 > 2 ^ 2068 ∧ Omega168 ^ 8 > 2 ^ 2048 := by decide

/-- Multi-chunk dominance in 48-bit mode across 512-bit, 1024-bit, and 2048-bit key spaces. -/
theorem Omega48_multi_chunk_dominance :
    Omega48 ^ 8 > 2 ^ 512 ∧
    Omega48 ^ 15 > 2 ^ 1024 ∧
    Omega48 ^ 30 > 2 ^ 2048 := by decide

/--
  Effective cross-message 48-bit chunk space when combined with the hidden 32-bit (`2^32`)
  `interlock_nonce` fold `v` in `[0x03 ‖ LE64(groupIdx) ‖ v]` (Proof 11):
  `Omega48WithFold = Omega48 * 2^32`.
-/
def Omega48WithFold : Nat := Omega48 * 2 ^ 32

/--
  Effective cross-message 168-bit chunk space when combined with the hidden 32-bit (`2^32`)
  `interlock_nonce` fold `v` in `[0x03 ‖ LE64(groupIdx) ‖ v]` (Proof 11):
  `Omega168WithFold = Omega168 * 2^32`.
-/
def Omega168WithFold : Nat := Omega168 * 2 ^ 32

/--
  Exact evaluation and bit-width bracket for `Omega48WithFold`:
  While `Omega48 ≈ 2^70.20` (`2^70 < Omega48 < 2^71`) is the guaranteed per-chunk
  combinatorial mask-triple lower bound, an attacker who must also resolve the hidden
  32-bit `interlock_nonce` fold `v` faces `Omega48 * 2^32 = 5821164444405766844290097479680`,
  bracketed by `2^102 < Omega48WithFold < 2^103` (`≈ 2^102.20`).
-/
theorem Omega48WithFold_bounds :
    Omega48WithFold = 5821164444405766844290097479680 ∧
    2 ^ 102 < Omega48WithFold ∧
    Omega48WithFold < 2 ^ 103 := by decide

/--
  Bit-width bracket for `Omega168WithFold`:
  Combining `Omega168 ≈ 2^258.60` (`2^258 < Omega168 < 2^259`) with the hidden 32-bit
  `interlock_nonce` fold `v` yields `2^290 < Omega168WithFold < 2^291` (`≈ 2^290.60`).
-/
theorem Omega168WithFold_bounds :
    2 ^ 290 < Omega168WithFold ∧
    Omega168WithFold < 2 ^ 291 := by decide

/-! ## Two-Step Unrank Surjectivity and Preimage Count Theorem -/

/-- Two-step unrank map `r ↦ ((r / B) % A, r % B)`. -/
def twoStepUnrank (A B r : Nat) : Nat × Nat :=
  ((r / B) % A, r % B)

/-- Explicit preimage witness `(k * A + a) * B + b` for target `(a, b)` and quotient index `k`. -/
def twoStepWitness (A B k a b : Nat) : Nat :=
  (k * A + a) * B + b

/-- Helper lemma: `((k * A + a) * B + b) / B = k * A + a` when `b < B`. -/
theorem twoStepWitness_div_B (A B k a b : Nat) (hb : b < B) :
    twoStepWitness A B k a b / B = k * A + a := by
  have hB : 0 < B := by omega
  unfold twoStepWitness
  rw [Nat.add_comm ((k * A + a) * B) b, Nat.add_mul_div_right _ _ hB, Nat.div_eq_of_lt hb, Nat.zero_add]

/-- Helper lemma: `((k * A + a) * B + b) % B = b` when `b < B`. -/
theorem twoStepWitness_mod_B (A B k a b : Nat) (hb : b < B) :
    twoStepWitness A B k a b % B = b := by
  unfold twoStepWitness
  rw [Nat.add_comm ((k * A + a) * B) b, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hb]

/-- Helper lemma: `(k * A + a) % A = a` when `a < A`. -/
theorem mul_add_mod_self (A k a : Nat) (ha : a < A) :
    (k * A + a) % A = a := by
  rw [Nat.add_comm (k * A) a, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt ha]

/-- Helper lemma: `(k * A + a) / A = k` when `a < A`. -/
theorem mul_add_div_self (A k a : Nat) (ha : a < A) :
    (k * A + a) / A = k := by
  have hA : 0 < A := by omega
  rw [Nat.add_comm (k * A) a, Nat.add_mul_div_right _ _ hA, Nat.div_eq_of_lt ha, Nat.zero_add]

/--
  Surjectivity of two-step unrank: for any `a < A`, `b < B`, and preimage index `k`,
  `twoStepUnrank A B (twoStepWitness A B k a b) = (a, b)`.
-/
theorem twoStepUnrank_witness (A B k a b : Nat) (ha : a < A) (hb : b < B) :
    twoStepUnrank A B (twoStepWitness A B k a b) = (a, b) := by
  unfold twoStepUnrank
  rw [twoStepWitness_div_B A B k a b hb, twoStepWitness_mod_B A B k a b hb, mul_add_mod_self A k a ha]

/--
  Injectivity of the preimage parameterization: distinct `(k, a, b)` triples
  with `a < A` and `b < B` produce strictly distinct rank inputs `r`.
-/
theorem twoStepWitness_injective (A B k1 k2 a1 a2 b1 b2 : Nat)
    (ha1 : a1 < A) (ha2 : a2 < A) (hb1 : b1 < B) (hb2 : b2 < B)
    (heq : twoStepWitness A B k1 a1 b1 = twoStepWitness A B k2 a2 b2) :
    k1 = k2 ∧ a1 = a2 ∧ b1 = b2 := by
  have hb : b1 = b2 := by
    have h1 := twoStepWitness_mod_B A B k1 a1 b1 hb1
    have h2 := twoStepWitness_mod_B A B k2 a2 b2 hb2
    rw [heq] at h1
    omega
  have hdiv : k1 * A + a1 = k2 * A + a2 := by
    have h1 := twoStepWitness_div_B A B k1 a1 b1 hb1
    have h2 := twoStepWitness_div_B A B k2 a2 b2 hb2
    rw [heq] at h1
    omega
  have ha : a1 = a2 := by
    have h1 := mul_add_mod_self A k1 a1 ha1
    have h2 := mul_add_mod_self A k2 a2 ha2
    rw [hdiv] at h1
    omega
  have hk : k1 = k2 := by
    have h1 := mul_add_div_self A k1 a1 ha1
    have h2 := mul_add_div_self A k2 a2 ha2
    rw [hdiv] at h1
    omega
  exact ⟨hk, ha, hb⟩

/--
  Domain bound for preimage witnesses: for every `a < A`, `b < B`, and
  `k < N / (A * B)`, the witness `twoStepWitness A B k a b` lies strictly in `[0, N)`.
  Together with `twoStepUnrank_witness` and `twoStepWitness_injective`, this proves
  every pair `(a, b) ∈ [0, A) × [0, B)` has at least `⌊N / (A * B)⌋` distinct preimages in `[0, N)`.
-/
theorem twoStepWitness_lt (N A B k a b : Nat)
    (ha : a < A) (hb : b < B) (hk : k < N / (A * B)) :
    twoStepWitness A B k a b < N := by
  unfold twoStepWitness
  have hab_lt : a * B + b < A * B := by
    have h1 : a + 1 ≤ A := by omega
    have h2 : (a + 1) * B ≤ A * B := Nat.mul_le_mul_right B h1
    rw [Nat.add_mul, Nat.one_mul] at h2
    omega
  have hk1 : k + 1 ≤ N / (A * B) := by omega
  have hmul : (k + 1) * (A * B) ≤ (N / (A * B)) * (A * B) :=
    Nat.mul_le_mul_right (A * B) hk1
  have hdiv_le : (N / (A * B)) * (A * B) ≤ N := by
    rw [Nat.mul_comm]
    exact Nat.mul_div_le N (A * B)
  have hexpand : (k * A + a) * B + b = k * (A * B) + (a * B + b) := by
    rw [Nat.add_mul, Nat.mul_assoc, Nat.add_assoc]
  have hk1_expand : (k + 1) * (A * B) = k * (A * B) + A * B := by
    rw [Nat.add_mul, Nat.one_mul]
  omega

/-! ## Proof 12: `gcd(A, B)` Anti-Collapse Trap -/

/-- Exact greatest common divisor in 48-bit mode: `gcd(C(48, 16), C(32, 16)) = 66861`. -/
theorem gcd_A48_B48 : Nat.gcd A48 B48 = 66861 := by decide

/-- Prime factorization of `gcd(A48, B48)`: `66861 = 3^2 * 17 * 19 * 23`. -/
theorem gcd_A48_B48_factorization : 66861 = 3 ^ 2 * 17 * 19 * 23 := by decide

/-- Bit-width bracket for `gcd(A48, B48)`: `2^16 < 66861 < 2^17`. -/
theorem gcd_A48_B48_bounds : 2 ^ 16 < 66861 ∧ 66861 < 2 ^ 17 := by decide

/-- Exact greatest common divisor in 168-bit mode: `gcd(C(168, 56), C(112, 56)) = 10078335949946663736`. -/
theorem gcd_A168_B168 : Nat.gcd A168 B168 = 10078335949946663736 := by decide

/-- Prime factorization of `gcd(A168, B168)`: `2^3 * 3^2 * 19 * 29 * 31 * 59 * 61 * 67 * 71 * 73 * 79 * 83`. -/
theorem gcd_A168_B168_factorization :
    10078335949946663736 = 2 ^ 3 * 3 ^ 2 * 19 * 29 * 31 * 59 * 61 * 67 * 71 * 73 * 79 * 83 := by decide

/-- Bit-width bracket for `gcd(A168, B168)`: `2^63 < 10078335949946663736 < 2^64`. -/
theorem gcd_A168_B168_bounds :
    2 ^ 63 < 10078335949946663736 ∧ 10078335949946663736 < 2 ^ 64 := by decide

/-- Rejected naive same-rank double-modulo map `r ↦ (r % A, r % B)`. -/
def naiveDoubleMod (A B r : Nat) : Nat × Nat :=
  (r % A, r % B)

/--
  Congruence invariant of naive double-modulo: if `d ∣ A` and `d ∣ B`,
  then for every input `r`, `(r % A) % d = (r % B) % d`.
-/
theorem naiveDoubleMod_mod_gcd_eq (A B d r : Nat) (hdA : d ∣ A) (hdB : d ∣ B) :
    (r % A) % d = (r % B) % d := by
  rw [Nat.mod_mod_of_dvd r hdA, Nat.mod_mod_of_dvd r hdB]

/--
  Naive Double-Modulo Collapse Theorem: for any common divisor `d` of `A` and `B`,
  any target pair `(a, b)` with `a % d ≠ b % d` has ZERO preimages under `r ↦ (r % A, r % B)`.
-/
theorem naiveDoubleMod_unreachable_of_mod_ne (A B d a b : Nat)
    (hdA : d ∣ A) (hdB : d ∣ B) (hne : a % d ≠ b % d) :
    ¬ ∃ r : Nat, naiveDoubleMod A B r = (a, b) := by
  intro ⟨r, hr⟩
  unfold naiveDoubleMod at hr
  injection hr with ha hb
  have hmod := naiveDoubleMod_mod_gcd_eq A B d r hdA hdB
  rw [ha, hb] at hmod
  exact hne hmod

/--
  Concrete 48-bit anti-collapse separation: every pair `(a, b)` with `a < A48`, `b < B48`,
  and `a % 66861 ≠ b % 66861` is unreachable under `naiveDoubleMod A48 B48`,
  whereas `twoStepUnrank A48 B48` reaches `(a, b)` via `twoStepWitness A48 B48 0 a b`.
-/
theorem anti_collapse_48_separation (a b : Nat)
    (ha : a < A48) (hb : b < B48) (hne : a % 66861 ≠ b % 66861) :
    (¬ ∃ r : Nat, naiveDoubleMod A48 B48 r = (a, b)) ∧
    twoStepUnrank A48 B48 (twoStepWitness A48 B48 0 a b) = (a, b) := by
  have hdA : 66861 ∣ A48 := by decide
  have hdB : 66861 ∣ B48 := by decide
  exact ⟨naiveDoubleMod_unreachable_of_mod_ne A48 B48 66861 a b hdA hdB hne,
         twoStepUnrank_witness A48 B48 0 a b ha hb⟩

/--
  Concrete 168-bit anti-collapse separation: every pair `(a, b)` with `a < A168`, `b < B168`,
  and `a % 10078335949946663736 ≠ b % 10078335949946663736` is unreachable under `naiveDoubleMod A168 B168`,
  whereas `twoStepUnrank A168 B168` reaches `(a, b)` via `twoStepWitness A168 B168 0 a b`.
-/
theorem anti_collapse_168_separation (a b : Nat)
    (ha : a < A168) (hb : b < B168) (hne : a % 10078335949946663736 ≠ b % 10078335949946663736) :
    (¬ ∃ r : Nat, naiveDoubleMod A168 B168 r = (a, b)) ∧
    twoStepUnrank A168 B168 (twoStepWitness A168 B168 0 a b) = (a, b) := by
  have hdA : 10078335949946663736 ∣ A168 := by decide
  have hdB : 10078335949946663736 ∣ B168 := by decide
  exact ⟨naiveDoubleMod_unreachable_of_mod_ne A168 B168 10078335949946663736 a b hdA hdB hne,
         twoStepUnrank_witness A168 B168 0 a b ha hb⟩

/--
  Horner incremental `qmod` identity (Proof 12): reducing the running quotient
  modulo `A` at each limb step (`qmod = (qmod * base + limb) % A`) computes the exact
  remainder `(q * base + limb) % A`.
-/
theorem horner_qmod_step (q limb base A : Nat) :
    (q * base + limb) % A = ((q % A) * base + limb) % A := by
  rw [Nat.add_mod (q * base) limb A,
      Nat.add_mod ((q % A) * base) limb A,
      Nat.mul_mod q base A,
      Nat.mul_mod (q % A) base A,
      Nat.mod_mod]

end ITB.RankBarrier
