/-
  Formal verification of integer exponent bounds, ambiguity dominance thresholds,
  noise barrier margins, container DRBG residue guarantees, and byte-splitting
  non-alignment across the ITB construction (Proofs 4, 5, 9, 10, and Byte-Splitting).
-/

namespace ITB.Thresholds

set_option exponentiation.threshold 60000

/-! ## Proof 4: Rotation Barrier -/

/-- Mode 2 container pixel count at a 1024-bit key (`21 * 21 = 441`). -/
def mode2Pixels1024 : Nat := 21 * 21

/-- Mode 1 container pixel count at a 1024-bit key (`35 * 35 = 1225`). -/
def mode1Pixels1024 : Nat := 35 * 35

/-- Theoretical single-region baseline pixel count at a 1024-bit key (`20 * 20 = 400`). -/
def singleRegionPixels1024 : Nat := 20 * 20

theorem mode2Pixels1024_eq : mode2Pixels1024 = 441 := rfl
theorem mode1Pixels1024_eq : mode1Pixels1024 = 1225 := rfl
theorem singleRegionPixels1024_eq : singleRegionPixels1024 = 400 := rfl

/-- Mode 2 rotation ambiguity lower bound: `7^441 > 2^1238`. -/
theorem rotation_barrier_mode2_lower : 7 ^ 441 > 2 ^ 1238 := by decide

/-- Mode 2 rotation ambiguity upper bound: `7^441 < 2^1239`. -/
theorem rotation_barrier_mode2_upper : 7 ^ 441 < 2 ^ 1239 := by decide

/-- Mode 1 rotation ambiguity lower bound: `7^1225 > 2^3439`. -/
theorem rotation_barrier_mode1_lower : 7 ^ 1225 > 2 ^ 3439 := by decide

/-- Mode 1 rotation ambiguity upper bound: `7^1225 < 2^3440`. -/
theorem rotation_barrier_mode1_upper : 7 ^ 1225 < 2 ^ 3440 := by decide

/-- Single-region baseline rotation ambiguity lower bound: `7^400 > 2^1122`. -/
theorem rotation_barrier_single_lower : 7 ^ 400 > 2 ^ 1122 := by decide

/-- Single-region baseline rotation ambiguity upper bound: `7^400 < 2^1123`. -/
theorem rotation_barrier_single_upper : 7 ^ 400 < 2 ^ 1123 := by decide

/-- Mode 2 rotation ambiguity strictly exceeds the 1024-bit key space (`7^441 > 2^1024`). -/
theorem rotation_barrier_mode2_dominates_key1024 : 7 ^ 441 > 2 ^ 1024 := by decide

/-- Mode 1 rotation ambiguity strictly exceeds the 1024-bit key space (`7^1225 > 2^1024`). -/
theorem rotation_barrier_mode1_dominates_key1024 : 7 ^ 1225 > 2 ^ 1024 := by decide

/-- Single-region baseline rotation ambiguity strictly exceeds the 1024-bit key space (`7^400 > 2^1024`). -/
theorem rotation_barrier_single_dominates_key1024 : 7 ^ 400 > 2 ^ 1024 := by decide

/-- Mode 2 rotation ambiguity strictly exceeds the Landauer enumeration bound (`7^441 > 2^306`). -/
theorem rotation_barrier_mode2_exceeds_landauer : 7 ^ 441 > 2 ^ 306 := by decide

/-! ## Proof 5: Noise Barrier Bound -/

/-- Mode 1 noise barrier exponent at a 1024-bit key (`8 * 1225 = 9800`). -/
theorem noise_barrier_mode1_exp : 8 * 1225 = 9800 := rfl

/-- Mode 1 noise barrier margin over a 1024-bit key (`9800 - 1024 = 8776`). -/
theorem noise_barrier_mode1_margin : 8 * 1225 - 1024 = 8776 := rfl

/-- Mode 1 noise barrier exact factorization: `2^(8 * 1225) = 2^1024 * 2^8776`. -/
theorem noise_barrier_mode1_factor : (2 : Nat) ^ (8 * 1225) = 2 ^ 1024 * 2 ^ 8776 := by decide

/-- Mode 1 noise barrier strictly exceeds the 1024-bit key space (`2^(8 * 1225) > 2^1024`). -/
theorem noise_barrier_mode1_gt_key1024 : (2 : Nat) ^ (8 * 1225) > 2 ^ 1024 := by decide

/-- Mode 2 noise barrier exponent at a 1024-bit key (`8 * 441 = 3528`). -/
theorem noise_barrier_mode2_exp : 8 * 441 = 3528 := rfl

/-- Mode 2 noise barrier margin over a 1024-bit key (`3528 - 1024 = 2504`). -/
theorem noise_barrier_mode2_margin : 8 * 441 - 1024 = 2504 := rfl

/-- Mode 2 noise barrier exact factorization: `2^(8 * 441) = 2^1024 * 2^2504`. -/
theorem noise_barrier_mode2_factor : (2 : Nat) ^ (8 * 441) = 2 ^ 1024 * 2 ^ 2504 := by decide

/-- Mode 2 noise barrier strictly exceeds the 1024-bit key space (`2^(8 * 441) > 2^1024`). -/
theorem noise_barrier_mode2_gt_key1024 : (2 : Nat) ^ (8 * 441) > 2 ^ 1024 := by decide

/-- Single-region floor noise barrier exponent (`8 * 400 = 3200 > 1024`). -/
theorem noise_barrier_single_exp : 8 * 400 = 3200 ∧ 3200 > 1024 := by decide

/-- 512-bit key Mode 2 (`15 * 15 = 225`) and Mode 1 (`25 * 25 = 625`) noise barrier exponents. -/
theorem noise_barrier_key512_bounds :
    8 * (15 * 15) = 1800 ∧ 1800 > 512 ∧
    8 * (25 * 25) = 5000 ∧ 5000 > 512 := by decide

/-- 2048-bit key Mode 2 (`29 * 29 = 841`) and Mode 1 (`48 * 48 = 2304`) noise barrier exponents. -/
theorem noise_barrier_key2048_bounds :
    8 * (29 * 29) = 6728 ∧ 6728 > 2048 ∧
    8 * (48 * 48) = 18432 ∧ 18432 > 2048 := by decide

/-- Helper lemma: `7^P < 8^P` for all `P > 0`. -/
theorem pow7_lt_pow8 (P : Nat) (hP : P > 0) : 7 ^ P < 8 ^ P :=
  Nat.pow_lt_pow_left (by decide) (by omega)

/-- Helper lemma: `8^P = 2^(3 * P)` for all `P : Nat`. -/
theorem pow8_eq_pow2_mul3 (P : Nat) : 8 ^ P = 2 ^ (3 * P) := by
  induction P with
  | zero => rfl
  | succ n ih =>
    have hstep : 3 * (n + 1) = 3 * n + 3 := by omega
    rw [Nat.pow_succ, ih, hstep, Nat.pow_add]

/-- Helper lemma: `2^a ≤ 2^b` when `a ≤ b`. -/
theorem pow2_mono {a b : Nat} (h : a ≤ b) : 2 ^ a ≤ 2 ^ b :=
  Nat.pow_le_pow_right (by decide) h

/--
  General Proof 5 theorem: for any positive key size `k` and pixel count `P`,
  if the CCA rotation ambiguity satisfies `7^P ≥ 2^k`, then the 8-channel
  noise barrier strictly exceeds the key space (`2^(8 * P) > 2^k`).
-/
theorem noise_barrier_dominates_of_rotation_threshold (k P : Nat) (hk : k > 0) (hrot : 7 ^ P ≥ 2 ^ k) :
    2 ^ (8 * P) > 2 ^ k := by
  cases P with
  | zero =>
    have h2k : 2 ^ k ≥ 2 ^ 1 := Nat.pow_le_pow_right (by decide) hk
    omega
  | succ n =>
    have h78 : 7 ^ (n + 1) < 8 ^ (n + 1) := pow7_lt_pow8 (n + 1) (by omega)
    have h82 : 8 ^ (n + 1) = 2 ^ (3 * (n + 1)) := pow8_eq_pow2_mul3 (n + 1)
    have h38 : 2 ^ (3 * (n + 1)) ≤ 2 ^ (8 * (n + 1)) := pow2_mono (by omega)
    omega

/-! ## Proof 9: Ambiguity Dominance Threshold -/

/-- 512-bit key CCA threshold tightness (`P_threshold = 183`): `7^183 > 2^512` and `7^182 < 2^512`. -/
theorem threshold_512_cca_above : 7 ^ 183 > 2 ^ 512 := by decide
theorem threshold_512_cca_below : 7 ^ 182 < 2 ^ 512 := by decide

/-- 512-bit key No-CCA threshold tightness (`P_threshold = 89`): `56^89 > 2^512` and `56^88 < 2^512`. -/
theorem threshold_512_nocca_above : 56 ^ 89 > 2 ^ 512 := by decide
theorem threshold_512_nocca_below : 56 ^ 88 < 2 ^ 512 := by decide

/-- 1024-bit key CCA threshold tightness (`P_threshold = 365`): `7^365 > 2^1024` and `7^364 < 2^1024`. -/
theorem threshold_1024_cca_above : 7 ^ 365 > 2 ^ 1024 := by decide
theorem threshold_1024_cca_below : 7 ^ 364 < 2 ^ 1024 := by decide

/-- 1024-bit key No-CCA threshold tightness (`P_threshold = 177`): `56^177 > 2^1024` and `56^176 < 2^1024`. -/
theorem threshold_1024_nocca_above : 56 ^ 177 > 2 ^ 1024 := by decide
theorem threshold_1024_nocca_below : 56 ^ 176 < 2 ^ 1024 := by decide

/-- 2048-bit key CCA threshold tightness (`P_threshold = 730`): `7^730 > 2^2048` and `7^729 < 2^2048`. -/
theorem threshold_2048_cca_above : 7 ^ 730 > 2 ^ 2048 := by decide
theorem threshold_2048_cca_below : 7 ^ 729 < 2 ^ 2048 := by decide

/-- 2048-bit key No-CCA threshold tightness (`P_threshold = 353`): `56^353 > 2^2048` and `56^352 < 2^2048`. -/
theorem threshold_2048_nocca_above : 56 ^ 353 > 2 ^ 2048 := by decide
theorem threshold_2048_nocca_below : 56 ^ 352 < 2 ^ 2048 := by decide

/-- Mode 2 No-CCA encoding ambiguity bounds at 1024-bit key (`2^2561 < 56^441 < 2^2562`). -/
theorem nocca_ambiguity_mode2_gt_2560 : 56 ^ 441 > 2 ^ 2560 := by decide
theorem nocca_ambiguity_mode2_lower : 56 ^ 441 > 2 ^ 2561 := by decide
theorem nocca_ambiguity_mode2_upper : 56 ^ 441 < 2 ^ 2562 := by decide

/-- 64 KB container (`99 * 99 = 9801` pixels) CCA and No-CCA ambiguity bounds (`2^27514 < 7^9801 < 2^27515` and `2^56917 < 56^9801 < 2^56918`). -/
theorem ambiguity_64kb_cca_bounds : 7 ^ 9801 > 2 ^ 27514 ∧ 7 ^ 9801 < 2 ^ 27515 := by decide
theorem ambiguity_64kb_nocca_bounds : 56 ^ 9801 > 2 ^ 56917 ∧ 56 ^ 9801 < 2 ^ 56918 := by decide

/-- Mode 1 No-CCA encoding ambiguity bounds at 1024-bit key (`2^7114 < 56^1225 < 2^7115`). -/
theorem nocca_ambiguity_mode1_lower : 56 ^ 1225 > 2 ^ 7114 := by decide
theorem nocca_ambiguity_mode1_upper : 56 ^ 1225 < 2 ^ 7115 := by decide

/-- Single-region baseline No-CCA encoding ambiguity bounds (`2^2322 < 56^400 < 2^2323`). -/
theorem nocca_ambiguity_single_lower : 56 ^ 400 > 2 ^ 2322 := by decide
theorem nocca_ambiguity_single_upper : 56 ^ 400 < 2 ^ 2323 := by decide

/-- Config map space exponents (`62 * P` bits per pixel: `62 * 441 = 27342`, `62 * 1225 = 75950`, `62 * 400 = 24800`). -/
theorem config_map_exponents :
    62 * 441 = 27342 ∧ 62 * 1225 = 75950 ∧ 62 * 400 = 24800 := by decide

/--
  Monotonicity of ambiguity dominance: for any base `C ≥ 1`, if `C ^ P_th > 2 ^ k`,
  then for every container pixel count `P ≥ P_th`, `C ^ P > 2 ^ k`.
-/
theorem ambiguity_dominates_of_ge {C P_th P k : Nat} (hC : C ≥ 1) (hP : P ≥ P_th) (hth : C ^ P_th > 2 ^ k) :
    C ^ P > 2 ^ k := by
  have hle : C ^ P_th ≤ C ^ P := Nat.pow_le_pow_right hC hP
  omega

/-! ## Proof 10: Guaranteed DRBG Residue (No Perfect Fill) -/

/--
  General algebraic identity for container `side + 1` expansion:
  `((s + 1)^2 - s^2) * 7 = (2 * s + 1) * 7`.
-/
theorem drbg_gap_identity (s : Nat) :
    (s + 1) ^ 2 * 7 - s ^ 2 * 7 = (2 * s + 1) * 7 := by
  have hsq : (s + 1) ^ 2 = s ^ 2 + (2 * s + 1) := by
    rw [Nat.pow_two, Nat.pow_two, Nat.add_mul, Nat.mul_add, Nat.mul_add]
    omega
  rw [hsq, Nat.add_mul, Nat.add_sub_cancel_left]

/--
  General Proof 10 lower bound: for every container base side `s ≥ 1`,
  the guaranteed DRBG fill gap `(2 * s + 1) * 7` is at least 21 bytes (`> 0`).
-/
theorem drbg_gap_ge_21 (s : Nat) (hs : s ≥ 1) :
    (2 * s + 1) * 7 ≥ 21 := by omega

/--
  Combined Proof 10 theorem: for every `s ≥ 1`, the capacity increment
  `(s + 1)^2 * 7 - s^2 * 7` equals `(2 * s + 1) * 7` and is strictly positive (`≥ 21`).
-/
theorem drbg_no_perfect_fill (s : Nat) (hs : s ≥ 1) :
    (s + 1) ^ 2 * 7 - s ^ 2 * 7 = (2 * s + 1) * 7 ∧
    (s + 1) ^ 2 * 7 - s ^ 2 * 7 ≥ 21 := by
  rw [drbg_gap_identity]
  exact ⟨rfl, drbg_gap_ge_21 s hs⟩

/-- Mode 2 container (`s = 20`, `21 * 21 = 441`): minimum gap `287` B, floor gap `532` B at `365` px. -/
theorem drbg_residue_mode2 :
    (20 + 1) ^ 2 = 441 ∧
    (2 * 20 + 1) * 7 = 287 ∧
    (441 - 365) * 7 = 532 := by decide

/-- Mode 1 container (`s = 34`, `35 * 35 = 1225`): minimum gap `483` B, floor gap `910` B at `1095` px. -/
theorem drbg_residue_mode1 :
    (34 + 1) ^ 2 = 1225 ∧
    (2 * 34 + 1) * 7 = 483 ∧
    (1225 - 1095) * 7 = 910 := by decide

/-- Theoretical single-region floor (`s = 19`, `20 * 20 = 400`): minimum gap `273` B, floor gap `245` B at `365` px. -/
theorem drbg_residue_single_region :
    (19 + 1) ^ 2 = 400 ∧
    (2 * 19 + 1) * 7 = 273 ∧
    (400 - 365) * 7 = 245 := by decide

/-- 16 KB container (`s = 49`): guaranteed minimum DRBG residue is `693` bytes. -/
theorem drbg_residue_16kb : (2 * 49 + 1) * 7 = 693 := by decide

/-- 1 MB container (`s = 388`): guaranteed minimum DRBG residue is `5439` bytes. -/
theorem drbg_residue_1mb : (2 * 388 + 1) * 7 = 5439 := by decide

/-- 64 MB container (`s = 3103`): guaranteed minimum DRBG residue is `43449` bytes. -/
theorem drbg_residue_64mb : (2 * 3103 + 1) * 7 = 43449 := by decide

/-! ## Byte-Splitting Property (`gcd(7, 8) = 1`) -/

/-- 7 data bits per channel and 8 bits per byte are coprime (`gcd(7, 8) = 1`). -/
theorem gcd_7_8_eq_1 : Nat.gcd 7 8 = 1 := by decide

/--
  No interior byte boundary `8 * b` (`1 ≤ b ≤ 6`) aligns with any interior
  7-bit channel boundary `7 * c` (`1 ≤ c ≤ 7`) within a 56-bit (7-byte, 8-channel) pixel.
-/
theorem byte_channel_no_interior_alignment :
    ∀ b c : Nat, 1 ≤ b → b ≤ 6 → 1 ≤ c → c ≤ 7 → 8 * b ≠ 7 * c := by
  intro b c hb1 hb2 hc1 hc2
  omega

/--
  Every plaintext byte `b ∈ Fin 7` in a 56-bit pixel (spanning bit offsets
  `8 * b.val` through `8 * b.val + 7`) starts in channel `b.val` (`(8 * b.val) / 7 = b.val`)
  and ends in channel `b.val + 1` (`(8 * b.val + 7) / 7 = b.val + 1`),
  proving that every plaintext byte is split across two adjacent channels.
-/
theorem every_byte_spans_two_adjacent_channels :
    ∀ b : Fin 7,
      (8 * b.val) / 7 = b.val ∧
      (8 * b.val + 7) / 7 = b.val + 1 := by
  decide

/-! ## Square Container Third Partition (`tripleThirdCaps`, `triplepayload.go:144-153`) -/

/--
  Quadratic residue mod 3: for every square container side `s`, `(s * s) % 3` is
  either `0` (`s ≡ 0 (mod 3)`) or `1` (`s ≡ 1, 2 (mod 3)`), and never `2`.
-/
theorem square_mod3_ne_two (s : Nat) : (s * s) % 3 = 0 ∨ (s * s) % 3 = 1 := by
  rw [Nat.mul_mod]
  have h : s % 3 = 0 ∨ s % 3 = 1 ∨ s % 3 = 2 := by omega
  rcases h with h0 | h0 | h0 <;> rw [h0] <;> decide

/--
  In `tripleThirdCaps` (`triplepayload.go:144-153`), a square container of
  `totalPixels = s * s` pixels is partitioned into two equal thirds of
  `third = totalPixels / 3` pixels and a final third of
  `thirdPixels2 = totalPixels - 2 * third` pixels.
  Because `(s * s) % 3 ∈ {0, 1}`, `thirdPixels2` is always either `third`
  (when `3 ∣ s`, e.g. `21 × 21 = 441 = 3 × 147` or `99 × 99 = 9801 = 3 × 3267`)
  or `third + 1` (when `3 ∤ s`, e.g. `35 × 35 = 1225 = 2 × 408 + 409`),
  and never `third + 2`.
-/
theorem tripleThirdCaps_square_gap (s : Nat) :
    let totalPixels := s * s
    let third := totalPixels / 3
    let thirdPixels2 := totalPixels - 2 * third
    thirdPixels2 = third ∨ thirdPixels2 = third + 1 := by
  have hmod := square_mod3_ne_two s
  omega

end ITB.Thresholds
