/-
  Formal verification of 8-seed isolation and minimality (Proofs 3 and 3a),
  ChainHash full component utilization and XOR-cancelling counterexample (Proof 3b),
  multi-factor Full KPA work factor bounds (Proof 4a), oracle-free deniability
  bijection (Proof 8), MAC-Inside-Encrypt composition (Verify-before-COBS and
  interlock_nonce 3-lane authenticated split), and Nonce Uniqueness.
-/
import ITB.PixelBarrier

namespace ITB.SeedIsolation

open ITB.PixelBarrier

set_option exponentiation.threshold 10000

/-! ## Proof 3 and Proof 3a: 8-Seed Isolation and Minimality -/

/-- The 8 disjoint derivation domains of the Triple Ouroboros constellation. -/
inductive Domain8 where
  | N  -- Noise bit position per pixel (noiseSeed, CCA observable under MAC + Reveal)
  | L  -- Per-chunk Rank Barrier mask triple (lockSeed, unobservable register/table kernel)
  | D1 -- Region 1 rotation + channelXOR (dataSeed1, unobservable register-only)
  | D2 -- Region 2 rotation + channelXOR (dataSeed2, unobservable register-only)
  | D3 -- Region 3 rotation + channelXOR (dataSeed3, unobservable register-only)
  | S1 -- Region 1 starting pixel offset (startSeed1, cache side-channel observable)
  | S2 -- Region 2 starting pixel offset (startSeed2, cache side-channel observable)
  | S3 -- Region 3 starting pixel offset (startSeed3, cache side-channel observable)
  deriving DecidableEq, Repr

/-- Enumeration of all 8 derivation domains. -/
def allDomains8 : List Domain8 :=
  [.N, .L, .D1, .D2, .D3, .S1, .S2, .S3]

/-- Cardinality of the derivation domain list is 8. -/
theorem allDomains8_length : allDomains8.length = 8 := rfl

/-- Canonical bijection from `Domain8` to `Fin 8`. -/
def domainToFin8 : Domain8 → Fin 8
  | .N  => ⟨0, by decide⟩
  | .L  => ⟨1, by decide⟩
  | .D1 => ⟨2, by decide⟩
  | .D2 => ⟨3, by decide⟩
  | .D3 => ⟨4, by decide⟩
  | .S1 => ⟨5, by decide⟩
  | .S2 => ⟨6, by decide⟩
  | .S3 => ⟨7, by decide⟩

/-- Canonical inverse from `Fin 8` to `Domain8`. -/
def fin8ToDomain : Fin 8 → Domain8
  | ⟨0, _⟩ => .N
  | ⟨1, _⟩ => .L
  | ⟨2, _⟩ => .D1
  | ⟨3, _⟩ => .D2
  | ⟨4, _⟩ => .D3
  | ⟨5, _⟩ => .S1
  | ⟨6, _⟩ => .S2
  | ⟨7, _⟩ => .S3

/-- `fin8ToDomain` is the left inverse of `domainToFin8`. -/
theorem fin8ToDomain_domainToFin8 (d : Domain8) :
    fin8ToDomain (domainToFin8 d) = d := by
  cases d <;> rfl

/-- `domainToFin8` is injective: 8 seeds assign a distinct seed to every domain. -/
theorem domainToFin8_injective (d1 d2 : Domain8)
    (h : domainToFin8 d1 = domainToFin8 d2) : d1 = d2 := by
  have h1 := congrArg fin8ToDomain h
  rw [fin8ToDomain_domainToFin8, fin8ToDomain_domainToFin8] at h1
  exact h1

/-- Indicator `1` if `v = c`, else `0`. -/
def eqInd (c v : Nat) : Nat :=
  if v = c then 1 else 0

/-- Every `v : Fin 7` matches exactly one residue in `0..6`. -/
theorem eqInd_sum_seven : ∀ v : Fin 7,
    eqInd 0 v.val + eqInd 1 v.val + eqInd 2 v.val + eqInd 3 v.val +
    eqInd 4 v.val + eqInd 5 v.val + eqInd 6 v.val = 1 := by
  decide

/-- If `v0..v7` are pairwise distinct, at most one of them equals any given `c`. -/
theorem eqInd_bucket_le_one (c v0 v1 v2 v3 v4 v5 v6 v7 : Nat)
    (h01 : v0 ≠ v1) (h02 : v0 ≠ v2) (h03 : v0 ≠ v3) (h04 : v0 ≠ v4) (h05 : v0 ≠ v5) (h06 : v0 ≠ v6) (h07 : v0 ≠ v7)
    (h12 : v1 ≠ v2) (h13 : v1 ≠ v3) (h14 : v1 ≠ v4) (h15 : v1 ≠ v5) (h16 : v1 ≠ v6) (h17 : v1 ≠ v7)
    (h23 : v2 ≠ v3) (h24 : v2 ≠ v4) (h25 : v2 ≠ v5) (h26 : v2 ≠ v6) (h27 : v2 ≠ v7)
    (h34 : v3 ≠ v4) (h35 : v3 ≠ v5) (h36 : v3 ≠ v6) (h37 : v3 ≠ v7)
    (h45 : v4 ≠ v5) (h46 : v4 ≠ v6) (h47 : v4 ≠ v7)
    (h56 : v5 ≠ v6) (h57 : v5 ≠ v7)
    (h67 : v6 ≠ v7) :
    eqInd c v0 + eqInd c v1 + eqInd c v2 + eqInd c v3 +
    eqInd c v4 + eqInd c v5 + eqInd c v6 + eqInd c v7 ≤ 1 := by
  unfold eqInd
  by_cases hc0 : v0 = c
  · subst hc0; simp [Ne.symm h01, Ne.symm h02, Ne.symm h03, Ne.symm h04, Ne.symm h05, Ne.symm h06, Ne.symm h07]
  by_cases hc1 : v1 = c
  · subst hc1; simp [hc0, Ne.symm h12, Ne.symm h13, Ne.symm h14, Ne.symm h15, Ne.symm h16, Ne.symm h17]
  by_cases hc2 : v2 = c
  · subst hc2; simp [hc0, hc1, Ne.symm h23, Ne.symm h24, Ne.symm h25, Ne.symm h26, Ne.symm h27]
  by_cases hc3 : v3 = c
  · subst hc3; simp [hc0, hc1, hc2, Ne.symm h34, Ne.symm h35, Ne.symm h36, Ne.symm h37]
  by_cases hc4 : v4 = c
  · subst hc4; simp [hc0, hc1, hc2, hc3, Ne.symm h45, Ne.symm h46, Ne.symm h47]
  by_cases hc5 : v5 = c
  · subst hc5; simp [hc0, hc1, hc2, hc3, hc4, Ne.symm h56, Ne.symm h57]
  by_cases hc6 : v6 = c
  · subst hc6; simp [hc0, hc1, hc2, hc3, hc4, hc5, Ne.symm h67]
  by_cases hc7 : v7 = c
  · subst hc7; simp [hc0, hc1, hc2, hc3, hc4, hc5, hc6]
  · simp [hc0, hc1, hc2, hc3, hc4, hc5, hc6, hc7]

/--
  Core arithmetic pigeonhole lemma via double counting (`8 ≤ 7` contradiction):
  8 natural numbers strictly bounded by 7 cannot be pairwise distinct across all 28 pairs.
-/
theorem nat8_pigeonhole_lt_7 (v0 v1 v2 v3 v4 v5 v6 v7 : Nat)
    (h0 : v0 < 7) (h1 : v1 < 7) (h2 : v2 < 7) (h3 : v3 < 7)
    (h4 : v4 < 7) (h5 : v5 < 7) (h6 : v6 < 7) (h7 : v7 < 7) :
    ¬ (v0 ≠ v1 ∧ v0 ≠ v2 ∧ v0 ≠ v3 ∧ v0 ≠ v4 ∧ v0 ≠ v5 ∧ v0 ≠ v6 ∧ v0 ≠ v7 ∧
       v1 ≠ v2 ∧ v1 ≠ v3 ∧ v1 ≠ v4 ∧ v1 ≠ v5 ∧ v1 ≠ v6 ∧ v1 ≠ v7 ∧
       v2 ≠ v3 ∧ v2 ≠ v4 ∧ v2 ≠ v5 ∧ v2 ≠ v6 ∧ v2 ≠ v7 ∧
       v3 ≠ v4 ∧ v3 ≠ v5 ∧ v3 ≠ v6 ∧ v3 ≠ v7 ∧
       v4 ≠ v5 ∧ v4 ≠ v6 ∧ v4 ≠ v7 ∧
       v5 ≠ v6 ∧ v5 ≠ v7 ∧
       v6 ≠ v7) := by
  intro ⟨h01, h02, h03, h04, h05, h06, h07,
         h12, h13, h14, h15, h16, h17,
         h23, h24, h25, h26, h27,
         h34, h35, h36, h37,
         h45, h46, h47,
         h56, h57, h67⟩
  have s0 := eqInd_sum_seven ⟨v0, h0⟩
  have s1 := eqInd_sum_seven ⟨v1, h1⟩
  have s2 := eqInd_sum_seven ⟨v2, h2⟩
  have s3 := eqInd_sum_seven ⟨v3, h3⟩
  have s4 := eqInd_sum_seven ⟨v4, h4⟩
  have s5 := eqInd_sum_seven ⟨v5, h5⟩
  have s6 := eqInd_sum_seven ⟨v6, h6⟩
  have s7 := eqInd_sum_seven ⟨v7, h7⟩
  dsimp only at s0 s1 s2 s3 s4 s5 s6 s7
  have b0 := eqInd_bucket_le_one 0 v0 v1 v2 v3 v4 v5 v6 v7 h01 h02 h03 h04 h05 h06 h07 h12 h13 h14 h15 h16 h17 h23 h24 h25 h26 h27 h34 h35 h36 h37 h45 h46 h47 h56 h57 h67
  have b1 := eqInd_bucket_le_one 1 v0 v1 v2 v3 v4 v5 v6 v7 h01 h02 h03 h04 h05 h06 h07 h12 h13 h14 h15 h16 h17 h23 h24 h25 h26 h27 h34 h35 h36 h37 h45 h46 h47 h56 h57 h67
  have b2 := eqInd_bucket_le_one 2 v0 v1 v2 v3 v4 v5 v6 v7 h01 h02 h03 h04 h05 h06 h07 h12 h13 h14 h15 h16 h17 h23 h24 h25 h26 h27 h34 h35 h36 h37 h45 h46 h47 h56 h57 h67
  have b3 := eqInd_bucket_le_one 3 v0 v1 v2 v3 v4 v5 v6 v7 h01 h02 h03 h04 h05 h06 h07 h12 h13 h14 h15 h16 h17 h23 h24 h25 h26 h27 h34 h35 h36 h37 h45 h46 h47 h56 h57 h67
  have b4 := eqInd_bucket_le_one 4 v0 v1 v2 v3 v4 v5 v6 v7 h01 h02 h03 h04 h05 h06 h07 h12 h13 h14 h15 h16 h17 h23 h24 h25 h26 h27 h34 h35 h36 h37 h45 h46 h47 h56 h57 h67
  have b5 := eqInd_bucket_le_one 5 v0 v1 v2 v3 v4 v5 v6 v7 h01 h02 h03 h04 h05 h06 h07 h12 h13 h14 h15 h16 h17 h23 h24 h25 h26 h27 h34 h35 h36 h37 h45 h46 h47 h56 h57 h67
  have b6 := eqInd_bucket_le_one 6 v0 v1 v2 v3 v4 v5 v6 v7 h01 h02 h03 h04 h05 h06 h07 h12 h13 h14 h15 h16 h17 h23 h24 h25 h26 h27 h34 h35 h36 h37 h45 h46 h47 h56 h57 h67
  omega

/--
  Proof 3a (8-Seed Minimality via Pigeonhole):
  For any seed count `k ≤ 7` and any assignment `f : Domain8 → Fin k` mapping the
  8 derivation domains onto `k` seeds, there exist two distinct domains `d1 ≠ d2`
  that share the same seed (`f d1 = f d2`).
-/
theorem eight_seed_minimality (k : Nat) (hk : k ≤ 7) (f : Domain8 → Fin k) :
    ∃ d1 d2 : Domain8, d1 ≠ d2 ∧ f d1 = f d2 := by
  by_cases h01 : f .N = f .L;   · exact ⟨.N,  .L,  by decide, h01⟩
  by_cases h02 : f .N = f .D1;  · exact ⟨.N,  .D1, by decide, h02⟩
  by_cases h03 : f .N = f .D2;  · exact ⟨.N,  .D2, by decide, h03⟩
  by_cases h04 : f .N = f .D3;  · exact ⟨.N,  .D3, by decide, h04⟩
  by_cases h05 : f .N = f .S1;  · exact ⟨.N,  .S1, by decide, h05⟩
  by_cases h06 : f .N = f .S2;  · exact ⟨.N,  .S2, by decide, h06⟩
  by_cases h07 : f .N = f .S3;  · exact ⟨.N,  .S3, by decide, h07⟩
  by_cases h12 : f .L = f .D1;  · exact ⟨.L,  .D1, by decide, h12⟩
  by_cases h13 : f .L = f .D2;  · exact ⟨.L,  .D2, by decide, h13⟩
  by_cases h14 : f .L = f .D3;  · exact ⟨.L,  .D3, by decide, h14⟩
  by_cases h15 : f .L = f .S1;  · exact ⟨.L,  .S1, by decide, h15⟩
  by_cases h16 : f .L = f .S2;  · exact ⟨.L,  .S2, by decide, h16⟩
  by_cases h17 : f .L = f .S3;  · exact ⟨.L,  .S3, by decide, h17⟩
  by_cases h23 : f .D1 = f .D2; · exact ⟨.D1, .D2, by decide, h23⟩
  by_cases h24 : f .D1 = f .D3; · exact ⟨.D1, .D3, by decide, h24⟩
  by_cases h25 : f .D1 = f .S1; · exact ⟨.D1, .S1, by decide, h25⟩
  by_cases h26 : f .D1 = f .S2; · exact ⟨.D1, .S2, by decide, h26⟩
  by_cases h27 : f .D1 = f .S3; · exact ⟨.D1, .S3, by decide, h27⟩
  by_cases h34 : f .D2 = f .D3; · exact ⟨.D2, .D3, by decide, h34⟩
  by_cases h35 : f .D2 = f .S1; · exact ⟨.D2, .S1, by decide, h35⟩
  by_cases h36 : f .D2 = f .S2; · exact ⟨.D2, .S2, by decide, h36⟩
  by_cases h37 : f .D2 = f .S3; · exact ⟨.D2, .S3, by decide, h37⟩
  by_cases h45 : f .D3 = f .S1; · exact ⟨.D3, .S1, by decide, h45⟩
  by_cases h46 : f .D3 = f .S2; · exact ⟨.D3, .S2, by decide, h46⟩
  by_cases h47 : f .D3 = f .S3; · exact ⟨.D3, .S3, by decide, h47⟩
  by_cases h56 : f .S1 = f .S2; · exact ⟨.S1, .S2, by decide, h56⟩
  by_cases h57 : f .S1 = f .S3; · exact ⟨.S1, .S3, by decide, h57⟩
  by_cases h67 : f .S2 = f .S3; · exact ⟨.S2, .S3, by decide, h67⟩
  exfalso
  have hv0 : (f .N).val < 7  := Nat.lt_of_lt_of_le (f .N).isLt hk
  have hv1 : (f .L).val < 7  := Nat.lt_of_lt_of_le (f .L).isLt hk
  have hv2 : (f .D1).val < 7 := Nat.lt_of_lt_of_le (f .D1).isLt hk
  have hv3 : (f .D2).val < 7 := Nat.lt_of_lt_of_le (f .D2).isLt hk
  have hv4 : (f .D3).val < 7 := Nat.lt_of_lt_of_le (f .D3).isLt hk
  have hv5 : (f .S1).val < 7 := Nat.lt_of_lt_of_le (f .S1).isLt hk
  have hv6 : (f .S2).val < 7 := Nat.lt_of_lt_of_le (f .S2).isLt hk
  have hv7 : (f .S3).val < 7 := Nat.lt_of_lt_of_le (f .S3).isLt hk
  exact nat8_pigeonhole_lt_7
    (f .N).val (f .L).val (f .D1).val (f .D2).val
    (f .D3).val (f .S1).val (f .S2).val (f .S3).val
    hv0 hv1 hv2 hv3 hv4 hv5 hv6 hv7
    ⟨Fin.val_ne_of_ne h01, Fin.val_ne_of_ne h02, Fin.val_ne_of_ne h03,
     Fin.val_ne_of_ne h04, Fin.val_ne_of_ne h05, Fin.val_ne_of_ne h06,
     Fin.val_ne_of_ne h07, Fin.val_ne_of_ne h12, Fin.val_ne_of_ne h13,
     Fin.val_ne_of_ne h14, Fin.val_ne_of_ne h15, Fin.val_ne_of_ne h16,
     Fin.val_ne_of_ne h17, Fin.val_ne_of_ne h23, Fin.val_ne_of_ne h24,
     Fin.val_ne_of_ne h25, Fin.val_ne_of_ne h26, Fin.val_ne_of_ne h27,
     Fin.val_ne_of_ne h34, Fin.val_ne_of_ne h35, Fin.val_ne_of_ne h36,
     Fin.val_ne_of_ne h37, Fin.val_ne_of_ne h45, Fin.val_ne_of_ne h46,
     Fin.val_ne_of_ne h47, Fin.val_ne_of_ne h56, Fin.val_ne_of_ne h57,
     Fin.val_ne_of_ne h67⟩

/--
  Attack-surface observability predicate on `Domain8` (Proof 3a Part 1):
  `N` (CCA bit-flip oracle under MAC + Reveal) and `S1, S2, S3` (cache side-channel)
  have documented observable surfaces; `L` and `D1, D2, D3` execute in constant-time
  registers/tables with zero software-observable side-channel.
-/
def isObservable : Domain8 → Bool
  | .N | .S1 | .S2 | .S3 => true
  | .L | .D1 | .D2 | .D3 => false

/-- The three cross-domain leakage classes of Proof 3a Part 5. -/
inductive LeakageClass where
  | ObservableAndUnobservable   -- N or S_i merged with L or D_j (16 unordered pairs)
  | ObservableAndObservable     -- N merged with S_i, or S_i with S_j (6 unordered pairs)
  | UnobservableAndUnobservable -- L merged with D_i, or D_i with D_j (6 unordered pairs)
  deriving DecidableEq, Repr

/-- Classify the cross-domain leakage induced by merging `d1` and `d2` onto one seed. -/
def classifyMerge (d1 d2 : Domain8) : LeakageClass :=
  match isObservable d1, isObservable d2 with
  | true,  true  => .ObservableAndObservable
  | false, false => .UnobservableAndUnobservable
  | _,     _     => .ObservableAndUnobservable

/--
  Proof 3a Part 5 Exhaustive Partition:
  Every distinct unordered pair `{d1, d2}` (`28` unordered pairs = `56` ordered pairs)
  falls symmetrically into one of the three leakage classes, with exact ordered pair
  counts `32` (`16` unordered), `12` (`6` unordered), and `12` (`6` unordered):
  `16 + 6 + 6 = 28 = C(8, 2)`.
-/
theorem proof3a_leakage_partition_counts :
    let pairs := (allDomains8.flatMap fun d1 => allDomains8.map fun d2 => (d1, d2)).filter
      (fun p => p.1 != p.2)
    pairs.length = 56 ∧
    (pairs.filter (fun p => classifyMerge p.1 p.2 == .ObservableAndUnobservable)).length = 32 ∧
    (pairs.filter (fun p => classifyMerge p.1 p.2 == .ObservableAndObservable)).length = 12 ∧
    (pairs.filter (fun p => classifyMerge p.1 p.2 == .UnobservableAndUnobservable)).length = 12 ∧
    (pairs.all (fun p => classifyMerge p.1 p.2 == classifyMerge p.2 p.1)) = true := by
  decide

/-! ## Proof 3: Per-Region Noise Counter Disjointness -/

/--
  Per-region noise counter `(i - 1) * regionPixels + p` (with 0-based `region : Fin 3`),
  matching `noiseBase = regionIdx * regionPixels` in `process_generic.go`.
-/
def noiseCounter (region : Fin 3) (regionPixels p : Nat) : Nat :=
  region.val * regionPixels + p

/--
  Proof 3 Disjoint Noise Counter Ranges:
  Because the noise counter is not restarted per region, any two noise counter queries
  `(r1, p1)` and `(r2, p2)` with `p1 < regionPixels` and `p2 < regionPixels` collide
  if and only if `r1 = r2` and `p1 = p2`. In particular, distinct regions `r1 ≠ r2`
  use strictly disjoint counter ranges.
-/
theorem noiseCounter_injective (r1 r2 : Fin 3) (regionPixels p1 p2 : Nat)
    (hp1 : p1 < regionPixels) (hp2 : p2 < regionPixels)
    (heq : noiseCounter r1 regionPixels p1 = noiseCounter r2 regionPixels p2) :
    r1 = r2 ∧ p1 = p2 := by
  unfold noiseCounter at heq
  have hP : 0 < regionPixels := by omega
  have hdiv1 : (r1.val * regionPixels + p1) / regionPixels = r1.val := by
    rw [Nat.add_comm (r1.val * regionPixels) p1, Nat.add_mul_div_right _ _ hP,
        Nat.div_eq_of_lt hp1, Nat.zero_add]
  have hdiv2 : (r2.val * regionPixels + p2) / regionPixels = r2.val := by
    rw [Nat.add_comm (r2.val * regionPixels) p2, Nat.add_mul_div_right _ _ hP,
        Nat.div_eq_of_lt hp2, Nat.zero_add]
  have hr_val : r1.val = r2.val := by
    rw [← hdiv1, ← hdiv2, heq]
  have hr : r1 = r2 := Fin.ext hr_val
  have hp : p1 = p2 := by
    rw [hr_val] at heq
    omega
  exact ⟨hr, hp⟩

/-! ## `interlock_nonce` 3-Region Lane Split (`nonceSplit`) and 4-Byte XOR Fold `v` -/

/--
  3-lane byte split of an `nonceLen`-byte `interlock_nonce` matching `nonceSplit`
  in `interlock_nonce.go`:
  `base = nonceLen / 3`, `rem = nonceLen % 3`,
  `l0 = base + (if 0 < rem then 1 else 0)`,
  `l1 = base + (if 1 < rem then 1 else 0)`,
  `l2 = base`.
  Prepended to the three lane buffers ahead of COBS framing inside the MAC-covered capacity.
-/
def nonceSplit (nonceLen : Nat) : Nat × Nat × Nat :=
  let base := nonceLen / 3
  let rem := nonceLen % 3
  let l0 := base + (if 0 < rem then 1 else 0)
  let l1 := base + (if 1 < rem then 1 else 0)
  let l2 := base
  (l0, l1, l2)

/--
  Exact reconstruction of the total `interlock_nonce` byte length across the 3 lanes
  for any `nonceLen : Nat`: `l0 + l1 + l2 = nonceLen`, and consecutive lanes differ by at most 1 byte.
-/
theorem nonceSplit_sum_and_balance (nonceLen : Nat) :
    let (l0, l1, l2) := nonceSplit nonceLen
    l0 + l1 + l2 = nonceLen ∧ l2 ≤ l1 ∧ l1 ≤ l0 ∧ l0 ≤ l2 + 1 := by
  unfold nonceSplit
  dsimp only
  split <;> split <;> omega

/--
  Exact `nonceSplit` values across all three supported nonce widths (`16`, `32`, `64` bytes):
  - `128`-bit (`16` B): `nonceSplit 16 = (6, 5, 5)` (`6 + 5 + 5 = 16`)
  - `256`-bit (`32` B): `nonceSplit 32 = (11, 11, 10)` (`11 + 11 + 10 = 32`)
  - `512`-bit (`64` B, default): `nonceSplit 64 = (22, 21, 21)` (`22 + 21 + 21 = 64`)
  In all three supported widths, `nonceLen % 3 ≠ 0` and `l0 ≠ l2` (strictly asymmetric 3-region split).
-/
theorem nonceSplit_shipped_widths :
    nonceSplit 16 = (6, 5, 5)     ∧ 6 + 5 + 5 = 16     ∧ 16 * 8 = 128 ∧ 16 % 3 ≠ 0 ∧
    nonceSplit 32 = (11, 11, 10)  ∧ 11 + 11 + 10 = 32  ∧ 32 * 8 = 256 ∧ 32 % 3 ≠ 0 ∧
    nonceSplit 64 = (22, 21, 21)  ∧ 22 + 21 + 21 = 64  ∧ 64 * 8 = 512 ∧ 64 % 3 ≠ 0 := by
  decide

/--
  Per-lane alignment asymmetry induced by all three shipped `interlock_nonce` widths
  (`64` B `= (22, 21, 21)` at 512-bit, `32` B `= (11, 11, 10)` at 256-bit, `16` B `= (6, 5, 5)` at 128-bit)
  prepended ahead of the Rank Barrier lane payloads:
  - Under `Interlock = "48"` (`2` bytes per lane per chunk, `7` bytes per pixel):
    `l0 % 2 ≠ l2 % 2` (`22 % 2 ≠ 21 % 2`, `11 % 2 ≠ 10 % 2`, `6 % 2 ≠ 5 % 2`, opposite 16-bit lane parity),
    and `l0 % 7 ≠ l2 % 7` (`22 % 7 ≠ 21 % 7`, `11 % 7 ≠ 10 % 7`, `6 % 7 ≠ 5 % 7`, `+1 mod 7` pixel shift).
  - Under `Interlock = "168"` (`7` bytes per lane per chunk, `7` bytes per pixel):
    `l0 % 7 ≠ l2 % 7` across all three widths (`22 % 7 = 1 ≠ 21 % 7 = 0`, `11 % 7 = 4 ≠ 10 % 7 = 3`,
    `6 % 7 = 6 ≠ 5 % 7 = 5`), shifting 7-byte lane words and pixel boundaries by `+1 mod 7`.
-/
theorem nonceSplit_64_lane_alignment_asymmetry :
    22 % 2 = 0 ∧ 21 % 2 = 1 ∧ 22 % 2 ≠ 21 % 2 ∧
    22 % 7 = 1 ∧ 21 % 7 = 0 ∧ 22 % 7 ≠ 21 % 7 ∧
    11 % 2 = 1 ∧ 10 % 2 = 0 ∧ 11 % 2 ≠ 10 % 2 ∧
    11 % 7 = 4 ∧ 10 % 7 = 3 ∧ 11 % 7 ≠ 10 % 7 ∧
    6 % 2 = 0  ∧ 5 % 2 = 1  ∧ 6 % 2 ≠ 5 % 2 ∧
    6 % 7 = 6  ∧ 5 % 7 = 5  ∧ 6 % 7 ≠ 5 % 7 := by
  decide

/--
  48-bit Rank Barrier (`2` B = `16` bits per lane per chunk) vs Pixel Barrier (`7` bits/channel,
  `56` bits = `7` B per pixel) non-alignability:
  1. `gcd(2, 7) = 1` (`gcd(16, 56) = 8`), so `2`-byte lane fragments cycle through all 7 pixel-byte
     phase offsets `(2 * c) % 7 ∈ {0..6}` across `c ∈ Fin 7` before repeating every 7 chunks (`14` B = `2` pixels).
  2. Within any 56-bit pixel (`8` channels of `7` bits), a contiguous 16-bit fragment starting at bit
     offset `b0 ≤ 40` has first bit in channel `b0 / 7` and last bit `b0 + 15` in channel `(b0 + 15) / 7`,
     spanning `(b0 + 15) / 7 - b0 / 7 + 1 ∈ {3, 4}` channels (never fewer than 3 channels, since `16 > 2 * 7`).
-/
theorem interlock48_pixel_channel_nonalignment :
    Nat.gcd 2 7 = 1 ∧
    Nat.gcd 16 56 = 8 ∧
    16 > 2 * 7 ∧
    (∀ c1 c2 : Fin 7, (2 * c1.val) % 7 = (2 * c2.val) % 7 → c1 = c2) ∧
    (∀ b0 : Fin 41,
      let chSpan := (b0.val + 15) / 7 - b0.val / 7 + 1
      3 ≤ chSpan ∧ chSpan ≤ 4) := by
  decide

/--
  168-bit Rank Barrier (`7` B = `56` bits per lane per chunk) vs `interlock_nonce` + COBS + Pixel Barrier
  pixel-boundary straddling:
  Although a 168-bit chunk outputs three `7`-byte (`56`-bit) lane fragments matching a single pixel's
  `56`-bit capacity, the lane stream prepends the `interlock_nonce` fragment (`22`, `21`, `21` B at 512-bit,
  `11`, `11`, `10` B at 256-bit, `6`, `5`, `5` B at 128-bit) and undergoes COBS framing (`+1` leading
  overhead byte before the first payload byte, plus `+1` overhead byte per `254`-byte block, `255 % 7 = 3 ≠ 0`):
  - At the default 512-bit nonce, the first 7-byte lane fragment starts at byte offset `22 + 1 = 23`
    in Region 0 (`23 % 7 = 2 ≠ 0`, splitting every 7-byte lane fragment `5` B + `2` B across two pixels)
    and at byte offset `21 + 1 = 22` in Regions 1–2 (`22 % 7 = 1 ≠ 0`, splitting every 7-byte lane fragment
    `6` B + `1` B across two pixels).
  - Each full 254-byte COBS block (`255` encoded bytes) shifts subsequent pixel alignment by `255 % 7 = 3 ≠ 0`.
-/
theorem interlock168_cobs_pixel_straddling :
    (22 + 1) % 7 = 2 ∧ (22 + 1) % 7 ≠ 0 ∧
    (21 + 1) % 7 = 1 ∧ (21 + 1) % 7 ≠ 0 ∧
    (11 + 1) % 7 = 5 ∧ (10 + 1) % 7 = 4 ∧
    (6 + 1) % 7 = 0  ∧ (5 + 1) % 7 = 6 ∧
    255 % 7 = 3      ∧ 255 % 7 ≠ 0 := by
  decide

/--
  32-bit (`4`-byte) XOR fold `v` of the `interlock_nonce` 4-byte slices:
  given initial 32-bit word `w0` and remaining 32-bit words `rest` (15 words for a 64-byte nonce),
  `xorFold32` XORs all slices into a single 32-bit value `v` per message.
-/
def xorFold32 (w0 : BitVec 32) (rest : List (BitVec 32)) : BitVec 32 :=
  rest.foldl (fun acc w => acc ^^^ w) w0

/-- Helper lemma: `foldl (· ^^^ ·)` shifts out the initial accumulator via XOR associativity. -/
theorem foldl_xor_assoc {w : Nat} (init a : BitVec w) (xs : List (BitVec w)) :
    xs.foldl (fun acc x => acc ^^^ x) (init ^^^ a) =
    init ^^^ xs.foldl (fun acc x => acc ^^^ x) a := by
  induction xs generalizing init a with
  | nil => rfl
  | cons x rest ih =>
    simp only [List.foldl]
    rw [BitVec.xor_assoc init a x]
    exact ih init (a ^^^ x)

/--
  Explicit decomposition of `xorFold32`:
  `xorFold32 w0 rest = w0 ^^^ rest.foldl (· ^^^ ·) 0`.
-/
theorem xorFold32_eq_xor_tail (w0 : BitVec 32) (rest : List (BitVec 32)) :
    xorFold32 w0 rest = w0 ^^^ rest.foldl (fun acc w => acc ^^^ w) 0#32 := by
  unfold xorFold32
  have h : w0 = w0 ^^^ 0#32 := by simp
  conv => lhs; rw [h]
  exact foldl_xor_assoc w0 0#32 rest

/--
  Bijection of `xorFold32` in the first 32-bit word `w0` for any fixed remaining words `rest`:
  Recovering `w0` from `v = xorFold32 w0 rest` via `v ^^^ rest.foldl (· ^^^ ·) 0` is an exact
  two-sided inverse on `BitVec 32`. Consequently, uniform 512-bit `interlock_nonce` hidden
  behind the Pixel Barrier induces a strictly uniform 32-bit (`2^32 = 4294967296`) distribution on `v`.
-/
theorem xorFold32_bijection (w0 v : BitVec 32) (rest : List (BitVec 32)) :
    let tailXor := rest.foldl (fun acc w => acc ^^^ w) 0#32
    xorFold32 (v ^^^ tailXor) rest = v ∧
    (xorFold32 w0 rest) ^^^ tailXor = w0 := by
  dsimp only
  rw [xorFold32_eq_xor_tail, xorFold32_eq_xor_tail]
  constructor
  · rw [BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero]
  · rw [BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero]

/--
  13-byte (`104`-bit) Rank Barrier evaluation block `[0x03 ‖ LE64(groupIdx) ‖ v]`
  (`1 + 8 + 4 = 13` bytes).
-/
def rankEvalBlock (groupIdx : BitVec 64) (v : BitVec 32) : BitVec 8 × BitVec 64 × BitVec 32 :=
  (0x03#8, groupIdx, v)

/-- Byte and bit width of the Rank Barrier evaluation block (`1 + 8 + 4 = 13` B = `104` bits). -/
theorem rankEvalBlock_width : 1 + 8 + 4 = 13 ∧ 13 * 8 = 104 := by decide

/--
  Intra-message PRF input distinctness (Proof 11):
  Distinct `groupIdx` values produce strictly distinct 13-byte Rank Barrier PRF inputs.
-/
theorem rankEvalBlock_injective (g1 g2 : BitVec 64) (v1 v2 : BitVec 32)
    (h : rankEvalBlock g1 v1 = rankEvalBlock g2 v2) :
    g1 = g2 ∧ v1 = v2 := by
  unfold rankEvalBlock at h
  injection h with _ hrest
  injection hrest with hg hv
  exact ⟨hg, hv⟩

/-! ## Proof 3b: ChainHash Full Component Utilization and XOR-Cancelling Failure Mode -/

/--
  Iterated `ChainHash(data, S)` over `S = s0 :: rest`:
  `h_0 = H(data, s_0)` and `h_i = H(data, s_i ⊕ h_{i-1})`.
-/
def chainHashSteps {Data : Type} {w : Nat}
    (H : Data → BitVec w → BitVec w) (d : Data) (acc : BitVec w) : List (BitVec w) → BitVec w
  | [] => acc
  | s :: rest => chainHashSteps H d (H d (s ^^^ acc)) rest

/-- Full `ChainHash` evaluation starting from the first seed component `s0`. -/
def chainHash {Data : Type} {w : Nat}
    (H : Data → BitVec w → BitVec w) (d : Data) (s0 : BitVec w) (rest : List (BitVec w)) : BitVec w :=
  chainHashSteps H d (H d s0) rest

/-- `chainHashSteps` distributes over list concatenation `pre ++ suf`. -/
theorem chainHashSteps_append {Data : Type} {w : Nat}
    (H : Data → BitVec w → BitVec w) (d : Data) (acc : BitVec w)
    (pre suf : List (BitVec w)) :
    chainHashSteps H d acc (pre ++ suf) =
    chainHashSteps H d (chainHashSteps H d acc pre) suf := by
  induction pre generalizing acc with
  | nil => rfl
  | cons s rest ih =>
    simp only [List.cons_append, chainHashSteps]
    exact ih (H d (s ^^^ acc))

/--
  Step 3 of Proof 3b (Cascade Propagation): if `H d` is injective on `BitVec w`,
  then any distinct intermediate state `acc1 ≠ acc2` remains distinct after any
  number of subsequent `chainHashSteps` rounds.
-/
theorem chainHashSteps_injective_of_injective {Data : Type} {w : Nat}
    (H : Data → BitVec w → BitVec w) (d : Data)
    (hinj : ∀ x y : BitVec w, H d x = H d y → x = y)
    (rest : List (BitVec w)) (acc1 acc2 : BitVec w)
    (heq : chainHashSteps H d acc1 rest = chainHashSteps H d acc2 rest) :
    acc1 = acc2 := by
  induction rest generalizing acc1 acc2 with
  | nil => exact heq
  | cons s tail ih =>
    simp only [chainHashSteps] at heq
    have hstep := ih (H d (s ^^^ acc1)) (H d (s ^^^ acc2)) heq
    have hxor := hinj (s ^^^ acc1) (s ^^^ acc2) hstep
    have hcancel := congrArg (fun x => s ^^^ x) hxor
    rw [← BitVec.xor_assoc, ← BitVec.xor_assoc, BitVec.xor_self, BitVec.zero_xor, BitVec.zero_xor] at hcancel
    exact hcancel

/--
  Proof 3b (Head Component Utilization): if `H d` is injective on `BitVec w`,
  modifying the initial seed component `s0 ≠ s0'` strictly changes the final output
  `chainHash H d s0 rest`.
-/
theorem proof3b_head_component_utilization {Data : Type} {w : Nat}
    (H : Data → BitVec w → BitVec w) (d : Data)
    (hinj : ∀ x y : BitVec w, H d x = H d y → x = y)
    (s0 s0' : BitVec w) (rest : List (BitVec w))
    (hne : s0 ≠ s0') :
    chainHash H d s0 rest ≠ chainHash H d s0' rest := by
  intro heq
  unfold chainHash at heq
  have h0 := chainHashSteps_injective_of_injective H d hinj rest (H d s0) (H d s0') heq
  exact hne (hinj s0 s0' h0)

/--
  Proof 3b (Arbitrary Interior Component Utilization): if `H d` is injective on `BitVec w`,
  modifying any interior component `sk` to `sk' ≠ sk` at position `pre.length + 1`
  strictly changes the final output `chainHash H d s0 (pre ++ sk :: suf)`.
-/
theorem proof3b_interior_component_utilization {Data : Type} {w : Nat}
    (H : Data → BitVec w → BitVec w) (d : Data)
    (hinj : ∀ x y : BitVec w, H d x = H d y → x = y)
    (s0 sk sk' : BitVec w) (pre suf : List (BitVec w))
    (hne : sk ≠ sk') :
    chainHash H d s0 (pre ++ sk :: suf) ≠ chainHash H d s0 (pre ++ sk' :: suf) := by
  intro heq
  unfold chainHash at heq
  rw [chainHashSteps_append, chainHashSteps_append] at heq
  simp only [chainHashSteps] at heq
  let prev := chainHashSteps H d (H d s0) pre
  have hmid := chainHashSteps_injective_of_injective H d hinj suf
    (H d (sk ^^^ prev)) (H d (sk' ^^^ prev)) heq
  have hxor := hinj (sk ^^^ prev) (sk' ^^^ prev) hmid
  have hcancel := congrArg (fun x => x ^^^ prev) hxor
  rw [BitVec.xor_assoc, BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero, BitVec.xor_zero] at hcancel
  exact hne hcancel

/--
  Proof 3b XOR-Cancelling Failure Mode:
  Define `xorCancelHash f d k = k ^^^ f d`.
-/
def xorCancelHash {Data : Type} {w : Nat} (f : Data → BitVec w) (d : Data) (k : BitVec w) : BitVec w :=
  k ^^^ f d

/--
  In a 2-component chain `[s0, s1]`, `xorCancelHash` cancels `f d` completely:
  `chainHash (xorCancelHash f) d s0 [s1] = s1 ^^^ s0`, losing all dependence on `d`.
-/
theorem proof3b_xor_cancelling_two_rounds {Data : Type} {w : Nat}
    (f : Data → BitVec w) (d : Data) (s0 s1 : BitVec w) :
    chainHash (xorCancelHash f) d s0 [s1] = s1 ^^^ s0 := by
  unfold chainHash chainHashSteps xorCancelHash
  simp only [chainHashSteps]
  rw [BitVec.xor_assoc, BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero]

/-! ## Two-Stage Cascade Fill Round Counts (`4/8/16` vs `5/9/17`) and Primer Round Binding -/

/--
  Pixel Barrier `ChainHash` round count (`r = keyBits / width`), matching `SCIENCE.md § 1.2.1`.
-/
def pixelCascadeRounds (keyBits width : Nat) : Nat :=
  keyBits / width

/--
  Rank Barrier Two-Stage Cascade Fill round count (`r = 1 + keyBits / width`), matching
  `interlock48_cascade.go` and `interlock168.go` (`lockComps = [K, c[0], ..., c[n-1]]`).
-/
def interlockCascadeRounds (keyBits width : Nat) : Nat :=
  1 + keyBits / width

/--
  Round-count invariant (`SCIENCE.md § 1.2.1`): the Rank Barrier cascade fill is
  strictly 1 round deeper than the Pixel Barrier cascade for every `keyBits` and `width`.
-/
theorem interlockCascadeRounds_eq_succ (keyBits width : Nat) :
    interlockCascadeRounds keyBits width = pixelCascadeRounds keyBits width + 1 := by
  unfold interlockCascadeRounds pixelCascadeRounds
  omega

/--
  Exact shipped `ChainHash` round counts across `keyBits ∈ {512, 1024, 2048}` and
  `width ∈ {128, 256, 512}` (`SCIENCE.md § 1.2.1`):
  - Width 128: Pixel Barrier `(4, 8, 16)` vs Rank Barrier `(5, 9, 17)`.
  - Width 256: Pixel Barrier `(2, 4, 8)` vs Rank Barrier `(3, 5, 9)`.
  - Width 512: Pixel Barrier `(1, 2, 4)` vs Rank Barrier `(2, 3, 5)`.
-/
theorem cascade_round_counts_shipped :
    pixelCascadeRounds 512 128 = 4  ∧ interlockCascadeRounds 512 128 = 5 ∧
    pixelCascadeRounds 1024 128 = 8 ∧ interlockCascadeRounds 1024 128 = 9 ∧
    pixelCascadeRounds 2048 128 = 16 ∧ interlockCascadeRounds 2048 128 = 17 ∧
    pixelCascadeRounds 512 256 = 2  ∧ interlockCascadeRounds 512 256 = 3 ∧
    pixelCascadeRounds 1024 256 = 4 ∧ interlockCascadeRounds 1024 256 = 5 ∧
    pixelCascadeRounds 2048 256 = 8 ∧ interlockCascadeRounds 2048 256 = 9 ∧
    pixelCascadeRounds 512 512 = 1  ∧ interlockCascadeRounds 512 512 = 2 ∧
    pixelCascadeRounds 1024 512 = 2 ∧ interlockCascadeRounds 1024 512 = 3 ∧
    pixelCascadeRounds 2048 512 = 4 ∧ interlockCascadeRounds 2048 512 = 5 := by
  decide

/--
  Two-Stage Cascade Fill (`interlock48_cascade.go`, `interlock168.go`):
  Stage 1 derives intermediate key `K = chainHash H deriveBlock s0 rest` (domain tag `0x04 ‖ N_il`);
  Stage 2 prepends `K` as the Round 1 primer key ahead of session components `s0 :: rest`
  and evaluates `chainHash H groupBlock K (s0 :: rest)` over `[0x03 ‖ LE64(groupIdx) ‖ v]`.
-/
def interlockCascade {Data : Type} {w : Nat}
    (H : Data → BitVec w → BitVec w) (deriveBlock groupBlock : Data)
    (s0 : BitVec w) (rest : List (BitVec w)) : BitVec w :=
  let K := chainHash H deriveBlock s0 rest
  chainHash H groupBlock K (s0 :: rest)

/--
  Stage 2 of `interlockCascade` sensitive to both the primer key `K` (Round 1) and
  every subsequent session component `sk` in `s0 :: rest = pre ++ sk :: suf` (Rounds `2..n+1`).
-/
theorem interlockCascade_primer_and_session_utilization {Data : Type} {w : Nat}
    (H : Data → BitVec w → BitVec w) (groupBlock : Data)
    (hinj : ∀ x y : BitVec w, H groupBlock x = H groupBlock y → x = y)
    (K K' s0 sk sk' : BitVec w) (rest pre suf : List (BitVec w))
    (hK : K ≠ K') (hsk : sk ≠ sk') :
    chainHash H groupBlock K (s0 :: rest) ≠ chainHash H groupBlock K' (s0 :: rest) ∧
    chainHash H groupBlock K (pre ++ sk :: suf) ≠ chainHash H groupBlock K (pre ++ sk' :: suf) :=
  ⟨proof3b_head_component_utilization H groupBlock hinj K K' (s0 :: rest) hK,
   proof3b_interior_component_utilization H groupBlock hinj K sk sk' pre suf hsk⟩

/-! ## Proof 4a: Multi-Factor Full KPA Brute-Force Work Factor Bounds -/

/--
  Full KPA brute-force work factor bounds at a 1024-bit key (Proof 4a and `SECURITY.md § 3`):
  - Mode 1 (`P = 1225`): Core ITB / Silent Drop `P * 2^(2 * 1024)` lies in `(2^2058, 2^2059)`,
    and MAC + Reveal `P * 2^1024` lies in `(2^1034, 2^1035)`.
  - Mode 2 (`P = 441`): Core ITB / Silent Drop `P * 2^(2 * 1024)` lies in `(2^2056, 2^2057)`,
    and MAC + Reveal `P * 2^1024` lies in `(2^1032, 2^1033)`.
-/
theorem proof4a_full_kpa_work_factors_1024 :
    2 ^ 2058 < 1225 * 2 ^ (2 * 1024) ∧ 1225 * 2 ^ (2 * 1024) < 2 ^ 2059 ∧
    2 ^ 1034 < 1225 * 2 ^ 1024       ∧ 1225 * 2 ^ 1024 < 2 ^ 1035 ∧
    2 ^ 2056 < 441 * 2 ^ (2 * 1024)  ∧ 441 * 2 ^ (2 * 1024) < 2 ^ 2057 ∧
    2 ^ 1032 < 441 * 2 ^ 1024        ∧ 441 * 2 ^ 1024 < 2 ^ 1033 := by
  decide

/-! ## Proof 8: Oracle-Free Deniability Bijection -/

/--
  Inverse mapping for `decodeChannel` under a candidate seed configuration `(m', r', np')`
  when the container byte is formed with noise bit `nb` at `np'`.
-/
def encodeWrongCandidate (out m' : BitVec 7) (r' : Fin 7) (np' : Fin 8) (nb : Bool) : BitVec 8 :=
  insertBit (rotate7 (out ^^^ m') r') nb np'

/--
  Proof 8 (Oracle-Free Deniability Channel Bijection):
  For any candidate seed configuration `(m' : BitVec 7, r' : Fin 7, np' : Fin 8)`,
  decoding a uniform container byte `v : BitVec 8` via `decodeChannel v m' r' np'` is a
  2-to-1 surjection from `BitVec 8` (256 values) onto `BitVec 7` (128 values):
  for every target 7-bit output `out : BitVec 7` and every noise bit `nb : Bool`,
  there is a unique container byte `v` with `v.getLsbD np'.val = nb` and
  `decodeChannel v m' r' np' = out`. Uniform container bytes therefore decode to
  strictly uniform 7-bit data under any wrong seed tuple.
-/
theorem proof8_deniability_channel_surjection
    (m' : BitVec 7) (r' : Fin 7) (np' : Fin 8) (out : BitVec 7) (nb : Bool) :
    let v := encodeChannel out m' r' np' nb
    decodeChannel v m' r' np' = out ∧
    v.getLsbD np'.val = nb ∧
    ∀ v' : BitVec 8,
      decodeChannel v' m' r' np' = out →
      v'.getLsbD np'.val = nb →
      v' = v := by
  dsimp only
  refine ⟨decode_encode_id out m' r' np' nb, encode_getLsbD_np out m' r' np' nb, ?_⟩
  intro v' hdec hnb
  have h1 := encode_decode_id v' m' r' np'
  rw [hdec, hnb] at h1
  exact h1.symm

/-! ## Additional Theorem 1: MAC-Inside-Encrypt Composition (`Verify-before-COBS`) -/

/-- Outcome of the two-stage authenticated decoder (`DecryptAuthenticated3x*Cfg`). -/
inductive AuthDecodeResult (Payload : Type) where
  | macRejected
  | cobsDecoded (out : Payload)
  deriving DecidableEq, Repr

/--
  Two-stage `Verify-before-COBS-Null-Search` state machine:
  Step 1 verifies the full-capacity MAC tag (`payload ‖ streamID ‖ [prefix_i] ‖ LE64(offset) ‖ flag`);
  Step 2 searches for the `0x00` COBS null terminator ONLY IF MAC verification succeeds.
-/
def authDecode {Capacity Payload : Type}
    (verifyMAC : Capacity → Bool)
    (cobsSearchNull : Capacity → Payload)
    (cap : Capacity) : AuthDecodeResult Payload :=
  if verifyMAC cap then .cobsDecoded (cobsSearchNull cap)
  else .macRejected

/--
  MAC-Inside-Encrypt Part B (False Null-Terminator Prevention):
  Whenever `verifyMAC cap = false` (including any bit flip in the `interlock_nonce` lane
  prefixes, COBS payload bytes, `0x00` null terminator, or DRBG fill bytes), `authDecode`
  returns `.macRejected` and is completely invariant to `cobsSearchNull` (the COBS null-search
  parser is never reached).
-/
theorem mac_inside_encrypt_verify_before_cobs {Capacity Payload : Type}
    (verifyMAC : Capacity → Bool)
    (cobsSearch1 cobsSearch2 : Capacity → Payload)
    (cap : Capacity)
    (hfail : verifyMAC cap = false) :
    authDecode verifyMAC cobsSearch1 cap = .macRejected ∧
    authDecode verifyMAC cobsSearch1 cap = authDecode verifyMAC cobsSearch2 cap := by
  unfold authDecode
  rw [hfail]
  exact ⟨rfl, rfl⟩

/--
  MAC-Inside-Encrypt Part A (Uniform 1/8 Accept vs 7/8 Reject Across All Pixels):
  For every channel byte `v : BitVec 8` and noise position `np : Fin 8` (whether the byte
  encodes an `interlock_nonce` lane prefix bit, a COBS data bit, a `0x00` null-terminator bit,
  or a DRBG fill bit), out of the 8 single-bit flips `b ∈ Fin 8`, exactly 1 flip (`b = np`)
  preserves `extractBits` and 7 flips (`b ≠ np`) alter `extractBits`, eliminating spatial patterns.
-/
theorem mac_inside_encrypt_uniform_bitflip_classification :
    ∀ (v : BitVec 8) (np : Fin 8),
      ((List.finRange 8).filter (fun b => extractBits (flipBit8 v b) np == extractBits v np)).length = 1 ∧
      ((List.finRange 8).filter (fun b => extractBits (flipBit8 v b) np != extractBits v np)).length = 7 := by
  decide

/--
  Authenticated MAC input tuple bound inside Region 2 (`full2 = payload2 ++ tag ++ [flag]`,
  `auth128.go:17-20`, `PROOFS.md § MAC-Inside-Encrypt Composition`) and encrypted behind
  the Pixel Barrier:
  `(payload_0, payload_1, payload_2, streamID, chunkPrefix, cumulativePixelOffset, finalFlag)`.
-/
structure StreamMACInput (Payload : Type) where
  payload0 : Payload
  payload1 : Payload
  payload2 : Payload
  streamID : BitVec 256
  chunkPrefix : Option (BitVec 256)
  cumulativePixelOffset : Nat
  finalFlag : Bool
  deriving DecidableEq

/-- Cumulative pixel offset `Σ_{k < n} chunkPixels(k)` at chunk index `n`. -/
def cumOffset (chunkPixels : Nat → Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => cumOffset chunkPixels n + chunkPixels n

/--
  Strict monotonicity of `cumOffset`: if every chunk has positive pixel count
  (`∀ k, chunkPixels k > 0`), then `i < j → cumOffset chunkPixels i < cumOffset chunkPixels j`.
-/
theorem stream_offset_strict_mono (chunkPixels : Nat → Nat)
    (hpos : ∀ k, chunkPixels k > 0) :
    ∀ {i j : Nat}, i < j → cumOffset chunkPixels i < cumOffset chunkPixels j := by
  intro i j hij
  induction j with
  | zero => omega
  | succ m ih =>
    have hstep : cumOffset chunkPixels (m + 1) = cumOffset chunkPixels m + chunkPixels m := rfl
    have hm_pos : chunkPixels m > 0 := hpos m
    by_cases him : i = m
    · subst him
      omega
    · have hil : i < m := by omega
      have ih_step := ih hil
      omega

/--
  Injectivity of `cumOffset`: for positive chunk pixel counts, distinct chunk indices `i ≠ j`
  always have distinct cumulative pixel offsets (`cumOffset chunkPixels i ≠ cumOffset chunkPixels j`).
-/
theorem stream_offset_injective (chunkPixels : Nat → Nat)
    (hpos : ∀ k, chunkPixels k > 0) {i j : Nat} (hne : i ≠ j) :
    cumOffset chunkPixels i ≠ cumOffset chunkPixels j := by
  intro heq
  have hlt : i < j ∨ j < i := by omega
  rcases hlt with h1 | h2
  · have := stream_offset_strict_mono chunkPixels hpos h1
    omega
  · have := stream_offset_strict_mono chunkPixels hpos h2
    omega

/--
  Anti-reordering and anti-duplication theorem for Streaming AEAD:
  if every chunk has positive pixel count (`∀ k, chunkPixels k > 0`), any two chunks at
  distinct indices `i ≠ j` produce distinct `StreamMACInput` records regardless of their
  payloads, prefixes, or flags.
-/
theorem stream_reorder_distinguishes {Payload : Type}
    (chunkPixels : Nat → Nat) (hpos : ∀ k, chunkPixels k > 0)
    (p0 p1 p2 p0' p1' p2' : Payload)
    (sid sid' : BitVec 256)
    (cp cp' : Option (BitVec 256))
    (ff ff' : Bool)
    {i j : Nat} (hne : i ≠ j) :
    ({ payload0 := p0, payload1 := p1, payload2 := p2,
       streamID := sid, chunkPrefix := cp,
       cumulativePixelOffset := cumOffset chunkPixels i, finalFlag := ff } : StreamMACInput Payload) ≠
    { payload0 := p0', payload1 := p1', payload2 := p2',
      streamID := sid', chunkPrefix := cp',
      cumulativePixelOffset := cumOffset chunkPixels j, finalFlag := ff' } := by
  intro heq
  have hoff := congrArg StreamMACInput.cumulativePixelOffset heq
  exact stream_offset_injective chunkPixels hpos hne hoff

/--
  Anti-truncation theorem for Streaming AEAD and Single Message MAC (`auth128.go:70-79`):
  a non-final chunk (`finalFlag = false`, `0x00`) and a final chunk (`finalFlag = true`, `0xFF`)
  produce strictly distinct `StreamMACInput` records.
-/
theorem stream_finalFlag_distinguishes {Payload : Type}
    (p0 p1 p2 p0' p1' p2' : Payload)
    (sid sid' : BitVec 256)
    (cp cp' : Option (BitVec 256))
    (off off' : Nat) :
    ({ payload0 := p0, payload1 := p1, payload2 := p2,
       streamID := sid, chunkPrefix := cp,
       cumulativePixelOffset := off, finalFlag := false } : StreamMACInput Payload) ≠
    { payload0 := p0', payload1 := p1', payload2 := p2',
      streamID := sid', chunkPrefix := cp',
      cumulativePixelOffset := off', finalFlag := true } := by
  intro heq
  have hff := congrArg StreamMACInput.finalFlag heq
  contradiction

/--
  Cross-stream anti-splice theorem (`auth128.go:17-20`):
  chunks from two streams with `sid ≠ sid'` produce strictly distinct `StreamMACInput` records.
-/
theorem stream_id_distinguishes {Payload : Type}
    (p0 p1 p2 p0' p1' p2' : Payload)
    (sid sid' : BitVec 256)
    (cp cp' : Option (BitVec 256))
    (off off' : Nat)
    (ff ff' : Bool)
    (hsid : sid ≠ sid') :
    ({ payload0 := p0, payload1 := p1, payload2 := p2,
       streamID := sid, chunkPrefix := cp,
       cumulativePixelOffset := off, finalFlag := ff } : StreamMACInput Payload) ≠
    { payload0 := p0', payload1 := p1', payload2 := p2',
      streamID := sid', chunkPrefix := cp',
      cumulativePixelOffset := off', finalFlag := ff' } := by
  intro heq
  have h := congrArg StreamMACInput.streamID heq
  exact hsid h

/-! ## 4-Way Wire-Shape Indistinguishability (`No MAC` / `MAC` × `Single Message` / `Streaming`) -/

/--
  Model of `nomacTagStubSizeCfg` (`stream_envelope.go:35-41`): reserves `tagStubSize + 1` bytes
  in Region 2 under `No MAC` (defaulting to `32 + 1 = 33` bytes when `tagStubSize = 0`).
-/
def nomacTagStubSize (tagStubSize : Nat) : Nat :=
  (if tagStubSize > 0 then tagStubSize else 32) + 1

/--
  Region 2 AEAD trailer reservation (`tagSize` MAC tag bytes + `1` byte `finalFlag`,
  `triplepayload.go:185-190,269,351`).
-/
def region2Reserve (tagSize : Nat) : Nat := tagSize + 1

/--
  Per-region available data payload capacities `(caps0, caps1, caps2 - reserve)`
  in `buildTripleWire3Into` (`triplepayload.go:351`).
-/
def tripleDataPayloadCaps (caps0 caps1 caps2 reserve : Nat) : Nat × Nat × Nat :=
  (caps0, caps1, caps2 - reserve)

/--
  On-wire record byte length `[prefix(32)][main nonce][W(2)][H(2)][W×H×8 pixels]`
  shared across all four pipeline modes (`itb128.go:139`, `auth128.go:14`).
-/
def wireRecordLen (nonceBytes W H : Nat) : Nat :=
  32 + nonceBytes + 4 + W * H * 8

/--
  Exact `nomacTagStubSize` values for the default (`0 → 33` B) and the three
  hash/MAC widths (`128, 256, 512` bits → `16, 32, 64` B tags → `17, 33, 65` B reserves).
-/
theorem nomacTagStubSize_shipped_widths :
    nomacTagStubSize 0 = 33 ∧
    nomacTagStubSize 16 = 17 ∧
    nomacTagStubSize 32 = 33 ∧
    nomacTagStubSize 64 = 65 ∧
    nomacTagStubSize 0 = region2Reserve 32 ∧
    nomacTagStubSize 16 = region2Reserve 16 ∧
    nomacTagStubSize 32 = region2Reserve 32 ∧
    nomacTagStubSize 64 = region2Reserve 64 := by decide

/--
  4-Way Wire-Shape Indistinguishability (`No MAC` / `MAC` × `Single Message` / `Streaming`,
  `itb128.go:139-147,213-220`, `auth128.go:14-24`, `stream_envelope.go:10-41`):
  Because `MinPixels = MinPixelsAuth` (both use `sizeFn`) and `nomacTagStubSize tagSize = region2Reserve tagSize = tagSize + 1`
  for every `tagSize > 0`, all four modes (`Single Message No MAC`, `Single Message MAC`,
  `Streaming No-AEAD` chunk, and `Streaming AEAD` chunk) produce:
  1. Identical Region 2 reserve `tagSize + 1` (`fillReserve = true` DRBG stub vs `tag ‖ flag`),
  2. Identical per-region data payload capacities `(caps0, caps1, caps2 - (tagSize + 1))`,
  3. Identical container dimensions `(W, H) = sizeFn bound0 bound1 (bound2 + tagSize + 1)`, and
  4. Identical on-wire record byte length `32 + nonceBytes + 4 + 8 * W * H`.
-/
theorem four_way_wire_shape_parity
    (sizeFn : Nat → Nat → Nat → Nat × Nat)
    (bound0 bound1 bound2 tagSize caps0 caps1 caps2 nonceBytes : Nat)
    (ht : tagSize > 0) :
    let nomacRes := nomacTagStubSize tagSize
    let aeadRes := region2Reserve tagSize
    let (wNomac, hNomac) := sizeFn bound0 bound1 (bound2 + nomacRes)
    let (wAead, hAead) := sizeFn bound0 bound1 (bound2 + aeadRes)
    nomacRes = aeadRes ∧
    tripleDataPayloadCaps caps0 caps1 caps2 nomacRes =
      tripleDataPayloadCaps caps0 caps1 caps2 aeadRes ∧
    (wNomac, hNomac) = (wAead, hAead) ∧
    wireRecordLen nonceBytes wNomac hNomac = wireRecordLen nonceBytes wAead hAead := by
  have hres : nomacTagStubSize tagSize = region2Reserve tagSize := by
    unfold nomacTagStubSize region2Reserve
    simp [ht]
  dsimp only
  rw [hres]
  exact ⟨rfl, rfl, rfl, rfl⟩

/-! ## Additional Theorem 2: Nonce Uniqueness and Dual-Nonce Axis Independence -/

/--
  Birthday paradox exponents for the shipped 512-bit (`2^256` single-axis, `2^512` dual-axis)
  and 128-bit (`2^64` single-axis, `2^128` dual-axis) nonce widths.
-/
theorem nonce_birthday_exponents :
    512 / 2 = 256 ∧ (2 : Nat) ^ 256 * 2 ^ 256 = 2 ^ 512 ∧
    128 / 2 = 64  ∧ (2 : Nat) ^ 64 * 2 ^ 64 = 2 ^ 128 := by
  decide

/--
  Dual-Nonce Partial-Collision Independence:
  A message's barrier parametrization is determined by the pair `(N_m, N_il)`.
  If two messages do not suffer a simultaneous dual-slot collision (`(N_m1, N_il1) ≠ (N_m2, N_il2)`),
  then either the Pixel Barrier / startPixel axis has a fresh nonce (`N_m1 ≠ N_m2`)
  or the Rank Barrier axis has a fresh nonce (`N_il1 ≠ N_il2`).
-/
theorem dual_nonce_fresh_axis_of_ne {Nonce : Type} [DecidableEq Nonce]
    (Nm1 Nil1 Nm2 Nil2 : Nonce)
    (hne : (Nm1, Nil1) ≠ (Nm2, Nil2)) :
    Nm1 ≠ Nm2 ∨ Nil1 ≠ Nil2 := by
  by_cases hm : Nm1 = Nm2
  · right
    intro hil
    exact hne (Prod.ext hm hil)
  · left
    exact hm

end ITB.SeedIsolation
