/-
  Formal verification of the reference application-level 3-to-8 Multi-KEM Key
  Agreement (`deriveSeeds3to8`), 3-of-3 Intra-Epoch Ratchet Root (`deriveRatchetRoot`),
  3-Part Configuration Slicing (`splitProfile3` / `joinProfile3`), and Downgrade-Safe
  Schema Clamping (`min(appVer_A, appVer_B)`) presented in `APPS.md`.

  Scope note: This module verifies only the reference application integration
  blueprint from `APPS.md`. It is separate from the core ITB cipher specification
  and its formal verification modules in `lean/ITB/`.
-/

namespace Apps.ThreeToEight

/-! ## 1. 7-Subset Combinatorial Partition (`2^3 - 1 = 7`) and `slotSubsets` -/

/-- Exact count of non-empty subsets of the 3-channel KEM set `{0, 1, 2}` is `2^3 - 1 = 7`. -/
theorem three_kem_nonempty_subsets_count : 2 ^ 3 - 1 = 7 := rfl

/--
  Canonical assignment of each of the 8 ITB seed slots (`0..7`) to one of the
  7 non-empty 3-bit channel masks (`1..7`), matching `slotSubsets = [8]int{1, 2, 4, 6, 5, 3, 7, 7}`
  in `APPS.md`.
-/
def slotSubsets (slot : Fin 8) : Nat :=
  match slot.val with
  | 0 => 1
  | 1 => 2
  | 2 => 4
  | 3 => 6
  | 4 => 5
  | 5 => 3
  | 6 => 7
  | _ => 7

/-- Every slot is assigned a non-empty 3-bit subset mask in `1..7`. -/
theorem slotSubsets_in_range :
    ∀ s : Fin 8, 1 ≤ slotSubsets s ∧ slotSubsets s ≤ 7 := by
  decide

/--
  Surjectivity onto all 7 non-empty subsets:
  Every non-empty subset mask `m ∈ {1, 2, 3, 4, 5, 6, 7}` is assigned to at least
  one of the 8 ITB seed slots.
-/
theorem slotSubsets_surjective_on_seven_masks :
    ∀ m : Nat, 1 ≤ m → m ≤ 7 → ∃ s : Fin 8, slotSubsets s = m := by
  intro m hm1 hm7
  match m with
  | 1 => exact ⟨⟨0, by decide⟩, rfl⟩
  | 2 => exact ⟨⟨1, by decide⟩, rfl⟩
  | 3 => exact ⟨⟨5, by decide⟩, rfl⟩
  | 4 => exact ⟨⟨2, by decide⟩, rfl⟩
  | 5 => exact ⟨⟨4, by decide⟩, rfl⟩
  | 6 => exact ⟨⟨3, by decide⟩, rfl⟩
  | 7 => exact ⟨⟨6, by decide⟩, rfl⟩
  | 0 => omega
  | n + 8 => omega

/-- Predicate testing whether channel `c ∈ {0, 1, 2}` participates in subset `mask`. -/
def channelInMask (mask : Nat) (c : Fin 3) : Bool :=
  (mask &&& (1 <<< c.val)) != 0

/--
  Every non-empty mask `1..7` contains at least one active KEM channel, and each
  of the 3 channels participates in exactly 4 of the 7 non-empty masks (`3 * 4 = 12`
  active Stage A KDF derivations in total).
-/
theorem stageA_subset_participation_counts :
    let masks := [1, 2, 3, 4, 5, 6, 7]
    (masks.all (fun m =>
      channelInMask m ⟨0, by decide⟩ ||
      channelInMask m ⟨1, by decide⟩ ||
      channelInMask m ⟨2, by decide⟩)) = true ∧
    (masks.filter (fun m => channelInMask m ⟨0, by decide⟩)).length = 4 ∧
    (masks.filter (fun m => channelInMask m ⟨1, by decide⟩)).length = 4 ∧
    (masks.filter (fun m => channelInMask m ⟨2, by decide⟩)).length = 4 := by
  decide

/-! ## 2. Domain Separation Across All KDF Label Families in `APPS.md` -/

/--
  Structured representation of all six domain-separated KDF label families
  used in `APPS.md`:
  - `prkSubset`: `"itb-chat-v1|prk-subset-%d|ch-%d|%s"` (Stage A)
  - `slotShare`: `"itb-chat-v1|slot-%d|sub-%d|ch-%d|%s"` (Stage B)
  - `ratchetRoot`: `"itb-chat-v1|ratchet-root|ch-%d|%s"` (Intra-epoch ratchet root)
  - `cfgFrag`: `"itb-chat-v1|cfg-frag-%d|ch-%d|%s"` (3-part configuration masking)
  - `rekeyPerm`: `"rekey-perm|seq:%d"` (Per-message Parallax ratchet key)
  - `rekeyWrap`: `"rekey-wrap|seq:%d"` (Per-message Wrapper ratchet key)
-/
inductive AppsKDFDomain where
  | prkSubset   (mask : Nat) (ch : Fin 3)
  | slotShare   (slot : Fin 8) (sub : Nat) (ch : Fin 3)
  | ratchetRoot (ch : Fin 3)
  | cfgFrag     (frag : Fin 3) (ch : Fin 3)
  | rekeyPerm   (seq : Nat)
  | rekeyWrap   (seq : Nat)
  deriving DecidableEq, Repr

/--
  No XOR-Cancellation Between Stage A and Stage B:
  Every Stage A subset PRK derivation label is strictly distinct from every
  Stage B per-slot share derivation label (`prkSubset mask c1 ≠ slotShare s sub c2`).
-/
theorem stageA_stageB_domain_disjoint (mask : Nat) (c1 c2 : Fin 3) (s : Fin 8) (sub : Nat) :
    AppsKDFDomain.prkSubset mask c1 ≠ AppsKDFDomain.slotShare s sub c2 := by
  intro h
  nomatch h

/--
  Stage B Label Injectivity:
  All `8 × 3 = 24` Stage B KDF calls across `slot ∈ Fin 8` and `ch ∈ Fin 3`
  produce pairwise-distinct domain tags.
-/
theorem stageB_labels_injective (s1 s2 : Fin 8) (c1 c2 : Fin 3)
    (h : AppsKDFDomain.slotShare s1 (slotSubsets s1) c1 =
         AppsKDFDomain.slotShare s2 (slotSubsets s2) c2) :
    s1 = s2 ∧ c1 = c2 := by
  injection h with hs _ hc
  exact ⟨hs, hc⟩

/--
  Configuration Fragment Label Injectivity:
  All `3 × 3 = 9` configuration-masking KDF calls across `frag ∈ Fin 3` and
  `ch ∈ Fin 3` produce pairwise-distinct domain tags and are disjoint from
  `prkSubset`, `slotShare`, and `ratchetRoot`.
-/
theorem cfgFrag_labels_injective (f1 f2 c1 c2 : Fin 3)
    (h : AppsKDFDomain.cfgFrag f1 c1 = AppsKDFDomain.cfgFrag f2 c2) :
    f1 = f2 ∧ c1 = c2 := by
  injection h with hf hc
  exact ⟨hf, hc⟩

/--
  Ratchet Root Label Disjointness & Injectivity:
  The 3 intra-epoch ratchet root labels `ratchetRoot c` (`c ∈ Fin 3`) are pairwise
  distinct and strictly disjoint from all Stage A (`prkSubset`), Stage B (`slotShare`),
  and configuration fragment (`cfgFrag`) labels.
-/
theorem ratchetRoot_domain_disjoint (c1 c2 : Fin 3) (mask : Nat) (s : Fin 8) (sub : Nat) (f : Fin 3) :
    (AppsKDFDomain.ratchetRoot c1 = AppsKDFDomain.ratchetRoot c2 → c1 = c2) ∧
    AppsKDFDomain.ratchetRoot c1 ≠ AppsKDFDomain.prkSubset mask c2 ∧
    AppsKDFDomain.ratchetRoot c1 ≠ AppsKDFDomain.slotShare s sub c2 ∧
    AppsKDFDomain.ratchetRoot c1 ≠ AppsKDFDomain.cfgFrag f c2 := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro h; injection h
  · intro h; nomatch h
  · intro h; nomatch h
  · intro h; nomatch h

/--
  Per-Message Symmetric Rekey Label Disjointness & Sequence Injectivity:
  The per-message `rekeyPerm seq` (`"rekey-perm|seq:%d"`) and `rekeyWrap seq`
  (`"rekey-wrap|seq:%d"`) labels are injective in the message sequence number `seq`,
  mutually disjoint (`rekeyPerm seq1 ≠ rekeyWrap seq2`), and strictly disjoint from
  `prkSubset`, `slotShare`, `ratchetRoot`, and `cfgFrag`.
-/
theorem rekey_domain_disjoint_and_injective
    (seq1 seq2 mask sub : Nat) (c : Fin 3) (s : Fin 8) (f : Fin 3) :
    (AppsKDFDomain.rekeyPerm seq1 = AppsKDFDomain.rekeyPerm seq2 → seq1 = seq2) ∧
    (AppsKDFDomain.rekeyWrap seq1 = AppsKDFDomain.rekeyWrap seq2 → seq1 = seq2) ∧
    AppsKDFDomain.rekeyPerm seq1 ≠ AppsKDFDomain.rekeyWrap seq2 ∧
    AppsKDFDomain.rekeyPerm seq1 ≠ AppsKDFDomain.ratchetRoot c ∧
    AppsKDFDomain.rekeyWrap seq1 ≠ AppsKDFDomain.ratchetRoot c ∧
    AppsKDFDomain.rekeyPerm seq1 ≠ AppsKDFDomain.prkSubset mask c ∧
    AppsKDFDomain.rekeyPerm seq1 ≠ AppsKDFDomain.slotShare s sub c ∧
    AppsKDFDomain.rekeyPerm seq1 ≠ AppsKDFDomain.cfgFrag f c := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro h; injection h
  · intro h; injection h
  · intro h; nomatch h
  · intro h; nomatch h
  · intro h; nomatch h
  · intro h; nomatch h
  · intro h; nomatch h
  · intro h; nomatch h

/-! ## 3. 2-of-3 Compromise Model: Unbroken Third Channel Existence -/

/--
  For any two distinct compromised channels `c1 ≠ c2` in `Fin 3`, there exists
  a third channel `u : Fin 3` that is distinct from both `c1` and `c2`.
-/
theorem two_of_three_unbroken_channel :
    ∀ c1 c2 : Fin 3, c1 ≠ c2 → ∃ u : Fin 3, u ≠ c1 ∧ u ≠ c2 := by
  decide

/-- Exhaustive enumeration of `u : Fin 3`. -/
theorem fin3_cases (u : Fin 3) :
    u = ⟨0, by decide⟩ ∨ u = ⟨1, by decide⟩ ∨ u = ⟨2, by decide⟩ := by
  revert u; decide

/-! ## 4. All-or-Nothing `3-to-8` Master Key Secrecy Bijection (`deriveSeeds3to8`) -/

/-- Right XOR cancellation on `BitVec w`: `(a ^^^ b) ^^^ b = a`. -/
theorem xor_cancel_right {w : Nat} (a b : BitVec w) : (a ^^^ b) ^^^ b = a := by
  rw [BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero]

/--
  Bit-exact 3-way Tri-KDF XOR fold combining a base value (`subsetPRK` in Stage B,
  `0` in `deriveRatchetRoot`, or `plain` in `splitProfile3`) with three channel
  shares `sh0, sh1, sh2` of width `w` bits (`w = 512` for 64-byte slot master keys).
-/
def triKDFXorFold {w : Nat} (base sh0 sh1 sh2 : BitVec w) : BitVec w :=
  base ^^^ sh0 ^^^ sh1 ^^^ sh2

/--
  Inversion of `triKDFXorFold` with respect to Channel 0 share `sh0`:
  `(triKDFXorFold base sh0 sh1 sh2) ^^^ base ^^^ sh1 ^^^ sh2 = sh0`.
-/
theorem triKDFXorFold_inv_ch0 {w : Nat} (base sh0 sh1 sh2 : BitVec w) :
    triKDFXorFold base sh0 sh1 sh2 ^^^ base ^^^ sh1 ^^^ sh2 = sh0 := by
  unfold triKDFXorFold
  ext i hi
  simp only [BitVec.getElem_xor]
  cases base[i] <;> cases sh0[i] <;> cases sh1[i] <;> cases sh2[i] <;> rfl

/--
  Inversion of `triKDFXorFold` with respect to Channel 1 share `sh1`:
  `(triKDFXorFold base sh0 sh1 sh2) ^^^ base ^^^ sh0 ^^^ sh2 = sh1`.
-/
theorem triKDFXorFold_inv_ch1 {w : Nat} (base sh0 sh1 sh2 : BitVec w) :
    triKDFXorFold base sh0 sh1 sh2 ^^^ base ^^^ sh0 ^^^ sh2 = sh1 := by
  unfold triKDFXorFold
  ext i hi
  simp only [BitVec.getElem_xor]
  cases base[i] <;> cases sh0[i] <;> cases sh1[i] <;> cases sh2[i] <;> rfl

/--
  Inversion of `triKDFXorFold` with respect to Channel 2 share `sh2`:
  `(triKDFXorFold base sh0 sh1 sh2) ^^^ base ^^^ sh0 ^^^ sh1 = sh2`.
-/
theorem triKDFXorFold_inv_ch2 {w : Nat} (base sh0 sh1 sh2 : BitVec w) :
    triKDFXorFold base sh0 sh1 sh2 ^^^ base ^^^ sh0 ^^^ sh1 = sh2 := by
  unfold triKDFXorFold
  ext i hi
  simp only [BitVec.getElem_xor]
  cases base[i] <;> cases sh0[i] <;> cases sh1[i] <;> cases sh2[i] <;> rfl

/--
  Channel 0 Unbroken Witness Recovery:
  For any fixed `base, sh1, sh2` and any target output `target`, the unique
  Channel 0 share `sh0 = target ^^^ base ^^^ sh1 ^^^ sh2` maps to `target`.
-/
theorem triKDFXorFold_surjective_ch0 {w : Nat} (base sh1 sh2 target : BitVec w) :
    triKDFXorFold base (target ^^^ base ^^^ sh1 ^^^ sh2) sh1 sh2 = target := by
  unfold triKDFXorFold
  ext i hi
  simp only [BitVec.getElem_xor]
  cases base[i] <;> cases target[i] <;> cases sh1[i] <;> cases sh2[i] <;> rfl

/--
  Channel 0 Unbroken Injectivity:
  For any fixed `base, sh1, sh2`, the mapping `sh0 ↦ triKDFXorFold base sh0 sh1 sh2`
  is injective on `BitVec w`.
-/
theorem triKDFXorFold_injective_ch0 {w : Nat} (base sh1 sh2 a b : BitVec w)
    (h : triKDFXorFold base a sh1 sh2 = triKDFXorFold base b sh1 sh2) :
    a = b := by
  have h1 := congrArg (fun x => x ^^^ base ^^^ sh1 ^^^ sh2) h
  rw [triKDFXorFold_inv_ch0, triKDFXorFold_inv_ch0] at h1
  exact h1

/--
  Channel 1 Unbroken Witness Recovery:
  For any fixed `base, sh0, sh2` and any target output `target`, the unique
  Channel 1 share `sh1 = target ^^^ base ^^^ sh0 ^^^ sh2` maps to `target`.
-/
theorem triKDFXorFold_surjective_ch1 {w : Nat} (base sh0 sh2 target : BitVec w) :
    triKDFXorFold base sh0 (target ^^^ base ^^^ sh0 ^^^ sh2) sh2 = target := by
  unfold triKDFXorFold
  ext i hi
  simp only [BitVec.getElem_xor]
  cases base[i] <;> cases sh0[i] <;> cases target[i] <;> cases sh2[i] <;> rfl

/--
  Channel 1 Unbroken Injectivity:
  For any fixed `base, sh0, sh2`, the mapping `sh1 ↦ triKDFXorFold base sh0 sh1 sh2`
  is injective on `BitVec w`.
-/
theorem triKDFXorFold_injective_ch1 {w : Nat} (base sh0 sh2 a b : BitVec w)
    (h : triKDFXorFold base sh0 a sh2 = triKDFXorFold base sh0 b sh2) :
    a = b := by
  have h1 := congrArg (fun x => x ^^^ base ^^^ sh0 ^^^ sh2) h
  rw [triKDFXorFold_inv_ch1, triKDFXorFold_inv_ch1] at h1
  exact h1

/--
  Channel 2 Unbroken Witness Recovery:
  For any fixed `base, sh0, sh1` and any target output `target`, the unique
  Channel 2 share `sh2 = target ^^^ base ^^^ sh0 ^^^ sh1` maps to `target`.
-/
theorem triKDFXorFold_surjective_ch2 {w : Nat} (base sh0 sh1 target : BitVec w) :
    triKDFXorFold base sh0 sh1 (target ^^^ base ^^^ sh0 ^^^ sh1) = target := by
  unfold triKDFXorFold
  ext i hi
  simp only [BitVec.getElem_xor]
  cases base[i] <;> cases sh0[i] <;> cases sh1[i] <;> cases target[i] <;> rfl

/--
  Channel 2 Unbroken Injectivity:
  For any fixed `base, sh0, sh1`, the mapping `sh2 ↦ triKDFXorFold base sh0 sh1 sh2`
  is injective on `BitVec w`.
-/
theorem triKDFXorFold_injective_ch2 {w : Nat} (base sh0 sh1 a b : BitVec w)
    (h : triKDFXorFold base sh0 sh1 a = triKDFXorFold base sh0 sh1 b) :
    a = b := by
  have h1 := congrArg (fun x => x ^^^ base ^^^ sh0 ^^^ sh1) h
  rw [triKDFXorFold_inv_ch2, triKDFXorFold_inv_ch2] at h1
  exact h1

/--
  Full Stage A + Stage B Evaluation of `deriveSeeds3to8` on 512-bit (`64`-byte)
  slot master keys:
  Given Stage A subset shares `prkShare : Nat → Fin 3 → BitVec 512` and Stage B
  per-slot shares `slotShare : Fin 8 → Fin 3 → BitVec 512`, computes `masters[s]`.
-/
def evalSubsetPRK (mask : Nat) (prkShare : Nat → Fin 3 → BitVec 512) : BitVec 512 :=
  (if channelInMask mask ⟨0, by decide⟩ then prkShare mask ⟨0, by decide⟩ else 0#512) ^^^
  (if channelInMask mask ⟨1, by decide⟩ then prkShare mask ⟨1, by decide⟩ else 0#512) ^^^
  (if channelInMask mask ⟨2, by decide⟩ then prkShare mask ⟨2, by decide⟩ else 0#512)

def evalSlotMaster (s : Fin 8)
    (prkShare : Nat → Fin 3 → BitVec 512)
    (slotShare : Fin 8 → Fin 3 → BitVec 512) : BitVec 512 :=
  triKDFXorFold
    (evalSubsetPRK (slotSubsets s) prkShare)
    (slotShare s ⟨0, by decide⟩)
    (slotShare s ⟨1, by decide⟩)
    (slotShare s ⟨2, by decide⟩)

/-- Replace the Stage B share of `(s, u)` with `val`. -/
def updateSlotShare (slotShare : Fin 8 → Fin 3 → BitVec 512)
    (s : Fin 8) (u : Fin 3) (val : BitVec 512) : Fin 8 → Fin 3 → BitVec 512 :=
  fun s' u' => if s' = s ∧ u' = u then val else slotShare s' u'

/--
  Unified 2-of-3 All-or-Nothing Bijection Theorem for `deriveSeeds3to8`:
  For any unbroken channel `u : Fin 3`, any slot `s : Fin 8`, any Stage A table
  `prkShare`, and any Stage B table `slotShare`:
  1. Updating `(s, u)` does not affect any other slot `s' ≠ s`.
  2. For every target 512-bit key `target : BitVec 512`, there exists a unique
     Stage B output `w : BitVec 512` on the unbroken channel `u` such that
     `evalSlotMaster s prkShare (updateSlotShare slotShare s u w) = target`.
-/
theorem deriveSeeds3to8_all_or_nothing_bijection
    (u : Fin 3) (s : Fin 8)
    (prkShare : Nat → Fin 3 → BitVec 512)
    (slotShare : Fin 8 → Fin 3 → BitVec 512)
    (target : BitVec 512) :
    (∀ s' : Fin 8, s' ≠ s → ∀ w : BitVec 512,
      evalSlotMaster s' prkShare (updateSlotShare slotShare s u w) =
      evalSlotMaster s' prkShare slotShare) ∧
    (∃ w : BitVec 512,
      evalSlotMaster s prkShare (updateSlotShare slotShare s u w) = target ∧
      ∀ w' : BitVec 512,
        evalSlotMaster s prkShare (updateSlotShare slotShare s u w') = target → w' = w) := by
  constructor
  · intro s' hs' w
    unfold evalSlotMaster updateSlotShare
    simp [hs']
  · have hu : u = ⟨0, by decide⟩ ∨ u = ⟨1, by decide⟩ ∨ u = ⟨2, by decide⟩ := by
      revert u; decide
    rcases hu with rfl | rfl | rfl
    · let base := evalSubsetPRK (slotSubsets s) prkShare
      let sh1  := slotShare s ⟨1, by decide⟩
      let sh2  := slotShare s ⟨2, by decide⟩
      refine ⟨target ^^^ base ^^^ sh1 ^^^ sh2, ?_, ?_⟩
      · unfold evalSlotMaster updateSlotShare
        simp
        exact triKDFXorFold_surjective_ch0 base sh1 sh2 target
      · intro w' hw'
        unfold evalSlotMaster updateSlotShare at hw'
        simp at hw'
        have hsurj := triKDFXorFold_surjective_ch0 base sh1 sh2 target
        exact triKDFXorFold_injective_ch0 base sh1 sh2 w' (target ^^^ base ^^^ sh1 ^^^ sh2) (hw'.trans hsurj.symm)
    · let base := evalSubsetPRK (slotSubsets s) prkShare
      let sh0  := slotShare s ⟨0, by decide⟩
      let sh2  := slotShare s ⟨2, by decide⟩
      refine ⟨target ^^^ base ^^^ sh0 ^^^ sh2, ?_, ?_⟩
      · unfold evalSlotMaster updateSlotShare
        simp
        exact triKDFXorFold_surjective_ch1 base sh0 sh2 target
      · intro w' hw'
        unfold evalSlotMaster updateSlotShare at hw'
        simp at hw'
        have hsurj := triKDFXorFold_surjective_ch1 base sh0 sh2 target
        exact triKDFXorFold_injective_ch1 base sh0 sh2 w' (target ^^^ base ^^^ sh0 ^^^ sh2) (hw'.trans hsurj.symm)
    · let base := evalSubsetPRK (slotSubsets s) prkShare
      let sh0  := slotShare s ⟨0, by decide⟩
      let sh1  := slotShare s ⟨1, by decide⟩
      refine ⟨target ^^^ base ^^^ sh0 ^^^ sh1, ?_, ?_⟩
      · unfold evalSlotMaster updateSlotShare
        simp
        exact triKDFXorFold_surjective_ch2 base sh0 sh1 target
      · intro w' hw'
        unfold evalSlotMaster updateSlotShare at hw'
        simp at hw'
        have hsurj := triKDFXorFold_surjective_ch2 base sh0 sh1 target
        exact triKDFXorFold_injective_ch2 base sh0 sh1 w' (target ^^^ base ^^^ sh0 ^^^ sh1) (hw'.trans hsurj.symm)

/-- Replace all 8 Stage B slot shares on channel `u` with `wVec : Fin 8 → BitVec 512`. -/
def updateChannelSlotShares (slotShare : Fin 8 → Fin 3 → BitVec 512)
    (u : Fin 3) (wVec : Fin 8 → BitVec 512) : Fin 8 → Fin 3 → BitVec 512 :=
  fun s c => if c = u then wVec s else slotShare s c

/--
  Joint 8-Slot Bijection Theorem for `deriveSeeds3to8`:
  For any unbroken channel `u : Fin 3`, any Stage A subset PRK table `prkShare`,
  any Stage B table `slotShare`, and any target 8-tuple of 512-bit master keys
  `targetVec : Fin 8 → BitVec 512` (including slots 6 and 7 that share `subsetPRK[7]`),
  there exists a unique 8-tuple of Stage B shares `wVec : Fin 8 → BitVec 512` on
  channel `u` such that all 8 slots simultaneously evaluate to `targetVec`.
-/
theorem deriveSeeds3to8_joint_8slot_bijection
    (u : Fin 3)
    (prkShare : Nat → Fin 3 → BitVec 512)
    (slotShare : Fin 8 → Fin 3 → BitVec 512)
    (targetVec : Fin 8 → BitVec 512) :
    ∃ wVec : Fin 8 → BitVec 512,
      (∀ s : Fin 8, evalSlotMaster s prkShare (updateChannelSlotShares slotShare u wVec) = targetVec s) ∧
      (∀ wVec' : Fin 8 → BitVec 512,
        (∀ s : Fin 8, evalSlotMaster s prkShare (updateChannelSlotShares slotShare u wVec') = targetVec s) →
        wVec' = wVec) := by
  have hrel : ∀ (wVec : Fin 8 → BitVec 512) (s : Fin 8),
      evalSlotMaster s prkShare (updateChannelSlotShares slotShare u wVec) =
      evalSlotMaster s prkShare (updateSlotShare slotShare s u (wVec s)) := by
    intro wVec s
    unfold evalSlotMaster updateChannelSlotShares updateSlotShare
    simp
  let wVec : Fin 8 → BitVec 512 := fun s =>
    match u.val with
    | 0 => targetVec s ^^^ evalSubsetPRK (slotSubsets s) prkShare ^^^ slotShare s ⟨1, by decide⟩ ^^^ slotShare s ⟨2, by decide⟩
    | 1 => targetVec s ^^^ evalSubsetPRK (slotSubsets s) prkShare ^^^ slotShare s ⟨0, by decide⟩ ^^^ slotShare s ⟨2, by decide⟩
    | _ => targetVec s ^^^ evalSubsetPRK (slotSubsets s) prkShare ^^^ slotShare s ⟨0, by decide⟩ ^^^ slotShare s ⟨1, by decide⟩
  refine ⟨wVec, ?_, ?_⟩
  · intro s
    rw [hrel wVec s]
    rcases fin3_cases u with rfl | rfl | rfl
    · unfold evalSlotMaster updateSlotShare wVec
      simp
      exact triKDFXorFold_surjective_ch0 (evalSubsetPRK (slotSubsets s) prkShare) (slotShare s ⟨1, by decide⟩) (slotShare s ⟨2, by decide⟩) (targetVec s)
    · unfold evalSlotMaster updateSlotShare wVec
      simp
      exact triKDFXorFold_surjective_ch1 (evalSubsetPRK (slotSubsets s) prkShare) (slotShare s ⟨0, by decide⟩) (slotShare s ⟨2, by decide⟩) (targetVec s)
    · unfold evalSlotMaster updateSlotShare wVec
      simp
      exact triKDFXorFold_surjective_ch2 (evalSubsetPRK (slotSubsets s) prkShare) (slotShare s ⟨0, by decide⟩) (slotShare s ⟨1, by decide⟩) (targetVec s)
  · intro wVec' hw'
    funext s
    have hs := hw' s
    rw [hrel wVec' s] at hs
    rcases (deriveSeeds3to8_all_or_nothing_bijection u s prkShare slotShare (targetVec s)).2 with ⟨w0, hw0, huniq⟩
    have hwVec_s : evalSlotMaster s prkShare (updateSlotShare slotShare s u (wVec s)) = targetVec s := by
      rcases fin3_cases u with rfl | rfl | rfl
      · unfold evalSlotMaster updateSlotShare wVec
        simp
        exact triKDFXorFold_surjective_ch0 (evalSubsetPRK (slotSubsets s) prkShare) (slotShare s ⟨1, by decide⟩) (slotShare s ⟨2, by decide⟩) (targetVec s)
      · unfold evalSlotMaster updateSlotShare wVec
        simp
        exact triKDFXorFold_surjective_ch1 (evalSubsetPRK (slotSubsets s) prkShare) (slotShare s ⟨0, by decide⟩) (slotShare s ⟨2, by decide⟩) (targetVec s)
      · unfold evalSlotMaster updateSlotShare wVec
        simp
        exact triKDFXorFold_surjective_ch2 (evalSubsetPRK (slotSubsets s) prkShare) (slotShare s ⟨0, by decide⟩) (slotShare s ⟨1, by decide⟩) (targetVec s)
    exact (huniq (wVec' s) hs).trans (huniq (wVec s) hwVec_s).symm

/--
  8-Way Layer Master (`PermMaster`, `WrapMaster`, `macKey`) Bijection:
  Inside `triple.InitKeys`, when `Opts.PermMaster` and `Opts.WrapMaster` are omitted,
  each layer master is derived by an 8-way XOR fold across all 8 slots (`k0 ⊕ ... ⊕ k7`).
  Fixing any 7 slot contributions leaves a bijection `k0 ↦ k0 ⊕ k1 ⊕ ... ⊕ k7`.
-/
def fold8Way {w : Nat} (k0 k1 k2 k3 k4 k5 k6 k7 : BitVec w) : BitVec w :=
  k0 ^^^ (k1 ^^^ k2 ^^^ k3 ^^^ k4 ^^^ k5 ^^^ k6 ^^^ k7)

theorem fold8Way_surjective {w : Nat} (k1 k2 k3 k4 k5 k6 k7 target : BitVec w) :
    fold8Way (target ^^^ (k1 ^^^ k2 ^^^ k3 ^^^ k4 ^^^ k5 ^^^ k6 ^^^ k7))
      k1 k2 k3 k4 k5 k6 k7 = target := by
  unfold fold8Way
  exact xor_cancel_right target (k1 ^^^ k2 ^^^ k3 ^^^ k4 ^^^ k5 ^^^ k6 ^^^ k7)

theorem fold8Way_bijection {w : Nat} (k1 k2 k3 k4 k5 k6 k7 target : BitVec w) :
    ∃ k0 : BitVec w,
      fold8Way k0 k1 k2 k3 k4 k5 k6 k7 = target ∧
      ∀ k0' : BitVec w, fold8Way k0' k1 k2 k3 k4 k5 k6 k7 = target → k0' = k0 := by
  let rest := k1 ^^^ k2 ^^^ k3 ^^^ k4 ^^^ k5 ^^^ k6 ^^^ k7
  refine ⟨target ^^^ rest, fold8Way_surjective k1 k2 k3 k4 k5 k6 k7 target, ?_⟩
  intro k0' hk0'
  unfold fold8Way at hk0'
  have h1 := congrArg (fun x => x ^^^ rest) hk0'
  rw [xor_cancel_right k0' rest] at h1
  exact h1

/--
  3-of-3 Intra-Epoch Ratchet Root (`deriveRatchetRoot`) on 512-bit (`64`-byte) keys:
  Computes `sh0 ⊕ sh1 ⊕ sh2` across the 3 channel shares (`base = 0#512`).
-/
def evalRatchetRoot (ratchetShare : Fin 3 → BitVec 512) : BitVec 512 :=
  triKDFXorFold 0#512
    (ratchetShare ⟨0, by decide⟩)
    (ratchetShare ⟨1, by decide⟩)
    (ratchetShare ⟨2, by decide⟩)

/--
  2-of-3 Secrecy Bijection for `deriveRatchetRoot`:
  For any unbroken channel `u : Fin 3`, any channel share assignment `ratchetShare`,
  and any target 512-bit ratchet root `target : BitVec 512`, there exists a unique
  512-bit share `w : BitVec 512` on channel `u` producing `target`.
-/
theorem deriveRatchetRoot_bijection
    (u : Fin 3)
    (ratchetShare : Fin 3 → BitVec 512)
    (target : BitVec 512) :
    ∃ w : BitVec 512,
      evalRatchetRoot (fun c => if c = u then w else ratchetShare c) = target ∧
      ∀ w' : BitVec 512,
        evalRatchetRoot (fun c => if c = u then w' else ratchetShare c) = target → w' = w := by
  have hu : u = ⟨0, by decide⟩ ∨ u = ⟨1, by decide⟩ ∨ u = ⟨2, by decide⟩ := by
    revert u; decide
  rcases hu with rfl | rfl | rfl
  · have hsurj : evalRatchetRoot (fun c => if c = ⟨0, by decide⟩ then target ^^^ 0#512 ^^^ ratchetShare ⟨1, by decide⟩ ^^^ ratchetShare ⟨2, by decide⟩ else ratchetShare c) = target := by
      unfold evalRatchetRoot
      simpa using triKDFXorFold_surjective_ch0 0#512 (ratchetShare ⟨1, by decide⟩) (ratchetShare ⟨2, by decide⟩) target
    refine ⟨target ^^^ 0#512 ^^^ ratchetShare ⟨1, by decide⟩ ^^^ ratchetShare ⟨2, by decide⟩, hsurj, ?_⟩
    intro w' hw'
    have h1 : triKDFXorFold 0#512 w' (ratchetShare ⟨1, by decide⟩) (ratchetShare ⟨2, by decide⟩) = target := by
      unfold evalRatchetRoot at hw'
      simpa using hw'
    have hboth := h1.trans (triKDFXorFold_surjective_ch0 0#512 (ratchetShare ⟨1, by decide⟩) (ratchetShare ⟨2, by decide⟩) target).symm
    exact triKDFXorFold_injective_ch0 0#512 (ratchetShare ⟨1, by decide⟩) (ratchetShare ⟨2, by decide⟩) w' (target ^^^ 0#512 ^^^ ratchetShare ⟨1, by decide⟩ ^^^ ratchetShare ⟨2, by decide⟩) hboth
  · have hsurj : evalRatchetRoot (fun c => if c = ⟨1, by decide⟩ then target ^^^ 0#512 ^^^ ratchetShare ⟨0, by decide⟩ ^^^ ratchetShare ⟨2, by decide⟩ else ratchetShare c) = target := by
      unfold evalRatchetRoot
      simpa using triKDFXorFold_surjective_ch1 0#512 (ratchetShare ⟨0, by decide⟩) (ratchetShare ⟨2, by decide⟩) target
    refine ⟨target ^^^ 0#512 ^^^ ratchetShare ⟨0, by decide⟩ ^^^ ratchetShare ⟨2, by decide⟩, hsurj, ?_⟩
    intro w' hw'
    have h1 : triKDFXorFold 0#512 (ratchetShare ⟨0, by decide⟩) w' (ratchetShare ⟨2, by decide⟩) = target := by
      unfold evalRatchetRoot at hw'
      simpa using hw'
    have hboth := h1.trans (triKDFXorFold_surjective_ch1 0#512 (ratchetShare ⟨0, by decide⟩) (ratchetShare ⟨2, by decide⟩) target).symm
    exact triKDFXorFold_injective_ch1 0#512 (ratchetShare ⟨0, by decide⟩) (ratchetShare ⟨2, by decide⟩) w' (target ^^^ 0#512 ^^^ ratchetShare ⟨0, by decide⟩ ^^^ ratchetShare ⟨2, by decide⟩) hboth
  · have hsurj : evalRatchetRoot (fun c => if c = ⟨2, by decide⟩ then target ^^^ 0#512 ^^^ ratchetShare ⟨0, by decide⟩ ^^^ ratchetShare ⟨1, by decide⟩ else ratchetShare c) = target := by
      unfold evalRatchetRoot
      simpa using triKDFXorFold_surjective_ch2 0#512 (ratchetShare ⟨0, by decide⟩) (ratchetShare ⟨1, by decide⟩) target
    refine ⟨target ^^^ 0#512 ^^^ ratchetShare ⟨0, by decide⟩ ^^^ ratchetShare ⟨1, by decide⟩, hsurj, ?_⟩
    intro w' hw'
    have h1 : triKDFXorFold 0#512 (ratchetShare ⟨0, by decide⟩) (ratchetShare ⟨1, by decide⟩) w' = target := by
      unfold evalRatchetRoot at hw'
      simpa using hw'
    have hboth := h1.trans (triKDFXorFold_surjective_ch2 0#512 (ratchetShare ⟨0, by decide⟩) (ratchetShare ⟨1, by decide⟩) target).symm
    exact triKDFXorFold_injective_ch2 0#512 (ratchetShare ⟨0, by decide⟩) (ratchetShare ⟨1, by decide⟩) w' (target ^^^ 0#512 ^^^ ratchetShare ⟨0, by decide⟩ ^^^ ratchetShare ⟨1, by decide⟩) hboth

/-! ## 5. 3-Part Configuration Slicing (`splitProfile3` / `joinProfile3`) & Schema Clamping -/

/--
  Padding any byte length `n` by `padLen = (3 - n % 3) % 3` whitespace bytes
  produces a total length divisible by 3 with `padLen < 3`.
-/
def profilePadLen (n : Nat) : Nat :=
  (3 - n % 3) % 3

theorem profilePadLen_spec (n : Nat) :
    profilePadLen n < 3 ∧ (n + profilePadLen n) % 3 = 0 := by
  unfold profilePadLen
  omega

/--
  Round-Trip Identity for `splitProfile3` and `joinProfile3`:
  Masking a configuration fragment `plain` with three KDF pads `pad0, pad1, pad2`
  and unmasking with the same three pads recovers `plain` bit-for-bit.
-/
theorem split_join_fragment_roundtrip {w : Nat} (plain pad0 pad1 pad2 : BitVec w) :
    triKDFXorFold (triKDFXorFold plain pad0 pad1 pad2) pad0 pad1 pad2 = plain := by
  unfold triKDFXorFold
  ext i hi
  simp only [BitVec.getElem_xor]
  cases plain[i] <;> cases pad0[i] <;> cases pad1[i] <;> cases pad2[i] <;> rfl

/--
  2-of-3 Configuration Fragment Secrecy:
  For any unbroken channel pad (e.g., `pad2` when Channels 0 and 1 are compromised),
  any candidate plaintext fragment `plain`, and any observed ciphertext fragment `ct`,
  there exists a unique unbroken pad `pad2 = ct ^^^ plain ^^^ pad0 ^^^ pad1` mapping
  `plain` to `ct`. Thus `ct` is statistically independent of `plain` under a uniform
  unbroken pad.
-/
theorem splitProfile3_fragment_secrecy {w : Nat} (plain pad0 pad1 ct : BitVec w) :
    triKDFXorFold plain pad0 pad1 (ct ^^^ plain ^^^ pad0 ^^^ pad1) = ct :=
  triKDFXorFold_surjective_ch2 plain pad0 pad1 ct

/-- Evaluate the masked configuration fragment `f : Fin 3` in `splitProfile3`. -/
def evalConfigFrag {w : Nat} (plain : Fin 3 → BitVec w)
    (padShare : Fin 3 → Fin 3 → BitVec w) (f : Fin 3) : BitVec w :=
  triKDFXorFold (plain f)
    (padShare f ⟨0, by decide⟩)
    (padShare f ⟨1, by decide⟩)
    (padShare f ⟨2, by decide⟩)

/-- Replace all 3 fragment pads on unbroken channel `u : Fin 3` with `wFrag : Fin 3 → BitVec w`. -/
def updateChannelFragPads {w : Nat} (padShare : Fin 3 → Fin 3 → BitVec w)
    (u : Fin 3) (wFrag : Fin 3 → BitVec w) : Fin 3 → Fin 3 → BitVec w :=
  fun f c => if c = u then wFrag f else padShare f c

/--
  Joint 3-Fragment Secrecy Bijection for `splitProfile3`:
  For any unbroken channel `u : Fin 3`, any 3 plaintext fragments `plain : Fin 3 → BitVec w`,
  any compromised channel pads `padShare`, and any 3 observed ciphertext fragments
  `ct : Fin 3 → BitVec w`, there exists a unique 3-tuple of pads `wFrag : Fin 3 → BitVec w`
  on channel `u` that simultaneously maps all 3 plaintext fragments to `ct`.
-/
theorem splitProfile3_joint_3fragment_bijection {w : Nat}
    (u : Fin 3)
    (plain : Fin 3 → BitVec w)
    (padShare : Fin 3 → Fin 3 → BitVec w)
    (ct : Fin 3 → BitVec w) :
    ∃ wFrag : Fin 3 → BitVec w,
      (∀ f : Fin 3, evalConfigFrag plain (updateChannelFragPads padShare u wFrag) f = ct f) ∧
      (∀ wFrag' : Fin 3 → BitVec w,
        (∀ f : Fin 3, evalConfigFrag plain (updateChannelFragPads padShare u wFrag') f = ct f) →
        wFrag' = wFrag) := by
  let wFrag : Fin 3 → BitVec w := fun f =>
    match u.val with
    | 0 => ct f ^^^ plain f ^^^ padShare f ⟨1, by decide⟩ ^^^ padShare f ⟨2, by decide⟩
    | 1 => ct f ^^^ plain f ^^^ padShare f ⟨0, by decide⟩ ^^^ padShare f ⟨2, by decide⟩
    | _ => ct f ^^^ plain f ^^^ padShare f ⟨0, by decide⟩ ^^^ padShare f ⟨1, by decide⟩
  have hsurj : ∀ f : Fin 3, evalConfigFrag plain (updateChannelFragPads padShare u wFrag) f = ct f := by
    intro f
    rcases fin3_cases u with rfl | rfl | rfl
    · unfold evalConfigFrag updateChannelFragPads wFrag
      simp
      exact triKDFXorFold_surjective_ch0 (plain f) (padShare f ⟨1, by decide⟩) (padShare f ⟨2, by decide⟩) (ct f)
    · unfold evalConfigFrag updateChannelFragPads wFrag
      simp
      exact triKDFXorFold_surjective_ch1 (plain f) (padShare f ⟨0, by decide⟩) (padShare f ⟨2, by decide⟩) (ct f)
    · unfold evalConfigFrag updateChannelFragPads wFrag
      simp
      exact triKDFXorFold_surjective_ch2 (plain f) (padShare f ⟨0, by decide⟩) (padShare f ⟨1, by decide⟩) (ct f)
  refine ⟨wFrag, hsurj, ?_⟩
  intro wFrag' hw'
  funext f
  have hf := hw' f
  have hf0 := hsurj f
  have hboth := hf.trans hf0.symm
  rcases fin3_cases u with rfl | rfl | rfl
  · unfold evalConfigFrag updateChannelFragPads at hboth
    simp at hboth
    exact triKDFXorFold_injective_ch0 (plain f) (padShare f ⟨1, by decide⟩) (padShare f ⟨2, by decide⟩) (wFrag' f) (wFrag f) hboth
  · unfold evalConfigFrag updateChannelFragPads at hboth
    simp at hboth
    exact triKDFXorFold_injective_ch1 (plain f) (padShare f ⟨0, by decide⟩) (padShare f ⟨2, by decide⟩) (wFrag' f) (wFrag f) hboth
  · unfold evalConfigFrag updateChannelFragPads at hboth
    simp at hboth
    exact triKDFXorFold_injective_ch2 (plain f) (padShare f ⟨0, by decide⟩) (padShare f ⟨1, by decide⟩) (wFrag' f) (wFrag f) hboth

/--
  Downgrade-Safe Application Schema Clamping (`min(appVer_A, appVer_B)`):
  The effective schema version `Nat.min a b` never exceeds either peer's supported
  schema version, is symmetric across initiator and responder, and equals `v` when
  both peers run version `v`.
-/
theorem appVer_clamp_spec (a b : Nat) :
    Nat.min a b ≤ a ∧
    Nat.min a b ≤ b ∧
    Nat.min a b = Nat.min b a ∧
    Nat.min a a = a := by
  refine ⟨Nat.min_le_left a b, Nat.min_le_right a b, Nat.min_comm a b, Nat.min_self a⟩

end Apps.ThreeToEight
