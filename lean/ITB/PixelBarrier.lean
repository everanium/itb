import Std.Tactic.BVDecide

/-
  Bit-precise formal verification of the Pixel Barrier channel operations
  over `BitVec 7` and `BitVec 8`: round-trip bijections, Proof 1
  (Information-Theoretic Barrier), Proof 2 (Per-Bit XOR KPA Resistance),
  Proof 6 (CCA Leak Upper Bound and Early-Stop Query Expectation), and
  Proof 7 (Bias Neutralization).
-/

namespace ITB.PixelBarrier

/-! ## Bit-Accurate Channel Operations Matching `itb.go` and `process_generic.go` -/

/--
  Cyclic left rotation of a 7-bit value `x` by `r ∈ Fin 7` bit positions,
  matching `rotateBits7` in `itb.go`.
-/
def rotate7 (x : BitVec 7) (r : Fin 7) : BitVec 7 :=
  if r.val == 0 then x
  else (x <<< r.val) ||| (x >>> (7 - r.val))

/--
  Inverse cyclic rotation of a 7-bit value `x` by `r ∈ Fin 7` bit positions,
  matching `rotateBits7(x, 7 - r)` in `process_generic.go`.
-/
def unrotate7 (x : BitVec 7) (r : Fin 7) : BitVec 7 :=
  if r.val == 0 then x
  else (x >>> r.val) ||| (x <<< (7 - r.val))

/--
  Insert 7 data bits `d7` around a single noise bit `noiseBit` at bit position `np ∈ Fin 8`,
  matching `low | (orig & noiseMask) | (high << (noisePos + 1))` in `process_generic.go`.
-/
def insertBit (d7 : BitVec 7) (noiseBit : Bool) (np : Fin 8) : BitVec 8 :=
  let d8 : BitVec 8 := d7.zeroExtend 8
  let noiseMask : BitVec 8 := (1 : BitVec 8) <<< np.val
  let lowMask : BitVec 8 := noiseMask - 1
  let low : BitVec 8 := d8 &&& lowMask
  let high : BitVec 8 := (d8 >>> np.val) <<< (np.val + 1)
  let nBit : BitVec 8 := (if noiseBit then (1 : BitVec 8) else 0) <<< np.val
  low ||| nBit ||| high

/--
  Extract the 7 data bits from an 8-bit channel byte `v` by removing the noise bit at `np ∈ Fin 8`,
  matching `(v & (noiseMask - 1)) | ((v >> (noisePos + 1)) << noisePos)` in `process_generic.go`.
-/
def extractBits (v : BitVec 8) (np : Fin 8) : BitVec 7 :=
  let noiseMask : BitVec 8 := (1 : BitVec 8) <<< np.val
  let lowMask : BitVec 8 := noiseMask - 1
  let low : BitVec 8 := v &&& lowMask
  let high : BitVec 8 := (v >>> (np.val + 1)) <<< np.val
  (low ||| high).truncate 7

/--
  Per-channel Pixel Barrier encoding: XOR 7-bit plaintext `d` with mask `m`,
  rotate left by `r ∈ Fin 7`, and insert `noiseBit` at position `np ∈ Fin 8`.
-/
def encodeChannel (d m : BitVec 7) (r : Fin 7) (np : Fin 8) (noiseBit : Bool) : BitVec 8 :=
  insertBit (rotate7 (d ^^^ m) r) noiseBit np

/--
  Per-channel Pixel Barrier decoding: extract the 7 data bits around `np ∈ Fin 8`,
  inverse-rotate by `r ∈ Fin 7`, and XOR with mask `m`.
-/
def decodeChannel (v : BitVec 8) (m : BitVec 7) (r : Fin 7) (np : Fin 8) : BitVec 7 :=
  unrotate7 (extractBits v np) r ^^^ m

/-! ## Round-Trip and Bijection Lemmas -/

/-- `unrotate7` is the left inverse of `rotate7` on all `128 × 7 = 896` inputs. -/
theorem unrotate7_rotate7 : ∀ (x : BitVec 7) (r : Fin 7), unrotate7 (rotate7 x r) r = x := by
  decide

/-- `rotate7` is the right inverse of `unrotate7` on all `128 × 7 = 896` inputs. -/
theorem rotate7_unrotate7 : ∀ (x : BitVec 7) (r : Fin 7), rotate7 (unrotate7 x r) r = x := by
  decide

/-- `extractBits` recovers the exact 7-bit payload inserted by `insertBit` (`128 × 2 × 8 = 2048` cases). -/
theorem extract_insert_id :
    ∀ (d7 : BitVec 7) (noiseBit : Bool) (np : Fin 8),
      extractBits (insertBit d7 noiseBit np) np = d7 := by
  decide

/-- `insertBit` places `noiseBit` at bit index `np.val` (`128 × 2 × 8 = 2048` cases). -/
theorem insert_getLsbD_np :
    ∀ (d7 : BitVec 7) (noiseBit : Bool) (np : Fin 8),
      (insertBit d7 noiseBit np).getLsbD np.val = noiseBit := by
  decide

/-- `insertBit` after `extractBits` and bit-at-`np` lookup reconstructs any byte `v : BitVec 8` (`256 × 8 = 2048` cases). -/
theorem insert_extract_id :
    ∀ (v : BitVec 8) (np : Fin 8),
      insertBit (extractBits v np) (v.getLsbD np.val) np = v := by
  decide

/-- Self-inverse property of 7-bit XOR: `(d ^^^ m) ^^^ m = d`. -/
theorem xor7_cancel_right (d m : BitVec 7) : (d ^^^ m) ^^^ m = d := by
  rw [BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero]

/-- Self-inverse property of 7-bit XOR: `d ^^^ (x ^^^ d) = x`. -/
theorem xor7_cancel_left (x d : BitVec 7) : d ^^^ (x ^^^ d) = x := by
  rw [BitVec.xor_comm x d, ← BitVec.xor_assoc, BitVec.xor_self, BitVec.zero_xor]

/-- Self-inverse property of 7-bit XOR: `(d ^^^ m) ^^^ d = m`. -/
theorem xor7_cancel_mid (d m : BitVec 7) : (d ^^^ m) ^^^ d = m := by
  rw [BitVec.xor_comm d m, BitVec.xor_assoc, BitVec.xor_self, BitVec.xor_zero]

/--
  Channel decode-after-encode round-trip theorem: for every plaintext `d`, mask `m`,
  rotation `r`, noise position `np`, and noise bit `noiseBit`, decoding the encoded byte
  recovers `d` exactly.
-/
theorem decode_encode_id (d m : BitVec 7) (r : Fin 7) (np : Fin 8) (noiseBit : Bool) :
    decodeChannel (encodeChannel d m r np noiseBit) m r np = d := by
  unfold decodeChannel encodeChannel
  rw [extract_insert_id, unrotate7_rotate7, xor7_cancel_right]

/--
  Noise-bit preservation theorem: the bit at position `np.val` of `encodeChannel d m r np noiseBit`
  equals `noiseBit`.
-/
theorem encode_getLsbD_np (d m : BitVec 7) (r : Fin 7) (np : Fin 8) (noiseBit : Bool) :
    (encodeChannel d m r np noiseBit).getLsbD np.val = noiseBit := by
  unfold encodeChannel
  exact insert_getLsbD_np (rotate7 (d ^^^ m) r) noiseBit np

/--
  Channel encode-after-decode round-trip theorem: for every observed byte `v`, mask `m`,
  rotation `r`, and noise position `np`, re-encoding `decodeChannel v m r np` with the
  observed noise bit `v.getLsbD np.val` reproduces `v` exactly.
-/
theorem encode_decode_id (v : BitVec 8) (m : BitVec 7) (r : Fin 7) (np : Fin 8) :
    encodeChannel (decodeChannel v m r np) m r np (v.getLsbD np.val) = v := by
  unfold encodeChannel decodeChannel
  rw [xor7_cancel_right, rotate7_unrotate7, insert_extract_id]

/-! ## Proof 1: Information-Theoretic Barrier -/

/--
  Proof 1 Bijection (Left Inverse): for any fixed hash configuration `(m, r, np)`,
  the map `(d, noiseBit) ↦ encodeChannel d m r np noiseBit` from `BitVec 7 × Bool` (256 pairs)
  to `BitVec 8` (256 byte values) has explicit left inverse
  `v ↦ (decodeChannel v m r np, v.getLsbD np.val)`.
-/
theorem proof1_encode_bijection_left_inv (m : BitVec 7) (r : Fin 7) (np : Fin 8)
    (d : BitVec 7) (noiseBit : Bool) :
    (decodeChannel (encodeChannel d m r np noiseBit) m r np,
     (encodeChannel d m r np noiseBit).getLsbD np.val) = (d, noiseBit) := by
  rw [decode_encode_id, encode_getLsbD_np]

/--
  Proof 1 Bijection (Right Inverse / Surjectivity): for any fixed hash configuration `(m, r, np)`
  and any observed byte `v : BitVec 8`, the pair `(decodeChannel v m r np, v.getLsbD np.val)`
  maps onto `v`. Because `BitVec 7 × Bool` and `BitVec 8` both have cardinality 256 and the
  mapping is a bijection for every `(m, r, np)`, uniform `(d, noiseBit)` induces the uniform
  distribution `P(v | h) = 1/256` independent of `h = (m, r, np)`.
-/
theorem proof1_encode_bijection_right_inv (m : BitVec 7) (r : Fin 7) (np : Fin 8) (v : BitVec 8) :
    encodeChannel (decodeChannel v m r np) m r np (v.getLsbD np.val) = v :=
  encode_decode_id v m r np

/--
  Proof 1 Compatibility Formula: for every observed byte `v`, every candidate configuration
  `(m, r, np)`, and container noise bit `v.getLsbD np.val`, there exists a unique 7-bit
  plaintext `d` producing `v`.
-/
theorem proof1_unique_plaintext_for_observation (v : BitVec 8) (m : BitVec 7) (r : Fin 7) (np : Fin 8) :
    encodeChannel (decodeChannel v m r np) m r np (v.getLsbD np.val) = v ∧
    ∀ d' : BitVec 7, encodeChannel d' m r np (v.getLsbD np.val) = v → d' = decodeChannel v m r np := by
  refine ⟨encode_decode_id v m r np, ?_⟩
  intro d' hd'
  have h := congrArg (fun b => decodeChannel b m r np) hd'
  rw [decode_encode_id] at h
  exact h

/--
  Proof 1 Fixed-Plaintext Two-Outcome Property: for fixed `(d, m, r, np)`, the two noise-bit
  outcomes `noiseBit = false` and `noiseBit = true` produce distinct bytes in `BitVec 8`
  that carry identical 7-bit extracted data.
-/
theorem proof1_fixed_plaintext_two_outcomes (d m : BitVec 7) (r : Fin 7) (np : Fin 8) :
    encodeChannel d m r np false ≠ encodeChannel d m r np true ∧
    extractBits (encodeChannel d m r np false) np = extractBits (encodeChannel d m r np true) np := by
  refine ⟨?_, ?_⟩
  · intro heq
    have hbit := congrArg (fun v => v.getLsbD np.val) heq
    rw [encode_getLsbD_np, encode_getLsbD_np] at hbit
    contradiction
  · unfold encodeChannel
    rw [extract_insert_id, extract_insert_id]

/-! ## Proof 2: Per-Bit XOR KPA Resistance -/

/--
  Candidate 7-bit XOR mask for observed channel byte `v`, known plaintext `d`,
  candidate noise position `np`, and candidate rotation `r`:
  `m = rotate⁻¹(extract(v, np), r) ⊕ d`.
-/
def candidateMask (v : BitVec 8) (d : BitVec 7) (np : Fin 8) (r : Fin 7) : BitVec 7 :=
  unrotate7 (extractBits v np) r ^^^ d

/--
  Proof 2 (Existence): for every known 7-bit plaintext `d`, observed channel byte `v`,
  candidate noise position `np ∈ Fin 8`, and candidate rotation `r ∈ Fin 7`, encoding `d`
  with `candidateMask v d np r` reproduces `v` exactly.
-/
theorem candidateMask_consistent (v : BitVec 8) (d : BitVec 7) (np : Fin 8) (r : Fin 7) :
    encodeChannel d (candidateMask v d np r) r np (v.getLsbD np.val) = v := by
  unfold encodeChannel candidateMask
  rw [xor7_cancel_left, rotate7_unrotate7, insert_extract_id]

/--
  Proof 2 (Uniqueness): any 7-bit mask `m'` whose encoding of `d` at `(r, np)` produces `v`
  is necessarily equal to `candidateMask v d np r`.
-/
theorem candidateMask_unique (v : BitVec 8) (d m' : BitVec 7) (np : Fin 8) (r : Fin 7)
    (h : encodeChannel d m' r np (v.getLsbD np.val) = v) :
    m' = candidateMask v d np r := by
  unfold encodeChannel at h
  have hex := congrArg (fun b => extractBits b np) h
  rw [extract_insert_id] at hex
  have hunrot := congrArg (fun x => unrotate7 x r) hex
  rw [unrotate7_rotate7] at hunrot
  unfold candidateMask
  rw [← hunrot, xor7_cancel_mid]

/--
  Proof 2 (Full Exists-Unique Theorem): for every `d ∈ BitVec 7`, `v ∈ BitVec 8`,
  `np ∈ Fin 8`, and `r ∈ Fin 7`, there exists a unique 7-bit mask `m` consistent with `v`.
  All `8 × 7 = 56` candidate `(np, r)` pairs without CCA (and all `7` candidate rotations
  with CCA) admit a unique valid mask.
-/
theorem proof2_exists_unique_mask (d : BitVec 7) (v : BitVec 8) (np : Fin 8) (r : Fin 7) :
    encodeChannel d (candidateMask v d np r) r np (v.getLsbD np.val) = v ∧
    ∀ m' : BitVec 7, encodeChannel d m' r np (v.getLsbD np.val) = v → m' = candidateMask v d np r :=
  ⟨candidateMask_consistent v d np r, fun m' hm' => candidateMask_unique v d m' np r hm'⟩

/--
  Proof 2 Corollary (`startPixel` Indistinguishability Under KPA and CCA):
  For any container size `totalPixels > 0`, any candidate starting offset `startPixel`,
  any pixel step `p`, any observed channel byte `v` at `(startPixel + p) % totalPixels`,
  any known plaintext `d`, and even with CCA-revealed noise position `np`, every candidate
  rotation `r ∈ Fin 7` yields a valid `(d, candidateMask v d np r)` pair consistent with `v`.
  Consequently, known plaintext combined with CCA noise-position revelation provides zero
  elimination predicate on candidate `startPixel` offsets.
-/
theorem proof2_corollary_startPixel_indistinguishable
    (totalPixels startPixel p : Nat) (obs : Nat → BitVec 8)
    (d : BitVec 7) (np : Fin 8) (r : Fin 7) :
    let linearIdx := (startPixel + p) % totalPixels
    let v := obs linearIdx
    encodeChannel d (candidateMask v d np r) r np (v.getLsbD np.val) = v := by
  dsimp only
  exact candidateMask_consistent (obs ((startPixel + p) % totalPixels)) d np r

/-- Per-pixel candidate pair counts: `8 * 7 = 56` without CCA and `7` under CCA. -/
theorem proof2_candidate_counts : 8 * 7 = 56 := rfl

/--
  Exact semantic per-pixel configuration count before CCA:
  `8` noise positions × `7` rotations × `2^56` channelXOR masks = `56 * 2^56`.
-/
def pixelSemanticConfigs : Nat := 8 * 7 * 2 ^ 56

/--
  Exact semantic per-pixel `dataSeed` configuration count after CCA reveals `noisePos`:
  `7` rotations × `2^56` channelXOR masks = `7 * 2^56`.
-/
def pixelPostCCAConfigs : Nat := 7 * 2 ^ 56

/--
  Nominal 62-bit field width (`3` noisePos bits + `3` rotation bits + `56` channelXOR bits = `62` bits).
-/
def pixelBitFieldSpace : Nat := 2 ^ 62

/--
  Exact integer brackets for the per-pixel semantic configuration spaces (`SCIENCE.md § 1.2.3`,
  `SECURITY.md § 3`):
  - Pre-CCA semantic configurations: `8 * 7 * 2^56 = 4035225266123964416`, satisfying
    `2^61 < pixelSemanticConfigs < 2^62` (`log₂(56 · 2^56) ≈ 61.807` bits, within the 62-bit field `2^62`).
  - Post-CCA semantic configurations: `7 * 2^56 = 504403158265495552`, satisfying
    `2^58 < pixelPostCCAConfigs < 2^59` (`log₂(7 · 2^56) ≈ 58.807` bits, within the 59-bit field `2^59`),
    with `pixelSemanticConfigs = 8 * pixelPostCCAConfigs`.
-/
theorem pixel_semantic_config_bounds :
    pixelSemanticConfigs = 56 * 2 ^ 56 ∧
    pixelSemanticConfigs = 4035225266123964416 ∧
    2 ^ 61 < pixelSemanticConfigs ∧ pixelSemanticConfigs < 2 ^ 62 ∧
    pixelPostCCAConfigs = 7 * 2 ^ 56 ∧
    pixelPostCCAConfigs = 504403158265495552 ∧
    2 ^ 58 < pixelPostCCAConfigs ∧ pixelPostCCAConfigs < 2 ^ 59 ∧
    pixelSemanticConfigs = 8 * pixelPostCCAConfigs ∧
    pixelBitFieldSpace = 4611686018427387904 := by decide

/-! ## Proof 6: CCA Leak Upper Bound and Early-Stop Query Budget -/

/-- Flip bit `b ∈ Fin 8` of an 8-bit channel byte `v`. -/
def flipBit8 (v : BitVec 8) (b : Fin 8) : BitVec 8 :=
  v ^^^ ((1 : BitVec 8) <<< b.val)

/--
  Proof 6 (Steps 1 and 2 — Noise-Bit Flip Invariance):
  Flipping bit `b` in channel byte `v` preserves the 7 extracted data bits
  if and only if `b` is the noise position `np` (`256 × 8 × 8 = 16,384` cases).
-/
theorem flipBit8_extractBits_eq_iff :
    ∀ (v : BitVec 8) (np b : Fin 8),
      (extractBits (flipBit8 v b) np == extractBits v np) = (b == np) := by
  decide

/--
  Propositional equivalence for Proof 6: flipping bit `b` leaves `extractBits` unchanged
  if and only if `b = np`.
-/
theorem flipBit8_extractBits_eq (v : BitVec 8) (np b : Fin 8) :
    extractBits (flipBit8 v b) np = extractBits v np ↔ b = np := by
  have h := flipBit8_extractBits_eq_iff v np b
  constructor
  · intro heq
    have hbeq : (extractBits (flipBit8 v b) np == extractBits v np) = true := beq_iff_eq.mpr heq
    rw [hbeq] at h
    exact beq_iff_eq.mp h.symm
  · intro hbn
    have hbeq : (b == np) = true := beq_iff_eq.mpr hbn
    rw [hbeq] at h
    exact beq_iff_eq.mp h

/--
  Proof 6 Decoded-Channel Invariance Theorem: flipping bit `b` of channel byte `v`
  preserves the decoded 7-bit plaintext `decodeChannel` (so the full-capacity MAC accepts)
  if and only if `b = np`.
-/
theorem flipBit8_decodeChannel_eq_iff (v : BitVec 8) (m : BitVec 7) (r : Fin 7) (np b : Fin 8) :
    decodeChannel (flipBit8 v b) m r np = decodeChannel v m r np ↔ b = np := by
  constructor
  · intro hdec
    unfold decodeChannel at hdec
    have h1 := congrArg (fun x => x ^^^ m) hdec
    rw [xor7_cancel_right, xor7_cancel_right] at h1
    have h2 := congrArg (fun x => rotate7 x r) h1
    rw [rotate7_unrotate7, rotate7_unrotate7] at h2
    exact (flipBit8_extractBits_eq v np b).mp h2
  · intro hbn
    unfold decodeChannel
    rw [(flipBit8_extractBits_eq v np b).mpr hbn]

/--
  Number of oracle queries consumed when testing bit positions `0, 1, ..., 6` sequentially
  and stopping at the first accepted flip (inferring `np = 7` after 7 rejections):
  `1, 2, 3, 4, 5, 6, 7, 7` for `np = 0, 1, 2, 3, 4, 5, 6, 7`.
-/
def earlyStopQueries (np : Fin 8) : Nat :=
  if np.val < 7 then np.val + 1 else 7

/-- Sum of `earlyStopQueries np` over all 8 equiprobable noise positions is `35` (`35 / 8 = 4.375`). -/
theorem earlyStopQueries_sum_eq_35 :
    earlyStopQueries ⟨0, by decide⟩ +
    earlyStopQueries ⟨1, by decide⟩ +
    earlyStopQueries ⟨2, by decide⟩ +
    earlyStopQueries ⟨3, by decide⟩ +
    earlyStopQueries ⟨4, by decide⟩ +
    earlyStopQueries ⟨5, by decide⟩ +
    earlyStopQueries ⟨6, by decide⟩ +
    earlyStopQueries ⟨7, by decide⟩ = 35 := by decide

/--
  Across a Mode 1 minimum container (`P = 1225` pixels), the expected early-stop query
  budget numerator over 8 outcomes is `35 * 1225 = 42875` (`42875 / 8 = 5359` with remainder `3`,
  i.e., `5359.375` queries vs `8 * 1225 = 9800` exhaustive queries).
-/
theorem earlyStopQueries_mode1_budget :
    35 * 1225 = 42875 ∧
    42875 / 8 = 5359 ∧
    42875 % 8 = 3 ∧
    8 * 1225 = 9800 := by decide

/-! ## Proof 7: Bias Neutralization -/

/--
  Proof 7 (Rotation-Mask Convolution Bijection): for every plaintext `d : BitVec 7`,
  every candidate rotation `r : Fin 7`, and every observed 7-bit pre-insertion value `y : BitVec 7`,
  `m = unrotate7 y r ^^^ d` is the unique mask satisfying `rotate7 (d ^^^ m) r = y`.
-/
theorem proof7_rotation_mask_bijection (d y : BitVec 7) (r : Fin 7) :
    rotate7 (d ^^^ (unrotate7 y r ^^^ d)) r = y ∧
    ∀ m : BitVec 7, rotate7 (d ^^^ m) r = y → m = unrotate7 y r ^^^ d := by
  refine ⟨?_, ?_⟩
  · rw [xor7_cancel_left, rotate7_unrotate7]
  · intro m hm
    have h1 := congrArg (fun x => unrotate7 x r) hm
    rw [unrotate7_rotate7] at h1
    rw [← h1, xor7_cancel_mid]

/-! ## `noiseFold3` Full 64-Bit Single-Bit Flip Sensitivity (`noisepos.go:9-16`) -/

/--
  Bit-exact model of `noiseFold3` in `noisepos.go:9-16`, reducing a 64-bit
  mixed hash word `w` (`noiseMix(word0, word1)`) to a 3-bit noise position `0..7`.
-/
def noiseFold3 (w : BitVec 64) : BitVec 3 :=
  let w1 := w ^^^ (w >>> 32)
  let w2 := w1 ^^^ (w1 >>> 16)
  let w3 := w2 ^^^ (w2 >>> 8)
  let w4 := w3 ^^^ (w3 >>> 4)
  let n := w4 &&& 15#64
  ((n ^^^ (n >>> 3)) &&& 7#64).truncate 3

/-- `noiseFold3` is GF(2)-linear (`noiseFold3 (a ^^^ b) = noiseFold3 a ^^^ noiseFold3 b`). -/
theorem noiseFold3_xor_hom (a b : BitVec 64) :
    noiseFold3 (a ^^^ b) = noiseFold3 a ^^^ noiseFold3 b := by
  unfold noiseFold3
  bv_decide

/--
  Every single basis bit `1 <<< i` (`i ∈ Fin 64`) maps to a nonzero 3-bit weight
  (`1#3`, `2#3`, or `4#3`), with 32, 16, and 16 input bits reaching output bits
  0, 1, and 2 respectively (`noisepos.go:6-8`).
-/
theorem noiseFold3_basis_nonzero :
    (∀ i : Fin 64, noiseFold3 (1#64 <<< i.val) ≠ 0#3) ∧
    ((List.finRange 64).filter (fun i => noiseFold3 (1#64 <<< i.val) == 1#3)).length = 32 ∧
    ((List.finRange 64).filter (fun i => noiseFold3 (1#64 <<< i.val) == 2#3)).length = 16 ∧
    ((List.finRange 64).filter (fun i => noiseFold3 (1#64 <<< i.val) == 4#3)).length = 16 := by
  decide

/-- Helper lemma: in `BitVec 3`, `x ^^^ y = x` implies `y = 0#3`. -/
theorem bitvec3_xor_eq_self (x y : BitVec 3) (h : x ^^^ y = x) : y = 0#3 := by
  bv_decide

/--
  Full 64-bit single-bit flip sensitivity of `noiseFold3`: flipping any bit `i ∈ Fin 64`
  of the 64-bit `noiseMix` word strictly changes the 3-bit `noisePos` output.
-/
theorem noiseFold3_single_bit_flip (w : BitVec 64) (i : Fin 64) :
    noiseFold3 (w ^^^ (1#64 <<< i.val)) ≠ noiseFold3 w := by
  intro h
  rw [noiseFold3_xor_hom] at h
  have h0 : noiseFold3 (1#64 <<< i.val) = 0#3 := bitvec3_xor_eq_self _ _ h
  exact noiseFold3_basis_nonzero.1 i h0

/-! ## `dataHash % 7` vs `dataHash >> 3` Full `(rot, mask56)` Realizability (`process_generic.go:69-70`) -/

/--
  In `process_generic.go:69-70`, a 64-bit `dataHash` word is decomposed into
  `low3` (bits `0..2`, `< 8`), `mask56 = (dataHash >> 3) & (2^56 - 1)` (bits `3..58`),
  and `top5 = dataHash >> 59` (bits `59..63`, `< 32`), so
  `dataHash = low3 + 8 * mask56 + 2^59 * top5`.
  Since `8 % 7 = 1` and `2^59 % 7 = 4`, `dataHash % 7 = (low3 + (mask56 % 7) + 4 * top5) % 7`.
-/
theorem dataHash_mod7_decomp (low3 m top5 : Nat) :
    (low3 + 8 * m + (2 ^ 59) * top5) % 7 = (low3 + (m % 7) + 4 * top5) % 7 := by
  omega

/--
  Count of `(low3, top5) ∈ Fin 8 × Fin 32` (`256` pairs of the 8 non-mask bits in `dataHash`)
  that produce target rotation `r : Fin 7` for a given `mask56` residue `mMod7 : Fin 7`.
-/
def rotResidueCount (mMod7 r : Fin 7) : Nat :=
  (List.finRange 8).foldl (fun acc (low3 : Fin 8) =>
    acc + ((List.finRange 32).filter (fun (top5 : Fin 32) =>
      (low3.val + mMod7.val + 4 * top5.val) % 7 == r.val)).length) 0

/--
  For every 56-bit mask residue `mMod7 : Fin 7` and every target rotation `r : Fin 7`,
  between `36` and `37` of the `256` non-mask bit assignments `(low3, top5) ∈ Fin 8 × Fin 32`
  realize `rot = r` (`256 = 36 * 7 + 4`), proving that all `7 × 2^56 = 504,403,158,265,495,552`
  semantic `(rot, mask56)` configurations are realizable from `dataHash`.
-/
theorem dataHash_rot_mask_realizable :
    ∀ (mMod7 r : Fin 7),
      rotResidueCount mMod7 r ≥ 36 ∧
      (rotResidueCount mMod7 r = 36 ∨ rotResidueCount mMod7 r = 37) ∧
      ∃ (low3 : Fin 8) (top5 : Fin 32),
        (low3.val + mMod7.val + 4 * top5.val) % 7 = r.val := by
  decide

end ITB.PixelBarrier
