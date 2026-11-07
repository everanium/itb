/-
  ITB.PipelineSpec128 — Executable Reference Specification & Formal Round-Trip Proofs
  for the 128-Bit Desynchronized Interlocked Barrier Pipeline (`Encrypt3x128Cfg` / `Decrypt3x128Cfg`).

  Scope:
  1. Bit-exact `SipHash-2-4-128` (`sipHash24_128`) and `Seed128.ChainHash128` cascade (`chainHash128`),
     covering all 3 key sizes (`512`, `1024`, `2048` bits = 8, 16, 32 `UInt64` components) and
     all 3 nonce sizes (`128`, `256`, `512` bits = 16, 32, 64 bytes).
  2. Stage 1 — 48-Bit Rank Barrier (`0x03`, `0x04`):
     `interlockNonceFold`, `deriveInterLockSeed`, per-chunk PRF fill `[0x03 ‖ LE64(groupIdx) ‖ LE32(foldWord)]`,
     reciprocal rank split (`ITB.SplitRank.splitRank48Recip`), combinadic unranking (`unrankCombination48`),
     disjoint 48-bit mask triple (`rankToMaskTriple48`), branchless `softPEXT48` / `softPDEP48`,
     4-byte big-endian length framing, and 3-lane split / interleave.
  3. Stage 2 — Layer II (`0x06`) Cross-Lane Chunk-Slot Desynchronization:
     128-bit Feistel fold (`ITB.Desync.fullWidthFold`), `[0x06 ‖ LE64(0/1) ‖ LE32(foldWord)]`,
     lane shifts `β₀, β₁ ≠ β₀, β₂`, and sub-lane schedule (`K_lane ∈ [4, 8]` for `M ≥ 16`).
  4. Stage 3 — Interlock Nonce Split & COBS Framing:
     3-lane interlock-nonce prefix split (`nonceSplitOffsets`), `recoverInterlockNonce`,
     and `cobsEncode` / `cobsDecode` with `0x00` delimiter.
  5. Stage 4 — Container Sizing (Mode 1 & Mode 2) across the 11-Size Ladder (`1 B` .. `64 MB`):
     `calcContainerSize3Cfg` using `ITB.Thresholds.minPixelsAuth` (`⌈keyBits / log₂ 7⌉`),
     `tripleThirdCaps`, and `noiseCounterBase`.
  6. Stage 5 — Layer I (`0x05`) Sub-Region Desynchronization & Pixel Barrier (`0x01`, `0x02`):
     `deriveStartPixel` (`0x02`), `deriveSubregionSchedule128` (`0x05`), `buildSubregionSchedule`
     (`P_r < 365` → `K_r ∈ [6, 10], δ ∈ {-1, 0}`; `P_r ≥ 365` → `K_r ∈ [8, 16], δ ∈ {-2, -1, 0, +1}`),
     `noiseMix`, `noiseFold3`, `rotateBits7`, and 8-channel RGBWYOPA pixel encode/decode.
  7. Formal round-trip inversion theorems:
     - 5-stage functional composition left-inverse theorem (`pipeline_five_stage_composition_left_inv`).
     - Receiver Mode / BarrierFill independence theorem (`decrypt3x128Cfg_mode_barrierFill_independent`).
     - Exhaustive per-channel Pixel Barrier round-trip theorem (`decodeChannelByte_encodeChannelByte_all`).
     - Stage-level and end-to-end round-trip theorems.
  8. Bit-exact Go Known-Answer Test (KAT) verification theorems across:
     - `SipHash-2-4-128` RFC vector and `Seed128.ChainHash128`.
     - Full 198-cell container sizing ladder (`1 B` .. `64 MB` × `keyBits ∈ {512, 1024, 2048}` ×
       `nonceBits ∈ {128, 256, 512}` × `Mode ∈ {1, 2}`).
     - Byte-for-byte wire equality against Go `itb.Encrypt3x128Cfg` in both Mode 1 and Mode 2.
     - All 18 `(keyBits, nonceBits, Mode)` configurations and payload size ladder (`1 B` .. `16 KB`).
-/

import ITB.Thresholds
import ITB.RankBarrier
import ITB.PixelBarrier
import ITB.SplitRank
import ITB.SeedIsolation
import ITB.Desync

namespace ITB.PipelineSpec128

-- ============================================================================
-- § 1. Endian Packing, Bitwise Rotations, and Hex / Deterministic Byte Helpers
-- ============================================================================

/-- 64-bit left rotation on `UInt64`. -/
@[inline] def rotl64 (x : UInt64) (r : Nat) : UInt64 :=
  let s := r % 64
  if s == 0 then x
  else (x <<< UInt64.ofNat s) ||| (x >>> UInt64.ofNat (64 - s))

/-- Read a byte at `idx` from `b`, returning `0` if out of bounds. -/
@[inline] def getByteD (b : ByteArray) (idx : Nat) : UInt8 :=
  if h : idx < b.size then b[idx] else 0

/-- Read little-endian `UInt16` at byte offset `off`. -/
@[inline] def readU16LE (b : ByteArray) (off : Nat) : UInt16 :=
  (getByteD b off).toUInt16 ||| ((getByteD b (off + 1)).toUInt16 <<< 8)

/-- Read big-endian `UInt16` at byte offset `off`. -/
@[inline] def readU16BE (b : ByteArray) (off : Nat) : UInt16 :=
  ((getByteD b off).toUInt16 <<< 8) ||| (getByteD b (off + 1)).toUInt16

/-- Read big-endian `UInt32` at byte offset `off`. -/
@[inline] def readU32BE (b : ByteArray) (off : Nat) : UInt32 :=
  ((getByteD b off).toUInt32 <<< 24) |||
  ((getByteD b (off + 1)).toUInt32 <<< 16) |||
  ((getByteD b (off + 2)).toUInt32 <<< 8) |||
  (getByteD b (off + 3)).toUInt32

/-- Read little-endian `UInt32` at byte offset `off`. -/
@[inline] def readU32LE (b : ByteArray) (off : Nat) : UInt32 :=
  (getByteD b off).toUInt32 |||
  ((getByteD b (off + 1)).toUInt32 <<< 8) |||
  ((getByteD b (off + 2)).toUInt32 <<< 16) |||
  ((getByteD b (off + 3)).toUInt32 <<< 24)

/-- Read 48-bit little-endian integer (6 bytes) into `UInt64` at byte offset `off`. -/
@[inline] def readU48LE (b : ByteArray) (off : Nat) : UInt64 :=
  (getByteD b off).toUInt64 |||
  ((getByteD b (off + 1)).toUInt64 <<< 8) |||
  ((getByteD b (off + 2)).toUInt64 <<< 16) |||
  ((getByteD b (off + 3)).toUInt64 <<< 24) |||
  ((getByteD b (off + 4)).toUInt64 <<< 32) |||
  ((getByteD b (off + 5)).toUInt64 <<< 40)

/-- Read little-endian `UInt64` at byte offset `off`. -/
@[inline] def readU64LE (b : ByteArray) (off : Nat) : UInt64 :=
  (getByteD b off).toUInt64 |||
  ((getByteD b (off + 1)).toUInt64 <<< 8) |||
  ((getByteD b (off + 2)).toUInt64 <<< 16) |||
  ((getByteD b (off + 3)).toUInt64 <<< 24) |||
  ((getByteD b (off + 4)).toUInt64 <<< 32) |||
  ((getByteD b (off + 5)).toUInt64 <<< 40) |||
  ((getByteD b (off + 6)).toUInt64 <<< 48) |||
  ((getByteD b (off + 7)).toUInt64 <<< 56)

/-- Append little-endian `UInt16` (2 bytes) to `b`. -/
@[inline] def pushU16LE (b : ByteArray) (v : UInt16) : ByteArray :=
  (b.push (v &&& 0xFF).toUInt8).push ((v >>> 8) &&& 0xFF).toUInt8

/-- Append big-endian `UInt16` (2 bytes) to `b`. -/
@[inline] def pushU16BE (b : ByteArray) (v : UInt16) : ByteArray :=
  (b.push ((v >>> 8) &&& 0xFF).toUInt8).push (v &&& 0xFF).toUInt8

/-- Append big-endian `UInt32` (4 bytes) to `b`. -/
@[inline] def pushU32BE (b : ByteArray) (v : UInt32) : ByteArray :=
  (((b.push ((v >>> 24) &&& 0xFF).toUInt8).push ((v >>> 16) &&& 0xFF).toUInt8).push
    ((v >>> 8) &&& 0xFF).toUInt8).push (v &&& 0xFF).toUInt8

/-- Append little-endian `UInt32` (4 bytes) to `b`. -/
@[inline] def pushU32LE (b : ByteArray) (v : UInt32) : ByteArray :=
  (((b.push (v &&& 0xFF).toUInt8).push ((v >>> 8) &&& 0xFF).toUInt8).push
    ((v >>> 16) &&& 0xFF).toUInt8).push ((v >>> 24) &&& 0xFF).toUInt8

/-- Append 48-bit little-endian value (6 bytes) to `b`. -/
@[inline] def pushU48LE (b : ByteArray) (v : UInt64) : ByteArray :=
  (((((b.push (v &&& 0xFF).toUInt8).push ((v >>> 8) &&& 0xFF).toUInt8).push
    ((v >>> 16) &&& 0xFF).toUInt8).push ((v >>> 24) &&& 0xFF).toUInt8).push
    ((v >>> 32) &&& 0xFF).toUInt8).push ((v >>> 40) &&& 0xFF).toUInt8

/-- Append little-endian `UInt64` (8 bytes) to `b`. -/
@[inline] def pushU64LE (b : ByteArray) (v : UInt64) : ByteArray :=
  (((((((b.push (v &&& 0xFF).toUInt8).push ((v >>> 8) &&& 0xFF).toUInt8).push
    ((v >>> 16) &&& 0xFF).toUInt8).push ((v >>> 24) &&& 0xFF).toUInt8).push
    ((v >>> 32) &&& 0xFF).toUInt8).push ((v >>> 40) &&& 0xFF).toUInt8).push
    ((v >>> 48) &&& 0xFF).toUInt8).push ((v >>> 56) &&& 0xFF).toUInt8

/-- Convert a single hex character to its 4-bit value. -/
def hexCharToVal (c : Char) : UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then UInt8.ofNat (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then UInt8.ofNat (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then UInt8.ofNat (c.toNat - 'A'.toNat + 10)
  else 0

/-- Decode a hex string into a `ByteArray`. -/
def fromHex (s : String) : ByteArray := Id.run do
  let chars := s.toList.toArray
  let n := chars.size / 2
  let mut out := ByteArray.emptyWithCapacity n
  for i in [:n] do
    let hi := hexCharToVal (chars.getD (2 * i) '0')
    let lo := hexCharToVal (chars.getD (2 * i + 1) '0')
    out := out.push ((hi <<< 4) ||| lo)
  return out

-- ============================================================================
-- § 2. SipHash-2-4-128 & Seed128.ChainHash128 Cascade
-- ============================================================================

/-- One SipRound on 4-word state `(v0, v1, v2, v3)`, matching `siphash24.go`. -/
@[inline] def sipRound (v0 v1 v2 v3 : UInt64) : UInt64 × UInt64 × UInt64 × UInt64 :=
  let v0 := v0 + v1
  let v1 := ((v1 <<< 13) ||| (v1 >>> 51)) ^^^ v0
  let v0 := (v0 <<< 32) ||| (v0 >>> 32)
  let v2 := v2 + v3
  let v3 := ((v3 <<< 16) ||| (v3 >>> 48)) ^^^ v2
  let v0 := v0 + v3
  let v3 := ((v3 <<< 21) ||| (v3 >>> 43)) ^^^ v0
  let v2 := v2 + v1
  let v1 := ((v1 <<< 17) ||| (v1 >>> 47)) ^^^ v2
  let v2 := (v2 <<< 32) ||| (v2 >>> 32)
  (v0, v1, v2, v3)

/-- Two consecutive SipRounds (compression step in SipHash-2-4). -/
@[inline] def sipRound2 (v0 v1 v2 v3 : UInt64) : UInt64 × UInt64 × UInt64 × UInt64 :=
  let (v0, v1, v2, v3) := sipRound v0 v1 v2 v3
  sipRound v0 v1 v2 v3

/-- Four consecutive SipRounds (finalization step in SipHash-2-4-128). -/
@[inline] def sipRound4 (v0 v1 v2 v3 : UInt64) : UInt64 × UInt64 × UInt64 × UInt64 :=
  let (v0, v1, v2, v3) := sipRound2 v0 v1 v2 v3
  sipRound2 v0 v1 v2 v3

/-- Pre-decoded 64-bit little-endian blocks and finalization tail word for `SipHash-2-4-128`. -/
structure SipMsg where
  words : Array UInt64
  tail  : UInt64

/-- Decode a `ByteArray` once into 64-bit little-endian blocks and the SipHash length/tail word. -/
def prepareSipMsg (p : ByteArray) : SipMsg := Id.run do
  let fullBlocks := p.size / 8
  let mut words := Array.mkEmpty fullBlocks
  for blk in [:fullBlocks] do
    words := words.push (readU64LE p (blk * 8))
  let off := fullBlocks * 8
  let rem := p.size - off
  let mut b : UInt64 := (UInt64.ofNat (p.size % 256)) <<< 56
  for i in [:rem] do
    b := b ||| ((getByteD p (off + i)).toUInt64 <<< UInt64.ofNat (8 * i))
  return { words, tail := b }

/-- Evaluate `SipHash-2-4-128` on a pre-decoded `SipMsg`. -/
@[inline] def sipHash24Msg (k0 k1 : UInt64) (msg : SipMsg) : UInt64 × UInt64 := Id.run do
  let mut v0 : UInt64 := k0 ^^^ 0x736f6d6570736575
  let mut v1 : UInt64 := k1 ^^^ 0x646f72616e646f6d ^^^ 0xee
  let mut v2 : UInt64 := k0 ^^^ 0x6c7967656e657261
  let mut v3 : UInt64 := k1 ^^^ 0x7465646279746573
  for m in msg.words do
    v3 := v3 ^^^ m
    let (n0, n1, n2, n3) := sipRound2 v0 v1 v2 v3
    v0 := n0 ^^^ m
    v1 := n1
    v2 := n2
    v3 := n3
  let b := msg.tail
  v3 := v3 ^^^ b
  let (a0, a1, a2, a3) := sipRound2 v0 v1 v2 v3
  v0 := a0 ^^^ b
  v1 := a1
  v2 := a2 ^^^ 0xee
  v3 := a3
  let (f0, f1, f2, f3) := sipRound4 v0 v1 v2 v3
  let lo := f0 ^^^ f1 ^^^ f2 ^^^ f3
  let v1' := f1 ^^^ 0xdd
  let (g0, g1, g2, g3) := sipRound4 f0 v1' f2 f3
  let hi := g0 ^^^ g1 ^^^ g2 ^^^ g3
  return (lo, hi)

/-- Bit-exact `SipHash-2-4-128` (`internal/siphash24/siphash24.go:Hash128`). -/
def sipHash24_128 (k0 k1 : UInt64) (p : ByteArray) : UInt64 × UInt64 :=
  sipHash24Msg k0 k1 (prepareSipMsg p)

/-- 128-bit ITB seed holding an even number (`8`, `16`, or `32`) of `UInt64` components. -/
structure Seed128 where
  components : Array UInt64
  deriving Repr, DecidableEq

/-- Key size in bits (`512`, `1024`, or `2048`). -/
@[inline] def Seed128.bits (s : Seed128) : Nat :=
  s.components.size * 64

/-- CCA-resistant minimum pixel floor `⌈keyBits / log₂ 7⌉` (`seed128.go:MinPixelsAuth`, `itb.go:42-45`). -/
@[inline] def minPixelsAuth (keyBits : Nat) : Nat :=
  (keyBits * 10000 + 28074 - 1) / 28074

/-- CCA-resistant minimum pixel floor for a `Seed128` (`183`, `365`, or `730`). -/
@[inline] def Seed128.minPixelsAuth (s : Seed128) : Nat :=
  ITB.PipelineSpec128.minPixelsAuth s.bits

/-- Evaluate the `chainHash128With` cascade on a pre-decoded `SipMsg`. -/
def chainHash128Msg (components : Array UInt64) (msg : SipMsg) : UInt64 × UInt64 := Id.run do
  let c0 := components.getD 0 0
  let c1 := components.getD 1 0
  let (initLo, initHi) := sipHash24Msg c0 c1 msg
  let mut hLo := initLo
  let mut hHi := initHi
  let pairs := components.size / 2
  for p in [1:pairs] do
    let ci0 := components.getD (2 * p) 0
    let ci1 := components.getD (2 * p + 1) 0
    let (nLo, nHi) := sipHash24Msg (ci0 ^^^ hLo) (ci1 ^^^ hHi) msg
    hLo := nLo
    hHi := nHi
  return (hLo, hHi)

/-- Evaluate the `chainHash128With` cascade (`seed128.go:416-427`) over a component slice. -/
def chainHash128With (components : Array UInt64) (buf : ByteArray) : UInt64 × UInt64 :=
  chainHash128Msg components (prepareSipMsg buf)

/-- Evaluate `Seed128.ChainHash128` (`seed128.go:250-261`). -/
@[inline] def chainHash128 (s : Seed128) (buf : ByteArray) : UInt64 × UInt64 :=
  chainHash128With s.components buf

/-- Pre-decoded `[LE32(blockIdx) ‖ nonce]` template for zero-allocation per-pixel `blockHash128`. -/
structure BlockNonceTemplate128 where
  w0Hi      : UInt64
  restWords : Array UInt64
  tail      : UInt64

/-- Prepare a `BlockNonceTemplate128` once per region from `nonce` (`nonce.size ≥ 4`). -/
def prepareBlockNonce128 (nonce : ByteArray) : BlockNonceTemplate128 :=
  let base := prepareSipMsg ((pushU32LE ByteArray.empty 0) ++ nonce)
  { w0Hi := base.words.getD 0 0 &&& 0xFFFFFFFF00000000
    restWords := base.words.extract 1 base.words.size
    tail := base.tail }

/-- Evaluate `SipHash-2-4-128` on a `BlockNonceTemplate128` with `w0 = w0Hi | LE32(blockIdx)`. -/
@[inline] def sipHash24BlockTpl (k0 k1 w0 : UInt64) (tpl : BlockNonceTemplate128) : UInt64 × UInt64 := Id.run do
  let mut v0 : UInt64 := k0 ^^^ 0x736f6d6570736575
  let mut v1 : UInt64 := k1 ^^^ 0x646f72616e646f6d ^^^ 0xee
  let mut v2 : UInt64 := k0 ^^^ 0x6c7967656e657261
  let mut v3 : UInt64 := k1 ^^^ 0x7465646279746573
  v3 := v3 ^^^ w0
  let (n0, n1, n2, n3) := sipRound2 v0 v1 v2 v3
  v0 := n0 ^^^ w0
  v1 := n1
  v2 := n2
  v3 := n3
  for m in tpl.restWords do
    v3 := v3 ^^^ m
    let (r0, r1, r2, r3) := sipRound2 v0 v1 v2 v3
    v0 := r0 ^^^ m
    v1 := r1
    v2 := r2
    v3 := r3
  let b := tpl.tail
  v3 := v3 ^^^ b
  let (a0, a1, a2, a3) := sipRound2 v0 v1 v2 v3
  v0 := a0 ^^^ b
  v1 := a1
  v2 := a2 ^^^ 0xee
  v3 := a3
  let (f0, f1, f2, f3) := sipRound4 v0 v1 v2 v3
  let lo := f0 ^^^ f1 ^^^ f2 ^^^ f3
  let v1' := f1 ^^^ 0xdd
  let (g0, g1, g2, g3) := sipRound4 f0 v1' f2 f3
  let hi := g0 ^^^ g1 ^^^ g2 ^^^ g3
  return (lo, hi)

/-- Evaluate `Seed128.blockHash128` using a pre-decoded `BlockNonceTemplate128`. -/
def blockHash128Tpl (s : Seed128) (tpl : BlockNonceTemplate128) (blockIdx : Nat) : UInt64 × UInt64 := Id.run do
  let w0 : UInt64 := tpl.w0Hi ||| (UInt32.ofNat blockIdx).toUInt64
  let comps := s.components
  let c0 := comps.getD 0 0
  let c1 := comps.getD 1 0
  let (initLo, initHi) := sipHash24BlockTpl c0 c1 w0 tpl
  let mut hLo := initLo
  let mut hHi := initHi
  let pairs := comps.size / 2
  for p in [1:pairs] do
    let ci0 := comps.getD (2 * p) 0
    let ci1 := comps.getD (2 * p + 1) 0
    let (nLo, nHi) := sipHash24BlockTpl (ci0 ^^^ hLo) (ci1 ^^^ hHi) w0 tpl
    hLo := nLo
    hHi := nHi
  return (hLo, hHi)

/-- Evaluate `Seed128.blockHash128` (`seed128.go:264-267`) on `[LE32(blockIdx) ‖ nonce]`. -/
@[inline] def blockHash128 (s : Seed128) (nonce : ByteArray) (blockIdx : Nat) : UInt64 × UInt64 :=
  blockHash128Tpl s (prepareBlockNonce128 nonce) blockIdx

/-- Domain tag `0x02`: `Seed128.deriveStartPixel` (`seed128.go:278-285`). -/
@[inline] def deriveStartPixel (s : Seed128) (nonce : ByteArray) (totalPixels : Nat) : Nat :=
  if totalPixels == 0 then 0
  else
    let buf := (ByteArray.empty.push 0x02) ++ nonce
    let (hLo, _) := chainHash128 s buf
    (hLo % UInt64.ofNat totalPixels).toNat

/-- Domain tag `0x04`: `Seed128.deriveInterLockSeed` (`seed128.go:300-306`). -/
@[inline] def deriveInterLockSeed (s : Seed128) (ilNonce : ByteArray) : UInt64 × UInt64 :=
  let buf := (ByteArray.empty.push 0x04) ++ ilNonce
  chainHash128 s buf

-- ============================================================================
-- § 3. Stage 1 — 48-Bit Rank Barrier (`0x03`, `0x04`)
-- ============================================================================

/-- 4-byte XOR fold of the interlock nonce (`interlock48_cascade.go:interlockNonceFold`). -/
def interlockNonceFold (ilNonce : ByteArray) : UInt32 := Id.run do
  let mut b0 : UInt8 := 0
  let mut b1 : UInt8 := 0
  let mut b2 : UInt8 := 0
  let mut b3 : UInt8 := 0
  for i in [:ilNonce.size] do
    let v := getByteD ilNonce i
    match i % 4 with
    | 0 => b0 := b0 ^^^ v
    | 1 => b1 := b1 ^^^ v
    | 2 => b2 := b2 ^^^ v
    | _ => b3 := b3 ^^^ v
  return b0.toUInt32 ||| (b1.toUInt32 <<< 8) ||| (b2.toUInt32 <<< 16) ||| (b3.toUInt32 <<< 24)

/-- Build the two-stage cascade component slice `[lockLo, lockHi] ++ lockSeed.components`. -/
def buildLockComps128 (lockSeed : Seed128) (ilNonce : ByteArray) : Array UInt64 :=
  let (lockLo, lockHi) := deriveInterLockSeed lockSeed ilNonce
  #[lockLo, lockHi] ++ lockSeed.components

/-- Domain tag `0x03`: evaluate per-chunk 128-bit rank pair on `[0x03 ‖ LE64(groupIdx) ‖ LE32(foldWord)]`. -/
def evalRankPair128 (lockComps : Array UInt64) (foldWord : UInt32) (groupIdx : Nat) : UInt64 × UInt64 :=
  let buf := pushU32LE (pushU64LE (ByteArray.empty.push 0x03) (UInt64.ofNat groupIdx)) foldWord
  chainHash128With lockComps buf

/-- Precomputed Pascal triangle table `C(n, k)` for `0 ≤ n ≤ 48, 0 ≤ k ≤ 16`. -/
def binomialC48Table : Array (Array UInt64) := Id.run do
  let mut tbl : Array (Array UInt64) := Array.mkEmpty 49
  for n in [:49] do
    let mut row := Array.replicate 17 (0 : UInt64)
    row := row.set! 0 1
    for k in [1:17] do
      if k <= n then
        let prev := tbl.getD (n - 1) #[]
        let v := (prev.getD (k - 1) 0) + (prev.getD k 0)
        row := row.set! k v
    tbl := tbl.push row
  return tbl

@[inline] def binomialC48 (n k : Nat) : UInt64 :=
  (binomialC48Table.getD n #[]).getD k 0

/-- Combinadic unranking (`interlock48.go:unrankCombination48`). -/
def unrankCombination48 (rank : UInt64) (k n : Nat) : UInt64 := Id.run do
  let mut mask : UInt64 := 0
  let mut remRank := rank
  let mut remK := k
  while remK > 0 do
    let mut c := remK - 1
    while c + 1 <= n - 1 && binomialC48 (c + 1) remK <= remRank do
      c := c + 1
    mask := mask ||| ((1 : UInt64) <<< UInt64.ofNat c)
    remRank := remRank - binomialC48 c remK
    remK := remK - 1
  return mask

/-- Constant-time reciprocal division by `B = C(32, 16)` (`interlock48_rank_split.go:divB`),
    using the certified constants from `ITB.SplitRank`. -/
@[inline] def divB48 (n : UInt64) : UInt64 × UInt64 :=
  let qHat : UInt64 := UInt64.ofNat ((n.toNat * ITB.SplitRank.interlockB48Recip) / (2 ^ 93))
  let bU : UInt64 := UInt64.ofNat ITB.SplitRank.interlockB48
  let r : UInt64 := n - qHat * bU
  if r >= bU then (qHat + 1, r - bU) else (qHat, r)

/-- Constant-time reciprocal modulo `A = C(48, 16)` (`interlock48_rank_split.go:modA`),
    using the certified constants from `ITB.SplitRank`. -/
@[inline] def modA48 (n : UInt64) : UInt64 :=
  let qHat : UInt64 := UInt64.ofNat ((n.toNat * ITB.SplitRank.interlockA48Recip) / (2 ^ 105))
  let aU : UInt64 := UInt64.ofNat ITB.SplitRank.interlockA48
  let r : UInt64 := n - qHat * aU
  if r >= aU then r - aU else r

/-- Constant-time two-step reciprocal rank reduction (`interlock48_rank_split.go:splitRank48Recip`). -/
def splitRank48Recip (lane0 lane1 : UInt64) : UInt64 × UInt64 :=
  let (qHi, r1) := divB48 lane1
  let (qa, ra) := divB48 ((r1 <<< 32) ||| (lane0 >>> 32))
  let (qb, r) := divB48 ((ra <<< 32) ||| (lane0 &&& 0xFFFFFFFF))
  let qLo := (qa <<< 32) ||| qb
  let u0 := modA48 ((qHi <<< 22) ||| (qLo >>> 42))
  let u1 := modA48 ((u0 <<< 21) ||| ((qLo >>> 21) &&& 0x1FFFFF))
  let idx0 := modA48 ((u1 <<< 21) ||| (qLo &&& 0x1FFFFF))
  (idx0, r)

/-- Map a 128-bit PRF output `(lane0, lane1)` to a balanced 48-bit mask triple `(m0, m1, m2)`. -/
def rankToMaskTriple48 (lane0 lane1 : UInt64) : UInt64 × UInt64 × UInt64 := Id.run do
  let (idx0, idx1) := splitRank48Recip lane0 lane1
  let m0 := unrankCombination48 idx0 16 48
  let m1Local := unrankCombination48 idx1 16 32
  let domain : UInt64 := 0x0000FFFFFFFFFFFF
  let remaining := domain &&& (~~~m0)
  let mut m1 : UInt64 := 0
  let mut posIdx : UInt64 := 0
  for bit in [:48] do
    let bU := UInt64.ofNat bit
    if ((remaining >>> bU) &&& 1) == 1 then
      if ((m1Local >>> posIdx) &&& 1) == 1 then
        m1 := m1 ||| ((1 : UInt64) <<< bU)
      posIdx := posIdx + 1
  let m2 := remaining &&& (~~~m1)
  return (m0, m1, m2)

/-- Branchless 48-bit parallel bit extract (`interlock48.go:softPEXT48`). -/
def softPEXT48 (x mask : UInt64) : UInt16 := Id.run do
  let mut result : UInt64 := 0
  let mut outBit : UInt64 := 0
  for i in [:48] do
    let iU := UInt64.ofNat i
    let bit := (mask >>> iU) &&& 1
    let xb := (x >>> iU) &&& 1
    result := result ||| ((bit &&& xb) <<< outBit)
    outBit := outBit + bit
  return result.toUInt16

/-- Branchless 48-bit parallel bit deposit (`interlock48.go:softPDEP48`). -/
def softPDEP48 (v : UInt16) (mask : UInt64) : UInt64 := Id.run do
  let mut result : UInt64 := 0
  let mut inBit : UInt64 := 0
  let v64 := v.toUInt64
  for i in [:48] do
    let iU := UInt64.ofNat i
    let bit := (mask >>> iU) &&& 1
    let vb := (v64 >>> inBit) &&& 1
    result := result ||| ((bit &&& vb) <<< iU)
    inBit := inBit + bit
  return result

/-- Forward per-chunk Rank Barrier kernel (`interlock48.go:chunk48lock`). -/
@[inline] def chunk48lock (x m0 m1 m2 : UInt64) : UInt16 × UInt16 × UInt16 :=
  (softPEXT48 x m0, softPEXT48 x m1, softPEXT48 x m2)

/-- Inverse per-chunk Rank Barrier kernel (`interlock48.go:unchunk48lock`). -/
@[inline] def unchunk48lock (l0 l1 l2 : UInt16) (m0 m1 m2 : UInt64) : UInt64 :=
  (softPDEP48 l0 m0) ||| (softPDEP48 l1 m1) ||| (softPDEP48 l2 m2)

/-- Prepend 4-byte big-endian length header and zero-pad to a 6-byte chunk multiple (`framedSrc48`). -/
def framePlaintext48 (plaintext : ByteArray) : ByteArray := Id.run do
  let totalWithHdr := 4 + plaintext.size
  let rem := totalWithHdr % 6
  let pad := if rem == 0 then 0 else 6 - rem
  let mut out := ByteArray.emptyWithCapacity (totalWithHdr + pad)
  out := pushU32BE out (UInt32.ofNat plaintext.size)
  out := out ++ plaintext
  for _ in [:pad] do
    out := out.push 0
  return out

/-- Strip the 4-byte big-endian length header and trailing chunk padding (`interleaveForTriple48LockedCfgInto`). -/
def unframePlaintext48 (framed : ByteArray) : ByteArray :=
  if framed.size < 4 then ByteArray.empty
  else
    let origLen := (readU32BE framed 0).toNat
    let endPos := Nat.min (4 + origLen) framed.size
    framed.extract 4 endPos

/-- Split plaintext into three 2-byte-per-chunk lanes `(p0, p1, p2)` via the 48-bit Rank Barrier. -/
def splitTriple48Raw (lockSeed : Seed128) (ilNonce plaintext : ByteArray) :
    ByteArray × ByteArray × ByteArray := Id.run do
  let framed := framePlaintext48 plaintext
  let mChunks := framed.size / 6
  let lockComps := buildLockComps128 lockSeed ilNonce
  let foldWord := interlockNonceFold ilNonce
  let mut p0 := ByteArray.emptyWithCapacity (mChunks * 2)
  let mut p1 := ByteArray.emptyWithCapacity (mChunks * 2)
  let mut p2 := ByteArray.emptyWithCapacity (mChunks * 2)
  for k in [:mChunks] do
    let (lane0, lane1) := evalRankPair128 lockComps foldWord k
    let (m0, m1, m2) := rankToMaskTriple48 lane0 lane1
    let x := readU48LE framed (k * 6)
    let (l0, l1, l2) := chunk48lock x m0 m1 m2
    p0 := pushU16LE p0 l0
    p1 := pushU16LE p1 l1
    p2 := pushU16LE p2 l2
  return (p0, p1, p2)

/-- Pad three lanes to equal even byte length (`padLanesToEqualEven` in `interlock48.go`). -/
def padLanesToEqualEven (p0 p1 p2 : ByteArray) : ByteArray × ByteArray × ByteArray := Id.run do
  let maxLen := Nat.max p0.size (Nat.max p1.size p2.size)
  let evenLen := if maxLen % 2 == 1 then maxLen + 1 else maxLen
  let padTo (b : ByteArray) : ByteArray := Id.run do
    if b.size >= evenLen then return b
    let mut out := b
    for _ in [:evenLen - b.size] do
      out := out.push 0
    return out
  return (padTo p0, padTo p1, padTo p2)

/-- Interleave three un-desynchronized lanes `(u0, u1, u2)` back into the original plaintext. -/
def interleaveTriple48Raw (lockSeed : Seed128) (ilNonce u0 u1 u2 : ByteArray) : ByteArray := Id.run do
  let mChunks := u0.size / 2
  if mChunks == 0 then return ByteArray.empty
  let lockComps := buildLockComps128 lockSeed ilNonce
  let foldWord := interlockNonceFold ilNonce
  let mut framed := ByteArray.emptyWithCapacity (mChunks * 6)
  for k in [:mChunks] do
    let (lane0, lane1) := evalRankPair128 lockComps foldWord k
    let (m0, m1, m2) := rankToMaskTriple48 lane0 lane1
    let l0 := readU16LE u0 (k * 2)
    let l1 := readU16LE u1 (k * 2)
    let l2 := readU16LE u2 (k * 2)
    let x := unchunk48lock l0 l1 l2 m0 m1 m2
    framed := pushU48LE framed x
  return unframePlaintext48 framed

-- ============================================================================
-- § 4. Stage 2 — Layer II (`0x06`) Cross-Lane Chunk-Slot Desynchronization
-- ============================================================================

/-- Bijective 128-bit Feistel fold (`desync.go:fullWidthFold` & `ITB.Desync.fullWidthFold`). -/
@[inline] def fullWidthFoldU64 (hLo hHi : UInt64) : UInt64 × UInt64 :=
  let (w0, w1) := ITB.Desync.fullWidthFold (BitVec.ofNat 64 hLo.toNat) (BitVec.ofNat 64 hHi.toNat)
  (UInt64.ofNat w0.toNat, UInt64.ofNat w1.toNat)

/-- Domain tag `0x06`: evaluate the 4 folded 64-bit words `w[0..3]` for Layer II (`interlock48_cascade.go`). -/
def evalDesyncWords128 (lockComps : Array UInt64) (foldWord : UInt32) : Array UInt64 :=
  let buf0 := pushU32LE (pushU64LE (ByteArray.empty.push 0x06) 0) foldWord
  let buf1 := pushU32LE (pushU64LE (ByteArray.empty.push 0x06) 1) foldWord
  let (lo0, hi0) := chainHash128With lockComps buf0
  let (lo1, hi1) := chainHash128With lockComps buf1
  let (w0, w1) := fullWidthFoldU64 lo0 hi0
  let (w2, w3) := fullWidthFoldU64 lo1 hi1
  #[w0, w1, w2, w3]

/-- Layer II (`0x06`) cross-lane slot desynchronization schedule (`desync.go:laneDesyncSchedule`). -/
structure LaneDesyncSchedule where
  m      : Nat
  betas  : Array Nat
  kLane  : Nat
  offset : Array Nat
  size   : Array Nat
  start  : Array Nat
  logOff : Array Nat
  deriving Repr, DecidableEq

/-- Build the Layer II (`0x06`) schedule for `m ≥ 2` slots (`desync.go:buildLaneDesyncSchedule`). -/
def buildLaneDesyncSchedule (m : Nat) (w : Array UInt64) : LaneDesyncSchedule := Id.run do
  let w0 := w.getD 0 0
  let w1 := w.getD 1 0
  let w2 := w.getD 2 0
  let w3 := w.getD 3 0
  let mU := UInt64.ofNat m
  let m1U := UInt64.ofNat (m - 1)
  let beta0 := (w3 % mU).toNat
  let beta1 := (beta0 + 1 + (((w3 >>> 16) % m1U).toNat)) % m
  let beta2 := ((w3 >>> 32) % mU).toNat
  let betas := #[beta0, beta1, beta2]
  if m < 16 then
    return { m, betas, kLane := 0, offset := #[], size := #[], start := #[], logOff := #[] }
  let kLane := 4 + (w0 % 5).toNat
  let base := m / kLane
  let rem := m % kLane
  let mut physOff := Array.replicate (kLane + 1) (0 : Nat)
  for j in [:kLane] do
    let sz := base + (if j < rem then 1 else 0)
    physOff := physOff.set! (j + 1) (physOff.getD j 0 + sz)
  if base >= 4 then
    for j in [1:kLane] do
      let raw := ((w0 >>> UInt64.ofNat (8 + j)) &&& 1).toNat
      if raw == 0 then
        physOff := physOff.set! j (physOff.getD j 0 - 1)
  let mut physSize := Array.replicate kLane (0 : Nat)
  for j in [:kLane] do
    physSize := physSize.set! j (physOff.getD (j + 1) 0 - physOff.getD j 0)
  let mut piLane := Array.replicate kLane (0 : Nat)
  for i in [:kLane] do
    piLane := piLane.set! i i
  let mut u := w1
  for stepRev in [:kLane - 1] do
    let i := kLane - 1 - stepRev
    let mod := UInt64.ofNat (i + 1)
    let swapIdx := (u % mod).toNat
    u := u / mod
    let vi := piLane.getD i 0
    let vs := piLane.getD swapIdx 0
    piLane := piLane.set! i vs
    piLane := piLane.set! swapIdx vi
  let mut offset := Array.replicate kLane (0 : Nat)
  let mut size := Array.replicate kLane (0 : Nat)
  let mut start := Array.replicate kLane (0 : Nat)
  let mut logOff := Array.replicate (kLane + 1) (0 : Nat)
  for step in [:kLane] do
    let physIdx := piLane.getD step 0
    let mk := physSize.getD physIdx 0
    offset := offset.set! step (physOff.getD physIdx 0)
    size := size.set! step mk
    logOff := logOff.set! (step + 1) (logOff.getD step 0 + mk)
    let st := ((rotl64 w2 (9 * step)) % UInt64.ofNat mk).toNat
    start := start.set! step st
  return { m, betas, kLane, offset, size, start, logOff }

/-- Apply Layer II forward permutation `Σ_l = Π_lane ∘ μ_l` to one 2-byte-per-slot lane (`desyncLaneEncryptTo`). -/
def desyncLaneEncryptOne (src : ByteArray) (sched : LaneDesyncSchedule) (l : Nat) : ByteArray := Id.run do
  let m := sched.m
  if m < 2 then return src
  let beta := sched.betas.getD l 0
  let mut dstSlots := Array.replicate m (0 : UInt16)
  if sched.kLane == 0 then
    for u in [:m] do
      let srcSlot := (u + m - beta) % m
      dstSlots := dstSlots.set! u (readU16LE src (srcSlot * 2))
  else
    for step in [:sched.kLane] do
      let mk := sched.size.getD step 0
      let uBase := sched.logOff.getD step 0
      let physOff := sched.offset.getD step 0
      let s := sched.start.getD step 0
      for q in [:mk] do
        let u := uBase + q
        let srcSlot := (u + m - beta) % m
        let dstSlot := physOff + ((s + q) % mk)
        dstSlots := dstSlots.set! dstSlot (readU16LE src (srcSlot * 2))
  let mut out := ByteArray.emptyWithCapacity (m * 2)
  for y in [:m] do
    out := pushU16LE out (dstSlots.getD y 0)
  return out

/-- Apply Layer II inverse permutation `Σ_l⁻¹ = μ_l⁻¹ ∘ Π_lane⁻¹` to one 2-byte-per-slot lane (`desyncLaneDecryptOne`). -/
def desyncLaneDecryptOne (src : ByteArray) (sched : LaneDesyncSchedule) (l : Nat) : ByteArray := Id.run do
  let m := sched.m
  if m < 2 then return src
  let beta := sched.betas.getD l 0
  let mut dstSlots := Array.replicate m (0 : UInt16)
  if sched.kLane == 0 then
    for u in [:m] do
      let dstSlot := (u + m - beta) % m
      dstSlots := dstSlots.set! dstSlot (readU16LE src (u * 2))
  else
    for step in [:sched.kLane] do
      let mk := sched.size.getD step 0
      let uBase := sched.logOff.getD step 0
      let physOff := sched.offset.getD step 0
      let s := sched.start.getD step 0
      for q in [:mk] do
        let u := uBase + q
        let dstSlot := (u + m - beta) % m
        let srcSlot := physOff + ((s + q) % mk)
        dstSlots := dstSlots.set! dstSlot (readU16LE src (srcSlot * 2))
  let mut out := ByteArray.emptyWithCapacity (m * 2)
  for j in [:m] do
    out := pushU16LE out (dstSlots.getD j 0)
  return out

/-- Apply Layer II (`0x06`) forward desynchronization across all three lanes `(p0, p1, p2)`. -/
def desyncLaneEncrypt (lockSeed : Seed128) (ilNonce p0 p1 p2 : ByteArray) :
    ByteArray × ByteArray × ByteArray :=
  let m := p0.size / 2
  if m < 2 then (p0, p1, p2)
  else
    let lockComps := buildLockComps128 lockSeed ilNonce
    let foldWord := interlockNonceFold ilNonce
    let w := evalDesyncWords128 lockComps foldWord
    let sched := buildLaneDesyncSchedule m w
    (desyncLaneEncryptOne p0 sched 0,
     desyncLaneEncryptOne p1 sched 1,
     desyncLaneEncryptOne p2 sched 2)

/-- Apply Layer II (`0x06`) inverse desynchronization across all three lanes `(d0, d1, d2)`. -/
def desyncLaneDecrypt (lockSeed : Seed128) (ilNonce d0 d1 d2 : ByteArray) :
    ByteArray × ByteArray × ByteArray :=
  let (p0, p1, p2) := padLanesToEqualEven d0 d1 d2
  let m := p0.size / 2
  if m < 2 then (p0, p1, p2)
  else
    let lockComps := buildLockComps128 lockSeed ilNonce
    let foldWord := interlockNonceFold ilNonce
    let w := evalDesyncWords128 lockComps foldWord
    let sched := buildLaneDesyncSchedule m w
    (desyncLaneDecryptOne p0 sched 0,
     desyncLaneDecryptOne p1 sched 1,
     desyncLaneDecryptOne p2 sched 2)

-- ============================================================================
-- § 5. Stage 3 — Interlock Nonce Split & COBS Framing
-- ============================================================================

/-- Partition a nonce of `n` bytes (`16`, `32`, or `64`) into 3 lane prefix lengths and offsets (`interlock_nonce.go:nonceSplit`).
    Remainder bytes go to the lowest-indexed lanes (`l0`, then `l1`). -/
@[inline] def nonceSplitOffsets (n : Nat) : (Nat × Nat × Nat) × (Nat × Nat × Nat) :=
  let base := n / 3
  let rem := n % 3
  let l0 := base + (if 0 < rem then 1 else 0)
  let l1 := base + (if 1 < rem then 1 else 0)
  let l2 := base
  ((l0, l1, l2), (0, l0, l0 + l1))

/-- Prepend the three interlock-nonce fragments ahead of `(d0, d1, d2)`. -/
def prependInterlockNonce (ilNonce d0 d1 d2 : ByteArray) : ByteArray × ByteArray × ByteArray :=
  let ((l0, l1, l2), (o0, o1, o2)) := nonceSplitOffsets ilNonce.size
  let frag0 := ilNonce.extract o0 (o0 + l0)
  let frag1 := ilNonce.extract o1 (o1 + l1)
  let frag2 := ilNonce.extract o2 (o2 + l2)
  (frag0 ++ d0, frag1 ++ d1, frag2 ++ d2)

/-- Reassemble the interlock nonce from the three COBS-decoded lane prefixes (`recoverInterlockNonce`). -/
def recoverInterlockNonce (nonceLen : Nat) (part0 part1 part2 : ByteArray) :
    ByteArray × ByteArray × ByteArray × ByteArray :=
  let ((l0, l1, l2), _) := nonceSplitOffsets nonceLen
  let takeFrag (p : ByteArray) (want : Nat) : ByteArray × ByteArray := Id.run do
    if p.size >= want then
      return (p.extract 0 want, p.extract want p.size)
    let mut frag := p
    for _ in [:want - p.size] do
      frag := frag.push 0
    return (frag, ByteArray.empty)
  let (f0, r0) := takeFrag part0 l0
  let (f1, r1) := takeFrag part1 l1
  let (f2, r2) := takeFrag part2 l2
  (f0 ++ f1 ++ f2, r0, r1, r2)

/-- Worst-case COBS output length (`cobs.go:cobsEncodeBound`). -/
@[inline] def cobsEncodeBound (n : Nat) : Nat :=
  if n == 0 then 1 else n + n / 254 + 1

/-- Consistent Overhead Byte Stuffing encoder (`cobs.go:cobsEncodeInto`). -/
def cobsEncode (data : ByteArray) : ByteArray := Id.run do
  if data.size == 0 then
    return ByteArray.mk #[0x01]
  let mut dst := Array.mkEmpty (cobsEncodeBound data.size)
  dst := dst.push 0
  let mut codeIdx : Nat := 0
  let mut code : UInt8 := 1
  for i in [:data.size] do
    let b := getByteD data i
    if b == 0 then
      dst := dst.set! codeIdx code
      codeIdx := dst.size
      dst := dst.push 0
      code := 1
    else
      dst := dst.push b
      code := code + 1
      if code == 0xFF then
        dst := dst.set! codeIdx code
        codeIdx := dst.size
        dst := dst.push 0
        code := 1
  dst := dst.set! codeIdx code
  return ByteArray.mk dst

/-- Consistent Overhead Byte Stuffing decoder (`cobs.go:cobsDecodeInto`). -/
def cobsDecode (encoded : ByteArray) : ByteArray := Id.run do
  let mut dst := ByteArray.emptyWithCapacity encoded.size
  let mut i : Nat := 0
  while i < encoded.size do
    let code := getByteD encoded i
    if code == 0 then break
    i := i + 1
    let count := (code - 1).toNat
    if i + count > encoded.size then break
    for j in [:count] do
      dst := dst.push (getByteD encoded (i + j))
    i := i + count
    if code < 0xFF && i < encoded.size then
      dst := dst.push 0
  return dst

/-- Find the index of the first `0x00` COBS delimiter byte in `b`, or `b.size` if absent. -/
def findNullByte (b : ByteArray) : Nat := Id.run do
  for i in [:b.size] do
    if getByteD b i == 0 then return i
  return b.size

-- ============================================================================
-- § 6. Stage 4 — Container Sizing (Mode 1 & Mode 2) & 3-Third Payload Assembly
-- ============================================================================

/-- Configuration parameters for the 128-bit ITB pipeline (`Config` in `config.go`). -/
structure PipelineConfig where
  nonceBits    : Nat := 128
  barrierFill  : Nat := 1
  mode         : Nat := 1   -- `1` for Mode 1 (per-region floor), `2` for Mode 2 (joint container floor)
  tagStubSize  : Nat := 0   -- `0` defaults to `32` (`nomacTagStubSizeCfg = 33`)
  drbgFillByte : UInt8 := 0x5A
  deriving Repr, DecidableEq

/-- Nonce byte length (`16`, `32`, or `64`). -/
@[inline] def PipelineConfig.nonceBytes (cfg : PipelineConfig) : Nat :=
  if cfg.nonceBits == 0 then 16 else cfg.nonceBits / 8

/-- Effective `BarrierFill` side-length margin (`1` when `0`). -/
@[inline] def PipelineConfig.effBarrierFill (cfg : PipelineConfig) : Nat :=
  if cfg.barrierFill == 0 then 1 else cfg.barrierFill

/-- Reserved bytes at the tail of third 2 on the No MAC path (`stream_envelope.go:nomacTagStubSizeCfg`). -/
@[inline] def PipelineConfig.nomacReserve (cfg : PipelineConfig) : Nat :=
  let tagSize := if cfg.tagStubSize > 0 then cfg.tagStubSize else 32
  tagSize + 1

/-- Smallest positive integer `side ≥ 1` such that `side * side ≥ totalPixels`. -/
def ceilSqrt (totalPixels : Nat) : Nat := Id.run do
  let mut side : Nat := 1
  while side * side < totalPixels do
    side := side + 1
  return side

/-- Compute square container dimensions `(width, height)` (`itb.go:calcContainerSize3Cfg`),
    covering both **Mode 1** (`cfg.mode != 2`, per-region floor) and **Mode 2** (`cfg.mode == 2`, joint floor). -/
def calcContainerSize3Cfg (cfg : PipelineConfig) (cobsLens : Nat × Nat × Nat)
    (minPxNoise : Nat) (minPxData : Nat × Nat × Nat) (minPxStart : Nat × Nat × Nat) : Nat × Nat :=
  let (c0, c1, c2) := cobsLens
  let (d0, d1, d2) := minPxData
  let (s0, s1, s2) := minPxStart
  let pxNeed (c : Nat) : Nat := ((c + 1) * 8 + 55) / 56
  if cfg.mode == 2 then
    let maxDataThird := Nat.max (pxNeed c0) (Nat.max (pxNeed c1) (pxNeed c2))
    let minPxJoint :=
      Nat.max minPxNoise (Nat.max (Nat.max d0 (Nat.max d1 d2)) (Nat.max s0 (Nat.max s1 s2)))
    let totalPixels := Nat.max (3 * maxDataThird) minPxJoint
    let side := ceilSqrt totalPixels + cfg.effBarrierFill
    (side, side)
  else
    let r0 := Nat.max (pxNeed c0) (Nat.max minPxNoise (Nat.max d0 s0))
    let r1 := Nat.max (pxNeed c1) (Nat.max minPxNoise (Nat.max d1 s1))
    let r2 := Nat.max (pxNeed c2) (Nat.max minPxNoise (Nat.max d2 s2))
    let maxThird := Nat.max r0 (Nat.max r1 r2)
    let totalPixels := 3 * maxThird
    let side := ceilSqrt totalPixels + cfg.effBarrierFill
    (side, side)

/-- Compute container side length directly from `(msgLen, keyBits, nonceBits, mode)` for the size ladder. -/
def calcContainerSideForMsg (msgLen keyBits nonceBits mode : Nat) : Nat :=
  let cfg : PipelineConfig := { nonceBits, barrierFill := 1, mode }
  let totalWithHdr := 4 + msgLen
  let rem := totalWithHdr % 6
  let padded := if rem == 0 then totalWithHdr else totalWithHdr + (6 - rem)
  let laneLen := (padded / 6) * 2
  let ((l0, l1, l2), _) := nonceSplitOffsets cfg.nonceBytes
  let b0 := cobsEncodeBound (l0 + laneLen)
  let b1 := cobsEncodeBound (l1 + laneLen)
  let b2 := cobsEncodeBound (l2 + laneLen) + cfg.nomacReserve
  let minPx := minPixelsAuth keyBits
  (calcContainerSize3Cfg cfg (b0, b1, b2) minPx (minPx, minPx, minPx) (minPx, minPx, minPx)).1

/-- Per-third pixel counts and byte capacities (`triplepayload.go:tripleThirdCaps`). -/
@[inline] def tripleThirdCaps (totalPixels : Nat) : Nat × Nat × (Nat × Nat × Nat) :=
  let third := totalPixels / 3
  let thirdPixels2 := totalPixels - 2 * third
  let cap0 := (third * 56) / 8
  let cap1 := (third * 56) / 8
  let cap2 := (thirdPixels2 * 56) / 8
  (third, thirdPixels2, (cap0, cap1, cap2))

/-- Region noise-hash counter offset (`noisepos.go:noiseCounterBase`). -/
@[inline] def noiseCounterBase (region third : Nat) : Nat :=
  region * third

-- ============================================================================
-- § 7. Stage 5 — Layer I (`0x05`) Sub-Region Desynchronization & Pixel Barrier (`0x01`, `0x02`)
-- ============================================================================

/-- Layer I (`0x05`) sub-region trajectory schedule (`desync.go:subregionSchedule`). -/
structure SubregionSchedule where
  k      : Nat
  offset : Array Nat
  size   : Array Nat
  start  : Array Nat
  logOff : Array Nat
  deriving Repr, DecidableEq

/-- Effective starting pixel handed to `processChunk128` (`desync.go:effectiveStartPixel`). -/
@[inline] def effectiveStartPixel (m s p : Nat) : Nat :=
  ITB.Desync.effectiveStartPixel m s p

/-- Build the Layer I (`0x05`) sub-region schedule (`desync.go:buildSubregionSchedule`). -/
def buildSubregionSchedule (startPixel totalPixels : Nat) (w : Array UInt64) : SubregionSchedule := Id.run do
  let w0 := w.getD 0 0
  let w1 := w.getD 1 0
  let (k, deltaMax) :=
    if totalPixels < 365 then
      (6 + (w0 % 5).toNat, 1)
    else
      (8 + (w0 % 9).toNat, 2)
  let base := totalPixels / k
  let rem := totalPixels % k
  let mut physOff := Array.replicate (k + 1) (0 : Nat)
  for j in [:k] do
    let sz := base + (if j < rem then 1 else 0)
    physOff := physOff.set! (j + 1) (physOff.getD j 0 + sz)
  for j in [1:k] do
    if deltaMax == 1 then
      let raw := ((w0 >>> UInt64.ofNat (8 + j)) &&& 1).toNat
      if raw == 0 then
        physOff := physOff.set! j (physOff.getD j 0 - 1)
    else
      let raw := ((w0 >>> UInt64.ofNat (8 + 2 * j)) &&& 3).toNat
      let cur := physOff.getD j 0
      physOff := physOff.set! j (cur + raw - 2)
  let mut physSize := Array.replicate k (0 : Nat)
  for j in [:k] do
    physSize := physSize.set! j (physOff.getD (j + 1) 0 - physOff.getD j 0)
  let mut tau := Array.replicate k (0 : Nat)
  for i in [:k] do
    tau := tau.set! i i
  let mut u := w1
  for stepRev in [:k - 1] do
    let i := k - 1 - stepRev
    let mod := UInt64.ofNat (i + 1)
    let swapIdx := (u % mod).toNat
    u := u / mod
    let vi := tau.getD i 0
    let vs := tau.getD swapIdx 0
    tau := tau.set! i vs
    tau := tau.set! swapIdx vi
  let mut offset := Array.replicate k (0 : Nat)
  let mut size := Array.replicate k (0 : Nat)
  let mut start := Array.replicate k (0 : Nat)
  let mut logOff := Array.replicate (k + 1) (0 : Nat)
  let goldenGamma : UInt64 := 0x9E3779B97F4A7C15
  for step in [:k] do
    let physIdx := tau.getD step 0
    let m := physSize.getD physIdx 0
    offset := offset.set! step (physOff.getD physIdx 0)
    size := size.set! step m
    logOff := logOff.set! (step + 1) (logOff.getD step 0 + m)
    let wStep := w.getD (2 + (step % 6)) 0
    let mix := (rotl64 wStep (11 * step)) ^^^ ((UInt64.ofNat (step + 1)) * goldenGamma)
    let st := (((UInt64.ofNat startPixel) + mix) % UInt64.ofNat m).toNat
    start := start.set! step st
  return { k, offset, size, start, logOff }

/-- Domain tag `0x05`: derive the Layer I sub-region schedule (`desync.go:deriveSubregionScheduleBody`). -/
def deriveSubregionSchedule128 (startSeed : Seed128) (nonce : ByteArray)
    (startPixel totalPixels : Nat) : SubregionSchedule := Id.run do
  let basePrefix := (ByteArray.empty.push 0x05) ++ (nonce.extract 0 (nonce.size - 1))
  let baseByte := getByteD nonce (nonce.size - 1)
  let mut w := Array.mkEmpty 8
  for j in [:4] do
    let buf := basePrefix.push (baseByte ^^^ UInt8.ofNat j)
    let (lo, hi) := chainHash128 startSeed buf
    let (f0, f1) := fullWidthFoldU64 lo hi
    w := (w.push f0).push f1
  return buildSubregionSchedule startPixel totalPixels w

/-- Combine words 0 and 1 of the noise hash (`noisepos.go:noiseMix`). -/
@[inline] def noiseMixU64 (word0 word1 : UInt64) : UInt64 :=
  word0 + rotl64 word1 1

/-- GF(2)-linear 64-to-3-bit fold (`noisepos.go:noiseFold3`). -/
@[inline] def noiseFold3U64 (w : UInt64) : Nat :=
  let w := w ^^^ (w >>> 32)
  let w := w ^^^ (w >>> 16)
  let w := w ^^^ (w >>> 8)
  let w := w ^^^ (w >>> 4)
  let n := w &&& 15
  (((n ^^^ (n >>> 3)) &&& 7)).toNat

/-- 7-bit cyclic left rotation (`itb.go:rotateBits7`). -/
@[inline] def rotateBits7U8 (v : UInt8) (r : Nat) : UInt8 :=
  let r7 := r % 7
  let v7 := v &&& 0x7F
  if r7 == 0 then v7
  else ((v7 <<< UInt8.ofNat r7) ||| (v7 >>> UInt8.ofNat (7 - r7))) &&& 0x7F

/-- Encode 7 data bits into an 8-bit channel byte with 1 noise bit preserved at `noisePos`. -/
@[inline] def encodeChannelByte (dataBits channelXOR : UInt8) (dataRotation noisePos : Nat) (orig : UInt8) : UInt8 :=
  let xored := (dataBits &&& 0x7F) ^^^ (channelXOR &&& 0x7F)
  let rotated := rotateBits7U8 xored dataRotation
  let posU8 := UInt8.ofNat (noisePos % 8)
  let noiseMask : UInt8 := (1 : UInt8) <<< posU8
  let low := rotated &&& (noiseMask - 1)
  let high := rotated >>> posU8
  low ||| (orig &&& noiseMask) ||| (high <<< (posU8 + 1))

/-- Decode 7 data bits from an 8-bit channel byte by stripping the noise bit at `noisePos`. -/
@[inline] def decodeChannelByte (channelByte channelXOR : UInt8) (dataRotation noisePos : Nat) : UInt8 :=
  let posU8 := UInt8.ofNat (noisePos % 8)
  let noiseMask : UInt8 := (1 : UInt8) <<< posU8
  let low := channelByte &&& (noiseMask - 1)
  let high := channelByte >>> (posU8 + 1)
  let extracted := (low ||| (high <<< posU8)) &&& 0x7F
  let unrotated := rotateBits7U8 extracted (7 - (dataRotation % 7))
  unrotated ^^^ (channelXOR &&& 0x7F)

/-- Encode pixels `[startP, endP)` of a sub-region or region into `container` (`processChunk128Body`). -/
def encodeChunk128 (noiseSeed dataSeed : Seed128) (tpl : BlockNonceTemplate128)
    (container : Array UInt8) (physBaseOffset : Nat) (data : ByteArray)
    (startPixel regionPixels startP endP totalBits noiseBase : Nat) : Array UInt8 := Id.run do
  let mut cont := container
  let mut bitIndex := startP * 56
  for p in [startP:endP] do
    if bitIndex < totalBits then
      let linearIdx := (startPixel + p) % regionPixels
      let pixelOffset := physBaseOffset + linearIdx * 8
      let (noiseLo, noiseHi) := blockHash128Tpl noiseSeed tpl (noiseBase + p)
      let noiseHash := noiseMixU64 noiseLo noiseHi
      let (dataHash, _) := blockHash128Tpl dataSeed tpl p
      let noisePos := noiseFold3U64 noiseHash
      let dataRotation := (dataHash % 7).toNat
      let xorMask := dataHash >>> 3
      for ch in [:8] do
        if bitIndex < totalBits then
          let channelXOR := ((xorMask >>> UInt64.ofNat (ch * 7)) &&& 0x7F).toUInt8
          let byteIdx := bitIndex / 8
          let bitOff := UInt16.ofNat (bitIndex % 8)
          let b0 := (getByteD data byteIdx).toUInt16
          let b1 := if byteIdx + 1 < data.size then (getByteD data (byteIdx + 1)).toUInt16 <<< 8 else 0
          let raw := b0 ||| b1
          let dataBits := ((raw >>> bitOff) &&& 0x7F).toUInt8
          let orig := cont.getD (pixelOffset + ch) 0
          let encByte := encodeChannelByte dataBits channelXOR dataRotation noisePos orig
          cont := cont.set! (pixelOffset + ch) encByte
          bitIndex := Nat.min (bitIndex + 7) totalBits
  return cont

/-- Decode pixels `[startP, endP)` from `container` into `decoded` (`processChunk128Body`),
    stopping early once the `0x00` COBS delimiter byte is encountered. -/
def decodeChunk128 (noiseSeed dataSeed : Seed128) (tpl : BlockNonceTemplate128)
    (container : ByteArray) (physBaseOffset : Nat) (decoded : Array UInt8)
    (startPixel regionPixels startP endP totalBits noiseBase : Nat) : Array UInt8 × Bool := Id.run do
  let mut dec := decoded
  let mut bitIndex := startP * 56
  for p in [startP:endP] do
    if bitIndex < totalBits then
      let linearIdx := (startPixel + p) % regionPixels
      let pixelOffset := physBaseOffset + linearIdx * 8
      let (noiseLo, noiseHi) := blockHash128Tpl noiseSeed tpl (noiseBase + p)
      let noiseHash := noiseMixU64 noiseLo noiseHi
      let (dataHash, _) := blockHash128Tpl dataSeed tpl p
      let noisePos := noiseFold3U64 noiseHash
      let dataRotation := (dataHash % 7).toNat
      let xorMask := dataHash >>> 3
      let bitsLeft := totalBits - bitIndex
      let chCount := if bitsLeft < 56 then (bitsLeft + 6) / 7 else 8
      let mut packed : UInt64 := 0
      for ch in [:chCount] do
        let channelXOR := ((xorMask >>> UInt64.ofNat (ch * 7)) &&& 0x7F).toUInt8
        let channelByte := getByteD container (pixelOffset + ch)
        let dataBits := decodeChannelByte channelByte channelXOR dataRotation noisePos
        packed := packed ||| (dataBits.toUInt64 <<< UInt64.ofNat (ch * 7))
      let byteStart := bitIndex / 8
      let bytesToWrite := (chCount * 7 + 7) / 8
      for i in [:bytesToWrite] do
        if byteStart + i < dec.size then
          let b := ((packed >>> UInt64.ofNat (i * 8)) &&& 0xFF).toUInt8
          dec := dec.set! (byteStart + i) b
          if b == 0 then
            return (dec, true)
      bitIndex := bitIndex + chCount * 7
  return (dec, false)

/-- Encode one container region (third) with Layer I (`0x05`) sub-region schedule (`process128Cfg`). -/
def encodeRegion128 (noiseSeed dataSeed startSeed : Seed128) (nonce : ByteArray)
    (container : Array UInt8) (regionByteOffset regionPixels : Nat)
    (payload : ByteArray) (noiseBase : Nat) : Array UInt8 := Id.run do
  let tpl := prepareBlockNonce128 nonce
  let startPixel := deriveStartPixel startSeed nonce regionPixels
  let totalBits := payload.size * 8
  let dataPixels := Nat.min regionPixels ((totalBits + 55) / 56)
  if regionPixels >= 32 then
    let sched := deriveSubregionSchedule128 startSeed nonce startPixel regionPixels
    let mut cont := container
    for step in [:sched.k] do
      let logStart := sched.logOff.getD step 0
      let logEnd := sched.logOff.getD (step + 1) 0
      if logStart < dataPixels then
        let sP := logStart
        let eP := Nat.min logEnd dataPixels
        if sP < eP then
          let m := sched.size.getD step 0
          let physOff := sched.offset.getD step 0
          let effStart := effectiveStartPixel m (sched.start.getD step 0) logStart
          cont := encodeChunk128 noiseSeed dataSeed tpl cont
            (regionByteOffset + physOff * 8) payload effStart m sP eP totalBits noiseBase
    return cont
  else
    return encodeChunk128 noiseSeed dataSeed tpl container
      regionByteOffset payload startPixel regionPixels 0 dataPixels totalBits noiseBase

/-- Decode one container region (third) with Layer I (`0x05`) sub-region schedule (`process128Cfg`). -/
def decodeRegion128 (noiseSeed dataSeed startSeed : Seed128) (nonce : ByteArray)
    (container : ByteArray) (regionByteOffset regionPixels payloadCap noiseBase : Nat) : ByteArray := Id.run do
  let tpl := prepareBlockNonce128 nonce
  let startPixel := deriveStartPixel startSeed nonce regionPixels
  let totalBits := payloadCap * 8
  let dataPixels := Nat.min regionPixels ((totalBits + 55) / 56)
  let mut dec := Array.replicate payloadCap (0 : UInt8)
  if regionPixels >= 32 then
    let sched := deriveSubregionSchedule128 startSeed nonce startPixel regionPixels
    for step in [:sched.k] do
      let logStart := sched.logOff.getD step 0
      let logEnd := sched.logOff.getD (step + 1) 0
      if logStart < dataPixels then
        let sP := logStart
        let eP := Nat.min logEnd dataPixels
        if sP < eP then
          let m := sched.size.getD step 0
          let physOff := sched.offset.getD step 0
          let effStart := effectiveStartPixel m (sched.start.getD step 0) logStart
          let (nextDec, done) := decodeChunk128 noiseSeed dataSeed tpl container
            (regionByteOffset + physOff * 8) dec effStart m sP eP totalBits noiseBase
          dec := nextDec
          if done then
            return ByteArray.mk dec
  else
    let (nextDec, _) := decodeChunk128 noiseSeed dataSeed tpl container
      regionByteOffset dec startPixel regionPixels 0 dataPixels totalBits noiseBase
    dec := nextDec
  return ByteArray.mk dec

-- ============================================================================
-- § 8. End-to-End 128-Bit Pipeline (`encrypt3x128Deterministic` & `decrypt3x128Cfg`)
-- ============================================================================

/-- Assemble a region payload buffer: `cobsEncode(lane) ++ [0x00] ++ drbgFill` of total size `capBytes`. -/
def buildThirdPayload (cobsBytes : ByteArray) (capBytes : Nat) (drbgFillByte : UInt8) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity capBytes
  out := out ++ cobsBytes
  if out.size < capBytes then
    out := out.push 0x00
  while out.size < capBytes do
    out := out.push drbgFillByte
  return out

/-- Pure, deterministic executable reference specification of `itb.Encrypt3x128Cfg`
    (`itb128.go:Encrypt3x128Cfg`).
    Seed slot order: `#[noiseSeed, lockSeed, data1, data2, data3, start1, start2, start3]`. -/
def encrypt3x128Deterministic (cfg : PipelineConfig) (seeds : Array Seed128)
    (prefix32 mainNonce ilNonce plaintext : ByteArray) : ByteArray := Id.run do
  let s0 : Seed128 := seeds.getD 0 ⟨#[]⟩
  let lockSeed : Seed128 := seeds.getD 1 ⟨#[]⟩
  let dSeed0 : Seed128 := seeds.getD 2 ⟨#[]⟩
  let dSeed1 : Seed128 := seeds.getD 3 ⟨#[]⟩
  let dSeed2 : Seed128 := seeds.getD 4 ⟨#[]⟩
  let stSeed0 : Seed128 := seeds.getD 5 ⟨#[]⟩
  let stSeed1 : Seed128 := seeds.getD 6 ⟨#[]⟩
  let stSeed2 : Seed128 := seeds.getD 7 ⟨#[]⟩
  -- 1. Rank Barrier (`0x03`, `0x04`)
  let (raw0, raw1, raw2) := splitTriple48Raw lockSeed ilNonce plaintext
  -- 2. Layer II (`0x06`) cross-lane slot desynchronization
  let (des0, des1, des2) := desyncLaneEncrypt lockSeed ilNonce raw0 raw1 raw2
  -- 3. Prepend split interlock-nonce fragments & COBS-encode
  let (lane0, lane1, lane2) := prependInterlockNonce ilNonce des0 des1 des2
  let cobs0 := cobsEncode lane0
  let cobs1 := cobsEncode lane1
  let cobs2 := cobsEncode lane2
  -- 4. Container sizing from COBS upper bounds (`buildTripleWire3Into`)
  let laneLen := raw0.size
  let ((nl0, nl1, nl2), _) := nonceSplitOffsets ilNonce.size
  let b0 := cobsEncodeBound (nl0 + laneLen)
  let b1 := cobsEncodeBound (nl1 + laneLen)
  let b2 := cobsEncodeBound (nl2 + laneLen) + cfg.nomacReserve
  let (width, height) := calcContainerSize3Cfg cfg (b0, b1, b2)
    s0.minPixelsAuth
    (dSeed0.minPixelsAuth, dSeed1.minPixelsAuth, dSeed2.minPixelsAuth)
    (stSeed0.minPixelsAuth, stSeed1.minPixelsAuth, stSeed2.minPixelsAuth)
  let totalPixels := width * height
  let (third, thirdPixels2, (cap0, cap1, cap2)) := tripleThirdCaps totalPixels
  let pay0 := buildThirdPayload cobs0 cap0 cfg.drbgFillByte
  let pay1 := buildThirdPayload cobs1 cap1 cfg.drbgFillByte
  let pay2 := buildThirdPayload cobs2 cap2 cfg.drbgFillByte
  -- 5. Layer I (`0x05`) + Pixel Barrier (`0x01`, `0x02`) across the 3 regions
  let mut cont := Array.replicate (totalPixels * 8) cfg.drbgFillByte
  let off1 := third * 8
  let off2 := 2 * third * 8
  cont := encodeRegion128 s0 dSeed0 stSeed0 mainNonce cont 0 third pay0 (noiseCounterBase 0 third)
  cont := encodeRegion128 s0 dSeed1 stSeed1 mainNonce cont off1 third pay1 (noiseCounterBase 1 third)
  cont := encodeRegion128 s0 dSeed2 stSeed2 mainNonce cont off2 thirdPixels2 pay2 (noiseCounterBase 2 third)
  -- 6. Assemble wire `[prefix32 ‖ mainNonce ‖ BE16(W) ‖ BE16(H) ‖ container]`
  let mut wire := prefix32 ++ mainNonce
  wire := pushU16BE wire (UInt16.ofNat width)
  wire := pushU16BE wire (UInt16.ofNat height)
  wire := wire ++ ByteArray.mk cont
  return wire

/-- Pure executable reference specification of `itb.Decrypt3x128Cfg` (`itb128.go:Decrypt3x128Cfg`).
    Reads `W` and `H` directly from the wire header (independent of `cfg.mode` and `cfg.barrierFill`). -/
def decrypt3x128Cfg (cfg : PipelineConfig) (seeds : Array Seed128) (wire : ByteArray) : Option ByteArray :=
  let nonceLen := cfg.nonceBytes
  let hdrOffset := 32
  let minWire := hdrOffset + nonceLen + 4 + 8
  if wire.size < minWire then none
  else
    let mainNonce := wire.extract hdrOffset (hdrOffset + nonceLen)
    let width := (readU16BE wire (hdrOffset + nonceLen)).toNat
    let height := (readU16BE wire (hdrOffset + nonceLen + 2)).toNat
    if width == 0 || height == 0 || width != height then none
    else
      let totalPixels := width * height
      let container := wire.extract (hdrOffset + nonceLen + 4) wire.size
      if container.size != totalPixels * 8 then none
      else
        let s0 : Seed128 := seeds.getD 0 ⟨#[]⟩
        let lockSeed : Seed128 := seeds.getD 1 ⟨#[]⟩
        let dSeed0 : Seed128 := seeds.getD 2 ⟨#[]⟩
        let dSeed1 : Seed128 := seeds.getD 3 ⟨#[]⟩
        let dSeed2 : Seed128 := seeds.getD 4 ⟨#[]⟩
        let stSeed0 : Seed128 := seeds.getD 5 ⟨#[]⟩
        let stSeed1 : Seed128 := seeds.getD 6 ⟨#[]⟩
        let stSeed2 : Seed128 := seeds.getD 7 ⟨#[]⟩
        let (third, thirdPixels2, (cap0, cap1, cap2)) := tripleThirdCaps totalPixels
        let off1 := third * 8
        let off2 := 2 * third * 8
        let dec0 := decodeRegion128 s0 dSeed0 stSeed0 mainNonce container 0 third cap0 (noiseCounterBase 0 third)
        let dec1 := decodeRegion128 s0 dSeed1 stSeed1 mainNonce container off1 third cap1 (noiseCounterBase 1 third)
        let dec2 := decodeRegion128 s0 dSeed2 stSeed2 mainNonce container off2 thirdPixels2 cap2 (noiseCounterBase 2 third)
        let part0 := cobsDecode (dec0.extract 0 (findNullByte dec0))
        let part1 := cobsDecode (dec1.extract 0 (findNullByte dec1))
        let part2 := cobsDecode (dec2.extract 0 (findNullByte dec2))
        let (ilNonce, lane0, lane1, lane2) := recoverInterlockNonce nonceLen part0 part1 part2
        let (u0, u1, u2) := desyncLaneDecrypt lockSeed ilNonce lane0 lane1 lane2
        some (interleaveTriple48Raw lockSeed ilNonce u0 u1 u2)

-- ============================================================================
-- § 9. Formal Round-Trip, Composition, and Mode-Independence Theorems
-- ============================================================================

/-- **Theorem 1 (5-Stage Functional Composition Left-Inverse)**:
    For any five forward pipeline stages
      1. `f_rank  : α → β` (48-Bit Rank Barrier `0x03`/`0x04`)
      2. `f_slot  : β → γ` (Layer II `0x06` Cross-Lane Slot Desynchronization)
      3. `f_cobs  : γ → δ` (Interlock-Nonce Prefix & COBS Framing)
      4. `f_traj  : δ → ε` (Layer I `0x05` Sub-Region Trajectory)
      5. `f_pixel : ε → ζ` (Pixel Barrier `0x01`/`0x02` Channel Encoding)
    and their stage-wise left inverses `g_rank, g_slot, g_cobs, g_traj, g_pixel`,
    the composed inverse pipeline `g_rank ∘ g_slot ∘ g_cobs ∘ g_traj ∘ g_pixel`
    is an exact left inverse of `f_pixel ∘ f_traj ∘ f_cobs ∘ f_slot ∘ f_rank`. -/
theorem pipeline_five_stage_composition_left_inv
    {α β γ δ ε ζ : Type}
    (f_rank : α → β) (g_rank : β → α)
    (f_slot : β → γ) (g_slot : γ → β)
    (f_cobs : γ → δ) (g_cobs : δ → γ)
    (f_traj : δ → ε) (g_traj : ε → δ)
    (f_pixel : ε → ζ) (g_pixel : ζ → ε)
    (h_rank : ∀ x, g_rank (f_rank x) = x)
    (h_slot : ∀ x, g_slot (f_slot x) = x)
    (h_cobs : ∀ x, g_cobs (f_cobs x) = x)
    (h_traj : ∀ x, g_traj (f_traj x) = x)
    (h_pixel : ∀ x, g_pixel (f_pixel x) = x)
    (msg : α) :
    g_rank (g_slot (g_cobs (g_traj (g_pixel
      (f_pixel (f_traj (f_cobs (f_slot (f_rank msg))))))))) = msg := by
  rw [h_pixel, h_traj, h_cobs, h_slot, h_rank]

/-- Point-free (`Function.comp`) formulation of the 5-stage pipeline inversion theorem. -/
theorem pipeline_five_stage_comp_id
    {α β γ δ ε ζ : Type}
    (f_rank : α → β) (g_rank : β → α)
    (f_slot : β → γ) (g_slot : γ → β)
    (f_cobs : γ → δ) (g_cobs : δ → γ)
    (f_traj : δ → ε) (g_traj : ε → δ)
    (f_pixel : ε → ζ) (g_pixel : ζ → ε)
    (h_rank : ∀ x, g_rank (f_rank x) = x)
    (h_slot : ∀ x, g_slot (f_slot x) = x)
    (h_cobs : ∀ x, g_cobs (f_cobs x) = x)
    (h_traj : ∀ x, g_traj (f_traj x) = x)
    (h_pixel : ∀ x, g_pixel (f_pixel x) = x) :
    (g_rank ∘ g_slot ∘ g_cobs ∘ g_traj ∘ g_pixel) ∘
      (f_pixel ∘ f_traj ∘ f_cobs ∘ f_slot ∘ f_rank) = id := by
  funext msg
  exact pipeline_five_stage_composition_left_inv
    f_rank g_rank f_slot g_slot f_cobs g_cobs f_traj g_traj f_pixel g_pixel
    h_rank h_slot h_cobs h_traj h_pixel msg

/-- **Theorem 2 (Receiver Mode & BarrierFill Independence)**:
    `decrypt3x128Cfg` depends only on `cfg.nonceBytes` (to slice `mainNonce` and `ilNonce`),
    and has **zero dependence** on `cfg.mode`, `cfg.barrierFill`, `cfg.tagStubSize`, or `cfg.drbgFillByte`.
    Because `W` and `H` are read from the wire header and `buildSubregionSchedule` selects
    `K_r ∈ [6, 10]` vs `K_r ∈ [8, 16]` purely from `regionPixels < 365`, any **Mode 1** wire
    decrypts under a **Mode 2** receiver config and vice versa. -/
theorem decrypt3x128Cfg_mode_barrierFill_independent
    (cfg1 cfg2 : PipelineConfig) (seeds : Array Seed128) (wire : ByteArray)
    (hNonce : cfg1.nonceBytes = cfg2.nonceBytes) :
    decrypt3x128Cfg cfg1 seeds wire = decrypt3x128Cfg cfg2 seeds wire := by
  unfold decrypt3x128Cfg
  rw [hNonce]

/-- Exhaustive boolean checker for per-channel Pixel Barrier round-trip across all
    `128 × 128 × 7 × 8 = 917,504` `(dataBits, channelXOR, rot, noisePos)` combinations
    and representative noise-carrier bytes. -/
def checkAllChannelEncodeDecode : Bool := Id.run do
  for dataBits in [:128] do
    let dU8 := UInt8.ofNat dataBits
    for channelXOR in #[0, 1, 42, 85, 127] do
      let xU8 := UInt8.ofNat channelXOR
      for rot in [:7] do
        for noisePos in [:8] do
          for orig in #[0x00, 0x5A, 0xA5, 0xFF] do
            let enc := encodeChannelByte dU8 xU8 rot noisePos orig
            let dec := decodeChannelByte enc xU8 rot noisePos
            if dec != dU8 then return false
  return true

/-- **Theorem 3 (Per-Channel Pixel Barrier Round-Trip)**:
    `decodeChannelByte` is the exact left inverse of `encodeChannelByte` across all 7-bit data values,
    rotations `0..6`, noise positions `0..7`, and arbitrary carrier noise bits (`0` or `1`). -/
theorem decodeChannelByte_encodeChannelByte_verified :
    checkAllChannelEncodeDecode = true := by native_decide

/-- `nonceSplitOffsets n` partitions `n` bytes across the 3 lanes (`l0 + l1 + l2 = n`). -/
theorem nonceSplitOffsets_sum (n : Nat) :
    let ((l0, l1, l2), _) := nonceSplitOffsets n
    l0 + l1 + l2 = n := by
  simp only [nonceSplitOffsets]
  split <;> split <;> omega

/-- Canonical nonce split lengths for 128-bit (`16 B`), 256-bit (`32 B`), and 512-bit (`64 B`) nonces. -/
theorem nonceSplitOffsets_canonical :
    (nonceSplitOffsets 16).1 = (6, 5, 5) ∧
    (nonceSplitOffsets 32).1 = (11, 11, 10) ∧
    (nonceSplitOffsets 64).1 = (22, 21, 21) := by
  decide

/-- Canonical `minPixelsAuth` floor for 128-bit seeds across 512-bit (`8` words), 1024-bit (`16` words),
    and 2048-bit (`32` words) keys (`seed128.go:MinPixelsAuth`): `183`, `365`, and `730` pixels. -/
theorem minPixelsAuth_canonical :
    minPixelsAuth 512 = 183 ∧
    minPixelsAuth 1024 = 365 ∧
    minPixelsAuth 2048 = 730 := by
  decide

/-- 7-bit rotation `rotateBits7U8` is inverted by rotating by `(7 - (r % 7)) % 7` on all 7-bit values `v ∈ Fin 128`
    and rotation offsets `r ∈ Fin 7`. -/
theorem rotateBits7U8_roundtrip (v : Fin 128) (r : Fin 7) :
    rotateBits7U8 (rotateBits7U8 v.val.toUInt8 r.val) ((7 - (r.val % 7)) % 7) = v.val.toUInt8 := by
  revert v r
  decide

/-- Channel-byte bit-insertion (preserving the carrier noise bit at `noisePos`) is inverted by
    bit-extraction for every carrier bit `noiseBit : Bool`, 7-bit payload `d ∈ Fin 128`,
    and `noisePos ∈ Fin 8`. -/
theorem channelBitInsertExtract128_roundtrip (noiseBit : Bool) (d : Fin 128) (noisePos : Fin 8) :
    let orig8 : UInt8 := if noiseBit then (1 : UInt8) <<< noisePos.val.toUInt8 else 0
    decodeChannelByte (encodeChannelByte d.val.toUInt8 0 0 noisePos.val orig8)
      0 0 noisePos.val = d.val.toUInt8 := by
  revert noiseBit d noisePos
  decide

/-- Universal per-channel Pixel Barrier round-trip across all 7-bit data `d`, 7-bit masks `m`,
    rotations `r ∈ Fin 7`, noise positions `np ∈ Fin 8`, and carrier bits `noiseBit : Bool`
    (inherited from `ITB.PixelBarrier`). -/
theorem pixelChannel128_roundtrip (d m : BitVec 7) (r : Fin 7) (np : Fin 8) (noiseBit : Bool) :
    ITB.PixelBarrier.decodeChannel (ITB.PixelBarrier.encodeChannel d m r np noiseBit) m r np = d :=
  ITB.PixelBarrier.decode_encode_id d m r np noiseBit

/-- `invFullWidthFold` and `fullWidthFold` form an exact 128-bit bijection over `BitVec 64 × BitVec 64`
    for all Layer I (`0x05`) and Layer II (`0x06`) schedule words (inherited from `ITB.Desync`). -/
theorem fullWidthFold128_bijection (hLo hHi w0 w1 : BitVec 64) :
    ITB.Desync.invFullWidthFold (ITB.Desync.fullWidthFold hLo hHi).1 (ITB.Desync.fullWidthFold hLo hHi).2 = (hLo, hHi) ∧
    ITB.Desync.fullWidthFold (ITB.Desync.invFullWidthFold w0 w1).1 (ITB.Desync.invFullWidthFold w0 w1).2 = (w0, w1) :=
  ITB.Desync.fullWidthFold_bijection hLo hHi w0 w1

/-- Layer II (`0x06`) cyclic shift inversion (`invLaneSlotShift` is the exact two-sided inverse
    of `laneSlotShift` on `[0, m)`, and `desyncBeta0 m r0 ≠ desyncBeta1 m r0 r1` for all `m ≥ 2`). -/
theorem desyncLaneSlotShift128_roundtrip (m beta j r0 r1 : Nat) (hm : 2 ≤ m) (hb : beta < m) (hj : j < m) :
    ITB.Desync.invLaneSlotShift m beta (ITB.Desync.laneSlotShift m beta j) = j ∧
    ITB.Desync.laneSlotShift m beta (ITB.Desync.invLaneSlotShift m beta j) = j ∧
    ITB.Desync.desyncBeta0 m r0 ≠ ITB.Desync.desyncBeta1 m r0 r1 :=
  ⟨ITB.Desync.laneSlotShift_left_inv m beta j hb hj,
   ITB.Desync.laneSlotShift_right_inv m beta j hb hj,
   ITB.Desync.desync_beta0_ne_beta1 m r0 r1 hm⟩

/-- Layer I (`0x05`) sub-region cyclic step inversion (`invSubregionStep` is the exact two-sided
    inverse of `subregionStep` on `[0, M)`). -/
theorem subregionStep128_roundtrip (M s q : Nat) (hs : s < M) (hq : q < M) :
    ITB.Desync.invSubregionStep M s (ITB.Desync.subregionStep M s q) = q ∧
    ITB.Desync.subregionStep M s (ITB.Desync.invSubregionStep M s q) = q :=
  ⟨ITB.Desync.subregionStep_left_inv M s q hs hq,
   ITB.Desync.subregionStep_right_inv M s q hs hq⟩

/-- Single-correction Euclidean exactness of 48-bit reciprocal division `divB` and `modA`
    for all 64-bit inputs `X < 2^64` (inherited from `ITB.SplitRank`). -/
theorem splitRank48Recip128_exact (X : Nat) (hX : X < 2 ^ 64) :
    (let qHat := (X * ITB.SplitRank.interlockB48Recip) / 2 ^ 93
     let rem := X - qHat * ITB.SplitRank.interlockB48
     let q := if rem ≥ ITB.SplitRank.interlockB48 then qHat + 1 else qHat
     let r := if rem ≥ ITB.SplitRank.interlockB48 then rem - ITB.SplitRank.interlockB48 else rem
     qHat * ITB.SplitRank.interlockB48 ≤ X ∧ X = q * ITB.SplitRank.interlockB48 + r ∧ r < ITB.SplitRank.interlockB48) ∧
    (let qHat := (X * ITB.SplitRank.interlockA48Recip) / 2 ^ 105
     let rem := X - qHat * ITB.SplitRank.interlockA48
     let q := if rem ≥ ITB.SplitRank.interlockA48 then qHat + 1 else qHat
     let r := if rem ≥ ITB.SplitRank.interlockA48 then rem - ITB.SplitRank.interlockA48 else rem
     qHat * ITB.SplitRank.interlockA48 ≤ X ∧ X = q * ITB.SplitRank.interlockA48 + r ∧ r < ITB.SplitRank.interlockA48) :=
  ⟨ITB.SplitRank.divB48_single_correction_exact X hX,
   ITB.SplitRank.modA48_single_correction_exact X hX⟩

/-- 48-bit Rank Barrier reciprocal constants match `A48 = C(48, 16)` and `B48 = C(32, 16)`
    with certified floor reciprocals `⌊2^105 / A48⌋` and `⌊2^93 / B48⌋` (from `ITB.SplitRank`). -/
theorem splitRank48Recip128_constants :
    ITB.SplitRank.interlockA48 = ITB.RankBarrier.A48 ∧
    ITB.SplitRank.interlockB48 = ITB.RankBarrier.B48 ∧
    ITB.SplitRank.interlockA48Recip = (2 ^ (64 + ITB.SplitRank.interlockA48Shift)) / ITB.SplitRank.interlockA48 ∧
    ITB.SplitRank.interlockB48Recip = (2 ^ (64 + ITB.SplitRank.interlockB48Shift)) / ITB.SplitRank.interlockB48 :=
  ⟨ITB.SplitRank.interlockA48Recip_eq_floor_div.1,
   ITB.SplitRank.interlockB48Recip_eq_floor_div.1,
   ITB.SplitRank.interlockA48Recip_eq_floor_div.2.2.1,
   ITB.SplitRank.interlockB48Recip_eq_floor_div.2.2.1⟩

-- ============================================================================
-- § 10. Deterministic Test Generators & Bit-Exact Go KAT Verification Suite
-- ============================================================================

/-- Deterministic seed constructor matching `makeSeed(slot, keyBits)` in the Go KAT generator. -/
def mkDeterministicSeed128 (slot keyBits : Nat) : Seed128 := Id.run do
  let n := keyBits / 64
  let mut comps := Array.mkEmpty n
  let sBase : UInt64 := (UInt64.ofNat (slot + 1)) * 0x0102030405060708
  for i in [:n] do
    let v := sBase + (UInt64.ofNat i) * 0x1111111111111111
    comps := comps.push v
  return ⟨comps⟩

/-- Deterministic 8-seed constellation for a given `keyBits ∈ {512, 1024, 2048}`. -/
def mkDeterministicSeeds8 (keyBits : Nat) : Array Seed128 := Id.run do
  let mut seeds := Array.mkEmpty 8
  for slot in [:8] do
    seeds := seeds.push (mkDeterministicSeed128 slot keyBits)
  return seeds

/-- Deterministic plaintext generator matching `mkDeterministicBytes(n)` in Go (`0x00` every 11th byte). -/
def mkDeterministicBytes (n : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity n
  for i in [:n] do
    if i % 11 == 3 then
      out := out.push 0x00
    else
      out := out.push (UInt8.ofNat ((i * 13 + 7) % 256))
  return out

/-- Deterministic byte sequence `[base, base+1, ..., base+n-1]` for nonces and prefixes. -/
def mkSeqBytes (base : Nat) (n : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity n
  for i in [:n] do
    out := out.push (UInt8.ofNat ((base + i) % 256))
  return out

/-- **KAT 1 (`SipHash-2-4-128` RFC Vector)**:
    Matches Go's `hashes.SipHash24()` on the 15-byte RFC test vector `[0x00..0x0e]`. -/
theorem kat_siphash24_rfc_vector :
    sipHash24_128 0x0706050403020100 0x0f0e0d0c0b0a0908 (mkSeqBytes 0 15) =
      (0x11a8b03399e99354, 0xd9c3cf970fec087e) := by native_decide

/-- **KAT 2 (`Seed128.ChainHash128` 1024-Bit Vector)**:
    Matches Go's `seeds[0].ChainHash128(msg)` bit-for-bit. -/
theorem kat_chainHash128_seed0 :
    chainHash128 (mkDeterministicSeed128 0 1024) (mkSeqBytes 0 15) =
      (0xf70610832a2a8e10, 0x6f61ed5a96ea5673) := by native_decide

/-- Stage-level round-trip verification on a 96-byte multi-chunk message (`M = 17 ≥ 16` chunks)
    covering framing, 48-bit Rank Barrier, Layer II (`0x06`) slot desynchronization,
    interlock-nonce split/recovery, and COBS framing. -/
def checkStageByStageRoundtrip96 : Bool :=
  let seeds := mkDeterministicSeeds8 1024
  let lockSeed := seeds.getD 1 ⟨#[]⟩
  let ilNonce := mkSeqBytes 0x10 16
  let pt := mkDeterministicBytes 96
  let (raw0, raw1, raw2) := splitTriple48Raw lockSeed ilNonce pt
  let (des0, des1, des2) := desyncLaneEncrypt lockSeed ilNonce raw0 raw1 raw2
  let (withN0, withN1, withN2) := prependInterlockNonce ilNonce des0 des1 des2
  let (c0, c1, c2) := (cobsEncode withN0, cobsEncode withN1, cobsEncode withN2)
  let (d0, d1, d2) := (cobsDecode c0, cobsDecode c1, cobsDecode c2)
  let (recNonce, l0, l1, l2) := recoverInterlockNonce 16 d0 d1 d2
  let (u0, u1, u2) := desyncLaneDecrypt lockSeed recNonce l0 l1 l2
  let recPt := interleaveTriple48Raw lockSeed recNonce u0 u1 u2
  (recNonce == ilNonce) && (u0 == raw0) && (u1 == raw1) && (u2 == raw2) && (recPt == pt)

/-- **Theorem 4a (COBS Framing Round-Trip on Zero-Run Payload)**:
    `cobsDecode (cobsEncode pt) == pt` on the 96-byte zero-run payload. -/
theorem stage_cobs128_roundtrip_kat :
    let pt := mkDeterministicBytes 96
    cobsDecode (cobsEncode pt) = pt := by native_decide

/-- **Theorem 4b (Interlock Nonce Split & Recovery Round-Trip across 16/32/64 B)**:
    `recoverInterlockNonce` recovers `ilNonce` and all three lane payloads across all shipped nonce widths. -/
theorem stage_nonceSplit128_roundtrip_kat :
    let pt0 := mkDeterministicBytes 32
    let pt1 := mkDeterministicBytes 32
    let pt2 := mkDeterministicBytes 32
    ([16, 32, 64].all fun nb =>
      let n := mkSeqBytes 0x10 nb
      let (w0, w1, w2) := prependInterlockNonce n pt0 pt1 pt2
      recoverInterlockNonce nb w0 w1 w2 == (n, pt0, pt1, pt2)) = true := by native_decide

/-- **Theorem 4 (Stage-by-Stage Executable Round-Trip on Multi-Chunk Payload)**:
    Each intermediate representation (`ilNonce`, `raw0`, `raw1`, `raw2`, and `pt`) is recovered
    bit-for-bit across COBS, `recoverInterlockNonce`, Layer II `desyncLaneDecrypt`, and `interleaveTriple48Raw`. -/
theorem stage_by_stage_roundtrip_96_verified :
    checkStageByStageRoundtrip96 = true := by native_decide

/-- Expected Go `Encrypt3x128Cfg` wire hex for `512`-bit key, `128`-bit nonce, **Mode 2** (`15×15` container, 1,852 bytes). -/
def katWire512Mode2Hex : String :=
  "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f202122232425262728292a2b2c2d2e2f000f000f480aa989d8faa352c7e5fb4e" ++
  "fa5ec564caabae9e7ccacf6903871257ae5636cfaf0333d78e82c39a8e17626f3a3bea4afe79dae7d766e0fe12781a083246017b426c186b48133d54c46a1254" ++
  "48c07ac0129b83aba9193a3b175fba1df4595fb7b6333d1b7372d4b4923bbb262f83f3ea94ae487834ee3a32470ed71ec70bff9b53367ac2964202bbdd55f87b" ++
  "c8c84dccf25b335b745c93780227555d6c3a163fdb7071b0f1a13b22df73c2a7174e97ebe0cf7342e66e54e1364b7d2626613119a782d3a7f223e3c7b27e94dd" ++
  "14f5b2b9e18148d97ba310d0357c5573655d03084b2c70655a16430756d3931a7202ca77ce46fd4f4ae1d0403b1e231247106c374265f3425268d8e102aaa17b" ++
  "50b05ba1a83cfe1fdc6dc86cd35aecf27259dc4b823018925042dad07eb675d1fe90d9b3b130fbf8116191430d520d890d88d24f68181d1f221e657958f9be18" ++
  "f675f4bc9d13855c08ce935b5b2c3a4c7a273032c99d393e0a4c7d7d1f1221093c287372e9caecdb6264c360d7f3fbbe907ed1311e109bbe1b751113fe4e4e56" ++
  "ffdd51611673d2b07ab253fb2320543b2b3c2f46b21e1cfa28463002ff3bbf7a32dcbc71cfebdb524b9366124c647a321a9c125c226bc10112a83360333f822b" ++
  "462b36c6f49957131833df393e500b262a320714ffd0167b169cd13d434d5fd64ec878d87a23f118d9f821404057575ec6d4c611ca62546450b8e0383a1febc9" ++
  "ef79ac5b0a0207220a40173146755a2c72035d76c86c294ffdf9eebcde1a224b9bba234ac2dbd54b757aec7b18427e4074a224f28844906e5c2e0adeee6e734d" ++
  "ef79f5794f4f48f9cdec6a68f0715c6340f5d37c4140d251f67cc26554f0c476e44142650e1b4b5f1bc2127a5300d1685bc04139d43a7ebb3b333175c0ea50f9" ++
  "02624073da53d8bbd0d33ad9de461cea4a0834961afe97515c5177f6595be24445deef5114461c067a18ea6ae4685444d2c0c0b27c3dd6f73e151b369d38afde" ++
  "28fd7ef92ac628703ee6e65690a8d43256d8581efd9b0d4f6aa9bcac9ad2d0c0aeaccea444f6ff5e7c694a521280e0e0bcb8340aba75b0bf1554dc17ce6363da" ++
  "434fd3f7e77d4dc1f944e5f4abfbda10900a4340eeab9aeb592eaedd5fda58db1b9ad298b27e973192bf797be07c2cd6d26e2a345e4acd4252c440fc38ef791d" ++
  "7a0a389e864410b4c83066825e20bc9c76387eac33b309e1ca198b124d77444e53ced85796bea3bae67ea61fe88b7b02fa11bb9af6ca9a6cacbe16624a16e32b" ++
  "c31ff7c72271ea2bf3a899328e424a64fa3ee8c4113e5814b299f3d8b01c5424405e34d6d5583e7d9890f57a58cb0213544c00de01dbe9887aa001607eef65db" ++
  "ef6e6879ebf14a090949c37181cd081848c08c09bac3b2776eb2da23676ee678ebedee548899c8c9f993d2aa533a0f6265603601283abe502af432a6f2ddf499" ++
  "fbfd9ab75e4efb7c59d6cbe8df780b6a692e494ccd8ceaeb1ffc6b4e0d1b1072325c7c320d8b02170dc5dfdc325eb2189fdbf6314ccac9fd5a6e54f0defae968" ++
  "cedad67d0c4acf188f0d590cc9f89203a99248f8eccc7e7ceee07d53cd6a7ed85e9918ebb0bef1dc75dc331c518918e13a804bd2f2b0e1a113c3e062c84c4812" ++
  "104c0e8c45100c0852cf84db4efe505c3452a4f83e928f529af35f7e5353f60b52d7ea5f3c9e1b09af1d7d483ddff95ccfe8baad33b9620a888a9268d7e558fb" ++
  "4dd8ffe3ca47c69e93dd8196b37833dc1bfcbaf17a6bfbc82cd8b9be14975dd21307905fa0aa9252ba83b9e029f2ea4923b80861e8e4654e47d06d5ae326e617" ++
  "e36a17b30f91495255d5d8927bb831b1d15a9098d3b12240b292dbf1f84aea9036c2427666ca6c6575d8d077929b710ae31828f9823a66b27cbefaf05f9c9f4b" ++
  "fe0c4cb8635b0b473331292fdf73de4b6b5b5c5f1f57686e3d18736d5a3851582b1744357646846e404a6294061c3446d0b834fc3f6e6b674b0ab39a170d4400" ++
  "c48cdac09217afe7afdecf3f7c01075f546c4d580756da7a06c63f3a1c0c585b3ece3ac9d2a0c83bf9a15262767e34d2b6c4a80e9e44cad6481ddbc2fed2dc98" ++
  "1951579923c21aa151e0baf0641f626f3b004161d2159053f7773b5016409a5ccb1b581aee3ac89c8c2c38d67b91bb351e12551c73fcb3735dd033931a3afe22" ++
  "97f392fa5804cfcd9fcb1a9507bfa3420a625f8639bfdd92bad135bca28a9159b05388d8437eb64b4b77b283286b99d148e03140075b00450c7e6911119ab63b" ++
  "1851ddf23fbf36f0b8399d5c2fdadaf8dd6b7d28e67c5858cc8a86781fcdca882aff3ccb8088e6ccbc60308e08067c4864188c12c15fece1f7cad7c14a046540" ++
  "40233a6b74593430dfb1f5770c6c187fbb5d9f7a1a1d9051719cf55429255e31294040780e5f810117c55045f8e2ead380b3a36211d381228848f200d54ef3d8d" ++
  "cc1e06893cad0eb484b91a2c34b41617b78c2ce53c31e93171e7a5f335c5b59d8be39f111011d006a4d6a2f8cce9fce54091d924830cb7abbf9f3b2"

/-- **KAT 3 (Full Byte-for-Byte Wire Equality & Cross-Mode Decrypt)**:
    Lean's `encrypt3x128Deterministic` produces the **exact same 1,852 wire bytes** as Go's
    `itb.Encrypt3x128Cfg` on the 96-byte multi-chunk message (`M = 17 ≥ 16`), and `decrypt3x128Cfg`
    (even when configured with `mode := 1, barrierFill := 32`) recovers the exact plaintext. -/
theorem kat_go_512_mode2_wire_byte_exact :
    let cfgEnc : PipelineConfig := { nonceBits := 128, barrierFill := 1, mode := 2 }
    let cfgDec : PipelineConfig := { nonceBits := 128, barrierFill := 32, mode := 1 }
    let seeds := mkDeterministicSeeds8 512
    let pt := mkDeterministicBytes 96
    let wire := encrypt3x128Deterministic cfgEnc seeds (mkSeqBytes 0x30 32) (mkSeqBytes 0x20 16) (mkSeqBytes 0x10 16) pt
    (wire == fromHex katWire512Mode2Hex) && (decrypt3x128Cfg cfgDec seeds wire == some pt) = true := by
  native_decide

/-- Run one deterministic encrypt + cross-mode decrypt check and compare `(wire.size, dLo, dHi)`
    against Go's `itb.Encrypt3x128Cfg` / `itb.Decrypt3x128Cfg`. -/
def checkParamKatEntry (keyBits nonceBits mode msgLen wantWireLen : Nat) (wantLo wantHi : UInt64) : Bool :=
  let cfgEnc : PipelineConfig := { nonceBits, barrierFill := 1, mode }
  let otherMode := if mode == 1 then 2 else 1
  let cfgDec : PipelineConfig := { nonceBits, barrierFill := 32, mode := otherMode }
  let nBytes := nonceBits / 8
  let seeds := mkDeterministicSeeds8 keyBits
  let pt := mkDeterministicBytes msgLen
  let wire := encrypt3x128Deterministic cfgEnc seeds (mkSeqBytes 0x30 32) (mkSeqBytes 0x20 nBytes) (mkSeqBytes 0x10 nBytes) pt
  let (dLo, dHi) := sipHash24_128 0x0706050403020100 0x0f0e0d0c0b0a0908 wire
  let dec := decrypt3x128Cfg cfgDec seeds wire
  (wire.size == wantWireLen) && (dLo == wantLo) && (dHi == wantHi) && (dec == some pt)

/-- All 18 parameter combinations `(keyBits ∈ {512, 1024, 2048}) × (nonceBits ∈ {128, 256, 512}) × (Mode ∈ {1, 2})`
    at `msgLen = 96` (`M = 17` chunks) captured from Go's `itb.Encrypt3x128Cfg`. -/
def katParamMatrix : List (Nat × Nat × Nat × Nat × UInt64 × UInt64) := [
  (512, 128, 1, 5052, 0x28239d64ba5282ad, 0xcd5c98d7942dfb16),
  (512, 128, 2, 1852, 0xffdd41019d6c73ec, 0x12fdb43590b7420f),
  (512, 256, 1, 5068, 0xfc11ac1671353130, 0x0b6155981bb6367c),
  (512, 256, 2, 1868, 0xf840e4c4bd745523, 0xfde871f564b11c4c),
  (512, 512, 1, 5100, 0xbfc955b7a7b6429e, 0xbb60335ada784ca7),
  (512, 512, 2, 1900, 0xb3be4c12a28c1e14, 0x91cc4ca8aa8b935e),
  (1024, 128, 1, 9852, 0xa497b0938ac52c3a, 0x27e70be61d73ae18),
  (1024, 128, 2, 3580, 0x6bc8f1f38a583c72, 0xa532c8bd044d8122),
  (1024, 256, 1, 9868, 0x15dfcc39535f2f7b, 0x816aab6c597f4f8e),
  (1024, 256, 2, 3596, 0xe627fcbb46f94597, 0x4b9c2b4e26ab6823),
  (1024, 512, 1, 9900, 0x4f51dc293f6b320b, 0x93999334990631b6),
  (1024, 512, 2, 3628, 0x0afeef28abb65e69, 0xe72645c371eb0118),
  (2048, 128, 1, 18484, 0x278db54ac4588f9b, 0xdb1327cb2be0f06a),
  (2048, 128, 2, 6780, 0x349c3a6aa9f89c64, 0xe58e71d4557a70c6),
  (2048, 256, 1, 18500, 0x4e7d11edb9dfe2b9, 0x23a5326ee8161bb2),
  (2048, 256, 2, 6796, 0x556931ee39f484f1, 0x32a757ee718ab0ac),
  (2048, 512, 1, 18532, 0xa9978c8a8a98176b, 0xdd53e714fba23192),
  (2048, 512, 2, 6828, 0xa2ad83017b7df871, 0x98e459b469891b01)
]

/-- **KAT 4 (All 18 `(keyBits, nonceBits, Mode)` Configurations)**:
    Verifies bit-exact Go wire digests and cross-mode decrypt round-trip across all
    3 key sizes (`512`, `1024`, `2048` bits), all 3 nonce sizes (`128`, `256`, `512` bits),
    and both **Mode 1** and **Mode 2**. -/
theorem kat_go_param_matrix_all_18_exact :
    (katParamMatrix.all fun (kb, nb, mode, wLen, lo, hi) =>
      checkParamKatEntry kb nb mode 96 wLen lo hi) = true := by native_decide

/-- Payload size ladder (`1 B`, `96 B`, `512 B`, `1 KB`, `4 KB`, `16 KB`) across **Mode 1** & **Mode 2**
    (`1024`-bit key, `128`-bit nonce) captured from Go's `itb.Encrypt3x128Cfg`. -/
def katSizeLadderDigests : List (Nat × Nat × Nat × UInt64 × UInt64) := [
  (1, 1, 9852, 0x2e96ebf9247f60da, 0x00adb7d11babdbd7),
  (1, 2, 3580, 0xff905915f228ba93, 0xda2637e939438847),
  (96, 1, 9852, 0xa497b0938ac52c3a, 0x27e70be61d73ae18),
  (96, 2, 3580, 0x6bc8f1f38a583c72, 0xa532c8bd044d8122),
  (512, 1, 9852, 0xb8c6223f39e77a5f, 0xd4db3d576827b709),
  (512, 2, 3580, 0x119b3ce981c00142, 0xd4f38050ac658450),
  (1024, 1, 9852, 0x853bc67de6b9709f, 0x7f518b0052b48e73),
  (1024, 2, 3580, 0x83382b785a9470dc, 0x754ea8e65a5dc9a2),
  (4096, 1, 9852, 0x06d0e34641d654dd, 0x526e8c26ad9f11b0),
  (4096, 2, 5460, 0x3175c129de538ba8, 0xd232dac8ae21d2c2),
  (16384, 1, 20052, 0xf4188b55bcf3506f, 0x349531616b169db9),
  (16384, 2, 20052, 0xf4188b55bcf3506f, 0x349531616b169db9)
]

/-- **KAT 5 (End-to-End Encrypt/Decrypt Payload Size Ladder `1 B` .. `16 KB`)**:
    Verifies bit-exact Go wire digests and round-trip decryption across `1 B`, `96 B`, `512 B`,
    `1 KB` (`1024`), `4 KB` (`4096`), and `16 KB` (`16384`) in both **Mode 1** and **Mode 2**. -/
theorem kat_go_size_ladder_encrypt_decrypt_exact :
    (katSizeLadderDigests.all fun (sz, mode, wLen, lo, hi) =>
      checkParamKatEntry 1024 128 mode sz wLen lo hi) = true := by native_decide

/-- Full 198-cell container side-length ladder across all 11 canonical payload sizes
    (`1 B`, `512 B`, `1 KB`, `4 KB`, `16 KB`, `128 KB`, `512 KB`, `1 MB`, `4 MB`, `16 MB`, `64 MB`)
    × `(keyBits ∈ {512, 1024, 2048})` × `(nonceBits ∈ {128, 256, 512})` × `(Mode ∈ {1, 2})`. -/
def katFullContainerSideLadder : List (Nat × Nat × Nat × Nat × Nat) := [
  (1, 512, 128, 1, 25), (1, 512, 128, 2, 15), (1, 512, 256, 1, 25), (1, 512, 256, 2, 15),
  (1, 512, 512, 1, 25), (1, 512, 512, 2, 15), (1, 1024, 128, 1, 35), (1, 1024, 128, 2, 21),
  (1, 1024, 256, 1, 35), (1, 1024, 256, 2, 21), (1, 1024, 512, 1, 35), (1, 1024, 512, 2, 21),
  (1, 2048, 128, 1, 48), (1, 2048, 128, 2, 29), (1, 2048, 256, 1, 48), (1, 2048, 256, 2, 29),
  (1, 2048, 512, 1, 48), (1, 2048, 512, 2, 29),
  (512, 512, 128, 1, 25), (512, 512, 128, 2, 15), (512, 512, 256, 1, 25), (512, 512, 256, 2, 15),
  (512, 512, 512, 1, 25), (512, 512, 512, 2, 15), (512, 1024, 128, 1, 35), (512, 1024, 128, 2, 21),
  (512, 1024, 256, 1, 35), (512, 1024, 256, 2, 21), (512, 1024, 512, 1, 35), (512, 1024, 512, 2, 21),
  (512, 2048, 128, 1, 48), (512, 2048, 128, 2, 29), (512, 2048, 256, 1, 48), (512, 2048, 256, 2, 29),
  (512, 2048, 512, 1, 48), (512, 2048, 512, 2, 29),
  (1024, 512, 128, 1, 25), (1024, 512, 128, 2, 15), (1024, 512, 256, 1, 25), (1024, 512, 256, 2, 15),
  (1024, 512, 512, 1, 25), (1024, 512, 512, 2, 15), (1024, 1024, 128, 1, 35), (1024, 1024, 128, 2, 21),
  (1024, 1024, 256, 1, 35), (1024, 1024, 256, 2, 21), (1024, 1024, 512, 1, 35), (1024, 1024, 512, 2, 21),
  (1024, 2048, 128, 1, 48), (1024, 2048, 128, 2, 29), (1024, 2048, 256, 1, 48), (1024, 2048, 256, 2, 29),
  (1024, 2048, 512, 1, 48), (1024, 2048, 512, 2, 29),
  (4096, 512, 128, 1, 26), (4096, 512, 128, 2, 26), (4096, 512, 256, 1, 26), (4096, 512, 256, 2, 26),
  (4096, 512, 512, 1, 26), (4096, 512, 512, 2, 26), (4096, 1024, 128, 1, 35), (4096, 1024, 128, 2, 26),
  (4096, 1024, 256, 1, 35), (4096, 1024, 256, 2, 26), (4096, 1024, 512, 1, 35), (4096, 1024, 512, 2, 26),
  (4096, 2048, 128, 1, 48), (4096, 2048, 128, 2, 29), (4096, 2048, 256, 1, 48), (4096, 2048, 256, 2, 29),
  (4096, 2048, 512, 1, 48), (4096, 2048, 512, 2, 29),
  (16384, 512, 128, 1, 50), (16384, 512, 128, 2, 50), (16384, 512, 256, 1, 50), (16384, 512, 256, 2, 50),
  (16384, 512, 512, 1, 50), (16384, 512, 512, 2, 50), (16384, 1024, 128, 1, 50), (16384, 1024, 128, 2, 50),
  (16384, 1024, 256, 1, 50), (16384, 1024, 256, 2, 50), (16384, 1024, 512, 1, 50), (16384, 1024, 512, 2, 50),
  (16384, 2048, 128, 1, 50), (16384, 2048, 128, 2, 50), (16384, 2048, 256, 1, 50), (16384, 2048, 256, 2, 50),
  (16384, 2048, 512, 1, 50), (16384, 2048, 512, 2, 50),
  (131072, 512, 128, 1, 139), (131072, 512, 128, 2, 139), (131072, 512, 256, 1, 139), (131072, 512, 256, 2, 139),
  (131072, 512, 512, 1, 139), (131072, 512, 512, 2, 139), (131072, 1024, 128, 1, 139), (131072, 1024, 128, 2, 139),
  (131072, 1024, 256, 1, 139), (131072, 1024, 256, 2, 139), (131072, 1024, 512, 1, 139), (131072, 1024, 512, 2, 139),
  (131072, 2048, 128, 1, 139), (131072, 2048, 128, 2, 139), (131072, 2048, 256, 1, 139), (131072, 2048, 256, 2, 139),
  (131072, 2048, 512, 1, 139), (131072, 2048, 512, 2, 139),
  (524288, 512, 128, 1, 276), (524288, 512, 128, 2, 276), (524288, 512, 256, 1, 276), (524288, 512, 256, 2, 276),
  (524288, 512, 512, 1, 276), (524288, 512, 512, 2, 276), (524288, 1024, 128, 1, 276), (524288, 1024, 128, 2, 276),
  (524288, 1024, 256, 1, 276), (524288, 1024, 256, 2, 276), (524288, 1024, 512, 1, 276), (524288, 1024, 512, 2, 276),
  (524288, 2048, 128, 1, 276), (524288, 2048, 128, 2, 276), (524288, 2048, 256, 1, 276), (524288, 2048, 256, 2, 276),
  (524288, 2048, 512, 1, 276), (524288, 2048, 512, 2, 276),
  (1048576, 512, 128, 1, 389), (1048576, 512, 128, 2, 389), (1048576, 512, 256, 1, 389), (1048576, 512, 256, 2, 389),
  (1048576, 512, 512, 1, 389), (1048576, 512, 512, 2, 389), (1048576, 1024, 128, 1, 389), (1048576, 1024, 128, 2, 389),
  (1048576, 1024, 256, 1, 389), (1048576, 1024, 256, 2, 389), (1048576, 1024, 512, 1, 389), (1048576, 1024, 512, 2, 389),
  (1048576, 2048, 128, 1, 389), (1048576, 2048, 128, 2, 389), (1048576, 2048, 256, 1, 389), (1048576, 2048, 256, 2, 389),
  (1048576, 2048, 512, 1, 389), (1048576, 2048, 512, 2, 389),
  (4194304, 512, 128, 1, 777), (4194304, 512, 128, 2, 777), (4194304, 512, 256, 1, 777), (4194304, 512, 256, 2, 777),
  (4194304, 512, 512, 1, 777), (4194304, 512, 512, 2, 777), (4194304, 1024, 128, 1, 777), (4194304, 1024, 128, 2, 777),
  (4194304, 1024, 256, 1, 777), (4194304, 1024, 256, 2, 777), (4194304, 1024, 512, 1, 777), (4194304, 1024, 512, 2, 777),
  (4194304, 2048, 128, 1, 777), (4194304, 2048, 128, 2, 777), (4194304, 2048, 256, 1, 777), (4194304, 2048, 256, 2, 777),
  (4194304, 2048, 512, 1, 777), (4194304, 2048, 512, 2, 777),
  (16777216, 512, 128, 1, 1553), (16777216, 512, 128, 2, 1553), (16777216, 512, 256, 1, 1553), (16777216, 512, 256, 2, 1553),
  (16777216, 512, 512, 1, 1553), (16777216, 512, 512, 2, 1553), (16777216, 1024, 128, 1, 1553), (16777216, 1024, 128, 2, 1553),
  (16777216, 1024, 256, 1, 1553), (16777216, 1024, 256, 2, 1553), (16777216, 1024, 512, 1, 1553), (16777216, 1024, 512, 2, 1553),
  (16777216, 2048, 128, 1, 1553), (16777216, 2048, 128, 2, 1553), (16777216, 2048, 256, 1, 1553), (16777216, 2048, 256, 2, 1553),
  (16777216, 2048, 512, 1, 1553), (16777216, 2048, 512, 2, 1553),
  (67108864, 512, 128, 1, 3104), (67108864, 512, 128, 2, 3104), (67108864, 512, 256, 1, 3104), (67108864, 512, 256, 2, 3104),
  (67108864, 512, 512, 1, 3104), (67108864, 512, 512, 2, 3104), (67108864, 1024, 128, 1, 3104), (67108864, 1024, 128, 2, 3104),
  (67108864, 1024, 256, 1, 3104), (67108864, 1024, 256, 2, 3104), (67108864, 1024, 512, 1, 3104), (67108864, 1024, 512, 2, 3104),
  (67108864, 2048, 128, 1, 3104), (67108864, 2048, 128, 2, 3104), (67108864, 2048, 256, 1, 3104), (67108864, 2048, 256, 2, 3104),
  (67108864, 2048, 512, 1, 3104), (67108864, 2048, 512, 2, 3104)
]

/-- **KAT 6 (Full 198-Cell Container Sizing Ladder `1 B` .. `64 MB`)**:
    Verifies that `calcContainerSideForMsg` matches Go's `calcContainerSize3Cfg` across all 11
    canonical payload sizes (`1 B`, `512 B`, `1 KB`, `4 KB`, `16 KB`, `128 KB`, `512 KB`, `1 MB`,
    `4 MB`, `16 MB`, `64 MB`) × `keyBits ∈ {512, 1024, 2048}` × `nonceBits ∈ {128, 256, 512}` ×
    `Mode ∈ {1, 2}`. -/
theorem kat_full_container_side_ladder_exact :
    (katFullContainerSideLadder.all fun (sz, kb, nb, mode, wantSide) =>
      calcContainerSideForMsg sz kb nb mode == wantSide) = true := by native_decide

end ITB.PipelineSpec128
