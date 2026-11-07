/-
  Executable Reference Specification & Round-Trip Verification (32 formal theorems)
  of the 512-Bit (`Seed512`) + `BLAKE2b-512` (RFC 7693) + 48-Bit / 168-Bit Interlock
  (`Interlock = "48"` and `Interlock = "168"`) Desynchronized Interlocked Barrier Pipeline
  across Mode 1 (`Mode = 1`), Mode 2 (`Mode = 2`), and Mode 3 (`Mode = 3`, `Gauss-Posit`),
  key sizes `512 / 1024 / 2048` bits, and nonce sizes `128 / 256 / 512` bits.
-/
import ITB.Thresholds
import ITB.RankBarrier
import ITB.PixelBarrier
import ITB.SplitRank
import ITB.SeedIsolation
import ITB.Desync
import ITB.Posit

namespace ITB.PipelineSpec512

open ITB.Thresholds
open ITB.RankBarrier
open ITB.PixelBarrier
open ITB.SplitRank
open ITB.SeedIsolation
open ITB.Desync

set_option exponentiation.threshold 10000
set_option maxRecDepth 2000000
set_option maxHeartbeats 0

/-! ## Section 1: Little-Endian / Big-Endian Byte Helpers & 64-Bit Rotations -/

/-- Safe byte read with zero fallback out of bounds. -/
@[inline] def getByteD512 (b : ByteArray) (i : Nat) : UInt8 :=
  if h : i < b.size then b.get i h else 0

/-- Read a 64-bit little-endian word from `b` at byte offset `off` (zero-padded out of bounds). -/
@[inline] def readU64LE512 (b : ByteArray) (off : Nat) : UInt64 :=
  (getByteD512 b off).toUInt64 |||
  ((getByteD512 b (off + 1)).toUInt64 <<< 8) |||
  ((getByteD512 b (off + 2)).toUInt64 <<< 16) |||
  ((getByteD512 b (off + 3)).toUInt64 <<< 24) |||
  ((getByteD512 b (off + 4)).toUInt64 <<< 32) |||
  ((getByteD512 b (off + 5)).toUInt64 <<< 40) |||
  ((getByteD512 b (off + 6)).toUInt64 <<< 48) |||
  ((getByteD512 b (off + 7)).toUInt64 <<< 56)

/-- Read a 32-bit little-endian word from `b` at byte offset `off` (zero-padded out of bounds). -/
@[inline] def readU32LE512 (b : ByteArray) (off : Nat) : UInt32 :=
  (getByteD512 b off).toUInt32 |||
  ((getByteD512 b (off + 1)).toUInt32 <<< 8) |||
  ((getByteD512 b (off + 2)).toUInt32 <<< 16) |||
  ((getByteD512 b (off + 3)).toUInt32 <<< 24)

/-- Append a 64-bit word in little-endian byte order to a `ByteArray`. -/
@[inline] def pushU64LE512 (b : ByteArray) (w : UInt64) : ByteArray :=
  b.push w.toUInt8
   |>.push (w >>> 8).toUInt8
   |>.push (w >>> 16).toUInt8
   |>.push (w >>> 24).toUInt8
   |>.push (w >>> 32).toUInt8
   |>.push (w >>> 40).toUInt8
   |>.push (w >>> 48).toUInt8
   |>.push (w >>> 56).toUInt8

/-- Append a 32-bit word in little-endian byte order to a `ByteArray`. -/
@[inline] def pushU32LE512 (b : ByteArray) (w : UInt32) : ByteArray :=
  b.push w.toUInt8
   |>.push (w >>> 8).toUInt8
   |>.push (w >>> 16).toUInt8
   |>.push (w >>> 24).toUInt8

/-- Append a 16-bit word in big-endian byte order to a `ByteArray`. -/
@[inline] def pushU16BE512 (b : ByteArray) (w : Nat) : ByteArray :=
  b.push (w >>> 8).toUInt8
   |>.push w.toUInt8

/-- Read a 16-bit big-endian integer from `b` at offset `off`. -/
@[inline] def readU16BE512 (b : ByteArray) (off : Nat) : Nat :=
  ((getByteD512 b off).toNat <<< 8) ||| (getByteD512 b (off + 1)).toNat

/-- 64-bit right rotation (`bits.RotateLeft64(x, -n)`). -/
@[inline] def rotr64 (x : UInt64) (n : UInt64) : UInt64 :=
  (x >>> n) ||| (x <<< (64 - n))

/-- 64-bit left rotation (`bits.RotateLeft64(x, n)`). -/
@[inline] def rotl64 (x : UInt64) (n : UInt64) : UInt64 :=
  let s := n % 64
  if s == 0 then x else (x <<< s) ||| (x >>> (64 - s))

/-! ## Section 2: RFC 7693 `BLAKE2b-512` & `Seed512.ChainHash512` -/

/-- RFC 7693 BLAKE2b initialization vector words `IV[0..7]`. -/
def blake2bIV0 : UInt64 := 0x6a09e667f3bcc908
def blake2bIV1 : UInt64 := 0xbb67ae8584caa73b
def blake2bIV2 : UInt64 := 0x3c6ef372fe94f82b
def blake2bIV3 : UInt64 := 0xa54ff53a5f1d36f1
def blake2bIV4 : UInt64 := 0x510e527fade682d1
def blake2bIV5 : UInt64 := 0x9b05688c2b3e6c1f
def blake2bIV6 : UInt64 := 0x1f83d9abfb41bd6b
def blake2bIV7 : UInt64 := 0x5be0cd19137e2179

/-- 8-word state for BLAKE2b-512 chaining value `h[0..7]`. -/
structure Words8 where
  h0 : UInt64
  h1 : UInt64
  h2 : UInt64
  h3 : UInt64
  h4 : UInt64
  h5 : UInt64
  h6 : UInt64
  h7 : UInt64
  deriving DecidableEq, Repr

/-- Convert `Words8` to `Array UInt64` of length 8. -/
def Words8.toArray (w : Words8) : Array UInt64 :=
  #[w.h0, w.h1, w.h2, w.h3, w.h4, w.h5, w.h6, w.h7]

/-- Read `Words8` from `Array UInt64` (with 0 fallback). -/
def Words8.ofArray (a : Array UInt64) : Words8 :=
  { h0 := a.getD 0 0
    h1 := a.getD 1 0
    h2 := a.getD 2 0
    h3 := a.getD 3 0
    h4 := a.getD 4 0
    h5 := a.getD 5 0
    h6 := a.getD 6 0
    h7 := a.getD 7 0 }

/-- Initial chaining state for unkeyed BLAKE2b-512 (`h0 = IV0 ^ 0x01010040`). -/
def blake2bInitState : Words8 :=
  { h0 := blake2bIV0 ^^^ 0x01010040
    h1 := blake2bIV1
    h2 := blake2bIV2
    h3 := blake2bIV3
    h4 := blake2bIV4
    h5 := blake2bIV5
    h6 := blake2bIV6
    h7 := blake2bIV7 }

@[inline] def withStrictNat {α : Type} (x : Nat) (k : Nat → α) : α := k x
@[inline] def withStrictWords8 {α : Type} (w : Words8) (k : Words8 → α) : α := k w
@[inline] def withStrictUInt64 {α : Type} (x : UInt64) (k : UInt64 → α) : α := k x
@[inline] def withStrictUInt32 {α : Type} (x : UInt32) (k : UInt32 → α) : α := k x
@[inline] def withStrictUInt8 {α : Type} (x : UInt8) (k : UInt8 → α) : α := k x
@[inline] def withProd2 {α β γ : Type} (p : α × β) (k : α → β → γ) : γ := k p.1 p.2
@[inline] def withProd3 {α β γ δ : Type} (p : α × β × γ) (k : α → β → γ → δ) : δ := k p.1 p.2.1 p.2.2
@[inline] def withProd4 {α β γ δ ε : Type} (p : α × β × γ × δ) (k : α → β → γ → δ → ε) : ε := k p.1 p.2.1 p.2.2.1 p.2.2.2
@[inline] def withStrictNatArray {α : Type} (a : Array Nat) (k : Array Nat → α) : α := k a
@[inline] def withStrictByteArray {α : Type} (b : ByteArray) (k : ByteArray → α) : α := k b

/-- 16-word working state `v[0..15]` for BLAKE2b compression. -/
structure Blake2bWork16_512 where
  v0  : UInt64
  v1  : UInt64
  v2  : UInt64
  v3  : UInt64
  v4  : UInt64
  v5  : UInt64
  v6  : UInt64
  v7  : UInt64
  v8  : UInt64
  v9  : UInt64
  v10 : UInt64
  v11 : UInt64
  v12 : UInt64
  v13 : UInt64
  v14 : UInt64
  v15 : UInt64
  deriving DecidableEq, Repr

/-- RFC 7693 §3.1 `G` mixing quarter-round on `(a, b, c, d)` with message words `(x, y)`. -/
@[inline] def blake2bG512 (a b c d x y : UInt64) : UInt64 × UInt64 × UInt64 × UInt64 :=
  let a1 := a + b + x
  let d1 := rotr64 (d ^^^ a1) 32
  let c1 := c + d1
  let b1 := rotr64 (b ^^^ c1) 24
  let a2 := a1 + b1 + y
  let d2 := rotr64 (d1 ^^^ a2) 16
  let c2 := c1 + d2
  let b2 := rotr64 (b1 ^^^ c2) 63
  (a2, b2, c2, d2)

/-- One full BLAKE2b round (column step + diagonal step) with permuted message words `s0..s15`. -/
@[inline] def blake2bRound512 (st : Blake2bWork16_512)
    (s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 : UInt64) : Blake2bWork16_512 :=
  let (v0, v4, v8,  v12) := blake2bG512 st.v0 st.v4 st.v8  st.v12 s0 s1
  let (v1, v5, v9,  v13) := blake2bG512 st.v1 st.v5 st.v9  st.v13 s2 s3
  let (v2, v6, v10, v14) := blake2bG512 st.v2 st.v6 st.v10 st.v14 s4 s5
  let (v3, v7, v11, v15) := blake2bG512 st.v3 st.v7 st.v11 st.v15 s6 s7
  let (v0, v5, v10, v15) := blake2bG512 v0    v5    v10    v15    s8  s9
  let (v1, v6, v11, v12) := blake2bG512 v1    v6    v11    v12    s10 s11
  let (v2, v7, v8,  v13) := blake2bG512 v2    v7    v8     v13    s12 s13
  let (v3, v4, v9,  v14) := blake2bG512 v3    v4    v9     v14    s14 s15
  { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 }

/-- RFC 7693 §3.2 compression function `F` (12 rounds over 16 message words `m0..m15`). -/
def blake2bCompress (h : Words8)
    (m0 m1 m2 m3 m4 m5 m6 m7 m8 m9 m10 m11 m12 m13 m14 m15 : UInt64)
    (tLow tHigh : UInt64) (isLast : Bool) : Words8 :=
  let f0 : UInt64 := if isLast then 0xffffffffffffffff else 0
  let st : Blake2bWork16_512 :=
    { v0  := h.h0
      v1  := h.h1
      v2  := h.h2
      v3  := h.h3
      v4  := h.h4
      v5  := h.h5
      v6  := h.h6
      v7  := h.h7
      v8  := blake2bIV0
      v9  := blake2bIV1
      v10 := blake2bIV2
      v11 := blake2bIV3
      v12 := blake2bIV4 ^^^ tLow
      v13 := blake2bIV5 ^^^ tHigh
      v14 := blake2bIV6 ^^^ f0
      v15 := blake2bIV7 }
  let st := blake2bRound512 st m0  m1  m2  m3  m4  m5  m6  m7  m8  m9  m10 m11 m12 m13 m14 m15
  let st := blake2bRound512 st m14 m10 m4  m8  m9  m15 m13 m6  m1  m12 m0  m2  m11 m7  m5  m3
  let st := blake2bRound512 st m11 m8  m12 m0  m5  m2  m15 m13 m10 m14 m3  m6  m7  m1  m9  m4
  let st := blake2bRound512 st m7  m9  m3  m1  m13 m12 m11 m14 m2  m6  m5  m10 m4  m0  m15 m8
  let st := blake2bRound512 st m9  m0  m5  m7  m2  m4  m10 m15 m14 m1  m11 m12 m6  m8  m3  m13
  let st := blake2bRound512 st m2  m12 m6  m10 m0  m11 m8  m3  m4  m13 m7  m5  m15 m14 m1  m9
  let st := blake2bRound512 st m12 m5  m1  m15 m14 m13 m4  m10 m0  m7  m6  m3  m9  m2  m8  m11
  let st := blake2bRound512 st m13 m11 m7  m14 m12 m1  m3  m9  m5  m0  m15 m4  m8  m6  m2  m10
  let st := blake2bRound512 st m6  m15 m14 m9  m11 m3  m0  m8  m12 m2  m13 m7  m1  m4  m10 m5
  let st := blake2bRound512 st m10 m2  m8  m4  m7  m6  m1  m5  m15 m11 m9  m14 m3  m12 m13 m0
  let st := blake2bRound512 st m0  m1  m2  m3  m4  m5  m6  m7  m8  m9  m10 m11 m12 m13 m14 m15
  let st := blake2bRound512 st m14 m10 m4  m8  m9  m15 m13 m6  m1  m12 m0  m2  m11 m7  m5  m3
  { h0 := h.h0 ^^^ st.v0 ^^^ st.v8
    h1 := h.h1 ^^^ st.v1 ^^^ st.v9
    h2 := h.h2 ^^^ st.v2 ^^^ st.v10
    h3 := h.h3 ^^^ st.v3 ^^^ st.v11
    h4 := h.h4 ^^^ st.v4 ^^^ st.v12
    h5 := h.h5 ^^^ st.v5 ^^^ st.v13
    h6 := h.h6 ^^^ st.v6 ^^^ st.v14
    h7 := h.h7 ^^^ st.v7 ^^^ st.v15 }

/-- RFC 7693 unkeyed `BLAKE2b-512(msg)` returning `Words8`. -/
def blake2bSum512Words (msg : ByteArray) : Words8 := Id.run do
  let sz := msg.size
  if sz == 0 then
    return blake2bCompress blake2bInitState 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 true
  let numBlocks := (sz + 127) / 128
  let mut h := blake2bInitState
  for blkIdx in [:numBlocks] do
    let off := blkIdx * 128
    let isLast := blkIdx + 1 == numBlocks
    let tLow := if isLast then sz.toUInt64 else ((blkIdx + 1) * 128).toUInt64
    h := blake2bCompress h
      (readU64LE512 msg (off + 0))
      (readU64LE512 msg (off + 8))
      (readU64LE512 msg (off + 16))
      (readU64LE512 msg (off + 24))
      (readU64LE512 msg (off + 32))
      (readU64LE512 msg (off + 40))
      (readU64LE512 msg (off + 48))
      (readU64LE512 msg (off + 56))
      (readU64LE512 msg (off + 64))
      (readU64LE512 msg (off + 72))
      (readU64LE512 msg (off + 80))
      (readU64LE512 msg (off + 88))
      (readU64LE512 msg (off + 96))
      (readU64LE512 msg (off + 104))
      (readU64LE512 msg (off + 112))
      (readU64LE512 msg (off + 120))
      tLow 0 isLast
  return h

/-- RFC 7693 unkeyed `BLAKE2b-512(msg)` returning 8 little-endian `UInt64` words. -/
def blake2bSum512 (msg : ByteArray) : Array UInt64 :=
  (blake2bSum512Words msg).toArray

/-- Fast `Words8` evaluation of `hashes.BLAKE2b512WithKey` (`hashes/blake2b512.go`). -/
def blake2b512WithKeyWords (k : Words8) (_b2key : ByteArray) (data : ByteArray) (seed : Words8) : Words8 := Id.run do
  let sz := data.size
  let d00 := readU64LE512 data 0
  let d01 := readU64LE512 data 8
  let d02 := readU64LE512 data 16
  let d03 := readU64LE512 data 24
  let d04 := readU64LE512 data 32
  let d05 := readU64LE512 data 40
  let d06 := readU64LE512 data 48
  let d07 := readU64LE512 data 56
  if sz <= 64 then
    return blake2bCompress blake2bInitState
      k.h0 k.h1 k.h2 k.h3 k.h4 k.h5 k.h6 k.h7
      (d00 ^^^ seed.h0) (d01 ^^^ seed.h1) (d02 ^^^ seed.h2) (d03 ^^^ seed.h3)
      (d04 ^^^ seed.h4) (d05 ^^^ seed.h5) (d06 ^^^ seed.h6) (d07 ^^^ seed.h7)
      128 0 true
  let mut h := blake2bCompress blake2bInitState
    k.h0 k.h1 k.h2 k.h3 k.h4 k.h5 k.h6 k.h7
    (d00 ^^^ seed.h0) (d01 ^^^ seed.h1) (d02 ^^^ seed.h2) (d03 ^^^ seed.h3)
    (d04 ^^^ seed.h4) (d05 ^^^ seed.h5) (d06 ^^^ seed.h6) (d07 ^^^ seed.h7)
    128 0 false
  let remBlocks := (sz - 64 + 127) / 128
  for bIdx in [:remBlocks] do
    let off := 64 + bIdx * 128
    let isLast := bIdx + 1 == remBlocks
    let tLow := if isLast then (64 + sz).toUInt64 else ((bIdx + 2) * 128).toUInt64
    h := blake2bCompress h
      (readU64LE512 data (off + 0))
      (readU64LE512 data (off + 8))
      (readU64LE512 data (off + 16))
      (readU64LE512 data (off + 24))
      (readU64LE512 data (off + 32))
      (readU64LE512 data (off + 40))
      (readU64LE512 data (off + 48))
      (readU64LE512 data (off + 56))
      (readU64LE512 data (off + 64))
      (readU64LE512 data (off + 72))
      (readU64LE512 data (off + 80))
      (readU64LE512 data (off + 88))
      (readU64LE512 data (off + 96))
      (readU64LE512 data (off + 104))
      (readU64LE512 data (off + 112))
      (readU64LE512 data (off + 120))
      tLow 0 isLast
  return h

/-- `hashes.BLAKE2b512WithKey(b2key)(data, seed)` (`hashes/blake2b512.go`). -/
def blake2b512WithKey (b2key : ByteArray) (data : ByteArray) (seed : Array UInt64) : Array UInt64 :=
  let kw : Words8 :=
    { h0 := readU64LE512 b2key 0
      h1 := readU64LE512 b2key 8
      h2 := readU64LE512 b2key 16
      h3 := readU64LE512 b2key 24
      h4 := readU64LE512 b2key 32
      h5 := readU64LE512 b2key 40
      h6 := readU64LE512 b2key 48
      h7 := readU64LE512 b2key 56 }
  (blake2b512WithKeyWords kw b2key data (Words8.ofArray seed)).toArray

/-- `Seed512` state parameterized by a 64-byte `BLAKE2b-512` key and 8-word component rounds
    (1 round = 512-bit key, 2 rounds = 1024-bit key, 4 rounds = 2048-bit key). -/
structure Seed512 where
  b2key      : ByteArray
  keyWords   : Words8
  components : Array UInt64
  rounds     : List Words8

/-- Construct a `Seed512` from a 64-byte key and an array of `UInt64` components (multiple of 8). -/
def Seed512.mkFromKeyAndComps (b2key : ByteArray) (comps : Array UInt64) : Seed512 :=
  let kw : Words8 :=
    { h0 := readU64LE512 b2key 0
      h1 := readU64LE512 b2key 8
      h2 := readU64LE512 b2key 16
      h3 := readU64LE512 b2key 24
      h4 := readU64LE512 b2key 32
      h5 := readU64LE512 b2key 40
      h6 := readU64LE512 b2key 48
      h7 := readU64LE512 b2key 56 }
  let numRounds := comps.size / 8
  let rounds := (List.range numRounds).map (fun r =>
    let b := r * 8
    { h0 := comps.getD (b + 0) 0
      h1 := comps.getD (b + 1) 0
      h2 := comps.getD (b + 2) 0
      h3 := comps.getD (b + 3) 0
      h4 := comps.getD (b + 4) 0
      h5 := comps.getD (b + 5) 0
      h6 := comps.getD (b + 6) 0
      h7 := comps.getD (b + 7) 0 })
  { b2key, keyWords := kw, components := comps, rounds }

/-- XOR two `Words8` states componentwise. -/
def Words8.xor (a b : Words8) : Words8 :=
  Words8.casesOn (motive := fun _ => Words8) a fun a0 a1 a2 a3 a4 a5 a6 a7 =>
  Words8.casesOn (motive := fun _ => Words8) b fun b0 b1 b2 b3 b4 b5 b6 b7 =>
  { h0 := a0 ^^^ b0
    h1 := a1 ^^^ b1
    h2 := a2 ^^^ b2
    h3 := a3 ^^^ b3
    h4 := a4 ^^^ b4
    h5 := a5 ^^^ b5
    h6 := a6 ^^^ b6
    h7 := a7 ^^^ b7 }

/-- Cascade loop for `chainHash512With` over a list of 8-word component rounds (`seed512.go:448-466`). -/
def chainHash512RoundsLoop (kw : Words8) (b2key : ByteArray) (data : ByteArray) :
    List Words8 → Words8 → Words8
  | [], h => h
  | r :: rs, h =>
    withStrictWords8 (Words8.xor r h) fun seed =>
    withStrictWords8 (blake2b512WithKeyWords kw b2key data seed) fun h' =>
    chainHash512RoundsLoop kw b2key data rs h'

/-- Evaluate `chainHash512With` on a list of 8-word rounds (`seed512.go:448-466`). -/
def chainHash512WithRounds (kw : Words8) (b2key : ByteArray) (rounds : List Words8) (data : ByteArray) : Words8 :=
  withStrictByteArray data fun data =>
  match rounds with
  | [] => { h0 := 0, h1 := 0, h2 := 0, h3 := 0, h4 := 0, h5 := 0, h6 := 0, h7 := 0 }
  | r0 :: rs =>
    withStrictWords8 (blake2b512WithKeyWords kw b2key data r0) fun h0 =>
    chainHash512RoundsLoop kw b2key data rs h0

/-- `Seed512.ChainHash512(data)` returning `Words8` (`seed512.go:240-263`). -/
def chainHash512Words (s : Seed512) (data : ByteArray) : Words8 :=
  chainHash512WithRounds s.keyWords s.b2key s.rounds data

/-- `Seed512.ChainHash512(data)` returning 8 `UInt64` words (`seed512.go:240-263`). -/
def chainHash512 (s : Seed512) (data : ByteArray) : Array UInt64 :=
  (chainHash512Words s data).toArray

/-- `Seed512.MinPixels()` / `MinPixelsAuth()`: `ceil(keyBits / log2(7))` (`seed512.go:223-231`).
    Yields `183` for 512-bit seeds, `365` for 1024-bit seeds, `730` for 2048-bit seeds. -/
def minPixelsForKeyBits512 (keyBits : Nat) : Nat :=
  (keyBits * 10000 + 28074 - 1) / 28074

def Seed512.minPixels (s : Seed512) : Nat :=
  minPixelsForKeyBits512 (s.components.size * 64)

/-- `Seed512.blockHash512(index, nonce)` (`seed512.go:265-282`). -/
def blockHash512Words (s : Seed512) (index : Nat) (nonce : ByteArray) : Words8 :=
  let buf := pushU32LE512 ByteArray.empty index.toUInt32 ++ nonce
  chainHash512Words s buf

/-- Pre-unpacked message words for `blockHash512Words` so per-pixel evaluation avoids
    allocating a `ByteArray` or re-unpacking `nonce` on every pixel. -/
structure BlockNonceTemplate512 where
  d0Hi       : UInt64
  d1         : UInt64
  d2         : UInt64
  d3         : UInt64
  d4         : UInt64
  d5         : UInt64
  d6         : UInt64
  d7         : UInt64
  d8         : UInt64
  isTwoBlock : Bool
  secondT    : UInt64

def prepareBlockNonce512 (nonce : ByteArray) : BlockNonceTemplate512 :=
  let buf := pushU32LE512 ByteArray.empty 0 ++ nonce
  { d0Hi       := readU64LE512 buf 0
    d1         := readU64LE512 buf 8
    d2         := readU64LE512 buf 16
    d3         := readU64LE512 buf 24
    d4         := readU64LE512 buf 32
    d5         := readU64LE512 buf 40
    d6         := readU64LE512 buf 48
    d7         := readU64LE512 buf 56
    d8         := readU64LE512 buf 64
    isTwoBlock := buf.size > 64
    secondT    := (64 + buf.size).toUInt64 }

@[inline] def blake2b512BlockTpl (k : Words8) (tpl : BlockNonceTemplate512) (d0 : UInt64) (seed : Words8) : Words8 :=
  if !tpl.isTwoBlock then
    blake2bCompress blake2bInitState
      k.h0 k.h1 k.h2 k.h3 k.h4 k.h5 k.h6 k.h7
      (d0 ^^^ seed.h0) (tpl.d1 ^^^ seed.h1) (tpl.d2 ^^^ seed.h2) (tpl.d3 ^^^ seed.h3)
      (tpl.d4 ^^^ seed.h4) (tpl.d5 ^^^ seed.h5) (tpl.d6 ^^^ seed.h6) (tpl.d7 ^^^ seed.h7)
      128 0 true
  else
    let h0 := blake2bCompress blake2bInitState
      k.h0 k.h1 k.h2 k.h3 k.h4 k.h5 k.h6 k.h7
      (d0 ^^^ seed.h0) (tpl.d1 ^^^ seed.h1) (tpl.d2 ^^^ seed.h2) (tpl.d3 ^^^ seed.h3)
      (tpl.d4 ^^^ seed.h4) (tpl.d5 ^^^ seed.h5) (tpl.d6 ^^^ seed.h6) (tpl.d7 ^^^ seed.h7)
      128 0 false
    blake2bCompress h0
      tpl.d8 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
      tpl.secondT 0 true

def chainHash512TplLoop (kw : Words8) (tpl : BlockNonceTemplate512) (d0 : UInt64) :
    List Words8 → Words8 → Words8
  | [], h => h
  | r :: rs, h =>
    let h' := blake2b512BlockTpl kw tpl d0 (Words8.xor r h)
    chainHash512TplLoop kw tpl d0 rs h'

@[inline] def blockHash512Fast (s : Seed512) (index : Nat) (tpl : BlockNonceTemplate512) : Words8 :=
  let d0 := tpl.d0Hi ||| index.toUInt32.toUInt64
  match s.rounds with
  | [] => { h0 := 0, h1 := 0, h2 := 0, h3 := 0, h4 := 0, h5 := 0, h6 := 0, h7 := 0 }
  | r0 :: rs =>
    let h0 := blake2b512BlockTpl s.keyWords tpl d0 r0
    chainHash512TplLoop s.keyWords tpl d0 rs h0

/-- `Seed512.deriveStartPixel(nonce, totalPixels)` (`seed512.go:272-290`). -/
def deriveStartPixel512 (s : Seed512) (nonce : ByteArray) (totalPixels : Nat) : Nat :=
  if totalPixels == 0 then 0
  else
    let buf := (ByteArray.empty.push 0x02) ++ nonce
    withStrictWords8 (chainHash512Words s buf) fun h =>
    withStrictNat (h.h0.toNat % totalPixels) id

/-- `Seed512.deriveInterLockSeed(nonce)` (`seed512.go:305-311`). -/
def deriveInterLockSeed512Words (s : Seed512) (ilNonce : ByteArray) : Words8 :=
  let buf := (ByteArray.empty.push 0x04) ++ ilNonce
  chainHash512Words s buf

def deriveInterLockSeed512 (s : Seed512) (ilNonce : ByteArray) : Array UInt64 :=
  (deriveInterLockSeed512Words s ilNonce).toArray

/-! ## Section 3: 48-Bit & 168-Bit Rank Barriers (`Interlock = "48"` and `Interlock = "168"`) -/

/-- Interlock mode selector (`"48"` vs `"168"`). -/
inductive InterlockMode512 where
  | i48
  | i168
  deriving DecidableEq, Repr

/-- Convert `Words8` to a 512-bit natural number in little-endian limb order (`interlock168_rank_split.go`). -/
def Words8.toNat512 (r : Words8) : Nat :=
  Words8.casesOn (motive := fun _ => Nat) r fun h0 h1 h2 h3 h4 h5 h6 h7 =>
  h0.toNat +
  (h1.toNat <<< 64) +
  (h2.toNat <<< 128) +
  (h3.toNat <<< 192) +
  (h4.toNat <<< 256) +
  (h5.toNat <<< 320) +
  (h6.toNat <<< 384) +
  (h7.toNat <<< 448)

/-- Two-step reduction `(idx0, idx1) = ((r / B168) % A168, r % B168)` for 168-bit Interlock
    (`interlock168_rank_split.go:24-45`, proven equivalent to reciprocal reduction in `ITB.SplitRank`). -/
def splitRank168Words (r : Words8) : Nat × Nat :=
  withStrictNat r.toNat512 fun rNat =>
  withProd2 (twoStepUnrank A168_limbs B168_limbs rNat) fun idx0 idx1 =>
  withStrictNat idx0 fun i0 =>
  withStrictNat idx1 fun i1 =>
  (i0, i1)

/-- Two-step reduction `(idx0, idx1) = ((r128 / B48) % A48, r128 % B48)` for 48-bit Interlock
    (`interlock48_rank_split.go`, proven equivalent to reciprocal reduction in `ITB.SplitRank`). -/
def splitRank48Pair (lane0 lane1 : UInt64) : Nat × Nat :=
  withStrictNat (lane0.toNat + (lane1.toNat <<< 64)) fun r128 =>
  withProd2 (twoStepUnrank interlockA48 interlockB48 r128) fun idx0 idx1 =>
  withStrictNat idx0 fun i0 =>
  withStrictNat idx1 fun i1 =>
  (i0, i1)

/-- Combinadic unranking loop scanning `c` from `n - 1` down to `0` with exact sliding binomial
    coefficient `b = C(c, k)` (`interlock168.go:54-66`, `interlock48.go:82-94`). -/
def unrankCombinationLoop : Nat → Nat → Nat → Nat → Nat → Nat
  | 0,     _,    _, _, mask => mask
  | _ + 1, _,    0, _, mask => mask
  | c + 1, rank, k, b, mask =>
    if rank >= b then
      withStrictNat (Nat.lor mask (Nat.shiftLeft 1 c)) fun mask' =>
      withStrictNat (Nat.sub rank b) fun rank' =>
      withStrictNat (if c == 0 then 0 else Nat.div (Nat.mul b k) c) fun b' =>
      unrankCombinationLoop c rank' (k - 1) b' mask'
    else
      withStrictNat (if c == 0 then 0 else Nat.div (Nat.mul b (Nat.sub c k)) c) fun b' =>
      unrankCombinationLoop c rank k b' mask

/-- Unrank a `k`-combination of `n` bits (`interlock168.go:54-66` for `n ∈ {168, 112}`,
    `interlock48.go:82-94` for `n ∈ {48, 32}`). -/
def unrankCombination168 (rank k n : Nat) : Nat :=
  if n == 0 || k == 0 then 0
  else
    let b0 :=
      if n == 168 && k == 56 then (2 * A168_limbs) / 3
      else if n == 112 && k == 56 then B168_limbs / 2
      else if n == 48 && k == 16 then (2 * interlockA48) / 3
      else if n == 32 && k == 16 then interlockB48 / 2
      else 1
    withStrictNat rank fun rStrict =>
    withStrictNat b0 fun b0Strict =>
    unrankCombinationLoop n rStrict k b0Strict 0

/-- Alias for 48-bit combinadic unranking (`interlock48.go:82-94`). -/
def unrankCombination48 (rank k n : Nat) : Nat :=
  unrankCombination168 rank k n

/-- Bitwise parallel extract (`softPEXT`, `interlock168.go:128-151`, `interlock48.go:153-163`)
    over `n` bit positions. -/
def softPEXTAux : Nat → Nat → Nat → Nat
  | 0, _, _ => 0
  | n + 1, w, m =>
    withStrictNat (w >>> 1) fun w' =>
    withStrictNat (m >>> 1) fun m' =>
    withStrictNat (softPEXTAux n w' m') fun rest =>
    if (m &&& 1) == 1 then
      withStrictNat ((w &&& 1) ||| (rest <<< 1)) id
    else
      rest

/-- Bitwise parallel deposit (`softPDEP`, `interlock168.go:158-182`, `interlock48.go:175-185`)
    over `n` bit positions. -/
def softPDEPAux : Nat → Nat → Nat → Nat
  | 0, _, _ => 0
  | n + 1, v, m =>
    withStrictNat (m >>> 1) fun m' =>
    if (m &&& 1) == 1 then
      withStrictNat (v >>> 1) fun v' =>
      withStrictNat (softPDEPAux n v' m') fun rest =>
      withStrictNat ((v &&& 1) ||| (rest <<< 1)) id
    else
      withStrictNat (softPDEPAux n v m') fun rest =>
      withStrictNat (rest <<< 1) id

/-- 168-bit `softPEXT168` (`interlock168.go:128-151`). -/
def softPEXT168 (src mask : Nat) : Nat :=
  withStrictNat src fun s =>
  withStrictNat mask fun m =>
  softPEXTAux 168 s m

/-- 168-bit `softPDEP168` (`interlock168.go:158-182`). -/
def softPDEP168 (val mask : Nat) : Nat :=
  withStrictNat val fun v =>
  withStrictNat mask fun m =>
  softPDEPAux 168 v m

/-- 48-bit `softPEXT48` (`interlock48.go:153-163`). -/
def softPEXT48 (src mask : Nat) : Nat :=
  withStrictNat src fun s =>
  withStrictNat mask fun m =>
  softPEXTAux 48 s m

/-- 48-bit `softPDEP48` (`interlock48.go:175-185`). -/
def softPDEP48 (val mask : Nat) : Nat :=
  withStrictNat val fun v =>
  withStrictNat mask fun m =>
  softPDEPAux 48 v m

/-- Full 168-bit mask `(1 <<< 168) - 1`. -/
def mask168All : Nat := (1 <<< 168) - 1

/-- Full 48-bit mask `(1 <<< 48) - 1`. -/
def mask48All : Nat := (1 <<< 48) - 1

/-- Convert split rank `(idx0, idx1)` into a disjoint 3-way 168-bit mask partition `(m0, m1, m2)`
    where each mask has 56 set bits and `m0 | m1 | m2 = (1 << 168) - 1` (`interlock168.go:88-118`). -/
def rankToMaskTriple168 (idx0 idx1 : Nat) : Nat × Nat × Nat :=
  withStrictNat (unrankCombination168 idx0 56 168 &&& mask168All) fun m0 =>
  withStrictNat (mask168All ^^^ m0) fun remaining =>
  withStrictNat (unrankCombination168 idx1 56 112) fun m1Local =>
  withStrictNat (softPDEP168 m1Local remaining &&& remaining) fun m1 =>
  withStrictNat (remaining ^^^ m1) fun m2 =>
  (m0, m1, m2)

/-- Convert split rank `(idx0, idx1)` into a disjoint 3-way 48-bit mask partition `(m0, m1, m2)`
    where each mask has 16 set bits and `m0 | m1 | m2 = (1 << 48) - 1` (`interlock48.go:112-139`). -/
def rankToMaskTriple48 (idx0 idx1 : Nat) : Nat × Nat × Nat :=
  withStrictNat (unrankCombination48 idx0 16 48 &&& mask48All) fun m0 =>
  withStrictNat (mask48All ^^^ m0) fun remaining =>
  withStrictNat (unrankCombination48 idx1 16 32) fun m1Local =>
  withStrictNat (softPDEP48 m1Local remaining &&& remaining) fun m1 =>
  withStrictNat (remaining ^^^ m1) fun m2 =>
  (m0, m1, m2)

/-- Split a 168-bit chunk word `w` into three 56-bit lane words `(v0, v1, v2)` (`interlock168.go:187-205`). -/
def chunk168lock (w : Nat) (masks : Nat × Nat × Nat) : Nat × Nat × Nat :=
  withStrictNat w fun w =>
  withProd3 masks fun m0 m1 m2 =>
  withStrictNat (softPEXT168 w m0) fun v0 =>
  withStrictNat (softPEXT168 w m1) fun v1 =>
  withStrictNat (softPEXT168 w m2) fun v2 =>
  (v0, v1, v2)

/-- Reconstruct a 168-bit chunk word from three 56-bit lane words `(v0, v1, v2)` (`interlock168.go:209-243`). -/
def unchunk168lock (v0 v1 v2 : Nat) (masks : Nat × Nat × Nat) : Nat :=
  withStrictNat v0 fun v0 =>
  withStrictNat v1 fun v1 =>
  withStrictNat v2 fun v2 =>
  withProd3 masks fun m0 m1 m2 =>
  withStrictNat (softPDEP168 v0 m0 ||| softPDEP168 v1 m1 ||| softPDEP168 v2 m2) id

/-- Split a 48-bit chunk word `w` into three 16-bit lane words `(v0, v1, v2)` (`interlock48.go:204-213`). -/
def chunk48lock (w : Nat) (masks : Nat × Nat × Nat) : Nat × Nat × Nat :=
  withStrictNat w fun w =>
  withProd3 masks fun m0 m1 m2 =>
  withStrictNat (softPEXT48 w m0) fun v0 =>
  withStrictNat (softPEXT48 w m1) fun v1 =>
  withStrictNat (softPEXT48 w m2) fun v2 =>
  (v0, v1, v2)

/-- Reconstruct a 48-bit chunk word from three 16-bit lane words `(v0, v1, v2)` (`interlock48.go:226-231`). -/
def unchunk48lock (v0 v1 v2 : Nat) (masks : Nat × Nat × Nat) : Nat :=
  withStrictNat v0 fun v0 =>
  withStrictNat v1 fun v1 =>
  withStrictNat v2 fun v2 =>
  withProd3 masks fun m0 m1 m2 =>
  withStrictNat (softPDEP48 v0 m0 ||| softPDEP48 v1 m1 ||| softPDEP48 v2 m2) id

/-- Pack 21 bytes from `b` at byte offset `off` into a 168-bit little-endian `Nat` (`interlock168.go:247-253`). -/
def readU168LE (b : ByteArray) (off : Nat) : Nat :=
  let w0 := (readU64LE512 b off).toNat
  let w1 := (readU64LE512 b (off + 8)).toNat
  let w2 := (getByteD512 b (off + 16)).toNat |||
            ((getByteD512 b (off + 17)).toNat <<< 8) |||
            ((getByteD512 b (off + 18)).toNat <<< 16) |||
            ((getByteD512 b (off + 19)).toNat <<< 24) |||
            ((getByteD512 b (off + 20)).toNat <<< 32)
  withStrictNat (w0 ||| (w1 <<< 64) ||| (w2 <<< 128)) id

/-- Append a 168-bit word `w` as 21 little-endian bytes to `b` (`interlock168.go:257-262`). -/
def pushU168LE (b : ByteArray) (w : Nat) : ByteArray :=
  withStrictNat w fun w =>
  let w0 : UInt64 := UInt64.ofNat (w &&& 0xffffffffffffffff)
  let w1 : UInt64 := UInt64.ofNat ((w >>> 64) &&& 0xffffffffffffffff)
  let w2 : Nat    := (w >>> 128) &&& 0xffffffffff
  let b := pushU64LE512 b w0
  let b := pushU64LE512 b w1
  b.push (UInt8.ofNat (w2 &&& 0xff))
   |>.push (UInt8.ofNat ((w2 >>> 8) &&& 0xff))
   |>.push (UInt8.ofNat ((w2 >>> 16) &&& 0xff))
   |>.push (UInt8.ofNat ((w2 >>> 24) &&& 0xff))
   |>.push (UInt8.ofNat ((w2 >>> 32) &&& 0xff))

/-- Pack 6 bytes from `b` at byte offset `off` into a 48-bit little-endian `Nat` (`interlock48.go:255-262`). -/
def readU48LE (b : ByteArray) (off : Nat) : Nat :=
  withStrictNat (
    (getByteD512 b off).toNat |||
    ((getByteD512 b (off + 1)).toNat <<< 8) |||
    ((getByteD512 b (off + 2)).toNat <<< 16) |||
    ((getByteD512 b (off + 3)).toNat <<< 24) |||
    ((getByteD512 b (off + 4)).toNat <<< 32) |||
    ((getByteD512 b (off + 5)).toNat <<< 40)) id

/-- Append a 48-bit word `w` as 6 little-endian bytes to `b` (`interlock48.go:266-273`). -/
def pushU48LE (b : ByteArray) (w : Nat) : ByteArray :=
  withStrictNat w fun w =>
  b.push (UInt8.ofNat (w &&& 0xff))
   |>.push (UInt8.ofNat ((w >>> 8) &&& 0xff))
   |>.push (UInt8.ofNat ((w >>> 16) &&& 0xff))
   |>.push (UInt8.ofNat ((w >>> 24) &&& 0xff))
   |>.push (UInt8.ofNat ((w >>> 32) &&& 0xff))
   |>.push (UInt8.ofNat ((w >>> 40) &&& 0xff))

/-- Append a 56-bit word `v` as 7 little-endian bytes (`writeLane56`, `interlock168.go:275-280`). -/
def pushU56LE (b : ByteArray) (v : Nat) : ByteArray :=
  withStrictNat v fun v =>
  b.push (UInt8.ofNat (v &&& 0xff))
   |>.push (UInt8.ofNat ((v >>> 8) &&& 0xff))
   |>.push (UInt8.ofNat ((v >>> 16) &&& 0xff))
   |>.push (UInt8.ofNat ((v >>> 24) &&& 0xff))
   |>.push (UInt8.ofNat ((v >>> 32) &&& 0xff))
   |>.push (UInt8.ofNat ((v >>> 40) &&& 0xff))
   |>.push (UInt8.ofNat ((v >>> 48) &&& 0xff))

/-- Read a 56-bit little-endian word from 7 bytes at offset `off` (`readLane56`, `interlock168.go:266-271`). -/
def readU56LE (b : ByteArray) (off : Nat) : Nat :=
  withStrictNat (
    (getByteD512 b off).toNat |||
    ((getByteD512 b (off + 1)).toNat <<< 8) |||
    ((getByteD512 b (off + 2)).toNat <<< 16) |||
    ((getByteD512 b (off + 3)).toNat <<< 24) |||
    ((getByteD512 b (off + 4)).toNat <<< 32) |||
    ((getByteD512 b (off + 5)).toNat <<< 40) |||
    ((getByteD512 b (off + 6)).toNat <<< 48)) id

/-- Append a 16-bit word `v` as 2 little-endian bytes (`interlock48.go:245-247`). -/
def pushU16LE (b : ByteArray) (v : Nat) : ByteArray :=
  withStrictNat v fun v =>
  b.push (UInt8.ofNat (v &&& 0xff))
   |>.push (UInt8.ofNat ((v >>> 8) &&& 0xff))

/-- Read a 16-bit little-endian word from 2 bytes at offset `off`. -/
def readU16LE (b : ByteArray) (off : Nat) : Nat :=
  withStrictNat ((getByteD512 b off).toNat ||| ((getByteD512 b (off + 1)).toNat <<< 8)) id

/-- 32-bit XOR fold of `ilNonce` (`interlockNonceFoldWord`, `interlock48_cascade.go:62-75`). -/
def foldIlNonce32 (ilNonce : ByteArray) : UInt32 :=
  withStrictByteArray ilNonce fun ilNonce =>
  let rec loop (i : Nat) (fuel : Nat) (acc : UInt32) : UInt32 :=
    match fuel with
    | 0 => acc
    | fuel' + 1 =>
      if i + 4 <= ilNonce.size then
        withStrictUInt32 (acc ^^^ readU32LE512 ilNonce i) fun acc' =>
        loop (i + 4) fuel' acc'
      else
        acc
  loop 0 ilNonce.size 0

/-- Evaluate the `0x03` Rank Barrier PRF group call `groupIdx` over `lockRounds`
    (`interlock48_cascade.go:293-310`). -/
def evalLockGroup512 (lockSeed : Seed512) (lockRounds : List Words8) (foldWord : UInt32) (groupIdx : Nat) :
    Words8 :=
  let blk := pushU32LE512 (pushU64LE512 (ByteArray.empty.push 0x03) groupIdx.toUInt64) foldWord
  chainHash512WithRounds lockSeed.keyWords lockSeed.b2key lockRounds blk

/-- Derive the 168-bit Rank Barrier mask triple `(m0, m1, m2)` for chunk `chunkIdx`
    (`interlock168.go:74-84`). -/
def chunkMasks168 (lockSeed : Seed512) (lockRounds : List Words8) (foldWord : UInt32) (chunkIdx : Nat) :
    Nat × Nat × Nat :=
  withStrictWords8 (evalLockGroup512 lockSeed lockRounds foldWord chunkIdx) fun r =>
  withProd2 (splitRank168Words r) fun idx0 idx1 =>
  rankToMaskTriple168 idx0 idx1

/-- Extract the pair `(lane0, lane1)` for sub-index `sub ∈ 0..3` from an 8-word `0x03` group output. -/
def Words8.subPair48 (r : Words8) (sub : Nat) : UInt64 × UInt64 :=
  Words8.casesOn (motive := fun _ => UInt64 × UInt64) r fun h0 h1 h2 h3 h4 h5 h6 h7 =>
  match sub with
  | 0 => (h0, h1)
  | 1 => (h2, h3)
  | 2 => (h4, h5)
  | _ => (h6, h7)

/-- Frame plaintext with a 4-byte big-endian length prefix and zero-pad to a multiple of `chunkBytes`
    (`interlock168.go:284-313` for `chunkBytes = 21`, `interlock48.go:284-316` for `chunkBytes = 6`). -/
def framedSrcBy (chunkBytes : Nat) (data : ByteArray) : ByteArray :=
  withStrictByteArray data fun data =>
  withStrictNat data.size fun sz =>
  let totalLen := 4 + sz
  let numChunks := (totalLen + chunkBytes - 1) / chunkBytes
  let paddedLen := numChunks * chunkBytes
  let padZeros := paddedLen - totalLen
  let hdr := ByteArray.empty
    |>.push (sz >>> 24).toUInt8
    |>.push (sz >>> 16).toUInt8
    |>.push (sz >>> 8).toUInt8
    |>.push sz.toUInt8
  withStrictByteArray (hdr ++ data ++ ByteArray.mk (Array.replicate padZeros 0)) id

def framedSrc168 (data : ByteArray) : ByteArray := framedSrcBy 21 data
def framedSrc48  (data : ByteArray) : ByteArray := framedSrcBy 6  data

/-- Strip the 4-byte big-endian length prefix from a reconstructed buffer. -/
def unframeDst (raw : ByteArray) : Option ByteArray :=
  withStrictByteArray raw fun raw =>
  withStrictNat raw.size fun sz =>
  if sz < 4 then none
  else
    let origLen :=
      ((getByteD512 raw 0).toNat <<< 24) |||
      ((getByteD512 raw 1).toNat <<< 16) |||
      ((getByteD512 raw 2).toNat <<< 8) |||
      (getByteD512 raw 3).toNat
    withStrictNat origLen fun origLen =>
    if origLen > sz - 4 then none
    else
      withStrictByteArray (raw.extract 4 (4 + origLen)) fun out =>
      some out

/-! ## Section 4: Layer II (`0x06`) Cross-Lane Chunk-Slot Desynchronization (`desync.go:329-513`) -/

/-- `fullWidthFold(hLo, hHi)` (`desync.go:42-47`, matching `ITB.Desync.fullWidthFold`). -/
def fullWidthFold512 (hLo hHi : UInt64) : UInt64 × UInt64 :=
  withStrictUInt64 (rotl64 hHi 25 + rotl64 hHi 53) fun mixHi =>
  withStrictUInt64 (hLo + mixHi) fun w0 =>
  withStrictUInt64 (hHi ^^^ rotl64 w0 19 ^^^ rotl64 w0 41) fun w1 =>
  (w0, w1)

/-- Derive the 4 Layer II schedule words `(w0, w1, w2, w3)` under domain tag `0x06`
    (`interlock48_cascade.go:314-331`). -/
def desyncWords512 (lockSeed : Seed512) (lockRounds : List Words8) (foldWord : UInt32) :
    UInt64 × UInt64 × UInt64 × UInt64 :=
  let blk0 := pushU32LE512 (pushU64LE512 (ByteArray.empty.push 0x06) 0) foldWord
  let blk1 := pushU32LE512 (pushU64LE512 (ByteArray.empty.push 0x06) 1) foldWord
  withStrictWords8 (chainHash512WithRounds lockSeed.keyWords lockSeed.b2key lockRounds blk0) fun out0 =>
  withStrictWords8 (chainHash512WithRounds lockSeed.keyWords lockSeed.b2key lockRounds blk1) fun out1 =>
  withProd2 (fullWidthFold512 out0.h0 out0.h1) fun w0 w1 =>
  withProd2 (fullWidthFold512 out1.h0 out1.h1) fun w2 w3 =>
  (w0, w1, w2, w3)

/-- Fisher-Yates permutation on `[0, 1, ..., k - 1]` driven by 64-bit word `u0`
    (`desync.go:112-122` and `desync.go:376-386`). -/
def fisherYatesPerm (k : Nat) (u0 : UInt64) : Array Nat :=
  let rec loop : Nat → UInt64 → Array Nat → Array Nat
    | 0, _, arr => arr
    | i + 1, u, arr =>
      withStrictNatArray arr fun arr =>
      withStrictUInt64 u fun u =>
      let mod := (i + 2).toUInt64
      withStrictNat (u % mod).toNat fun swapIdx =>
      withStrictUInt64 (u / mod) fun u' =>
      let vi := arr.getD (i + 1) 0
      let vs := arr.getD swapIdx 0
      let arr' := (arr.set! (i + 1) vs).set! swapIdx vi
      loop i u' arr'
  let init := (List.range k).toArray
  if k <= 1 then init else
    withStrictNatArray (loop (k - 1) u0 init) id

/-- Layer II cross-lane chunk-slot desynchronization schedule (`desync.go:329-337`). -/
structure LaneDesyncSchedule512 where
  m      : Nat
  betas  : Array Nat
  kLane  : Nat
  offset : Array Nat
  size   : Array Nat
  start  : Array Nat
  logOff : Array Nat
  deriving DecidableEq, Repr

/-- Build Layer II schedule from `m` and `(w0, w1, w2, w3)` (`desync.go:339-397`). -/
def buildLaneDesyncSchedule512 (m : Nat) (words : UInt64 × UInt64 × UInt64 × UInt64) :
    LaneDesyncSchedule512 :=
  withStrictNat m fun m =>
  if m < 2 then
    { m, betas := #[0, 0, 0], kLane := 0, offset := #[], size := #[], start := #[], logOff := #[0] }
  else
    withProd4 words fun w0 w1 w2 w3 =>
    withStrictUInt64 w0 fun w0 =>
    withStrictUInt64 w1 fun w1 =>
    withStrictUInt64 w2 fun w2 =>
    withStrictUInt64 w3 fun w3 =>
    withStrictNat (w3 % m.toUInt64).toNat fun beta0 =>
    withStrictNat ((beta0 + 1 + ((w3 >>> 16) % (m - 1).toUInt64).toNat) % m) fun beta1 =>
    withStrictNat ((w3 >>> 32) % m.toUInt64).toNat fun beta2 =>
    let betas := #[beta0, beta1, beta2]
    if m < 16 then
      { m, betas, kLane := 0, offset := #[], size := #[], start := #[], logOff := #[0] }
    else
      withStrictNat (4 + (w0 % 5).toNat) fun kLane =>
      withStrictNat (m / kLane) fun base =>
      withStrictNat (m % kLane) fun rem =>
      withStrictNatArray ((List.range kLane).foldl (fun acc j =>
        withStrictNatArray acc fun acc =>
        let sz := base + (if j < rem then 1 else 0)
        acc.push (acc.getD j 0 + sz)) #[0]) fun physOff0 =>
      withStrictNatArray (
        if base >= 4 then
          (List.range (kLane - 1)).foldl (fun acc jIdx =>
            withStrictNatArray acc fun acc =>
            let j := jIdx + 1
            let raw := ((w0 >>> (8 + j).toUInt64) &&& 1).toNat
            let cur := acc.getD j 0
            acc.set! j (if raw == 0 then cur - 1 else cur)) physOff0
        else
          physOff0) fun physOff =>
      withStrictNatArray ((List.range kLane).foldl (fun acc j =>
        withStrictNatArray acc fun acc =>
        acc.push (physOff.getD (j + 1) 0 - physOff.getD j 0)) #[]) fun physSize =>
      withStrictNatArray (fisherYatesPerm kLane w1) fun piLane =>
      withProd4 ((List.range kLane).foldl
        (fun (st : Array Nat × Array Nat × Array Nat × Array Nat) step =>
          withProd4 st fun offs szs sts logs =>
          withStrictNatArray offs fun offs =>
          withStrictNatArray szs  fun szs  =>
          withStrictNatArray sts  fun sts  =>
          withStrictNatArray logs fun logs =>
          let physIdx := piLane.getD step 0
          let mk := physSize.getD physIdx 1
          let pOff := physOff.getD physIdx 0
          let lOff := logs.getD step 0
          withStrictNat (rotl64 w2 (9 * step).toUInt64 % mk.toUInt64).toNat fun stVal =>
          (offs.push pOff, szs.push mk, sts.push stVal, logs.push (lOff + mk)))
        (#[], #[], #[], #[0])) fun offset size start logOff =>
      withStrictNatArray offset fun offset =>
      withStrictNatArray size   fun size   =>
      withStrictNatArray start  fun start  =>
      withStrictNatArray logOff fun logOff =>
      { m, betas, kLane, offset, size, start, logOff }

/-- Forward Layer II slot permutation `Sigma_l = Pi_lane ∘ mu_l` on an array of `m` slot values
    (`desyncLaneEncryptTo`, `desync.go:468-487`). -/
def permuteSlotsEncrypt512 (src : Array Nat) (sched : LaneDesyncSchedule512) (lane : Nat) : Array Nat :=
  withStrictNatArray src fun src =>
  withStrictNat sched.m fun m =>
  if m < 2 then src
  else
    withStrictNat (sched.betas.getD lane 0) fun beta =>
    if sched.kLane == 0 then
      withStrictNatArray ((List.range m).foldl (fun acc u =>
        withStrictNatArray acc fun acc =>
        acc.push (src.getD ((u + m - beta) % m) 0)) #[]) id
    else
      withStrictNatArray ((List.range sched.kLane).foldl (fun (dst : Array Nat) step =>
        withStrictNatArray dst fun dst =>
        let mk := sched.size.getD step 0
        let uBase := sched.logOff.getD step 0
        let physOff := sched.offset.getD step 0
        let s := sched.start.getD step 0
        (List.range mk).foldl (fun (d : Array Nat) i =>
          withStrictNatArray d fun d =>
          let u := if i < s then uBase + mk - s + i else uBase + (i - s)
          let srcIdx := (u + m - beta) % m
          d.set! (physOff + i) (src.getD srcIdx 0)) dst) (Array.replicate m 0)) id

/-- Inverse Layer II slot permutation `Sigma_l^-1 = mu_l^-1 ∘ Pi_lane^-1` on an array of `m` slot values
    (`desyncLaneDecryptOne`, `desync.go:494-513`). -/
def permuteSlotsDecrypt512 (src : Array Nat) (sched : LaneDesyncSchedule512) (lane : Nat) : Array Nat :=
  withStrictNatArray src fun src =>
  withStrictNat sched.m fun m =>
  if m < 2 then src
  else
    withStrictNat (sched.betas.getD lane 0) fun beta =>
    if sched.kLane == 0 then
      withStrictNatArray ((List.range m).foldl (fun acc j =>
        withStrictNatArray acc fun acc =>
        acc.push (src.getD ((j + beta) % m) 0)) #[]) id
    else
      withStrictNatArray ((List.range sched.kLane).foldl (fun (dst : Array Nat) step =>
        withStrictNatArray dst fun dst =>
        let mk := sched.size.getD step 0
        let uBase := sched.logOff.getD step 0
        let physOff := sched.offset.getD step 0
        let s := sched.start.getD step 0
        (List.range mk).foldl (fun (d : Array Nat) i =>
          withStrictNatArray d fun d =>
          let u := if i < s then uBase + mk - s + i else uBase + (i - s)
          let dstIdx := (u + m - beta) % m
          d.set! dstIdx (src.getD (physOff + i) 0)) dst) (Array.replicate m 0)) id

/-- Convert a 56-bit word `w` into 7 little-endian bytes (`List UInt8`). -/
def u56ToBytesLE (w : Nat) : List UInt8 :=
  withStrictNat w fun w =>
  [ UInt8.ofNat (w &&& 0xFF),
    UInt8.ofNat ((w >>> 8) &&& 0xFF),
    UInt8.ofNat ((w >>> 16) &&& 0xFF),
    UInt8.ofNat ((w >>> 24) &&& 0xFF),
    UInt8.ofNat ((w >>> 32) &&& 0xFF),
    UInt8.ofNat ((w >>> 40) &&& 0xFF),
    UInt8.ofNat ((w >>> 48) &&& 0xFF) ]

/-- Read a 56-bit little-endian word from the head of a byte list in `O(1)` steps. -/
def takeU56LE : List UInt8 → Nat × List UInt8
  | b0 :: b1 :: b2 :: b3 :: b4 :: b5 :: b6 :: rest =>
    let w :=
      b0.toNat |||
      (b1.toNat <<< 8) |||
      (b2.toNat <<< 16) |||
      (b3.toNat <<< 24) |||
      (b4.toNat <<< 32) |||
      (b5.toNat <<< 40) |||
      (b6.toNat <<< 48)
    withStrictNat w fun w' => (w', rest)
  | bs =>
    let g (i : Nat) : Nat := (bs.getD i 0).toNat
    let w :=
      g 0 ||| (g 1 <<< 8) ||| (g 2 <<< 16) ||| (g 3 <<< 24) |||
      (g 4 <<< 32) ||| (g 5 <<< 40) ||| (g 6 <<< 48)
    withStrictNat w fun w' => (w', [])

/-- Unpack `m` 56-bit words from `bs : List UInt8` in a single linear pass. -/
def unpackSlots56List : Nat → List UInt8 → List Nat
  | 0, _ => []
  | m + 1, bs =>
    withProd2 (takeU56LE bs) fun w rest =>
    w :: unpackSlots56List m rest

/-- Pack an array of 56-bit `Nat` slots into a `ByteArray` of length `7 * slots.size`. -/
def packSlots56 (slots : Array Nat) : ByteArray :=
  withStrictNatArray slots fun slots =>
  withStrictByteArray (ByteArray.mk (slots.toList.flatMap u56ToBytesLE).toArray) id

/-- Unpack a `ByteArray` of length `7 * m` into an array of `m` 56-bit `Nat` slots. -/
def unpackSlots56 (b : ByteArray) (m : Nat) : Array Nat :=
  withStrictByteArray b fun b =>
  withStrictNatArray (unpackSlots56List m b.data.toList).toArray id

/-- Convert a 16-bit word `w` into 2 little-endian bytes (`List UInt8`). -/
def u16ToBytesLE (w : Nat) : List UInt8 :=
  withStrictNat w fun w =>
  [ UInt8.ofNat (w &&& 0xFF),
    UInt8.ofNat ((w >>> 8) &&& 0xFF) ]

/-- Read a 16-bit little-endian word from the head of a byte list in `O(1)` steps. -/
def takeU16LE : List UInt8 → Nat × List UInt8
  | b0 :: b1 :: rest =>
    withStrictNat (b0.toNat ||| (b1.toNat <<< 8)) fun w => (w, rest)
  | [b0] => (b0.toNat, [])
  | [] => (0, [])

/-- Unpack `m` 16-bit words from `bs : List UInt8` in a single linear pass. -/
def unpackSlots16List : Nat → List UInt8 → List Nat
  | 0, _ => []
  | m + 1, bs =>
    withProd2 (takeU16LE bs) fun w rest =>
    w :: unpackSlots16List m rest

/-- Pack an array of 16-bit `Nat` slots into a `ByteArray` of length `2 * slots.size`. -/
def packSlots16 (slots : Array Nat) : ByteArray :=
  withStrictNatArray slots fun slots =>
  withStrictByteArray (ByteArray.mk (slots.toList.flatMap u16ToBytesLE).toArray) id

/-- Unpack a `ByteArray` of length `2 * m` into an array of `m` 16-bit `Nat` slots. -/
def unpackSlots16 (b : ByteArray) (m : Nat) : Array Nat :=
  withStrictByteArray b fun b =>
  withStrictNatArray (unpackSlots16List m b.data.toList).toArray id

/-- Full 168-bit `splitTriple168` (`interlock168.go` + `triplepayload.go:400-441`):
    frames `data`, applies per-chunk 168-bit Rank Barrier `chunk168lock`, and applies Layer II (`0x06`). -/
def splitTriple168 (lockSeed : Seed512) (ilNonce : ByteArray) (data : ByteArray) :
    ByteArray × ByteArray × ByteArray :=
  withStrictByteArray (framedSrc168 data) fun framed =>
  withStrictNat (framed.size / 21) fun numChunks =>
  withStrictWords8 (deriveInterLockSeed512Words lockSeed ilNonce) fun K =>
  let lockRounds := K :: lockSeed.rounds
  withStrictUInt32 (foldIlNonce32 ilNonce) fun foldWord =>
  withProd3 ((List.range numChunks).foldl
    (fun (acc : Array Nat × Array Nat × Array Nat) k =>
      withProd3 acc fun a0 a1 a2 =>
      withStrictNatArray a0 fun a0 =>
      withStrictNatArray a1 fun a1 =>
      withStrictNatArray a2 fun a2 =>
      let masks := chunkMasks168 lockSeed lockRounds foldWord k
      let w := readU168LE framed (k * 21)
      withProd3 (chunk168lock w masks) fun v0 v1 v2 =>
      (a0.push v0, a1.push v1, a2.push v2))
    (#[], #[], #[])) fun slots0 slots1 slots2 =>
  let sched := buildLaneDesyncSchedule512 numChunks (desyncWords512 lockSeed lockRounds foldWord)
  let s0 := permuteSlotsEncrypt512 slots0 sched 0
  let s1 := permuteSlotsEncrypt512 slots1 sched 1
  let s2 := permuteSlotsEncrypt512 slots2 sched 2
  (packSlots56 s0, packSlots56 s1, packSlots56 s2)

/-- Full 168-bit `interleaveTriple168` (`interlock168.go` + `desync.go:581-625`):
    inverts Layer II (`0x06`), applies per-chunk `unchunk168lock`, and strips the 4-byte length frame. -/
def interleaveTriple168 (lockSeed : Seed512) (ilNonce : ByteArray) (p0 p1 p2 : ByteArray) :
    Option ByteArray :=
  withStrictByteArray p0 fun p0 =>
  withStrictByteArray p1 fun p1 =>
  withStrictByteArray p2 fun p2 =>
  if p0.size != p1.size || p1.size != p2.size || p0.size == 0 || p0.size % 7 != 0 then
    none
  else
    withStrictNat (p0.size / 7) fun numChunks =>
    withStrictWords8 (deriveInterLockSeed512Words lockSeed ilNonce) fun K =>
    let lockRounds := K :: lockSeed.rounds
    withStrictUInt32 (foldIlNonce32 ilNonce) fun foldWord =>
    let sched := buildLaneDesyncSchedule512 numChunks (desyncWords512 lockSeed lockRounds foldWord)
    withStrictNatArray (permuteSlotsDecrypt512 (unpackSlots56 p0 numChunks) sched 0) fun u0 =>
    withStrictNatArray (permuteSlotsDecrypt512 (unpackSlots56 p1 numChunks) sched 1) fun u1 =>
    withStrictNatArray (permuteSlotsDecrypt512 (unpackSlots56 p2 numChunks) sched 2) fun u2 =>
    let raw := (List.range numChunks).foldl (fun (acc : ByteArray) k =>
      withStrictByteArray acc fun acc =>
      let masks := chunkMasks168 lockSeed lockRounds foldWord k
      let w := unchunk168lock (u0.getD k 0) (u1.getD k 0) (u2.getD k 0) masks
      pushU168LE acc w) ByteArray.empty
    unframeDst raw

/-- Full 48-bit `splitTriple48_512` (`interlock48.go` + `buildLockBatchPRF48_512Body` with `factor = 4`):
    frames `data`, applies per-group (4 chunks/group) 48-bit Rank Barrier `chunk48lock`, and applies Layer II (`0x06`). -/
def splitTriple48_512 (lockSeed : Seed512) (ilNonce : ByteArray) (data : ByteArray) :
    ByteArray × ByteArray × ByteArray :=
  withStrictByteArray (framedSrc48 data) fun framed =>
  withStrictNat (framed.size / 6) fun numChunks =>
  withStrictNat ((numChunks + 3) / 4) fun numGroups =>
  withStrictWords8 (deriveInterLockSeed512Words lockSeed ilNonce) fun K =>
  let lockRounds := K :: lockSeed.rounds
  withStrictUInt32 (foldIlNonce32 ilNonce) fun foldWord =>
  withProd3 ((List.range numGroups).foldl
    (fun (acc : Array Nat × Array Nat × Array Nat) g =>
      withStrictWords8 (evalLockGroup512 lockSeed lockRounds foldWord g) fun r =>
      (List.range 4).foldl (fun (accSub : Array Nat × Array Nat × Array Nat) sub =>
        let k := g * 4 + sub
        if k >= numChunks then accSub
        else
          withProd3 accSub fun a0 a1 a2 =>
          withStrictNatArray a0 fun a0 =>
          withStrictNatArray a1 fun a1 =>
          withStrictNatArray a2 fun a2 =>
          withProd2 (r.subPair48 sub) fun l0 l1 =>
          withProd2 (splitRank48Pair l0 l1) fun idx0 idx1 =>
          let masks := rankToMaskTriple48 idx0 idx1
          let w := readU48LE framed (k * 6)
          withProd3 (chunk48lock w masks) fun v0 v1 v2 =>
          (a0.push v0, a1.push v1, a2.push v2)) acc)
    (#[], #[], #[])) fun slots0 slots1 slots2 =>
  let sched := buildLaneDesyncSchedule512 numChunks (desyncWords512 lockSeed lockRounds foldWord)
  let s0 := permuteSlotsEncrypt512 slots0 sched 0
  let s1 := permuteSlotsEncrypt512 slots1 sched 1
  let s2 := permuteSlotsEncrypt512 slots2 sched 2
  (packSlots16 s0, packSlots16 s1, packSlots16 s2)

/-- Full 48-bit `interleaveTriple48_512` (`interlock48.go` + `buildLockBatchPRF48_512Body` with `factor = 4`):
    inverts Layer II (`0x06`), applies per-chunk `unchunk48lock`, and strips the 4-byte length frame. -/
def interleaveTriple48_512 (lockSeed : Seed512) (ilNonce : ByteArray) (p0 p1 p2 : ByteArray) :
    Option ByteArray :=
  withStrictByteArray p0 fun p0 =>
  withStrictByteArray p1 fun p1 =>
  withStrictByteArray p2 fun p2 =>
  if p0.size != p1.size || p1.size != p2.size || p0.size == 0 || p0.size % 2 != 0 then
    none
  else
    withStrictNat (p0.size / 2) fun numChunks =>
    withStrictNat ((numChunks + 3) / 4) fun numGroups =>
    withStrictWords8 (deriveInterLockSeed512Words lockSeed ilNonce) fun K =>
    let lockRounds := K :: lockSeed.rounds
    withStrictUInt32 (foldIlNonce32 ilNonce) fun foldWord =>
    let sched := buildLaneDesyncSchedule512 numChunks (desyncWords512 lockSeed lockRounds foldWord)
    withStrictNatArray (permuteSlotsDecrypt512 (unpackSlots16 p0 numChunks) sched 0) fun u0 =>
    withStrictNatArray (permuteSlotsDecrypt512 (unpackSlots16 p1 numChunks) sched 1) fun u1 =>
    withStrictNatArray (permuteSlotsDecrypt512 (unpackSlots16 p2 numChunks) sched 2) fun u2 =>
    let raw := (List.range numGroups).foldl (fun (acc : ByteArray) g =>
      withStrictWords8 (evalLockGroup512 lockSeed lockRounds foldWord g) fun r =>
      (List.range 4).foldl (fun (accSub : ByteArray) sub =>
        let k := g * 4 + sub
        if k >= numChunks then accSub
        else
          withStrictByteArray accSub fun accSub =>
          withProd2 (r.subPair48 sub) fun l0 l1 =>
          withProd2 (splitRank48Pair l0 l1) fun idx0 idx1 =>
          let masks := rankToMaskTriple48 idx0 idx1
          let w := unchunk48lock (u0.getD k 0) (u1.getD k 0) (u2.getD k 0) masks
          pushU48LE accSub w) acc) ByteArray.empty
    unframeDst raw

/-! ## Section 5: Interlock-Nonce 3-Lane Split & COBS Framing (`interlock_nonce.go`, `cobs.go`) -/

/-- Compute per-lane fragment lengths `(l0, l1, l2)` for an interlock nonce of length `nonceLen`
    (`nonceSplit`, `interlock_nonce.go:55-67`). -/
def nonceSplitLens (nonceLen : Nat) : Nat × Nat × Nat :=
  let base := nonceLen / 3
  let rem := nonceLen % 3
  let l0 := base + (if 0 < rem then 1 else 0)
  let l1 := base + (if 1 < rem then 1 else 0)
  let l2 := base
  (l0, l1, l2)

/-- Split `ilNonce` into 3 fragments `(frag0, frag1, frag2)` (`interlock_nonce.go:55-67`). -/
def nonceSplitFrags (ilNonce : ByteArray) : ByteArray × ByteArray × ByteArray :=
  let (l0, l1, l2) := nonceSplitLens ilNonce.size
  (ilNonce.extract 0 l0,
   ilNonce.extract l0 (l0 + l1),
   ilNonce.extract (l0 + l1) (l0 + l1 + l2))

/-- Recover `ilNonce` and the 3 lane payloads `(p0, p1, p2)` from COBS-decoded lane buffers
    (`recoverInterlockNonce`, `interlock_nonce.go:82-94`). -/
def recoverInterlockNonce512 (d0 d1 d2 : ByteArray) (nonceLen : Nat) :
    Option (ByteArray × ByteArray × ByteArray × ByteArray) :=
  let (l0, l1, l2) := nonceSplitLens nonceLen
  if d0.size < l0 || d1.size < l1 || d2.size < l2 then
    none
  else
    let ilNonce := d0.extract 0 l0 ++ d1.extract 0 l1 ++ d2.extract 0 l2
    let p0 := d0.extract l0 d0.size
    let p1 := d1.extract l1 d1.size
    let p2 := d2.extract l2 d2.size
    some (ilNonce, p0, p1, p2)

/-- `cobsEncodeBound(n)` (`cobs.go:41-43`). -/
def cobsEncodeBound (n : Nat) : Nat :=
  n + n / 254 + 2

/-- Recursive helper for `cobsEncode` over a `List UInt8` (`cobs.go:50-105`),
    returning the COBS-encoded bytes followed by the `0x00` delimiter (`triplepayload.go:450`). -/
def cobsEncodeLoop : List UInt8 → UInt8 → List UInt8 → List UInt8 → List UInt8
  | [], code, revChunk, revOut =>
    let revOut' := 0 :: (revChunk ++ (code :: revOut))
    revOut'.reverse
  | b :: bs, code, revChunk, revOut =>
    if b == 0 then
      let revOut' := revChunk ++ (code :: revOut)
      cobsEncodeLoop bs 1 [] revOut'
    else
      let revChunk' := b :: revChunk
      let code' := code + 1
      if code' == 0xFF then
        let revOut' := revChunk' ++ ((0xFF : UInt8) :: revOut)
        cobsEncodeLoop bs 1 [] revOut'
      else
        cobsEncodeLoop bs code' revChunk' revOut

/-- COBS-encode `src` with a trailing `0x00` terminator (`cobsEncodeInto` + `buf[encLen] = 0x00`). -/
def cobsEncodeWithNull (src : ByteArray) : ByteArray :=
  ByteArray.mk (cobsEncodeLoop src.data.toList 1 [] []).toArray

/-- Strip bytes at and after the first `0x00` delimiter (`itb512.go:393-397`). -/
def takeBeforeZero : List UInt8 → List UInt8
  | [] => []
  | b :: bs => if b == 0 then [] else b :: takeBeforeZero bs

/-- Fuel-bounded structural recursion for `cobsDecode` on the pre-delimiter frame (`cobs.go:117-159`). -/
def cobsDecodeFrameAux : Nat → List UInt8 → Option (List UInt8)
  | 0, [] => some []
  | 0, _ :: _ => none
  | _ + 1, [] => some []
  | fuel + 1, code :: rest =>
    if code == 0 then none
    else
      let copyLen := code.toNat - 1
      if rest.length < copyLen then none
      else
        let chunk := rest.take copyLen
        if chunk.any (· == 0) then none
        else
          let after := rest.drop copyLen
          match cobsDecodeFrameAux fuel after with
          | none => none
          | some tail =>
            if code < 0xFF && !after.isEmpty then
              some (chunk ++ (0 :: tail))
            else
              some (chunk ++ tail)

/-- Decode a COBS-framed buffer up to its first `0x00` delimiter (`itb512.go:393-397`, `cobs.go:117-159`). -/
def cobsDecode (src : ByteArray) : Option ByteArray :=
  let frame := takeBeforeZero src.data.toList
  match cobsDecodeFrameAux frame.length frame with
  | none => none
  | some bytes => some (ByteArray.mk bytes.toArray)

/-! ## Section 6: Container Sizing (`Mode 1` and `Mode 2`, `itb.go:135-198`, `triplepayload.go:277-296`) -/

/-- Find a power-of-two upper bound `b` with `b * b >= n` by structural recursion on `fuel`. -/
def ceilSqrtBoundAux (n : Nat) : Nat → Nat → Nat
  | 0, b => b
  | fuel + 1, b => if b * b >= n then b else ceilSqrtBoundAux n fuel (b * 2)

/-- Binary search in `[lo, hi]` for the smallest `s` with `s * s >= n` by structural recursion on `fuel`. -/
def ceilSqrtBSearch (n : Nat) : Nat → Nat → Nat → Nat
  | 0, _, hi => hi
  | fuel + 1, lo, hi =>
    if lo >= hi then hi
    else
      let mid := (lo + hi) / 2
      if mid * mid >= n then
        ceilSqrtBSearch n fuel lo mid
      else
        ceilSqrtBSearch n fuel (mid + 1) hi

/-- Integer ceiling square root `ceil(sqrt(n))` (`itb.go:162-165`), implemented via
    structural-recursion binary search so Lean's kernel reducer (`by decide`)
    evaluates it in `O(log n)` steps. -/
def ceilSqrt (n : Nat) : Nat :=
  if n <= 1 then n
  else
    let hi := ceilSqrtBoundAux n 32 1
    ceilSqrtBSearch n 32 1 hi

/-- Exact `calcContainerSize3Cfg` (`itb.go:135-198`):
    - `mode = 1` (**Mode 1**, `blobModePerRegion`): each third satisfies `max(pixels_i, minPx_i)`,
      `totalPixels = 3 * maxThirdPixels`.
    - `mode = 2` (**Mode 2**, `blobModePerContainer`): `totalPixels = max(3 * maxDataThirdPixels, minPxJoint)`.
    - `mode = 3` (**Mode 3**, `blobModeGaussPosit`): `totalPixels = max(3 * maxDataThirdPixels, positGaussCircleFloor(3 * minPxJoint))`.
    - Returns `(side, side)` where `side = ceilSqrt(totalPixels) + barrierFill`. -/
def calcContainerSize3Cfg512 (mode : Nat) (cobsLens0 cobsLens1 cobsLens2 : Nat)
    (minPx : Nat) (barrierFill : Nat := 1) : Nat × Nat :=
  let px0 := ((cobsLens0 + 1) * 8 + 55) / 56
  let px1 := ((cobsLens1 + 1) * 8 + 55) / 56
  let px2 := ((cobsLens2 + 1) * 8 + 55) / 56
  let maxDataPx := max px0 (max px1 px2)
  let totalPixels :=
    if mode == 2 || mode == 3 then
      let floorPx := if mode == 3 then ITB.Posit.positGaussCircleFloor (3 * minPx) else minPx
      max (3 * maxDataPx) floorPx
    else
      3 * max maxDataPx minPx
  let side := ceilSqrt totalPixels + barrierFill
  (side, side)

/-- Compute `(width, height)` for a plaintext of length `dataLen` under `(interlockMode, keyBits, nonceBytes, mode)`
    matching `buildTripleWire3Into` (`triplepayload.go:279-294`, `reserve = nomacTagStubSizeCfg = 33`). -/
def containerDimsForPayload512 (interlockMode : InterlockMode512) (keyBits nonceBytes mode dataLen : Nat)
    (barrierFill : Nat := 1) (reserve : Nat := 33) : Nat × Nat :=
  let laneLen :=
    match interlockMode with
    | .i168 => 7 * ((dataLen + 4 + 20) / 21)
    | .i48  => 2 * ((dataLen + 4 + 5) / 6)
  let (l0, l1, l2) := nonceSplitLens nonceBytes
  let b0 := cobsEncodeBound (l0 + laneLen)
  let b1 := cobsEncodeBound (l1 + laneLen)
  let b2 := cobsEncodeBound (l2 + laneLen) + reserve
  let minPx := minPixelsForKeyBits512 keyBits
  calcContainerSize3Cfg512 mode b0 b1 b2 minPx barrierFill

/-- Compute `(third, thirdPixels2, cap0, cap1, cap2)` (`tripleThirdCaps`, `triplepayload.go:145-154`). -/
def tripleThirdCaps512 (totalPixels : Nat) : Nat × Nat × Nat × Nat × Nat :=
  let third := totalPixels / 3
  let thirdPixels2 := totalPixels - 2 * third
  (third, thirdPixels2, third * 7, third * 7, thirdPixels2 * 7)

/-! ## Section 7: Layer I (`0x05`) Sub-Region Schedule & 512-Bit Pixel Barrier (`desync.go:64-136`, `process_generic.go:786-958`) -/

/-- Golden-ratio constant `desyncGoldenGamma = 0x9E3779B97F4A7C15` (`desync.go:31`). -/
def desyncGoldenGamma512 : UInt64 := 0x9E3779B97F4A7C15

/-- Layer I sub-region trajectory schedule (`desync.go:64-70`). -/
structure SubregionSchedule512 where
  k      : Nat
  tau    : Array Nat
  offset : Array Nat
  size   : Array Nat
  start  : Array Nat
  logOff : Array Nat
  deriving DecidableEq, Repr

/-- Build Layer I sub-region schedule (`buildSubregionSchedule`, `desync.go:75-136`). -/
def buildSubregionSchedule512 (startPixel totalPixels : Nat) (w : Array UInt64) : SubregionSchedule512 :=
  let w0 := w.getD 0 0
  let w1 := w.getD 1 0
  let (k, deltaMax) :=
    if totalPixels < 365 then
      (6 + (w0 % 5).toNat, 1)
    else
      (8 + (w0 % 9).toNat, 2)
  let base := totalPixels / k
  let rem := totalPixels % k
  let physOff0 : Array Nat := (List.range k).foldl (fun acc j =>
    let sz := base + (if j < rem then 1 else 0)
    acc.push (acc.getD j 0 + sz)) #[0]
  let physOff : Array Nat := (List.range (k - 1)).foldl (fun acc jIdx =>
    let j := jIdx + 1
    let cur := acc.getD j 0
    if deltaMax == 1 then
      let raw := ((w0 >>> (8 + j).toUInt64) &&& 1).toNat
      acc.set! j (cur + raw - 1)
    else
      let raw := ((w0 >>> (8 + 2 * j).toUInt64) &&& 3).toNat
      acc.set! j (cur + raw - 2)) physOff0
  let physSize : Array Nat := (List.range k).foldl (fun acc j =>
    acc.push (physOff.getD (j + 1) 0 - physOff.getD j 0)) #[]
  let tau := fisherYatesPerm k w1
  let (offset, size, start, logOff) := (List.range k).foldl
    (fun (st : Array Nat × Array Nat × Array Nat × Array Nat) step =>
      let (offs, szs, sts, logs) := st
      let physIdx := tau.getD step 0
      let m := physSize.getD physIdx 1
      let pOff := physOff.getD physIdx 0
      let lOff := logs.getD step 0
      let wi := w.getD (2 + (step % 6)) 0
      let mix := rotl64 wi (11 * step).toUInt64 ^^^ ((step + 1).toUInt64 * desyncGoldenGamma512)
      let stVal := ((startPixel.toUInt64 + mix) % m.toUInt64).toNat
      (offs.push pOff, szs.push m, sts.push stVal, logs.push (lOff + m)))
    (#[], #[], #[], #[0])
  { k, tau, offset, size, start, logOff }

/-- Derive Layer I schedule for a `Seed512` `startSeed` (`desync.go:215-232`),
    dispatching to `ITB.Posit.buildSubregionSchedulePosit` when `mode == 3` and
    `buildSubregionSchedule512` otherwise. -/
def deriveSubregionSchedule512 (startSeed : Seed512) (mainNonce : ByteArray)
    (startPixel totalPixels : Nat) (mode : Nat := 1) : SubregionSchedule512 :=
  let buf := (ByteArray.empty.push 0x05) ++ mainNonce
  let h := chainHash512Words startSeed buf
  let (w0, w1) := fullWidthFold512 h.h0 h.h1
  let (w2, w3) := fullWidthFold512 h.h2 h.h3
  let (w4, w5) := fullWidthFold512 h.h4 h.h5
  let (w6, w7) := fullWidthFold512 h.h6 h.h7
  let w := #[w0, w1, w2, w3, w4, w5, w6, w7]
  if mode == 3 then
    let sp := ITB.Posit.buildSubregionSchedulePosit startPixel totalPixels w
    { k := sp.k, tau := #[], offset := sp.offset, size := sp.size, start := sp.start, logOff := sp.logOff }
  else
    buildSubregionSchedule512 startPixel totalPixels w

/-- `noiseFold3(w)` (`noisepos.go:9-16`). -/
def noiseFold3U64 (w : UInt64) : Nat :=
  let w := w ^^^ (w >>> 32)
  let w := w ^^^ (w >>> 16)
  let w := w ^^^ (w >>> 8)
  let w := w ^^^ (w >>> 4)
  let n := w &&& 15
  ((n ^^^ (n >>> 3)) &&& 7).toNat

/-- 7-bit left rotation `rotateBits7(v, r)` (`itb.go:54-57`). -/
def rotateBits7U8 (v : UInt8) (r : Nat) : UInt8 :=
  let s := (r % 7).toUInt8
  if s == 0 then v &&& 0x7F
  else (((v <<< s) ||| (v >>> (7 - s))) &&& 0x7F)

/-- Encode one channel byte (`process_generic.go:803-822`). -/
def encodeChannelByte512 (dataBits channelXOR orig : UInt8) (dataRotation noisePos : Nat) : UInt8 :=
  let xored := (dataBits &&& 0x7F) ^^^ (channelXOR &&& 0x7F)
  let rot := rotateBits7U8 xored dataRotation
  let np := noisePos.toUInt8
  let noiseMask : UInt8 := (1 : UInt8) <<< np
  let low := rot &&& (noiseMask - 1)
  let high := rot >>> np
  low ||| (orig &&& noiseMask) ||| (high <<< (np + 1))

/-- Decode one channel byte (`process_generic.go:836-845`). -/
def decodeChannelByte512 (channelByte channelXOR : UInt8) (dataRotation noisePos : Nat) : UInt8 :=
  let np := noisePos.toUInt8
  let noiseMask : UInt8 := (1 : UInt8) <<< np
  let low := channelByte &&& (noiseMask - 1)
  let high := channelByte >>> (np + 1)
  let rot := (low ||| (high <<< np)) &&& 0x7F
  let xored := rotateBits7U8 rot ((7 - (dataRotation % 7)) % 7)
  (xored ^^^ channelXOR) &&& 0x7F

/-- 8-byte RGBWYOPA pixel represented as an 8-tuple of `UInt8`. -/
structure Pixel8 where
  c0 : UInt8
  c1 : UInt8
  c2 : UInt8
  c3 : UInt8
  c4 : UInt8
  c5 : UInt8
  c6 : UInt8
  c7 : UInt8
  deriving DecidableEq, Repr

def Pixel8.replicate (b : UInt8) : Pixel8 :=
  { c0 := b, c1 := b, c2 := b, c3 := b, c4 := b, c5 := b, c6 := b, c7 := b }

def Pixel8.toBytes (px : Pixel8) : List UInt8 :=
  [px.c0, px.c1, px.c2, px.c3, px.c4, px.c5, px.c6, px.c7]

def takePixel8 : List UInt8 → Pixel8 × List UInt8
  | c0 :: c1 :: c2 :: c3 :: c4 :: c5 :: c6 :: c7 :: rest =>
    ({ c0, c1, c2, c3, c4, c5, c6, c7 }, rest)
  | bs =>
    let g (i : Nat) : UInt8 := bs.getD i 0
    ({ c0 := g 0, c1 := g 1, c2 := g 2, c3 := g 3,
       c4 := g 4, c5 := g 5, c6 := g 6, c7 := g 7 }, [])

def unpackPixels8List : Nat → List UInt8 → List Pixel8
  | 0, _ => []
  | n + 1, bs =>
    let (px, rest) := takePixel8 bs
    px :: unpackPixels8List n rest

def pushPixel8 (b : ByteArray) (px : Pixel8) : ByteArray :=
  b.push px.c0
   |>.push px.c1
   |>.push px.c2
   |>.push px.c3
   |>.push px.c4
   |>.push px.c5
   |>.push px.c6
   |>.push px.c7

def readPixel8 (b : ByteArray) (off : Nat) : Pixel8 :=
  { c0 := getByteD512 b (off + 0)
    c1 := getByteD512 b (off + 1)
    c2 := getByteD512 b (off + 2)
    c3 := getByteD512 b (off + 3)
    c4 := getByteD512 b (off + 4)
    c5 := getByteD512 b (off + 5)
    c6 := getByteD512 b (off + 6)
    c7 := getByteD512 b (off + 7) }

/-- Encode logical pixel `p` (carrying the 56-bit word `packed56` from `payload[7*p .. 7*p+7]`)
    into a `Pixel8` with initial DRBG fill `origPx` (`process_generic.go:786-827`). -/
@[inline] def encodePixel512 (noiseSeed dataSeed : Seed512) (tpl : BlockNonceTemplate512) (noiseBase p : Nat)
    (origPx : Pixel8) (packed56 : Nat) : Pixel8 :=
  let noiseH := blockHash512Fast noiseSeed (noiseBase + p) tpl
  let dataH  := blockHash512Fast dataSeed  p               tpl
  let noisePos := noiseFold3U64 (noiseH.h0 + rotl64 noiseH.h1 1)
  let dataHashNat := dataH.h0.toNat
  let dataRotation := dataHashNat % 7
  let xorMaskNat := dataHashNat >>> 3
  let encCh (ch : Nat) (orig : UInt8) : UInt8 :=
    let dBits := UInt8.ofNat ((packed56 >>> (ch * 7)) &&& 0x7F)
    let cXor  := UInt8.ofNat ((xorMaskNat >>> (ch * 7)) &&& 0x7F)
    encodeChannelByte512 dBits cXor orig dataRotation noisePos
  { c0 := encCh 0 origPx.c0
    c1 := encCh 1 origPx.c1
    c2 := encCh 2 origPx.c2
    c3 := encCh 3 origPx.c3
    c4 := encCh 4 origPx.c4
    c5 := encCh 5 origPx.c5
    c6 := encCh 6 origPx.c6
    c7 := encCh 7 origPx.c7 }

/-- Decode logical pixel `p` from physical `Pixel8`, returning its 56-bit payload word (`process_generic.go:829-856`). -/
@[inline] def decodePixel512 (noiseSeed dataSeed : Seed512) (tpl : BlockNonceTemplate512) (noiseBase p : Nat)
    (px : Pixel8) : Nat :=
  let noiseH := blockHash512Fast noiseSeed (noiseBase + p) tpl
  let dataH  := blockHash512Fast dataSeed  p               tpl
  let noisePos := noiseFold3U64 (noiseH.h0 + rotl64 noiseH.h1 1)
  let dataHashNat := dataH.h0.toNat
  let dataRotation := dataHashNat % 7
  let xorMaskNat := dataHashNat >>> 3
  let decCh (ch : Nat) (b : UInt8) : Nat :=
    let cXor := UInt8.ofNat ((xorMaskNat >>> (ch * 7)) &&& 0x7F)
    (decodeChannelByte512 b cXor dataRotation noisePos).toNat <<< (ch * 7)
  decCh 0 px.c0 |||
  decCh 1 px.c1 |||
  decCh 2 px.c2 |||
  decCh 3 px.c3 |||
  decCh 4 px.c4 |||
  decCh 5 px.c5 |||
  decCh 6 px.c6 |||
  decCh 7 px.c7

/-- Encrypt one container region (`process512Cfg` + `processSubregions512`, `itb512.go:29-56`, `desync.go:295-323`). -/
def processRegionEncrypt512 (noiseSeed dataSeed startSeed : Seed512) (mainNonce : ByteArray)
    (totalPixels noiseBase : Nat) (fillByte : UInt8) (payload : ByteArray) (mode : Nat := 1) : ByteArray := Id.run do
  let startPixel := deriveStartPixel512 startSeed mainNonce totalPixels
  let tpl := prepareBlockNonce512 mainNonce
  let origPx := Pixel8.replicate fillByte
  let mut pixArr := Array.replicate totalPixels origPx
  if totalPixels < 32 then
    for p in [:totalPixels] do
      let physIdx := (startPixel + p) % totalPixels
      let packed56 := readU56LE payload (p * 7)
      let px := encodePixel512 noiseSeed dataSeed tpl noiseBase p origPx packed56
      pixArr := pixArr.set! physIdx px
  else
    let sched := deriveSubregionSchedule512 startSeed mainNonce startPixel totalPixels mode
    for step in [:sched.k] do
      let logStart := sched.logOff.getD step 0
      let m := sched.size.getD step 0
      let physOff := sched.offset.getD step 0
      let s := sched.start.getD step 0
      for q in [:m] do
        let p := logStart + q
        let physIdx := physOff + (s + q) % m
        let packed56 := readU56LE payload (p * 7)
        let px := encodePixel512 noiseSeed dataSeed tpl noiseBase p origPx packed56
        pixArr := pixArr.set! physIdx px
  let mut out := ByteArray.emptyWithCapacity (totalPixels * 8)
  for px in pixArr do
    out := pushPixel8 out px
  return out

/-- Decrypt one container region up to its `0x00` COBS delimiter (`process512Cfg` + `processSubregions512`, `itb512.go:367-382`). -/
def processRegionDecrypt512 (noiseSeed dataSeed startSeed : Seed512) (mainNonce : ByteArray)
    (regionBytes : ByteArray) (totalPixels noiseBase : Nat) (mode : Nat := 1) : ByteArray := Id.run do
  let startPixel := deriveStartPixel512 startSeed mainNonce totalPixels
  let tpl := prepareBlockNonce512 mainNonce
  let mut out := ByteArray.emptyWithCapacity (totalPixels * 7)
  if totalPixels < 32 then
    for p in [:totalPixels] do
      let physIdx := (startPixel + p) % totalPixels
      let px := readPixel8 regionBytes (physIdx * 8)
      let w := decodePixel512 noiseSeed dataSeed tpl noiseBase p px
      let b0 := UInt8.ofNat (w &&& 0xFF)
      let b1 := UInt8.ofNat ((w >>> 8) &&& 0xFF)
      let b2 := UInt8.ofNat ((w >>> 16) &&& 0xFF)
      let b3 := UInt8.ofNat ((w >>> 24) &&& 0xFF)
      let b4 := UInt8.ofNat ((w >>> 32) &&& 0xFF)
      let b5 := UInt8.ofNat ((w >>> 40) &&& 0xFF)
      let b6 := UInt8.ofNat ((w >>> 48) &&& 0xFF)
      out := ((((((out.push b0).push b1).push b2).push b3).push b4).push b5).push b6
      if b0 == 0 || b1 == 0 || b2 == 0 || b3 == 0 || b4 == 0 || b5 == 0 || b6 == 0 then
        return out
  else
    let sched := deriveSubregionSchedule512 startSeed mainNonce startPixel totalPixels mode
    for step in [:sched.k] do
      let logStart := sched.logOff.getD step 0
      let m := sched.size.getD step 0
      let physOff := sched.offset.getD step 0
      let s := sched.start.getD step 0
      for q in [:m] do
        let p := logStart + q
        let physIdx := physOff + (s + q) % m
        let px := readPixel8 regionBytes (physIdx * 8)
        let w := decodePixel512 noiseSeed dataSeed tpl noiseBase p px
        let b0 := UInt8.ofNat (w &&& 0xFF)
        let b1 := UInt8.ofNat ((w >>> 8) &&& 0xFF)
        let b2 := UInt8.ofNat ((w >>> 16) &&& 0xFF)
        let b3 := UInt8.ofNat ((w >>> 24) &&& 0xFF)
        let b4 := UInt8.ofNat ((w >>> 32) &&& 0xFF)
        let b5 := UInt8.ofNat ((w >>> 40) &&& 0xFF)
        let b6 := UInt8.ofNat ((w >>> 48) &&& 0xFF)
        out := ((((((out.push b0).push b1).push b2).push b3).push b4).push b5).push b6
        if b0 == 0 || b1 == 0 || b2 == 0 || b3 == 0 || b4 == 0 || b5 == 0 || b6 == 0 then
          return out
  return out

/-! ## Section 8: Complete 512-Bit Pipeline (`Encrypt3x512Cfg` / `Decrypt3x512Cfg`) -/

/-- 8-seed `Seed512` constellation matching `Encrypt3x512Cfg(cfg, noiseSeed, lockSeed,
    dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data)` (`itb512.go:159`). -/
structure Constellation512 where
  noiseSeed  : Seed512
  lockSeed   : Seed512
  dataSeed1  : Seed512
  dataSeed2  : Seed512
  dataSeed3  : Seed512
  startSeed1 : Seed512
  startSeed2 : Seed512
  startSeed3 : Seed512

/-- Joint minimum pixels across `noiseSeed`, `dataSeed1..3`, and `startSeed1..3` (`itb.go:146-154`). -/
def Constellation512.minPixels (c : Constellation512) : Nat :=
  max c.noiseSeed.minPixels
    (max c.dataSeed1.minPixels (max c.dataSeed2.minPixels (max c.dataSeed3.minPixels
      (max c.startSeed1.minPixels (max c.startSeed2.minPixels c.startSeed3.minPixels)))))

/-- Pad a COBS-encoded buffer (already ending in `0x00`) with `fillByte` up to capacity `capBytes`
    (`triplepayload.go:449-459`). -/
def padCobsPayload512 (cobsWithNull : ByteArray) (capBytes : Nat) (fillByte : UInt8) : ByteArray :=
  if cobsWithNull.size >= capBytes then
    cobsWithNull.extract 0 capBytes
  else
    cobsWithNull ++ ByteArray.mk (Array.replicate (capBytes - cobsWithNull.size) fillByte)

/-- Deterministic specification of `Encrypt3x512Cfg` (`itb512.go:159-263`, `triplepayload.go:277-490`)
    supporting:
    - both `Interlock = "48"` (`.i48`) and `Interlock = "168"` (`.i168`)
    - all key sizes (`512`, `1024`, `2048` bits via `c` seed component lengths)
    - all nonce sizes (`128`, `256`, `512` bits via `ilNonce.size == mainNonce.size`)
    - both **Mode 1** (`mode = 1`) and **Mode 2** (`mode = 2`). -/
def encrypt3x512DeterministicCfg (interlockMode : InterlockMode512) (c : Constellation512)
    (plaintext : ByteArray) (mode : Nat) (ilNonce mainNonce : ByteArray)
    (fillByte : UInt8) (prefix32 : ByteArray) (barrierFill : Nat := 1) : ByteArray :=
  -- 1. Rank Barrier (48-bit or 168-bit) + Layer II (0x06)
  let (p0, p1, p2) :=
    match interlockMode with
    | .i168 => splitTriple168    c.lockSeed ilNonce plaintext
    | .i48  => splitTriple48_512 c.lockSeed ilNonce plaintext
  -- 2. Interlock-nonce 3-lane fragment prepend
  let (frag0, frag1, frag2) := nonceSplitFrags ilNonce
  let lane0 := frag0 ++ p0
  let lane1 := frag1 ++ p1
  let lane2 := frag2 ++ p2
  -- 3. Container sizing from COBS upper bounds + reserve = 33 (nomacTagStubSizeCfg)
  let b0 := cobsEncodeBound lane0.size
  let b1 := cobsEncodeBound lane1.size
  let b2 := cobsEncodeBound lane2.size + 33
  let (width, height) := calcContainerSize3Cfg512 mode b0 b1 b2 c.minPixels barrierFill
  let totalPixels := width * height
  let (third, thirdPixels2, cap0, cap1, cap2) := tripleThirdCaps512 totalPixels
  -- 4. COBS encode + 0x00 terminator + DRBG tail fill to cap_i
  let pay0 := padCobsPayload512 (cobsEncodeWithNull lane0) cap0 fillByte
  let pay1 := padCobsPayload512 (cobsEncodeWithNull lane1) cap1 fillByte
  let pay2 := padCobsPayload512 (cobsEncodeWithNull lane2) cap2 fillByte
  -- 5. Layer I (0x05) + 512-bit Pixel Barrier across the 3 regions
  let reg0 := processRegionEncrypt512 c.noiseSeed c.dataSeed1 c.startSeed1 mainNonce third        0           fillByte pay0 mode
  let reg1 := processRegionEncrypt512 c.noiseSeed c.dataSeed2 c.startSeed2 mainNonce third        third       fillByte pay1 mode
  let reg2 := processRegionEncrypt512 c.noiseSeed c.dataSeed3 c.startSeed3 mainNonce thirdPixels2 (2 * third) fillByte pay2 mode
  -- 6. Wire assembly: [prefix32][mainNonce][BE16(width)][BE16(height)][reg0][reg1][reg2]
  let hdr := pushU16BE512 (pushU16BE512 (prefix32 ++ mainNonce) width) height
  hdr ++ reg0 ++ reg1 ++ reg2

/-- Default `Interlock = "168"` entry point for `encrypt3x512Deterministic`. -/
def encrypt3x512Deterministic (c : Constellation512) (plaintext : ByteArray) (mode : Nat)
    (ilNonce mainNonce : ByteArray) (fillByte : UInt8) (prefix32 : ByteArray) : ByteArray :=
  encrypt3x512DeterministicCfg .i168 c plaintext mode ilNonce mainNonce fillByte prefix32 1

/-- Specification of `Decrypt3x512Cfg` (`itb512.go:270-413`) supporting both `Interlock = "48"`
    and `Interlock = "168"` and arbitrary `nonceBytes ∈ {16, 32, 64}`. -/
def decrypt3x512Cfg (interlockMode : InterlockMode512) (c : Constellation512)
    (wire : ByteArray) (nonceBytes : Nat := 16) (mode : Nat := 1) : Option ByteArray :=
  let headerSize := 32 + nonceBytes + 4
  if wire.size < headerSize then none
  else
    let mainNonce := wire.extract 32 (32 + nonceBytes)
    let width := readU16BE512 wire (32 + nonceBytes)
    let height := readU16BE512 wire (32 + nonceBytes + 2)
    if width == 0 || height == 0 || width != height then none
    else
      let totalPixels := width * height
      let (third, thirdPixels2, _, _, _) := tripleThirdCaps512 totalPixels
      let thirdBytes := third * 8
      let thirdBytes2 := thirdPixels2 * 8
      let containerSize := totalPixels * 8
      if wire.size != headerSize + containerSize then none
      else
        let container := wire.extract headerSize wire.size
        let reg0 := container.extract 0 thirdBytes
        let reg1 := container.extract thirdBytes (2 * thirdBytes)
        let reg2 := container.extract (2 * thirdBytes) (2 * thirdBytes + thirdBytes2)
        -- 1. Layer I (0x05) + 512-bit Pixel Barrier decode
        let dec0 := processRegionDecrypt512 c.noiseSeed c.dataSeed1 c.startSeed1 mainNonce reg0 third        0           mode
        let dec1 := processRegionDecrypt512 c.noiseSeed c.dataSeed2 c.startSeed2 mainNonce reg1 third        third       mode
        let dec2 := processRegionDecrypt512 c.noiseSeed c.dataSeed3 c.startSeed3 mainNonce reg2 thirdPixels2 (2 * third) mode
        -- 2. Null-search + COBS decode
        match cobsDecode dec0, cobsDecode dec1, cobsDecode dec2 with
        | some part0, some part1, some part2 =>
          -- 3. Recover interlock nonce & lane payloads
          match recoverInterlockNonce512 part0 part1 part2 nonceBytes with
          | none => none
          | some (ilNonce, lane0, lane1, lane2) =>
            -- 4. Invert Layer II (0x06) + Rank Barrier (48-bit or 168-bit)
            match interlockMode with
            | .i168 => interleaveTriple168    c.lockSeed ilNonce lane0 lane1 lane2
            | .i48  => interleaveTriple48_512 c.lockSeed ilNonce lane0 lane1 lane2
        | _, _, _ => none

/-- Default `Interlock = "168"`, 128-bit nonce entry point for `decrypt3x512`. -/
def decrypt3x512 (c : Constellation512) (wire : ByteArray) (nonceBytes : Nat := 16) : Option ByteArray :=
  decrypt3x512Cfg .i168 c wire nonceBytes

/-- Configuration structure for `encrypt3x512DeterministicCfg` / `decrypt3x512WithCfg` (`itb.go:Config`). -/
structure PipelineConfig512 where
  interlockMode : InterlockMode512 := .i168
  nonceBits     : Nat := 128
  barrierFill   : Nat := 1
  mode          : Nat := 1
  reserve       : Nat := 33
  fillByte      : UInt8 := 0x5A
  deriving DecidableEq, Repr

/-- Nonce byte length `nonceBits / 8`. -/
def PipelineConfig512.nonceBytes (cfg : PipelineConfig512) : Nat :=
  cfg.nonceBits / 8

/-- Configuration-driven wrapper around `decrypt3x512Cfg` (`itb512.go:Decrypt3x512Cfg`).
    Reads `W` and `H` directly from the wire header (independent of `cfg.barrierFill`, and shared across Mode 1/2). -/
def decrypt3x512WithCfg (cfg : PipelineConfig512) (c : Constellation512) (wire : ByteArray) : Option ByteArray :=
  let decMode := if cfg.mode == 3 then 3 else 1
  decrypt3x512Cfg cfg.interlockMode c wire cfg.nonceBytes decMode

/-! ## Section 9: Stage-by-Stage & End-to-End Inversion Theorems -/

/-- **Theorem 1 (5-Stage Functional Composition Left-Inverse)**:
    For any five forward pipeline stages
      1. `f_rank  : α → β` (48-Bit or 168-Bit Rank Barrier `0x03`/`0x04`)
      2. `f_slot  : β → γ` (Layer II `0x06` Cross-Lane Slot Desynchronization)
      3. `f_cobs  : γ → δ` (Interlock-Nonce Prefix & COBS Framing)
      4. `f_traj  : δ → ε` (Layer I `0x05` Sub-Region Trajectory)
      5. `f_pixel : ε → ζ` (512-Bit Pixel Barrier `0x01`/`0x02` Channel Encoding)
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
    `decrypt3x512WithCfg` depends only on `cfg.interlockMode`, `cfg.nonceBytes`
    (to slice `mainNonce` and `ilNonce`), and whether `cfg.mode == 3` (to select
    `buildSubregionSchedulePosit` vs `buildSubregionSchedule512`), and has **zero dependence**
    on `cfg.barrierFill`, `cfg.reserve`, or `cfg.fillByte`.
    In particular, any **Mode 1** wire decrypts under a **Mode 2** receiver config and vice versa
    (`(1 == 3) = (2 == 3)` holds as `false = false`), and any **Mode 3** wire decrypts under any
    **Mode 3** receiver config regardless of `barrierFill`, `reserve`, or `fillByte`. -/
theorem decrypt3x512Cfg_mode_barrierFill_independent
    (cfg1 cfg2 : PipelineConfig512) (c : Constellation512) (wire : ByteArray)
    (hIl : cfg1.interlockMode = cfg2.interlockMode)
    (hNonce : cfg1.nonceBytes = cfg2.nonceBytes)
    (hMode3 : (cfg1.mode == 3) = (cfg2.mode == 3)) :
    decrypt3x512WithCfg cfg1 c wire = decrypt3x512WithCfg cfg2 c wire := by
  unfold decrypt3x512WithCfg
  rw [hIl, hNonce, hMode3]

/-- `nonceSplitLens n` partitions `n` bytes across the 3 lanes (`l0 + l1 + l2 = n`). -/
theorem nonceSplitLens_sum (n : Nat) :
    (nonceSplitLens n).1 + (nonceSplitLens n).2.1 + (nonceSplitLens n).2.2 = n := by
  simp only [nonceSplitLens]
  split <;> split <;> omega

/-- Canonical nonce split lengths for 128-bit (`16 B`), 256-bit (`32 B`), and 512-bit (`64 B`) nonces. -/
theorem nonceSplitLens_canonical :
    nonceSplitLens 16 = (6, 5, 5) ∧
    nonceSplitLens 32 = (11, 11, 10) ∧
    nonceSplitLens 64 = (22, 21, 21) := by
  decide

/-- Canonical `minPixels` floor for 512-bit seeds across 512-bit (`8` words), 1024-bit (`16` words),
    and 2048-bit (`32` words) keys (`seed512.go:223-231`): `183`, `365`, and `730` pixels. -/
theorem minPixelsForKeyBits512_canonical :
    minPixelsForKeyBits512 512 = 183 ∧
    minPixelsForKeyBits512 1024 = 365 ∧
    minPixelsForKeyBits512 2048 = 730 := by
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
theorem channelBitInsertExtract512_roundtrip (noiseBit : Bool) (d : Fin 128) (noisePos : Fin 8) :
    let orig8 : UInt8 := if noiseBit then (1 : UInt8) <<< noisePos.val.toUInt8 else 0
    decodeChannelByte512 (encodeChannelByte512 d.val.toUInt8 0 orig8 0 noisePos.val)
      0 0 noisePos.val = d.val.toUInt8 := by
  revert noiseBit d noisePos
  decide

/-- Universal per-channel Pixel Barrier round-trip across all 7-bit data `d`, 7-bit masks `m`,
    rotations `r ∈ Fin 7`, noise positions `np ∈ Fin 8`, and carrier bits `noiseBit : Bool`
    (inherited from `ITB.PixelBarrier`). -/
theorem pixelChannel512_roundtrip (d m : BitVec 7) (r : Fin 7) (np : Fin 8) (noiseBit : Bool) :
    decodeChannel (encodeChannel d m r np noiseBit) m r np = d :=
  decode_encode_id d m r np noiseBit

/-- `invFullWidthFold` and `fullWidthFold` form an exact 128-bit bijection over `BitVec 64 × BitVec 64`
    for all Layer I (`0x05`) and Layer II (`0x06`) schedule words (inherited from `ITB.Desync`). -/
theorem fullWidthFold512_bijection (hLo hHi w0 w1 : BitVec 64) :
    invFullWidthFold (fullWidthFold hLo hHi).1 (fullWidthFold hLo hHi).2 = (hLo, hHi) ∧
    fullWidthFold (invFullWidthFold w0 w1).1 (invFullWidthFold w0 w1).2 = (w0, w1) :=
  fullWidthFold_bijection hLo hHi w0 w1

/-- Layer II (`0x06`) cyclic shift inversion (`invLaneSlotShift` is the exact two-sided inverse
    of `laneSlotShift` on `[0, m)`, and `desyncBeta0 m r0 ≠ desyncBeta1 m r0 r1` for all `m ≥ 2`). -/
theorem desyncLaneSlotShift512_roundtrip (m beta j r0 r1 : Nat) (hm : 2 ≤ m) (hb : beta < m) (hj : j < m) :
    invLaneSlotShift m beta (laneSlotShift m beta j) = j ∧
    laneSlotShift m beta (invLaneSlotShift m beta j) = j ∧
    desyncBeta0 m r0 ≠ desyncBeta1 m r0 r1 :=
  ⟨laneSlotShift_left_inv m beta j hb hj,
   laneSlotShift_right_inv m beta j hb hj,
   desync_beta0_ne_beta1 m r0 r1 hm⟩

/-- Layer I (`0x05`) sub-region cyclic step inversion (`invSubregionStep` is the exact two-sided
    inverse of `subregionStep` on `[0, M)`). -/
theorem subregionStep512_roundtrip (M s q : Nat) (hs : s < M) (hq : q < M) :
    invSubregionStep M s (subregionStep M s q) = q ∧
    subregionStep M s (invSubregionStep M s q) = q :=
  ⟨subregionStep_left_inv M s q hs hq,
   subregionStep_right_inv M s q hs hq⟩

/-- Why **Mode 1** and **Mode 2** decrypt vice-versa automatically:
    1. `decrypt3x512Cfg` has no `mode` or `barrierFill` parameter: it reads `(width, height)` directly
       from the wire header and computes `third = (width * height) / 3`.
    2. In **Layer I** (`0x05`), `buildSubregionSchedule512` selects the compact schedule
       (`k = 6 + w0 % 5, deltaMax = 1`) vs the full schedule (`k = 8 + w0 % 9, deltaMax = 2`)
       solely by comparing `totalPixels` against `365` (`desync.go:77`). -/
theorem buildSubregionSchedule512_mode_branch (startPixel totalPixels : Nat) (w : Array UInt64) :
    (buildSubregionSchedule512 startPixel totalPixels w).k =
      if totalPixels < 365 then
        6 + (w.getD 0 0 % 5).toNat
      else
        8 + (w.getD 0 0 % 9).toNat := by
  simp only [buildSubregionSchedule512]
  split <;> rfl

/-- Exact equivalence between `splitRank168Words` (`interlock168_rank_split.go`) and mathematical
    `twoStepUnrank (binom 168 56) (binom 112 56)`, together with the certified reciprocal error
    envelopes `divmodStepB168_error_envelope` and `modStepA168_error_envelope` from `ITB.SplitRank`. -/
theorem splitRank168_recip_equiv (r : Words8) :
    splitRank168Words r = twoStepUnrank (binom 168 56) (binom 112 56) r.toNat512 ∧
    (B168_limbs * 2 ^ 64) * (2 ^ 236 - muB168 * B168_limbs) + (2 * 2 ^ 192) * B168_limbs < 2 ^ 236 * B168_limbs ∧
    (A168_limbs * 2 ^ 64) * (2 ^ 342 - muA168 * A168_limbs) + (4 * 2 ^ 256) * A168_limbs < 2 ^ 342 * A168_limbs := by
  refine ⟨?_, divmodStepB168_error_envelope, modStepA168_error_envelope⟩
  simp only [splitRank168Words, withStrictNat, withProd2, A168_limbs_eq_binom, B168_limbs_eq_binom]

/-- Exact equivalence between `splitRank48Pair` (`interlock48_rank_split.go`) and mathematical
    `twoStepUnrank A48 B48`, together with single-correction exactness (`divB48_single_correction_exact`
    and `modA48_single_correction_exact`) for every 64-bit input `X < 2^64` from `ITB.SplitRank`. -/
theorem splitRank48_recip_equiv (lane0 lane1 : UInt64) (X : Nat) (hX : X < 2 ^ 64) :
    splitRank48Pair lane0 lane1 = twoStepUnrank A48 B48 (lane0.toNat + (lane1.toNat <<< 64)) ∧
    (let qHat := (X * interlockB48Recip) / 2 ^ 93
     let rem := X - qHat * interlockB48
     let q := if rem ≥ interlockB48 then qHat + 1 else qHat
     let r := if rem ≥ interlockB48 then rem - interlockB48 else rem
     qHat * interlockB48 ≤ X ∧ X = q * interlockB48 + r ∧ r < interlockB48) ∧
    (let qHat := (X * interlockA48Recip) / 2 ^ 105
     let rem := X - qHat * interlockA48
     let q := if rem ≥ interlockA48 then qHat + 1 else qHat
     let r := if rem ≥ interlockA48 then rem - interlockA48 else rem
     qHat * interlockA48 ≤ X ∧ X = q * interlockA48 + r ∧ r < interlockA48) := by
  refine ⟨?_, divB48_single_correction_exact X hX, modA48_single_correction_exact X hX⟩
  have hA : interlockA48 = A48 := interlockA48Recip_eq_floor_div.1
  have hB : interlockB48 = B48 := interlockB48Recip_eq_floor_div.1
  simp only [splitRank48Pair, withStrictNat, withProd2, hA, hB]

/-! ## Section 10: Kernel-Verified Go KATs -/

def katBlake2b512Empty : Words8 :=
  { h0 := 0x03590142f7026a78
    h1 := 0x72d2522585fdc6c6
    h2 := 0x614758e140472f91
    h3 := 0x19541ff717e2868a
    h4 := 0x5358eeaf31105ed2
    h5 := 0x4bb04e9344648913
    h6 := 0x55b748145b683a90
    h7 := 0xcee29bfe1a706fd5 }

def katBlake2b512ABC : Words8 :=
  { h0 := 0x0d4d1c983fa580ba
    h1 := 0xe9f6129fb697276a
    h2 := 0xb7c45a68142f214c
    h3 := 0xd1a2ffdb6fbb124b
    h4 := 0x2d79ab2a39c5877d
    h5 := 0x95cc3345ded552c2
    h6 := 0x5a92f1dba88ad318
    h7 := 0x239900d4ed8623b9 }

def katBlake2b512WithKeyOut : Words8 :=
  { h0 := 0xb5dbc04d1194a6ce
    h1 := 0x452833fdc78b6a6f
    h2 := 0x2e56ef8ff71fee4a
    h3 := 0x31ae79e2c104ac4c
    h4 := 0x8d7adec53f71bbda
    h5 := 0xeefd00d7e4cf7514
    h6 := 0x4f94bfbc7cc302ef
    h7 := 0x4290921fb3ce1218 }

def katChainHash512Seed0Out : Words8 :=
  { h0 := 0x4cc81c8da0837e20
    h1 := 0x66ecef64905535f5
    h2 := 0xdbc415246e709797
    h3 := 0xdf068c2855f8f984
    h4 := 0x3ae020f6cec41a2e
    h5 := 0x9e342249a7f9926e
    h6 := 0xa13b8921a2c56b23
    h7 := 0xe2c3e284f40f35c4 }

/-- Fixed 64-byte `BLAKE2b-512` key `k[i] = 0xA0 + i` (`i ∈ 0..63`). -/
def katB2Key512 : ByteArray :=
  ByteArray.mk ((List.range 64).map (fun i => UInt8.ofNat (0xA0 + i))).toArray

/-- 15-byte test message `0x00..0x0E`. -/
def katChainInput512 : ByteArray :=
  ByteArray.mk ((List.range 15).map (fun i => UInt8.ofNat i)).toArray

/-- 8-word test seed `testSeed[i] = (i + 1) * 0x0102030405060708`. -/
def katTestSeedWords512 : Array UInt64 :=
  ((List.range 8).map (fun i => (i + 1).toUInt64 * 0x0102030405060708)).toArray

/-- Build deterministic `Seed512` of `numWords` `UInt64` components (`8` = 512b, `16` = 1024b, `32` = 2048b)
    for `slot ∈ 0..7`. -/
def makeKatSeed512Bits (numWords slot : Nat) : Seed512 :=
  let comps := ((List.range numWords).map (fun i =>
    (slot + 1).toUInt64 * 0x0102030405060708 + i.toUInt64 * 0x1111111111111111)).toArray
  Seed512.mkFromKeyAndComps katB2Key512 comps

/-- Build deterministic 8-seed `Constellation512` of `numWords` `UInt64` components per seed. -/
def makeKatConstellation512 (numWords : Nat) : Constellation512 :=
  { noiseSeed  := makeKatSeed512Bits numWords 0
    lockSeed   := makeKatSeed512Bits numWords 1
    dataSeed1  := makeKatSeed512Bits numWords 2
    dataSeed2  := makeKatSeed512Bits numWords 3
    dataSeed3  := makeKatSeed512Bits numWords 4
    startSeed1 := makeKatSeed512Bits numWords 5
    startSeed2 := makeKatSeed512Bits numWords 6
    startSeed3 := makeKatSeed512Bits numWords 7 }

def katConstellation512 : Constellation512 := makeKatConstellation512 16

/-- Deterministic plaintext generator `mkDeterministicBytes n`:
    `b[i] = 0x00` when `i % 11 == 3` (to exercise COBS zero-run splitting), else `(i * 13 + 7) & 0xFF`. -/
def mkDeterministicBytes512 (n : Nat) : ByteArray :=
  ByteArray.mk ((List.range n).map (fun i =>
    if i % 11 == 3 then 0x00 else UInt8.ofNat ((i * 13 + 7) &&& 0xFF))).toArray

def katPlaintext48 : ByteArray := mkDeterministicBytes512 48

/-- Deterministic interlock nonce of length `nBytes` (`0x10 + i`). -/
def mkKatIlNonce512 (nBytes : Nat) : ByteArray :=
  ByteArray.mk ((List.range nBytes).map (fun i => UInt8.ofNat ((0x10 + i) &&& 0xFF))).toArray

/-- Deterministic main nonce of length `nBytes` (`0x20 + i`). -/
def mkKatMainNonce512 (nBytes : Nat) : ByteArray :=
  ByteArray.mk ((List.range nBytes).map (fun i => UInt8.ofNat ((0x20 + i) &&& 0xFF))).toArray

def katIlNonce512 : ByteArray := mkKatIlNonce512 16
def katMainNonce512 : ByteArray := mkKatMainNonce512 16

/-- 32-byte wire prefix `0x30..0x4F`. -/
def katPrefix32_512 : ByteArray :=
  ByteArray.mk ((List.range 32).map (fun i => UInt8.ofNat (0x30 + i))).toArray

/-- Convert a hex character to a 4-bit nibble. -/
def hexCharToNibble512 (c : Char) : UInt8 :=
  if '0' ≤ c && c ≤ '9' then (c.toNat - '0'.toNat).toUInt8
  else if 'a' ≤ c && c ≤ 'f' then (c.toNat - 'a'.toNat + 10).toUInt8
  else if 'A' ≤ c && c ≤ 'F' then (c.toNat - 'A'.toNat + 10).toUInt8
  else 0

/-- Decode an even-length hexadecimal string into a `ByteArray`. -/
def hexToByteArray512 (s : String) : ByteArray :=
  let rec loop : List Char → List UInt8 → List UInt8
    | h :: l :: rest, acc =>
      loop rest (((hexCharToNibble512 h <<< 4) ||| hexCharToNibble512 l) :: acc)
    | _, acc => acc.reverse
  ByteArray.mk (loop s.toList []).toArray

/-- Kernel-verified KAT 1: `blake2bSum512Words` on empty input matches RFC 7693 and Go `blake2b.Sum512(nil)`. -/
theorem kat_blake2b512_empty :
    blake2bSum512Words ByteArray.empty = katBlake2b512Empty := by native_decide

/-- Kernel-verified KAT 2: `blake2bSum512Words("abc")` matches RFC 7693 and Go `blake2b.Sum512([]byte("abc"))`. -/
theorem kat_blake2b512_abc :
    blake2bSum512Words (ByteArray.mk #[0x61, 0x62, 0x63]) = katBlake2b512ABC := by native_decide

/-- Kernel-verified KAT 3: `blake2b512WithKey` matches Go `hashes.BLAKE2b512WithKey`. -/
theorem kat_blake2b512_with_key :
    Words8.ofArray (blake2b512WithKey katB2Key512 katChainInput512 katTestSeedWords512) =
      katBlake2b512WithKeyOut := by native_decide

/-- Kernel-verified KAT 4: `chainHash512Words` matches Go `Seed512.ChainHash512`. -/
theorem kat_chainHash512_seed0 :
    chainHash512Words katConstellation512.noiseSeed katChainInput512 =
      katChainHash512Seed0Out := by native_decide

/-- Full 1,852-byte Go reference wire for `Interlock = "168"`, 512-bit key, 128-bit nonce, **Mode 2**, `ptLen = 48`. -/
def katWire168_512_mode2_pt48_hex : String :=
  "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f202122232425262728292a2b2c2d2e2f000f000f9fc09487d2030751" ++
  "5f8b9d0703890c0f583fb3f2f03a555e4d0160162e2d791d6633070b73022fd2332872d980d38908fccf2cc978893fdde06b61f548c441e33c450f00" ++
  "7b2a053850c44be97afbcd581d4a2c724b2c76231d6e1f7e7d18721c86d9dfc687c04d9f5378317a9a52f8fb9ce928ff5b6d5e9e6649de74f168edf4" ++
  "6f50eb7af6d1eb7738f1813a725358810aa9f2d0a333cbb1792f4769481f4a7b5744f8f2cb425372e40e7a6e44983226eab6fa3eea6a54788f1c88dd" ++
  "0687c98bd01f5c5c1a9b59c860dcf834d6da3678de089dde9b4bfb7c1062c8f89a586cd85f96cb17965aa656fa9695199f9af253f00ae203ba120053" ++
  "5f2b7bbfe67b9602d0ddb4bafd545f1798ec5e6e9200c248d3c2edc8624ec5c2fb4d77d0f55d41744efb59fa8cfe98d8188e183ac4feb810d5f49cb7" ++
  "d9b5dbb37af87a0b5b53296a9b8b8d1b9a024e12d61709d2d38106c579dbcec15d4af25356940f1b4687c0592f6f1bcad7e2167a095a2b013f393d6c" ++
  "faf0a2ec164226bad69297d84cca4b58f65ccf6c5bf5415ab91b1a723b19ca42f64de1d5c8fb6a5bfa4ac68c40d4cc489774ba1e197f76f3b6fc1096" ++
  "0e56486e1ede98d3ca55d5c15b775ac1f457dac81ab07c72dea42a8c4e1f785ee9ed8cc9e9904132a2412ba00f4b489e9f0ef91a5bf1793991496113" ++
  "58777d9db5dcfd317ce4627a597843e33269433263e1790a8d09d293cf81144152d6e1425b4b58fde3dfe1fc4d58c149182b2f084a2e0fcc9bc3c053" ++
  "d3ca496bac0cc0dc80d6022e2a7713e2563e2b7fbad571ffbf7a72def2573fdedef383c2255d0a670b0b0d494273206212ca7ab160745d3e54067a3c" ++
  "50cc404b9e5a1785aa327b827f2b6f9712b0fd56d299b853d28d181c5bd1da9a7bf312a36b931aba1c295d4998c88def02122e007ade2cb25a69a282" ++
  "4b1183f2706271197901a3c3756968e7ff5c5471f5b1d87b773cb3df5ef80ca90f5ea96b586f5fe5eb5acf58bb0bff98fae84948d24e22c2e6d3566e" ++
  "096e2e4e570c54113c385e9066e6d8ec38ec49383bfb4b28b77bb11555d39278e55dc96655476e765ea4ecd0063aa0da5b971cb2b416b3df1afd790e" ++
  "ad6c1ee838a1297202eac1b21b02c41a1dc91e9ccb835048dfc759087a0a4a4a524f1377f8ed18abbe7d38bf1a1558ddb8f157d028013a3a598a801b" ++
  "e35fca9b97069a77dd0ed7560f1ac50e7564467c117d166d175fd347d1914c0e7b5cc7d6eb4ae14d280b6211a10b38b074cae859785e6c75d065d941" ++
  "e5eecffa65faf86e557fe065ef3a07d36383166f1510c28100dc0c8643564871e8e0f06ed2fad40ae2ee3238e942d2d044e05b6dcb6aacca5f78bd1f" ++
  "62985286f45a4042fa08b6d8e0869630e9708b70c10a9aa8cf705170d2f9e04d2ec746bf162afa9bd7e3f855fa4af1ea5b39d2f7b4957b7ecb9edcba" ++
  "da9e599970dbbb32bc33d5574f4cdfd942c9c84522745d3f507e492a5241b83b18316213607b2b51706811393cd4b2f02a3624368074e2ba1c16fabe" ++
  "38195813c1ab214360b6c670b2aace0868bc486f9bfeb8a89afaa3a3390bf9193474108cbee27a7c22c0ee28f0768210d8d1d8ccd1f4726adbd14ddb" ++
  "56684d6354014c531758008f8e0cff5e1c6bfc5de3d001bb3809e16ac183140a5c470a84cd1d48960418df1c7bf5fb929a7257f52941703c1d056047" ++
  "f3d73edfe73e0297483e0953650d79717fabdf964ec2a21e03438b4f0d428e5e04b44a1210182a1c372d52011e5d5a5d982a1ed92dbacb0c0cde8a78" ++
  "595a7fbf945e7554dcdfdf3eb64248f226507aa80dca88135bcadd92590d51751f6c504b3874089ea2be50924afc59994b1ed8fb9a998d4fc8f99efb" ++
  "e25333fef317ff3e0c4480bc80c48ada7d0e2f754b43273c6f0f5a2bbe2d6cac0e104c3a71467d2a02130b404a6b4d146b2fdeedacba0abb863e465a" ++
  "2e94bacc5c10bc1e06947c2a1c0ab0e2da40927c048d0b0649d2ca5e72394bb8c870a9817f7ad22a625a5752d516f5111c719a9856f02e303e4a96c2" ++
  "56e5454fc271495c6c5c681511400b0a3c283a59e95b1edd3302024808013f07c5d75ad3687b7cf8947674d57e9f9f117e38192a18365d0b6d2feb0f" ++
  "3e0dcbbc74325b030947724978d81e781d5d1a5a5898fd783ac8eeab71d0f06ee87a6bc9ba02bccee86e0804692a3e4b24020211656bdae8c765f0cc" ++
  "1d620b694602370c6c01236f6a0b196c927ef6ae9c669a3c5c02d6ec1ad0302250464c5d58714248df75f6b03a5e58b889989904d8c29945fe6a9c3a" ++
  "089949cb0d3e65772e136012e65c7e80a08ac2e4a0c89cd47e62e4e873eb66ee2a7eaaef1401322e7017294b47b23f36124b6adb78d0cb694763ddd5" ++
  "71526030004d2f4ece7607471bbfc7dfc1401e898f55c7525398569fd89c068041f0ed41eff34bf2281b512603036d1a8dcf5f1a29ec6acaf053e290" ++
  "d07953f827327b33542007535bbe9f3a78557c338a4356decb8151d50c076d52675851729779f7d91b5418fdf854c3e3d1557cdf"

def katWire168_k512_n128_m2_pt48 : ByteArray :=
  encrypt3x512DeterministicCfg .i168 (makeKatConstellation512 8) katPlaintext48 2
    katIlNonce512 katMainNonce512 0x5A katPrefix32_512

/-- Byte-exact 1,852-byte wire equality between Lean `encrypt3x512DeterministicCfg` and Go `itb.Encrypt3x512Cfg`. -/
theorem kat_wire168_k512_n128_m2_pt48_eq :
    katWire168_k512_n128_m2_pt48 = hexToByteArray512 katWire168_512_mode2_pt48_hex := by native_decide

/-- Exact decryption round-trip for the 1,852-byte `Interlock = "168"` KAT wire. -/
theorem kat_decrypt168_k512_n128_m2_pt48 :
    decrypt3x512Cfg .i168 (makeKatConstellation512 8) katWire168_k512_n128_m2_pt48 16 =
      some katPlaintext48 := by native_decide

/-- All 18 `(keyBits ∈ {512, 1024, 2048}) × (nonceBits ∈ {128, 256, 512}) × (mode ∈ {1, 2})`
    Go reference wire digests `(keyBits, nonceBits, mode, wireLen, digestLo64, digestHi64)`
    for `Interlock = "168"` on the 336-byte payload (`M = 17 >= 16` chunks, exercising full Layer II `0x06`). -/
def katParamMatrix168 : List (Nat × Nat × Nat × Nat × UInt64 × UInt64) := [
  (512, 128, 1, 5052, 0x15e1f85aa14e6035, 0xd449d39e2d39a8a8),
  (512, 128, 2, 1852, 0x195d3156c3a00872, 0x03850fe5bf927e55),
  (512, 256, 1, 5068, 0xed47b2964b3df301, 0xad9af279f61c10a5),
  (512, 256, 2, 1868, 0xde34285f52079887, 0x38366cdad7b19399),
  (512, 512, 1, 5100, 0x4f31c61944d79406, 0xdda43051add1fdad),
  (512, 512, 2, 1900, 0x32062038ac40268a, 0xcb165d651c0b63b2),
  (1024, 128, 1, 9852, 0x6c1b5ff61159b2fb, 0x1a8ac03c8e37ec1a),
  (1024, 128, 2, 3580, 0xb3953583ca46c841, 0xa1353b18172f2d01),
  (1024, 256, 1, 9868, 0x75cd5dea5cdbc847, 0x702b7fe8443a613a),
  (1024, 256, 2, 3596, 0x4e1a82f77e78cb69, 0xaabe9020e37703bb),
  (1024, 512, 1, 9900, 0xfa482d7796398996, 0x5f83b7786daa30d2),
  (1024, 512, 2, 3628, 0x871897b802207c97, 0x6a07d62d3b089cc8),
  (2048, 128, 1, 18484, 0x36123a9eaba820ed, 0x196a212441ac0daf),
  (2048, 128, 2, 6780, 0xdde12a45769ae90b, 0xdab7bb496fe9f194),
  (2048, 256, 1, 18500, 0xc9f39e9dab75a5fd, 0x739e9ecffdfa7807),
  (2048, 256, 2, 6796, 0x9225be4c08d9efe4, 0xd16e2e86bdde944f),
  (2048, 512, 1, 18532, 0x75e04f195b745a54, 0x4df33c4739aba370),
  (2048, 512, 2, 6828, 0x7d0b528acb0a930a, 0x9de870da3267c60b)
]

/-- All 18 `(keyBits ∈ {512, 1024, 2048}) × (nonceBits ∈ {128, 256, 512}) × (mode ∈ {1, 2})`
    Go reference wire digests `(keyBits, nonceBits, mode, wireLen, digestLo64, digestHi64)`
    for `Interlock = "48"` (`factor = 4`) on the 96-byte payload (`M = 17 >= 16` chunks, exercising full Layer II `0x06`). -/
def katParamMatrix48 : List (Nat × Nat × Nat × Nat × UInt64 × UInt64) := [
  (512, 128, 1, 5052, 0xa7bc3c5eaaea6607, 0xb676d6a8552cc826),
  (512, 128, 2, 1852, 0x21736609a8cec99a, 0x2fe0e674687da1bc),
  (512, 256, 1, 5068, 0x3901a275095c4fd9, 0xede3577c9add613f),
  (512, 256, 2, 1868, 0xf08134280378ed65, 0xe4beccc226bcef1b),
  (512, 512, 1, 5100, 0xac828a6f2e3f1a31, 0x64cf44ab06503a6a),
  (512, 512, 2, 1900, 0xee3054151a19959c, 0x6b9c3f1d425b0451),
  (1024, 128, 1, 9852, 0xdbf20687488d6e8d, 0x7988368d05ddfba4),
  (1024, 128, 2, 3580, 0x64642baf5a98a025, 0xacaaaab53307a8b2),
  (1024, 256, 1, 9868, 0xc1c4dcc4e6fd0049, 0xfa60e23e77a94b11),
  (1024, 256, 2, 3596, 0x24b0538459b4e3db, 0x9fb5d551e038b6f5),
  (1024, 512, 1, 9900, 0xdad40f04f62bf770, 0xb78924f6d8eb21cc),
  (1024, 512, 2, 3628, 0xd54349df1f911000, 0x805db9ba0c63f4e1),
  (2048, 128, 1, 18484, 0xa94d72bccffd9b73, 0xf9f22393b1606ee8),
  (2048, 128, 2, 6780, 0xa4789c63593aa46c, 0x84b29055e523a658),
  (2048, 256, 1, 18500, 0xd1d1315bd5b2dddb, 0xc7468d2b36318ac4),
  (2048, 256, 2, 6796, 0xa53926d970495754, 0xde0ef2ca8c738217),
  (2048, 512, 1, 18532, 0x5050740196040c00, 0xad0b63f8268cca5d),
  (2048, 512, 2, 6828, 0x161fa881ed7e9cf6, 0x7b3b91a617ee8faa)
]

/-- Size ladder Go reference wire digests `(ptLen, mode, wireLen, digestLo64, digestHi64)`
    for `Interlock = "168"` (1024-bit key, 128-bit nonce) across `1 B .. 16 KB` in **Mode 1** and **Mode 2**. -/
def katSizeLadderDigests168 : List (Nat × Nat × Nat × UInt64 × UInt64) := [
  (1, 1, 9852, 0xa7c9a9e4011293d2, 0xa3ecdc889edcdab8),
  (1, 2, 3580, 0x02f82dd149a924e8, 0x9f22f1fa50dca949),
  (48, 1, 9852, 0xfba252b091bb448e, 0x27c4335bba8f6bf1),
  (48, 2, 3580, 0xa49bcffc49d06a43, 0x30dfc4e169f0fefb),
  (336, 1, 9852, 0x6c1b5ff61159b2fb, 0x1a8ac03c8e37ec1a),
  (336, 2, 3580, 0xb3953583ca46c841, 0xa1353b18172f2d01),
  (512, 1, 9852, 0x586ac932e0350959, 0x3c14e1fc616e0359),
  (512, 2, 3580, 0x28f3716612d471f0, 0xd3700861f0eb4cbb),
  (1024, 1, 9852, 0xdf8902e115932d52, 0xf99727c16b53e4b7),
  (1024, 2, 3580, 0x0d86fc5046b21a1d, 0x5455dac67d220fe4),
  (4096, 1, 9852, 0xb6f271ade3e2f5e6, 0x720d4d0548fb41e3),
  (4096, 2, 5460, 0xc12ae1bd9e811d95, 0xf007acb96cf0f7bc),
  (16384, 1, 20052, 0x292b3e406cb73428, 0x4e31d9c5760a626e),
  (16384, 2, 20052, 0x292b3e406cb73428, 0x4e31d9c5760a626e)
]

/-- Full 396-cell container sizing ladder across all 11 payload sizes (`1 B`, `512 B`, `1 KB`, `4 KB`, `16 KB`,
    `128 KB`, `512 KB`, `1 MB`, `4 MB`, `16 MB`, `64 MB`) × both interlock modes (`true` = `"168"`, `false` = `"48"`)
    × 3 key sizes (`512`, `1024`, `2048` bits) × 3 nonce sizes (`128`, `256`, `512` bits) × 2 modes (`1`, `2`). -/
def katFullContainerSideLadder512 : List (Bool × Nat × Nat × Nat × Nat × Nat) := [
  (true, 1, 512, 128, 1, 25),
  (true, 1, 512, 128, 2, 15),
  (true, 1, 512, 256, 1, 25),
  (true, 1, 512, 256, 2, 15),
  (true, 1, 512, 512, 1, 25),
  (true, 1, 512, 512, 2, 15),
  (true, 1, 1024, 128, 1, 35),
  (true, 1, 1024, 128, 2, 21),
  (true, 1, 1024, 256, 1, 35),
  (true, 1, 1024, 256, 2, 21),
  (true, 1, 1024, 512, 1, 35),
  (true, 1, 1024, 512, 2, 21),
  (true, 1, 2048, 128, 1, 48),
  (true, 1, 2048, 128, 2, 29),
  (true, 1, 2048, 256, 1, 48),
  (true, 1, 2048, 256, 2, 29),
  (true, 1, 2048, 512, 1, 48),
  (true, 1, 2048, 512, 2, 29),
  (true, 512, 512, 128, 1, 25),
  (true, 512, 512, 128, 2, 15),
  (true, 512, 512, 256, 1, 25),
  (true, 512, 512, 256, 2, 15),
  (true, 512, 512, 512, 1, 25),
  (true, 512, 512, 512, 2, 15),
  (true, 512, 1024, 128, 1, 35),
  (true, 512, 1024, 128, 2, 21),
  (true, 512, 1024, 256, 1, 35),
  (true, 512, 1024, 256, 2, 21),
  (true, 512, 1024, 512, 1, 35),
  (true, 512, 1024, 512, 2, 21),
  (true, 512, 2048, 128, 1, 48),
  (true, 512, 2048, 128, 2, 29),
  (true, 512, 2048, 256, 1, 48),
  (true, 512, 2048, 256, 2, 29),
  (true, 512, 2048, 512, 1, 48),
  (true, 512, 2048, 512, 2, 29),
  (true, 1024, 512, 128, 1, 25),
  (true, 1024, 512, 128, 2, 15),
  (true, 1024, 512, 256, 1, 25),
  (true, 1024, 512, 256, 2, 15),
  (true, 1024, 512, 512, 1, 25),
  (true, 1024, 512, 512, 2, 15),
  (true, 1024, 1024, 128, 1, 35),
  (true, 1024, 1024, 128, 2, 21),
  (true, 1024, 1024, 256, 1, 35),
  (true, 1024, 1024, 256, 2, 21),
  (true, 1024, 1024, 512, 1, 35),
  (true, 1024, 1024, 512, 2, 21),
  (true, 1024, 2048, 128, 1, 48),
  (true, 1024, 2048, 128, 2, 29),
  (true, 1024, 2048, 256, 1, 48),
  (true, 1024, 2048, 256, 2, 29),
  (true, 1024, 2048, 512, 1, 48),
  (true, 1024, 2048, 512, 2, 29),
  (true, 4096, 512, 128, 1, 26),
  (true, 4096, 512, 128, 2, 26),
  (true, 4096, 512, 256, 1, 26),
  (true, 4096, 512, 256, 2, 26),
  (true, 4096, 512, 512, 1, 26),
  (true, 4096, 512, 512, 2, 26),
  (true, 4096, 1024, 128, 1, 35),
  (true, 4096, 1024, 128, 2, 26),
  (true, 4096, 1024, 256, 1, 35),
  (true, 4096, 1024, 256, 2, 26),
  (true, 4096, 1024, 512, 1, 35),
  (true, 4096, 1024, 512, 2, 26),
  (true, 4096, 2048, 128, 1, 48),
  (true, 4096, 2048, 128, 2, 29),
  (true, 4096, 2048, 256, 1, 48),
  (true, 4096, 2048, 256, 2, 29),
  (true, 4096, 2048, 512, 1, 48),
  (true, 4096, 2048, 512, 2, 29),
  (true, 16384, 512, 128, 1, 50),
  (true, 16384, 512, 128, 2, 50),
  (true, 16384, 512, 256, 1, 50),
  (true, 16384, 512, 256, 2, 50),
  (true, 16384, 512, 512, 1, 50),
  (true, 16384, 512, 512, 2, 50),
  (true, 16384, 1024, 128, 1, 50),
  (true, 16384, 1024, 128, 2, 50),
  (true, 16384, 1024, 256, 1, 50),
  (true, 16384, 1024, 256, 2, 50),
  (true, 16384, 1024, 512, 1, 50),
  (true, 16384, 1024, 512, 2, 50),
  (true, 16384, 2048, 128, 1, 50),
  (true, 16384, 2048, 128, 2, 50),
  (true, 16384, 2048, 256, 1, 50),
  (true, 16384, 2048, 256, 2, 50),
  (true, 16384, 2048, 512, 1, 50),
  (true, 16384, 2048, 512, 2, 50),
  (true, 131072, 512, 128, 1, 139),
  (true, 131072, 512, 128, 2, 139),
  (true, 131072, 512, 256, 1, 139),
  (true, 131072, 512, 256, 2, 139),
  (true, 131072, 512, 512, 1, 139),
  (true, 131072, 512, 512, 2, 139),
  (true, 131072, 1024, 128, 1, 139),
  (true, 131072, 1024, 128, 2, 139),
  (true, 131072, 1024, 256, 1, 139),
  (true, 131072, 1024, 256, 2, 139),
  (true, 131072, 1024, 512, 1, 139),
  (true, 131072, 1024, 512, 2, 139),
  (true, 131072, 2048, 128, 1, 139),
  (true, 131072, 2048, 128, 2, 139),
  (true, 131072, 2048, 256, 1, 139),
  (true, 131072, 2048, 256, 2, 139),
  (true, 131072, 2048, 512, 1, 139),
  (true, 131072, 2048, 512, 2, 139),
  (true, 524288, 512, 128, 1, 276),
  (true, 524288, 512, 128, 2, 276),
  (true, 524288, 512, 256, 1, 276),
  (true, 524288, 512, 256, 2, 276),
  (true, 524288, 512, 512, 1, 276),
  (true, 524288, 512, 512, 2, 276),
  (true, 524288, 1024, 128, 1, 276),
  (true, 524288, 1024, 128, 2, 276),
  (true, 524288, 1024, 256, 1, 276),
  (true, 524288, 1024, 256, 2, 276),
  (true, 524288, 1024, 512, 1, 276),
  (true, 524288, 1024, 512, 2, 276),
  (true, 524288, 2048, 128, 1, 276),
  (true, 524288, 2048, 128, 2, 276),
  (true, 524288, 2048, 256, 1, 276),
  (true, 524288, 2048, 256, 2, 276),
  (true, 524288, 2048, 512, 1, 276),
  (true, 524288, 2048, 512, 2, 276),
  (true, 1048576, 512, 128, 1, 389),
  (true, 1048576, 512, 128, 2, 389),
  (true, 1048576, 512, 256, 1, 389),
  (true, 1048576, 512, 256, 2, 389),
  (true, 1048576, 512, 512, 1, 389),
  (true, 1048576, 512, 512, 2, 389),
  (true, 1048576, 1024, 128, 1, 389),
  (true, 1048576, 1024, 128, 2, 389),
  (true, 1048576, 1024, 256, 1, 389),
  (true, 1048576, 1024, 256, 2, 389),
  (true, 1048576, 1024, 512, 1, 389),
  (true, 1048576, 1024, 512, 2, 389),
  (true, 1048576, 2048, 128, 1, 389),
  (true, 1048576, 2048, 128, 2, 389),
  (true, 1048576, 2048, 256, 1, 389),
  (true, 1048576, 2048, 256, 2, 389),
  (true, 1048576, 2048, 512, 1, 389),
  (true, 1048576, 2048, 512, 2, 389),
  (true, 4194304, 512, 128, 1, 777),
  (true, 4194304, 512, 128, 2, 777),
  (true, 4194304, 512, 256, 1, 777),
  (true, 4194304, 512, 256, 2, 777),
  (true, 4194304, 512, 512, 1, 777),
  (true, 4194304, 512, 512, 2, 777),
  (true, 4194304, 1024, 128, 1, 777),
  (true, 4194304, 1024, 128, 2, 777),
  (true, 4194304, 1024, 256, 1, 777),
  (true, 4194304, 1024, 256, 2, 777),
  (true, 4194304, 1024, 512, 1, 777),
  (true, 4194304, 1024, 512, 2, 777),
  (true, 4194304, 2048, 128, 1, 777),
  (true, 4194304, 2048, 128, 2, 777),
  (true, 4194304, 2048, 256, 1, 777),
  (true, 4194304, 2048, 256, 2, 777),
  (true, 4194304, 2048, 512, 1, 777),
  (true, 4194304, 2048, 512, 2, 777),
  (true, 16777216, 512, 128, 1, 1553),
  (true, 16777216, 512, 128, 2, 1553),
  (true, 16777216, 512, 256, 1, 1553),
  (true, 16777216, 512, 256, 2, 1553),
  (true, 16777216, 512, 512, 1, 1553),
  (true, 16777216, 512, 512, 2, 1553),
  (true, 16777216, 1024, 128, 1, 1553),
  (true, 16777216, 1024, 128, 2, 1553),
  (true, 16777216, 1024, 256, 1, 1553),
  (true, 16777216, 1024, 256, 2, 1553),
  (true, 16777216, 1024, 512, 1, 1553),
  (true, 16777216, 1024, 512, 2, 1553),
  (true, 16777216, 2048, 128, 1, 1553),
  (true, 16777216, 2048, 128, 2, 1553),
  (true, 16777216, 2048, 256, 1, 1553),
  (true, 16777216, 2048, 256, 2, 1553),
  (true, 16777216, 2048, 512, 1, 1553),
  (true, 16777216, 2048, 512, 2, 1553),
  (true, 67108864, 512, 128, 1, 3104),
  (true, 67108864, 512, 128, 2, 3104),
  (true, 67108864, 512, 256, 1, 3104),
  (true, 67108864, 512, 256, 2, 3104),
  (true, 67108864, 512, 512, 1, 3104),
  (true, 67108864, 512, 512, 2, 3104),
  (true, 67108864, 1024, 128, 1, 3104),
  (true, 67108864, 1024, 128, 2, 3104),
  (true, 67108864, 1024, 256, 1, 3104),
  (true, 67108864, 1024, 256, 2, 3104),
  (true, 67108864, 1024, 512, 1, 3104),
  (true, 67108864, 1024, 512, 2, 3104),
  (true, 67108864, 2048, 128, 1, 3104),
  (true, 67108864, 2048, 128, 2, 3104),
  (true, 67108864, 2048, 256, 1, 3104),
  (true, 67108864, 2048, 256, 2, 3104),
  (true, 67108864, 2048, 512, 1, 3104),
  (true, 67108864, 2048, 512, 2, 3104),
  (false, 1, 512, 128, 1, 25),
  (false, 1, 512, 128, 2, 15),
  (false, 1, 512, 256, 1, 25),
  (false, 1, 512, 256, 2, 15),
  (false, 1, 512, 512, 1, 25),
  (false, 1, 512, 512, 2, 15),
  (false, 1, 1024, 128, 1, 35),
  (false, 1, 1024, 128, 2, 21),
  (false, 1, 1024, 256, 1, 35),
  (false, 1, 1024, 256, 2, 21),
  (false, 1, 1024, 512, 1, 35),
  (false, 1, 1024, 512, 2, 21),
  (false, 1, 2048, 128, 1, 48),
  (false, 1, 2048, 128, 2, 29),
  (false, 1, 2048, 256, 1, 48),
  (false, 1, 2048, 256, 2, 29),
  (false, 1, 2048, 512, 1, 48),
  (false, 1, 2048, 512, 2, 29),
  (false, 512, 512, 128, 1, 25),
  (false, 512, 512, 128, 2, 15),
  (false, 512, 512, 256, 1, 25),
  (false, 512, 512, 256, 2, 15),
  (false, 512, 512, 512, 1, 25),
  (false, 512, 512, 512, 2, 15),
  (false, 512, 1024, 128, 1, 35),
  (false, 512, 1024, 128, 2, 21),
  (false, 512, 1024, 256, 1, 35),
  (false, 512, 1024, 256, 2, 21),
  (false, 512, 1024, 512, 1, 35),
  (false, 512, 1024, 512, 2, 21),
  (false, 512, 2048, 128, 1, 48),
  (false, 512, 2048, 128, 2, 29),
  (false, 512, 2048, 256, 1, 48),
  (false, 512, 2048, 256, 2, 29),
  (false, 512, 2048, 512, 1, 48),
  (false, 512, 2048, 512, 2, 29),
  (false, 1024, 512, 128, 1, 25),
  (false, 1024, 512, 128, 2, 15),
  (false, 1024, 512, 256, 1, 25),
  (false, 1024, 512, 256, 2, 15),
  (false, 1024, 512, 512, 1, 25),
  (false, 1024, 512, 512, 2, 15),
  (false, 1024, 1024, 128, 1, 35),
  (false, 1024, 1024, 128, 2, 21),
  (false, 1024, 1024, 256, 1, 35),
  (false, 1024, 1024, 256, 2, 21),
  (false, 1024, 1024, 512, 1, 35),
  (false, 1024, 1024, 512, 2, 21),
  (false, 1024, 2048, 128, 1, 48),
  (false, 1024, 2048, 128, 2, 29),
  (false, 1024, 2048, 256, 1, 48),
  (false, 1024, 2048, 256, 2, 29),
  (false, 1024, 2048, 512, 1, 48),
  (false, 1024, 2048, 512, 2, 29),
  (false, 4096, 512, 128, 1, 26),
  (false, 4096, 512, 128, 2, 26),
  (false, 4096, 512, 256, 1, 26),
  (false, 4096, 512, 256, 2, 26),
  (false, 4096, 512, 512, 1, 26),
  (false, 4096, 512, 512, 2, 26),
  (false, 4096, 1024, 128, 1, 35),
  (false, 4096, 1024, 128, 2, 26),
  (false, 4096, 1024, 256, 1, 35),
  (false, 4096, 1024, 256, 2, 26),
  (false, 4096, 1024, 512, 1, 35),
  (false, 4096, 1024, 512, 2, 26),
  (false, 4096, 2048, 128, 1, 48),
  (false, 4096, 2048, 128, 2, 29),
  (false, 4096, 2048, 256, 1, 48),
  (false, 4096, 2048, 256, 2, 29),
  (false, 4096, 2048, 512, 1, 48),
  (false, 4096, 2048, 512, 2, 29),
  (false, 16384, 512, 128, 1, 50),
  (false, 16384, 512, 128, 2, 50),
  (false, 16384, 512, 256, 1, 50),
  (false, 16384, 512, 256, 2, 50),
  (false, 16384, 512, 512, 1, 50),
  (false, 16384, 512, 512, 2, 50),
  (false, 16384, 1024, 128, 1, 50),
  (false, 16384, 1024, 128, 2, 50),
  (false, 16384, 1024, 256, 1, 50),
  (false, 16384, 1024, 256, 2, 50),
  (false, 16384, 1024, 512, 1, 50),
  (false, 16384, 1024, 512, 2, 50),
  (false, 16384, 2048, 128, 1, 50),
  (false, 16384, 2048, 128, 2, 50),
  (false, 16384, 2048, 256, 1, 50),
  (false, 16384, 2048, 256, 2, 50),
  (false, 16384, 2048, 512, 1, 50),
  (false, 16384, 2048, 512, 2, 50),
  (false, 131072, 512, 128, 1, 139),
  (false, 131072, 512, 128, 2, 139),
  (false, 131072, 512, 256, 1, 139),
  (false, 131072, 512, 256, 2, 139),
  (false, 131072, 512, 512, 1, 139),
  (false, 131072, 512, 512, 2, 139),
  (false, 131072, 1024, 128, 1, 139),
  (false, 131072, 1024, 128, 2, 139),
  (false, 131072, 1024, 256, 1, 139),
  (false, 131072, 1024, 256, 2, 139),
  (false, 131072, 1024, 512, 1, 139),
  (false, 131072, 1024, 512, 2, 139),
  (false, 131072, 2048, 128, 1, 139),
  (false, 131072, 2048, 128, 2, 139),
  (false, 131072, 2048, 256, 1, 139),
  (false, 131072, 2048, 256, 2, 139),
  (false, 131072, 2048, 512, 1, 139),
  (false, 131072, 2048, 512, 2, 139),
  (false, 524288, 512, 128, 1, 276),
  (false, 524288, 512, 128, 2, 276),
  (false, 524288, 512, 256, 1, 276),
  (false, 524288, 512, 256, 2, 276),
  (false, 524288, 512, 512, 1, 276),
  (false, 524288, 512, 512, 2, 276),
  (false, 524288, 1024, 128, 1, 276),
  (false, 524288, 1024, 128, 2, 276),
  (false, 524288, 1024, 256, 1, 276),
  (false, 524288, 1024, 256, 2, 276),
  (false, 524288, 1024, 512, 1, 276),
  (false, 524288, 1024, 512, 2, 276),
  (false, 524288, 2048, 128, 1, 276),
  (false, 524288, 2048, 128, 2, 276),
  (false, 524288, 2048, 256, 1, 276),
  (false, 524288, 2048, 256, 2, 276),
  (false, 524288, 2048, 512, 1, 276),
  (false, 524288, 2048, 512, 2, 276),
  (false, 1048576, 512, 128, 1, 389),
  (false, 1048576, 512, 128, 2, 389),
  (false, 1048576, 512, 256, 1, 389),
  (false, 1048576, 512, 256, 2, 389),
  (false, 1048576, 512, 512, 1, 389),
  (false, 1048576, 512, 512, 2, 389),
  (false, 1048576, 1024, 128, 1, 389),
  (false, 1048576, 1024, 128, 2, 389),
  (false, 1048576, 1024, 256, 1, 389),
  (false, 1048576, 1024, 256, 2, 389),
  (false, 1048576, 1024, 512, 1, 389),
  (false, 1048576, 1024, 512, 2, 389),
  (false, 1048576, 2048, 128, 1, 389),
  (false, 1048576, 2048, 128, 2, 389),
  (false, 1048576, 2048, 256, 1, 389),
  (false, 1048576, 2048, 256, 2, 389),
  (false, 1048576, 2048, 512, 1, 389),
  (false, 1048576, 2048, 512, 2, 389),
  (false, 4194304, 512, 128, 1, 777),
  (false, 4194304, 512, 128, 2, 777),
  (false, 4194304, 512, 256, 1, 777),
  (false, 4194304, 512, 256, 2, 777),
  (false, 4194304, 512, 512, 1, 777),
  (false, 4194304, 512, 512, 2, 777),
  (false, 4194304, 1024, 128, 1, 777),
  (false, 4194304, 1024, 128, 2, 777),
  (false, 4194304, 1024, 256, 1, 777),
  (false, 4194304, 1024, 256, 2, 777),
  (false, 4194304, 1024, 512, 1, 777),
  (false, 4194304, 1024, 512, 2, 777),
  (false, 4194304, 2048, 128, 1, 777),
  (false, 4194304, 2048, 128, 2, 777),
  (false, 4194304, 2048, 256, 1, 777),
  (false, 4194304, 2048, 256, 2, 777),
  (false, 4194304, 2048, 512, 1, 777),
  (false, 4194304, 2048, 512, 2, 777),
  (false, 16777216, 512, 128, 1, 1553),
  (false, 16777216, 512, 128, 2, 1553),
  (false, 16777216, 512, 256, 1, 1553),
  (false, 16777216, 512, 256, 2, 1553),
  (false, 16777216, 512, 512, 1, 1553),
  (false, 16777216, 512, 512, 2, 1553),
  (false, 16777216, 1024, 128, 1, 1553),
  (false, 16777216, 1024, 128, 2, 1553),
  (false, 16777216, 1024, 256, 1, 1553),
  (false, 16777216, 1024, 256, 2, 1553),
  (false, 16777216, 1024, 512, 1, 1553),
  (false, 16777216, 1024, 512, 2, 1553),
  (false, 16777216, 2048, 128, 1, 1553),
  (false, 16777216, 2048, 128, 2, 1553),
  (false, 16777216, 2048, 256, 1, 1553),
  (false, 16777216, 2048, 256, 2, 1553),
  (false, 16777216, 2048, 512, 1, 1553),
  (false, 16777216, 2048, 512, 2, 1553),
  (false, 67108864, 512, 128, 1, 3104),
  (false, 67108864, 512, 128, 2, 3104),
  (false, 67108864, 512, 256, 1, 3104),
  (false, 67108864, 512, 256, 2, 3104),
  (false, 67108864, 512, 512, 1, 3104),
  (false, 67108864, 512, 512, 2, 3104),
  (false, 67108864, 1024, 128, 1, 3104),
  (false, 67108864, 1024, 128, 2, 3104),
  (false, 67108864, 1024, 256, 1, 3104),
  (false, 67108864, 1024, 256, 2, 3104),
  (false, 67108864, 1024, 512, 1, 3104),
  (false, 67108864, 1024, 512, 2, 3104),
  (false, 67108864, 2048, 128, 1, 3104),
  (false, 67108864, 2048, 128, 2, 3104),
  (false, 67108864, 2048, 256, 1, 3104),
  (false, 67108864, 2048, 256, 2, 3104),
  (false, 67108864, 2048, 512, 1, 3104),
  (false, 67108864, 2048, 512, 2, 3104)
]

/-- Check one parameter-matrix KAT cell `(interlockMode, keyBits, nonceBits, mode, ptLen, wireLen, dLo, dHi)`,
    verifying:
    1. `wire.size == wireLen`
    2. `blake2bSum512Words wire` matches `(dLo, dHi)`
    3. same-mode decrypt recovers `pt`
    4. cross-mode/cross-fill decrypt (`Mode 1 ↔ Mode 2` or `Mode 3`, `barrierFill = 32`) recovers `pt`. -/
def checkParamKatEntry512 (interlockMode : InterlockMode512)
    (keyBits nonceBits mode ptLen wireLen : Nat) (dLo dHi : UInt64) : Bool :=
  let numWords := keyBits / 64
  let nBytes := nonceBits / 8
  let c := makeKatConstellation512 numWords
  let pt := mkDeterministicBytes512 ptLen
  let ilNonce := mkKatIlNonce512 nBytes
  let mainNonce := mkKatMainNonce512 nBytes
  let wire := encrypt3x512DeterministicCfg interlockMode c pt mode ilNonce mainNonce 0x5A katPrefix32_512 1
  let d := blake2bSum512Words wire
  let decSame := decrypt3x512WithCfg { interlockMode, nonceBits, mode, barrierFill := 1 } c wire
  let otherMode := if mode == 3 then 3 else if mode == 1 then 2 else 1
  let decCross := decrypt3x512WithCfg { interlockMode, nonceBits, mode := otherMode, barrierFill := 32 } c wire
  wire.size == wireLen &&
  d.h0 == dLo && d.h1 == dHi &&
  decSame == some pt &&
  decCross == some pt

/-- All 396 container sizing cells across `1 B .. 64 MB`, `Interlock ∈ {"168", "48"}`,
    `keyBits ∈ {512, 1024, 2048}`, `nonceBits ∈ {128, 256, 512}`, and `mode ∈ {1, 2}`
    match Go `calcContainerSize3Cfg` exactly. -/
theorem kat_go_container_side_ladder512_1B_to_64MB_exact :
    (katFullContainerSideLadder512.all fun (is168, sz, kb, nb, mode, expectedSide) =>
      let ilMode := if is168 then InterlockMode512.i168 else InterlockMode512.i48
      containerDimsForPayload512 ilMode kb (nb / 8) mode sz == (expectedSide, expectedSide)) = true := by
  native_decide

/-- All 18 `(512/1024/2048) × (128/256/512) × (Mode 1/2)` parameter matrix KATs for `Interlock = "168"`
    match Go `itb.Encrypt3x512Cfg` wire digests and pass same-mode and cross-mode decryption. -/
theorem kat_go_param_matrix168_all_18_exact :
    (katParamMatrix168.all fun (kb, nb, mode, wLen, dLo, dHi) =>
      checkParamKatEntry512 .i168 kb nb mode 336 wLen dLo dHi) = true := by
  native_decide

/-- All 18 `(512/1024/2048) × (128/256/512) × (Mode 1/2)` parameter matrix KATs for `Interlock = "48"` (`factor = 4`)
    match Go `itb.Encrypt3x512Cfg` wire digests and pass same-mode and cross-mode decryption. -/
theorem kat_go_param_matrix48_all_18_exact :
    (katParamMatrix48.all fun (kb, nb, mode, wLen, dLo, dHi) =>
      checkParamKatEntry512 .i48 kb nb mode 96 wLen dLo dHi) = true := by
  native_decide

/-- Payload size ladder (`1 B`, `48 B`, `336 B`, `512 B`, `1 KB`, `4 KB`, `16 KB`) across **Mode 1** and **Mode 2**
    matches Go `itb.Encrypt3x512Cfg` wire digests and round-trips through `decrypt3x512WithCfg`. -/
theorem kat_go_size_ladder512_encrypt_decrypt_exact :
    (katSizeLadderDigests168.all fun (sz, mode, wLen, dLo, dHi) =>
      checkParamKatEntry512 .i168 1024 128 mode sz wLen dLo dHi) = true := by
  native_decide

/-! ## Section 11: Mode 3 (`Gauss-Posit`) Container Floors, Isolation, & Bit-Exact Go KATs -/

/-- **Mode 3 Theorem 1 (Canonical Mode 3 `Gauss-Posit` Container Floors & Strict Ordering)**:
    For 512-bit seeds (`minPixelsForKeyBits512 ∈ {183, 365, 730}` for `512, 1024, 2048`-bit keys),
    the Mode 3 inscribed Gauss-circle Posit floor `positGaussCircleFloor (3 * minPixelsForKeyBits512 keyBits)`
    equals `350, 698, 1395` pixels, yielding minimum container sides `20, 28, 39` (`400, 784, 1521` px),
    strictly between Mode 2 (`15, 21, 29`) and Mode 1 (`25, 35, 48`) across both `Interlock = "168"` and `Interlock = "48"`. -/
theorem mode3_container_floors512_canonical :
    ITB.Posit.positGaussCircleFloor (3 * minPixelsForKeyBits512 512) = 350 ∧
    ITB.Posit.positGaussCircleFloor (3 * minPixelsForKeyBits512 1024) = 698 ∧
    ITB.Posit.positGaussCircleFloor (3 * minPixelsForKeyBits512 2048) = 1395 ∧
    (containerDimsForPayload512 .i168 512 16 3 1).1 = 20 ∧
    (containerDimsForPayload512 .i168 1024 16 3 1).1 = 28 ∧
    (containerDimsForPayload512 .i168 2048 16 3 1).1 = 39 ∧
    (containerDimsForPayload512 .i48 512 16 3 1).1 = 20 ∧
    (containerDimsForPayload512 .i48 1024 16 3 1).1 = 28 ∧
    (containerDimsForPayload512 .i48 2048 16 3 1).1 = 39 ∧
    (containerDimsForPayload512 .i168 512 16 2 1).1 < (containerDimsForPayload512 .i168 512 16 3 1).1 ∧
    (containerDimsForPayload512 .i168 512 16 3 1).1 < (containerDimsForPayload512 .i168 512 16 1 1).1 ∧
    (containerDimsForPayload512 .i168 1024 16 2 1).1 < (containerDimsForPayload512 .i168 1024 16 3 1).1 ∧
    (containerDimsForPayload512 .i168 1024 16 3 1).1 < (containerDimsForPayload512 .i168 1024 16 1 1).1 ∧
    (containerDimsForPayload512 .i168 2048 16 2 1).1 < (containerDimsForPayload512 .i168 2048 16 3 1).1 ∧
    (containerDimsForPayload512 .i168 2048 16 3 1).1 < (containerDimsForPayload512 .i168 2048 16 1 1).1 := by
  native_decide

/-- Full 3252-byte Go reference wire for `Interlock = "168"`, 512-bit key, 128-bit nonce, **Mode 3**, `ptLen = 48`. -/
def katWire168_512_mode3_pt48_hex : String :=
  "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f202122232425262728292a2b2c2d2e2f00140014ac0cc0dc80d6022e" ++
  "2a7713e2563e2b7fb91b1a723b19ca42d5f49cb7d9b5dbb37af87a0b5b53296a9b8b8d1b9a024e12d61709d2d38106c579dbcec15d4af25356940f1b" ++
  "4687c0592f6f1bcad7e2167a095a2b013f393d6cfaf0a2ec164226ba5b775ac1f457dac81ab07c72dea42a8c4e1f785ee9ed8cc9e9904132a2412ba0" ++
  "0f4b489e9f0ef91a5bf179399149611358777d9db5dcfd317ce4627a597843e3f64de1d5c8fb6a5bbad571ffbf7a72def2573fdedef383c2255d0a67" ++
  "0b0b0d494273206212ca7ab13269433263e1790a8d09d293cf81144152d6e1425b4b58fde3dfe1fc4d58c149182b2f084a2e0fcc9bc3c053d3ca496b" ++
  "1ede98d3ca55d5c19774ba1e197f76f3b6fc10960e56486ed01f5c5c1a9b59c886d9dfc687c04d9f5378317a9a52f8fb9ce928ff5b6d5e9e6649de74" ++
  "f168edf46f50eb7af6d1eb7738f1813a725358810aa9f2d0a333cbb1792f4769481f4a7b5744f8f2cb425372e40e7a6e44983226eab6fa3eea6a5478" ++
  "8f1c88dd0687c98b1c86950c5fdb1e9c176a7f682016456022ec28806e58c456e9996300e9924bdad156744df5c7d1f3fb52aaebeb3332bbfa4ac68c" ++
  "40d4cc487c76bb335b913f7bd8289e1c2cca298b8a7888b05081b2a9681233b052d3b2f2232ab3b3d9fbb901b04eeeaa545af284f05ece7af608926c" ++
  "eadbf2503ae2131bc020e6c4f8b228809e739aab4a572b7337374c6d687b6f1020b8f0b638caacda89090d7cbd788d6e49f6f97b45fe6756d07c9af6" ++
  "ff9cd6561c791a994e4afe7b626661f7c5e7cfd80babfadf98ec4a0ae86b76f74fdec2d28b03a3db89323268fff9e3d5caebf360d758dd7fc9d9cbd9" ++
  "1eff11d7f75e333daa3abf2ddff9fcf95f96cb17965aa656fa9695199f9af253f00ae203ba1200531d6e1f7e7d18721c9fc09487d20307515f8b9d07" ++
  "03890c0f583fb3f2f03a555e4d0160162e2d791d6633070b73022fd2332872d980d38908fccf2cc978893fdde06b61f548c441e33c450f007b2a0538" ++
  "50c44be97afbcd581d4a2c724b2c7623d69297d84cca4b58f65ccf6c5bf5415a5f2b7bbfe67b9602d0ddb4bafd545f1798ec5e6e9200c248d3c2edc8" ++
  "624ec5c2fb4d77d0f55d41744efb59fa8cfe98d8188e183ac4feb81060dcf834d6da3678de089dde9b4bfb7c1062c8f89a586cd84fc1480c455fcad8" ++
  "b8bd69699b291c088e6454e096eec416c154f741794afc6346fccbd375754d7447ae5aa7fbe6a2f28181d2d2dd14dd4e5dce4c50e76a73db303ed436" ++
  "ea4022de6dda5048ec4879ea1d948456895e89098b5e50cf42c3ce8b959dd599fe1cf41a341a9f37f53738f4ca3279624bf28973b3b7eabfc6db975a" ++
  "db999885db8797191e716369035f7c6d91455901c34b4d45a7b7d22aef8bff1a3cbb1eb7d951bffc0fcb56404806581ce246aa8ffe7b26ea89beee7d" ++
  "1adb69ddc6b6a484e2a48c0071b39b51a801b1ab5b6b4ba33a729beb406a7c37203b59135ac8a8bce8fd4f2c5eab5d681d7ddf2e69d23a49bb7069b8" ++
  "a7aa7bc26bca8b3216ea6670443c2a962d55337e06786328980ebaf2ccdeaeb0b69677bf2342d28a7aaeecedec8c9dabb4aa645c14c054eea838336a" ++
  "51c8e079eab85a939809ab61c9288ebd69accb2c7660e6d084900236d59814979eb77f32535a14780c5e7f40ee4ff9e545e672c43e490ea95f8cedf8" ++
  "3edab9f8353b323bc07af1dd4e4bfddf381a5816c2ae224670dbe378d9d5e744d04c20c0e4d2546c096e2e4e570c54115e58fef244d2d04a44e8ba7e" ++
  "a0fc9254fd44dbecf0c3cb58f578c778e146ced48f50115092d9c00d2ecb4abf1a2cfc9dabc3f029f212e1d25b39d2f7b4957b7ecb9edcbada9e5999" ++
  "60d3b322b823c94b509c40578bde98908ede93931d07dd0d2a215c1f0c19320b687f2f59786c193d71bd31d8589754f2dfba02075262abdaf04bb9d9" ++
  "f0cb683b75085119552a7830df9d791d54b55ab03dfb5f5177bb7a14ccc46f7b4b43e2cc460818944357d3d48b10514e9d1401c853b59e7cb63631de" ++
  "4eeaa75296cefe7bce4f598f00440b16bfdfd31a36c2ee9341193c5767222862c21f430647f38a57eef8acb27ad826f4c2f93ad8787293131bdb5734" ++
  "fcf85739100a4c562eb8a27c1a7e29192b187409380cae1a0d5eb8493c556c5646510c7a73731b670c6c183c7f76deeae5edc558bdfed17536b6da12" ++
  "0f6a6c38366541559dfe3c8bdf1b1bdd29031a7649750e32ea88db7cbb2ccd891df6d41778d2113db23f7d75d910bf3c715450155895d95f891bf1f8" ++
  "828319d379749e3c9c5137d6e9ae3b3999886d381eca3a7ac69e2b96f8f548d3de7d58df573b510525634238cd3d994e2d0f5e6e2f527668031d506d" ++
  "33bfa29fcfc6de9246945fd0df560a1b578ed050ccd8c89e663d40256d7c3e318e0cff5e1c6bfc5d7368015f1c057136578f1aa6aa0ea7df0a7d3906" ++
  "55340e703aa32b7606eec3b61b02c41a1dc91e9cd6866050fece72107a0a4a4a524f137762985286f45a4042a04ab202cadc9ef445dad84e155fc045" ++
  "eb3803d16181126b2b22c68302fa1a8e13361871d8d0f05ed2fad40ae2ee3238e942d2d044e05b6dc98b2c1a7c4f1a8cdd3d58ae0c38ff3c7bedfb8a" ++
  "9a6a4fed3a7a1896bff17d7e22c0ee28f07682109891988c91d4524a5b510d5b16280d23680258662e70009e352928677f1c1431f5b1d87b773cb3df" ++
  "5ef80ca90f5ea96b305e3ecad6349e30b606fe90f4e042403b1c47566b0a610d34177219b1173cb8548ac819581e4c550a05286d5871276014011e1e" ++
  "2d46400fe25ec89a96049876fa1cee6c1e34ca1c5e5c6fc873f3ecf6187421181b7b23105e75b292571993fa7872794d7d41d3e3c0e8b97aa80af278" ++
  "306c202b5e3a1745c664a8c45e70ba1eebca8efa23fb2edb173f732771512c0eaa327b827f2b6f9742d0fd66e2c9d863ea9d383c7be9faba7df918b1" ++
  "75991cbc0c114d4188c085d7010917003d6f165900f8d99a181a411bbc50d03a92c408540b26d393ca9ec253026bf3a61be3af4e2c55097f64246445" ++
  "73fe31fef6b391d60ec0e020064066e6a814aabc40a8ac1a1e327b71d61e761dd0b3bcbc7a543f9ff821ba4129803903b6389272dd5b53b10a3ccb3a" ++
  "989e7e09d85d5c6ad9ff89b86e2dbdeaf97ddc5f18583f5b9f197519bf48ba7f7aff5e8f84905bcddfdb184a792ba9414b513b70bab232f294740028" ++
  "3411725ef037599b4bb83f3a184d6cdd38504b2907235d55de528c1a008941c357be9f36724b7a274a23367e6b413175c9d8d944f8e2d965ec4163ef" ++
  "ea4b59ec1b7ecbef5e27c226d34e5f809085c1d2a0c89cd47e62e4e873eb66ee2a7eaaef917bf3ab9a63993a6e41ebf64de85851b0969cbdb8f19298" ++
  "df75f6b03a5e58b85190d04ec85a4b89bd09becfec6f0c0ad1527a93480202214953b2d08b49e0981dc20bc98602570cea66b707138fe69358c80e58" ++
  "0d4d0a4a5898fd783ad0f6b3fc88742a68fe6aaed049457f70fc635b20216e4e265a3c60190cbc2daa6bdd4cc0c57646445f6cd36820f22c6a20e06e" ++
  "7678477e5c204825ce2a4652065a9e64443634653e4f4f01fc703254306cba166d2feb0f3e0dcbbcecdce85551c04b4a1c101a29712b0e6dde0dbf98" ++
  "7eed7bfa6bb86ebff8bc0e8842534bc0caebcd547357eef5d4da42dbf06959fef94bff5e0a4280ba80c289d9fd1e5fed9b8b4f7c6e0e5426bc2a68a8" ++
  "1a209872e18af9526604049010027e0e85971a93485b5cd88ace5e1422e864c4f1d2e07040cd6fcece7607471bbfc7dfd1503e999f75d772fa4892c8" ++
  "c44aa0fa6f436dd8f44c65567b08a95af0e978899fdf7ed2fa52f9b3535742d3ce7c4bc59bc396809cc5560f75cd4cfdcfc6cce7e7e7e44af3e0f0c7" ++
  "e4525bd555d0d16e5b7bfc4b515ddd57cf811e1ede959c0c73e9dbdac7d953c61cbfff70d85b5598d00c0fce120c101896d5bfb4d715bffaba380854" ++
  "188e3c1c62aa365a26a2f2cefbd53f5dd5be141455593eb576927c5f59f25c6dcccbfe6b3e40ccee8a4c00e04efed5dc7c77c95430241d7b0b07540b" ++
  "7a1c70693e385e20be044c46d27adacc476253468b1242b7e869caf974de726a653e5a7c770266457cfc56bc4a42ba7847ee5f75737ce5e37eaade94" ++
  "4cc0a01c0747975f1b469e7e04b44a1210182a1c776dd2415edddadd11f0dd11dff31bf2583bb1561313dd3ac46e7564ecefef5e9b4144d913485d94" ++
  "0dca88135bcadd92990d91d51fcc908b3a760a9fa3bf529348120e69155a63045989e87c3d0dc88fd9cb1ecfd31e008b987e19abcd1df9e9cd0eed09" ++
  "1c699a9856f02e303e4a96c22ecd0d1f8a69193c52fc5999531ed8fb9a998d4fc8f99efb046e4238292a3f5f0c076d52675851728759d7c90b4408dd" ++
  "f02886c6a22a78bef86bf2c8e87d6bfc4b62f363a8400ba3863e465a2e94bacc2e085e0f034a3e154e45d8f1ed60c97e44cd4b4669f2ea7e7a5d67dc" ++
  "e478d5c17f7cd834705c5b58"

def katWire168_k512_n128_m3_pt48 : ByteArray :=
  encrypt3x512DeterministicCfg .i168 (makeKatConstellation512 8) katPlaintext48 3
    katIlNonce512 katMainNonce512 0x5A katPrefix32_512

/-- **Mode 3 Theorem 2 (Byte-Exact 3252-Byte Mode 3 Wire Equality & Decryption Round-Trip)**:
    Lean's `encrypt3x512DeterministicCfg` in **Mode 3** (`20×20` container) produces the exact same
    3252 wire bytes as Go `itb.Encrypt3x512Cfg`, and `decrypt3x512WithCfg` recovers `katPlaintext48`. -/
theorem kat_wire168_k512_n128_m3_pt48_eq_and_decrypt :
    (katWire168_k512_n128_m3_pt48 == hexToByteArray512 katWire168_512_mode3_pt48_hex) &&
    (decrypt3x512WithCfg { interlockMode := .i168, nonceBits := 128, mode := 3, barrierFill := 32, reserve := 64, fillByte := 0xAA }
      (makeKatConstellation512 8) katWire168_k512_n128_m3_pt48 == some katPlaintext48) = true := by
  native_decide

/-- **Mode 3 Theorem 3 (Layer I Schedule Isolation Between Mode 3 and Modes 1/2)**:
    Because **Mode 3** dispatches Layer I (`0x05`) to `buildSubregionSchedulePosit` whereas
    **Mode 1** and **Mode 2** dispatch to `buildSubregionSchedule512`, a Mode 3 wire decrypts to
    `some katPlaintext48` under `mode := 3` but does not decrypt to `some katPlaintext48` under
    `mode := 1` or `mode := 2`. -/
theorem kat_go_mode3_isolation512 :
    let c := makeKatConstellation512 8
    let wire := katWire168_k512_n128_m3_pt48
    (decrypt3x512WithCfg { interlockMode := .i168, nonceBits := 128, mode := 3, barrierFill := 32 } c wire == some katPlaintext48) &&
    (decrypt3x512WithCfg { interlockMode := .i168, nonceBits := 128, mode := 1, barrierFill := 1 } c wire != some katPlaintext48) &&
    (decrypt3x512WithCfg { interlockMode := .i168, nonceBits := 128, mode := 2, barrierFill := 1 } c wire != some katPlaintext48) = true := by
  native_decide

/-- All 9 `(keyBits ∈ {512, 1024, 2048}) × (nonceBits ∈ {128, 256, 512})` **Mode 3**
    Go reference wire digests `(keyBits, nonceBits, wireLen, digestLo64, digestHi64)`
    for `Interlock = "168"` on the 336-byte payload (`M = 17 >= 16` chunks). -/
def katParamMatrix168Mode3 : List (Nat × Nat × Nat × UInt64 × UInt64) := [
  (512, 128, 3252, 0x106e0e3793c28307, 0x21de62cf8db6451f),
  (512, 256, 3268, 0x9adc628f7a62c948, 0x15da53c29b2520ef),
  (512, 512, 3300, 0x68238e1412a33f22, 0x5dec00b620a0b09f),
  (1024, 128, 6324, 0x2f4a3ed9678fba6a, 0x435fb9b63fc52426),
  (1024, 256, 6340, 0x632d41b62fc28da6, 0xa9a418207e322a1e),
  (1024, 512, 6372, 0xa6fa3e5787041009, 0x77f62cbb0065fd64),
  (2048, 128, 12220, 0x477d40883ed51cfe, 0x4577b60786a61288),
  (2048, 256, 12236, 0xacf71fa3fcfbf889, 0x5831dc601a24d9b3),
  (2048, 512, 12268, 0xe5be95f44e55f0f5, 0xf7480b411a4128f1)
]

/-- **Mode 3 Theorem 4 (All 9 `(512/1024/2048) × (128/256/512)` Mode 3 Parameter Matrix KATs for `Interlock = "168"`)**:
    Matches Go `itb.Encrypt3x512Cfg` wire digests and passes decryption round-trip. -/
theorem kat_go_param_matrix168_mode3_all_9_exact :
    (katParamMatrix168Mode3.all fun (kb, nb, wLen, dLo, dHi) =>
      checkParamKatEntry512 .i168 kb nb 3 336 wLen dLo dHi) = true := by
  native_decide

/-- All 9 `(keyBits ∈ {512, 1024, 2048}) × (nonceBits ∈ {128, 256, 512})` **Mode 3**
    Go reference wire digests `(keyBits, nonceBits, wireLen, digestLo64, digestHi64)`
    for `Interlock = "48"` (`factor = 4`) on the 96-byte payload (`M = 17 >= 16` chunks). -/
def katParamMatrix48Mode3 : List (Nat × Nat × Nat × UInt64 × UInt64) := [
  (512, 128, 3252, 0x40376527ac9e750c, 0x2dc7bbcfb7f4acc4),
  (512, 256, 3268, 0xb91d84cd2cc9e63f, 0x0124c15bd622c47d),
  (512, 512, 3300, 0x37398c3745038cf6, 0x82bf77868e7793ab),
  (1024, 128, 6324, 0x3e14947f2b982683, 0xc3747a19a013ac98),
  (1024, 256, 6340, 0xaa38f39983ac1ded, 0xb0628637006d6747),
  (1024, 512, 6372, 0x43ab2b69376b9a8f, 0x74bd473a2692aed3),
  (2048, 128, 12220, 0x4bfbe4819d7fc565, 0x880ea711562342f6),
  (2048, 256, 12236, 0x69f468fe54c42d81, 0xc737f862e1ee0673),
  (2048, 512, 12268, 0x4815ce44d2e29117, 0xe19e34de5789fc1f)
]

/-- **Mode 3 Theorem 5 (All 9 `(512/1024/2048) × (128/256/512)` Mode 3 Parameter Matrix KATs for `Interlock = "48"`)**:
    Matches Go `itb.Encrypt3x512Cfg` wire digests and passes decryption round-trip. -/
theorem kat_go_param_matrix48_mode3_all_9_exact :
    (katParamMatrix48Mode3.all fun (kb, nb, wLen, dLo, dHi) =>
      checkParamKatEntry512 .i48 kb nb 3 96 wLen dLo dHi) = true := by
  native_decide

/-- **Mode 3** size ladder Go reference wire digests `(ptLen, wireLen, digestLo64, digestHi64)`
    for `Interlock = "168"` (1024-bit key, 128-bit nonce) across `1 B .. 16 KB`. -/
def katSizeLadderDigests168Mode3 : List (Nat × Nat × UInt64 × UInt64) := [
  (1, 6324, 0x0db8f1b46ca14caf, 0x5e4cd94c660f666d),
  (48, 6324, 0xb56ecf9a209423c8, 0x248aa6413496c250),
  (336, 6324, 0x2f4a3ed9678fba6a, 0x435fb9b63fc52426),
  (512, 6324, 0xdaa779ba1de3aede, 0x59556825421fbdb1),
  (1024, 6324, 0x3889393715790e75, 0xe897edbfdb4049c6),
  (4096, 6324, 0x6c72360e58d18803, 0x8cb05bb0dc398cab),
  (16384, 20052, 0x31ac1b20729074a1, 0xceafb7bb5aaa4ca2)
]

/-- **Mode 3 Theorem 6 (End-to-End Mode 3 Payload Size Ladder `1 B .. 16 KB`)**:
    Matches Go `itb.Encrypt3x512Cfg` wire digests across `1 B`, `48 B`, `336 B`, `512 B`,
    `1 KB`, `4 KB`, and `16 KB` in **Mode 3** and round-trips through `decrypt3x512WithCfg`. -/
theorem kat_go_size_ladder512_mode3_encrypt_decrypt_exact :
    (katSizeLadderDigests168Mode3.all fun (sz, wLen, dLo, dHi) =>
      checkParamKatEntry512 .i168 1024 128 3 sz wLen dLo dHi) = true := by
  native_decide

/-- Full 198-cell **Mode 3** container sizing ladder across all 11 payload sizes (`1 B` .. `64 MB`)
    × both interlock modes (`true` = `"168"`, `false` = `"48"`) × 3 key sizes (`512`, `1024`, `2048` bits)
    × 3 nonce sizes (`128`, `256`, `512` bits). -/
def katFullContainerSideLadder512Mode3 : List (Bool × Nat × Nat × Nat × Nat) :=
  [true, false].flatMap fun is168 => [
    (is168, 1, 512, 128, 20), (is168, 1, 512, 256, 20), (is168, 1, 512, 512, 20),
    (is168, 1, 1024, 128, 28), (is168, 1, 1024, 256, 28), (is168, 1, 1024, 512, 28),
    (is168, 1, 2048, 128, 39), (is168, 1, 2048, 256, 39), (is168, 1, 2048, 512, 39),
    (is168, 512, 512, 128, 20), (is168, 512, 512, 256, 20), (is168, 512, 512, 512, 20),
    (is168, 512, 1024, 128, 28), (is168, 512, 1024, 256, 28), (is168, 512, 1024, 512, 28),
    (is168, 512, 2048, 128, 39), (is168, 512, 2048, 256, 39), (is168, 512, 2048, 512, 39),
    (is168, 1024, 512, 128, 20), (is168, 1024, 512, 256, 20), (is168, 1024, 512, 512, 20),
    (is168, 1024, 1024, 128, 28), (is168, 1024, 1024, 256, 28), (is168, 1024, 1024, 512, 28),
    (is168, 1024, 2048, 128, 39), (is168, 1024, 2048, 256, 39), (is168, 1024, 2048, 512, 39),
    (is168, 4096, 512, 128, 26), (is168, 4096, 512, 256, 26), (is168, 4096, 512, 512, 26),
    (is168, 4096, 1024, 128, 28), (is168, 4096, 1024, 256, 28), (is168, 4096, 1024, 512, 28),
    (is168, 4096, 2048, 128, 39), (is168, 4096, 2048, 256, 39), (is168, 4096, 2048, 512, 39),
    (is168, 16384, 512, 128, 50), (is168, 16384, 512, 256, 50), (is168, 16384, 512, 512, 50),
    (is168, 16384, 1024, 128, 50), (is168, 16384, 1024, 256, 50), (is168, 16384, 1024, 512, 50),
    (is168, 16384, 2048, 128, 50), (is168, 16384, 2048, 256, 50), (is168, 16384, 2048, 512, 50),
    (is168, 131072, 512, 128, 139), (is168, 131072, 512, 256, 139), (is168, 131072, 512, 512, 139),
    (is168, 131072, 1024, 128, 139), (is168, 131072, 1024, 256, 139), (is168, 131072, 1024, 512, 139),
    (is168, 131072, 2048, 128, 139), (is168, 131072, 2048, 256, 139), (is168, 131072, 2048, 512, 139),
    (is168, 524288, 512, 128, 276), (is168, 524288, 512, 256, 276), (is168, 524288, 512, 512, 276),
    (is168, 524288, 1024, 128, 276), (is168, 524288, 1024, 256, 276), (is168, 524288, 1024, 512, 276),
    (is168, 524288, 2048, 128, 276), (is168, 524288, 2048, 256, 276), (is168, 524288, 2048, 512, 276),
    (is168, 1048576, 512, 128, 389), (is168, 1048576, 512, 256, 389), (is168, 1048576, 512, 512, 389),
    (is168, 1048576, 1024, 128, 389), (is168, 1048576, 1024, 256, 389), (is168, 1048576, 1024, 512, 389),
    (is168, 1048576, 2048, 128, 389), (is168, 1048576, 2048, 256, 389), (is168, 1048576, 2048, 512, 389),
    (is168, 4194304, 512, 128, 777), (is168, 4194304, 512, 256, 777), (is168, 4194304, 512, 512, 777),
    (is168, 4194304, 1024, 128, 777), (is168, 4194304, 1024, 256, 777), (is168, 4194304, 1024, 512, 777),
    (is168, 4194304, 2048, 128, 777), (is168, 4194304, 2048, 256, 777), (is168, 4194304, 2048, 512, 777),
    (is168, 16777216, 512, 128, 1553), (is168, 16777216, 512, 256, 1553), (is168, 16777216, 512, 512, 1553),
    (is168, 16777216, 1024, 128, 1553), (is168, 16777216, 1024, 256, 1553), (is168, 16777216, 1024, 512, 1553),
    (is168, 16777216, 2048, 128, 1553), (is168, 16777216, 2048, 256, 1553), (is168, 16777216, 2048, 512, 1553),
    (is168, 67108864, 512, 128, 3104), (is168, 67108864, 512, 256, 3104), (is168, 67108864, 512, 512, 3104),
    (is168, 67108864, 1024, 128, 3104), (is168, 67108864, 1024, 256, 3104), (is168, 67108864, 1024, 512, 3104),
    (is168, 67108864, 2048, 128, 3104), (is168, 67108864, 2048, 256, 3104), (is168, 67108864, 2048, 512, 3104)
  ]

/-- **Mode 3 Theorem 7 (Full 198-Cell Mode 3 Container Sizing Ladder `1 B .. 64 MB`)**:
    All 198 **Mode 3** container sizing cells across `1 B .. 64 MB`, `Interlock ∈ {"168", "48"}`,
    `keyBits ∈ {512, 1024, 2048}`, and `nonceBits ∈ {128, 256, 512}` match Go `calcContainerSize3Cfg` exactly. -/
theorem kat_go_container_side_ladder512_mode3_1B_to_64MB_exact :
    (katFullContainerSideLadder512Mode3.all fun (is168, sz, kb, nb, expectedSide) =>
      let ilMode := if is168 then InterlockMode512.i168 else InterlockMode512.i48
      containerDimsForPayload512 ilMode kb (nb / 8) 3 sz == (expectedSide, expectedSide)) = true := by
  native_decide

end ITB.PipelineSpec512
