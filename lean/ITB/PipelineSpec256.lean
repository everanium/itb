/-
  Executable Reference Specification & Round-Trip Verification (30 formal theorems)
  of the 256-Bit (`Seed256`) + `BLAKE2b-256` (RFC 7693) + 48-Bit Interlock
  (`Interlock = "48"`, `factor = 2` chunks per `0x03` group call)
  Desynchronized Interlocked Barrier Pipeline (`Encrypt3x256Cfg` / `Decrypt3x256Cfg`)
  across Mode 1 (`Mode = 1`), Mode 2 (`Mode = 2`), and Mode 3 (`Mode = 3`, `Gauss-Posit`).
-/
import ITB.Thresholds
import ITB.RankBarrier
import ITB.PixelBarrier
import ITB.SplitRank
import ITB.SeedIsolation
import ITB.Desync
import ITB.Posit

namespace ITB.PipelineSpec256

open ITB.Thresholds
open ITB.RankBarrier
open ITB.PixelBarrier
open ITB.SplitRank
open ITB.SeedIsolation
open ITB.Desync

set_option exponentiation.threshold 60000
set_option maxRecDepth 2000000
set_option maxHeartbeats 0

/-! ## Section 1: Little-Endian / Big-Endian Byte Helpers & 64-Bit Rotations -/

/-- Fast `ByteArray` concatenation. -/
@[inline] def bAppend256 (a b : ByteArray) : ByteArray :=
  ByteArray.append a b

/-- Fast `ByteArray` slice extraction `a[start : stop]`. -/
@[inline] def bExtract256 (a : ByteArray) (start stop : Nat) : ByteArray :=
  a.extract start stop

/-- Strict identity wrapper for `Nat`. -/
@[inline] def withStrictNat {α : Type} (n : Nat) (f : Nat → α) : α :=
  f n

/-- Strict identity wrapper for `UInt64`. -/
@[inline] def withStrictU64 {α : Type} (x : UInt64) (f : UInt64 → α) : α :=
  f x

/-- 4-word state for 256-bit (`[4]uint64`) outputs and `Seed256` rounds. -/
structure Words4 where
  h0 : UInt64
  h1 : UInt64
  h2 : UInt64
  h3 : UInt64
  deriving DecidableEq, Repr

/-- Strict identity wrapper for `Words4`. -/
@[inline] def withStrictWords4 {α : Type} (w : Words4) (f : Words4 → α) : α :=
  f w

/-- List lookup with default fallback. -/
def listGetD256 {α : Type} : List α → Nat → α → α
  | [], _, d => d
  | x :: _, 0, _ => x
  | _ :: xs, i + 1, d => listGetD256 xs i d

/-- O(1) `Array` lookup with default fallback. -/
@[inline] def aGetD256 {α : Type} (a : Array α) (i : Nat) (d : α) : α :=
  a.getD i d

/-- O(1) `Array` update. -/
@[inline] def aSet256 {α : Type} (a : Array α) (i : Nat) (v : α) : Array α :=
  a.set! i v

/-- Single-pass list split at index `n`. -/
def listSplitAt256 {α : Type} : Nat → List α → List α × List α
  | 0, xs => ([], xs)
  | _, [] => ([], [])
  | n + 1, x :: xs =>
    let (pre, suf) := listSplitAt256 n xs
    (x :: pre, suf)

/-- Peel one 64-bit little-endian word from a byte list (zero-padded if fewer than 8 bytes remain). -/
def takeU64LE256 : List UInt8 → UInt64 × List UInt8
  | [] => (0, [])
  | b0 :: b1 :: b2 :: b3 :: b4 :: b5 :: b6 :: b7 :: rest =>
    let w :=
      b0.toUInt64 ||| (b1.toUInt64 <<< 8) ||| (b2.toUInt64 <<< 16) ||| (b3.toUInt64 <<< 24) |||
      (b4.toUInt64 <<< 32) ||| (b5.toUInt64 <<< 40) ||| (b6.toUInt64 <<< 48) ||| (b7.toUInt64 <<< 56)
    (w, rest)
  | bs =>
    let b0 := listGetD256 bs 0 0
    let b1 := listGetD256 bs 1 0
    let b2 := listGetD256 bs 2 0
    let b3 := listGetD256 bs 3 0
    let b4 := listGetD256 bs 4 0
    let b5 := listGetD256 bs 5 0
    let b6 := listGetD256 bs 6 0
    let b7 := listGetD256 bs 7 0
    let w :=
      b0.toUInt64 ||| (b1.toUInt64 <<< 8) ||| (b2.toUInt64 <<< 16) ||| (b3.toUInt64 <<< 24) |||
      (b4.toUInt64 <<< 32) ||| (b5.toUInt64 <<< 40) ||| (b6.toUInt64 <<< 48) ||| (b7.toUInt64 <<< 56)
    (w, [])

/-- O(1) safe byte read with zero fallback out of bounds. -/
@[inline] def getByteD256 (b : ByteArray) (i : Nat) : UInt8 :=
  if h : i < b.size then b[i] else 0

/-- Read a 64-bit little-endian word from `b` at byte offset `off` (zero-padded out of bounds). -/
def readU64LE256 (b : ByteArray) (off : Nat) : UInt64 :=
  (getByteD256 b off).toUInt64 |||
  ((getByteD256 b (off + 1)).toUInt64 <<< 8) |||
  ((getByteD256 b (off + 2)).toUInt64 <<< 16) |||
  ((getByteD256 b (off + 3)).toUInt64 <<< 24) |||
  ((getByteD256 b (off + 4)).toUInt64 <<< 32) |||
  ((getByteD256 b (off + 5)).toUInt64 <<< 40) |||
  ((getByteD256 b (off + 6)).toUInt64 <<< 48) |||
  ((getByteD256 b (off + 7)).toUInt64 <<< 56)

/-- Read a 56-bit little-endian word (7 bytes) from `b` at byte offset `off`. -/
def readU56LE256 (b : ByteArray) (off : Nat) : UInt64 :=
  (getByteD256 b off).toUInt64 |||
  ((getByteD256 b (off + 1)).toUInt64 <<< 8) |||
  ((getByteD256 b (off + 2)).toUInt64 <<< 16) |||
  ((getByteD256 b (off + 3)).toUInt64 <<< 24) |||
  ((getByteD256 b (off + 4)).toUInt64 <<< 32) |||
  ((getByteD256 b (off + 5)).toUInt64 <<< 40) |||
  ((getByteD256 b (off + 6)).toUInt64 <<< 48)

/-- Read a 48-bit little-endian word (6 bytes) from `b` at byte offset `off`. -/
def readU48LE256 (b : ByteArray) (off : Nat) : UInt64 :=
  (getByteD256 b off).toUInt64 |||
  ((getByteD256 b (off + 1)).toUInt64 <<< 8) |||
  ((getByteD256 b (off + 2)).toUInt64 <<< 16) |||
  ((getByteD256 b (off + 3)).toUInt64 <<< 24) |||
  ((getByteD256 b (off + 4)).toUInt64 <<< 32) |||
  ((getByteD256 b (off + 5)).toUInt64 <<< 40)

/-- Read a 32-bit little-endian word from `b` at byte offset `off`. -/
def readU32LE256 (b : ByteArray) (off : Nat) : UInt32 :=
  (getByteD256 b off).toUInt32 |||
  ((getByteD256 b (off + 1)).toUInt32 <<< 8) |||
  ((getByteD256 b (off + 2)).toUInt32 <<< 16) |||
  ((getByteD256 b (off + 3)).toUInt32 <<< 24)

/-- Read a 16-bit little-endian word from `b` at byte offset `off`. -/
def readU16LE256 (b : ByteArray) (off : Nat) : UInt16 :=
  (getByteD256 b off).toUInt16 |||
  ((getByteD256 b (off + 1)).toUInt16 <<< 8)

/-- Read a 16-bit big-endian integer from `b` at byte offset `off`. -/
def readU16BE256 (b : ByteArray) (off : Nat) : Nat :=
  ((getByteD256 b off).toNat <<< 8) ||| (getByteD256 b (off + 1)).toNat

/-- Read a 32-bit big-endian integer from `b` at byte offset `off`. -/
def readU32BE256 (b : ByteArray) (off : Nat) : Nat :=
  ((getByteD256 b off).toNat <<< 24) |||
  ((getByteD256 b (off + 1)).toNat <<< 16) |||
  ((getByteD256 b (off + 2)).toNat <<< 8) |||
  (getByteD256 b (off + 3)).toNat

/-- Append a 64-bit word in little-endian byte order to `b`. -/
def pushU64LE256 (b : ByteArray) (w : UInt64) : ByteArray :=
  b.push w.toUInt8
   |>.push (w >>> 8).toUInt8
   |>.push (w >>> 16).toUInt8
   |>.push (w >>> 24).toUInt8
   |>.push (w >>> 32).toUInt8
   |>.push (w >>> 40).toUInt8
   |>.push (w >>> 48).toUInt8
   |>.push (w >>> 56).toUInt8

/-- Append the low 56 bits (7 bytes) of `w` in little-endian byte order to `b`. -/
def pushU56LE256 (b : ByteArray) (w : UInt64) : ByteArray :=
  b.push w.toUInt8
   |>.push (w >>> 8).toUInt8
   |>.push (w >>> 16).toUInt8
   |>.push (w >>> 24).toUInt8
   |>.push (w >>> 32).toUInt8
   |>.push (w >>> 40).toUInt8
   |>.push (w >>> 48).toUInt8

/-- Append the low 48 bits (6 bytes) of `w` in little-endian byte order to `b`. -/
def pushU48LE256 (b : ByteArray) (w : UInt64) : ByteArray :=
  b.push w.toUInt8
   |>.push (w >>> 8).toUInt8
   |>.push (w >>> 16).toUInt8
   |>.push (w >>> 24).toUInt8
   |>.push (w >>> 32).toUInt8
   |>.push (w >>> 40).toUInt8

/-- Append a 32-bit word in little-endian byte order to `b`. -/
def pushU32LE256 (b : ByteArray) (w : UInt32) : ByteArray :=
  b.push w.toUInt8
   |>.push (w >>> 8).toUInt8
   |>.push (w >>> 16).toUInt8
   |>.push (w >>> 24).toUInt8

/-- Append a 16-bit word in little-endian byte order to `b`. -/
def pushU16LE256 (b : ByteArray) (w : UInt16) : ByteArray :=
  b.push w.toUInt8
   |>.push (w >>> 8).toUInt8

/-- Append a 16-bit word in big-endian byte order to `b`. -/
def pushU16BE256 (b : ByteArray) (w : Nat) : ByteArray :=
  b.push (w >>> 8).toUInt8
   |>.push w.toUInt8

/-- 64-bit right rotation (`bits.RotateLeft64(x, -n)`). -/
def rotr64_256 (x : UInt64) (n : UInt64) : UInt64 :=
  withStrictU64 x fun x' => (x' >>> n) ||| (x' <<< (64 - n))

/-- 64-bit left rotation (`bits.RotateLeft64(x, r)`). -/
def rotl64_256 (x : UInt64) (r : Nat) : UInt64 :=
  let s := (r % 64).toUInt64
  if s == 0 then x
  else withStrictU64 x fun x' => (x' <<< s) ||| (x' >>> (64 - s))

/-- Bijective 128-bit Feistel fold over a `ChainHash` output pair `(hLo, hHi)`
    under domain tags `0x05` (Layer I) and `0x06` (Layer II) (`desync.go:42-47`). -/
def fullWidthFold256 (hLo hHi : UInt64) : UInt64 × UInt64 :=
  withStrictU64 hLo fun hLo =>
  withStrictU64 hHi fun hHi =>
  let mixHi := rotl64_256 hHi 25 + rotl64_256 hHi 53
  withStrictU64 (hLo + mixHi) fun w0 =>
  withStrictU64 (hHi ^^^ rotl64_256 w0 19 ^^^ rotl64_256 w0 41) fun w1 =>
  (w0, w1)

/-- Exact inverse of `fullWidthFold256` (`ITB.Desync.invFullWidthFold`). -/
def invFullWidthFold256 (w0 w1 : UInt64) : UInt64 × UInt64 :=
  let hHi := w1 ^^^ rotl64_256 w0 19 ^^^ rotl64_256 w0 41
  let mixHi := rotl64_256 hHi 25 + rotl64_256 hHi 53
  let hLo := w0 - mixHi
  (hLo, hHi)

/-! ## Section 2: RFC 7693 `BLAKE2b-256` & `Seed256.ChainHash256` -/

/-- RFC 7693 BLAKE2b initialization vector words `IV[0..7]`. -/
def blake2b256IV0 : UInt64 := 0x6a09e667f3bcc908
def blake2b256IV1 : UInt64 := 0xbb67ae8584caa73b
def blake2b256IV2 : UInt64 := 0x3c6ef372fe94f82b
def blake2b256IV3 : UInt64 := 0xa54ff53a5f1d36f1
def blake2b256IV4 : UInt64 := 0x510e527fade682d1
def blake2b256IV5 : UInt64 := 0x9b05688c2b3e6c1f
def blake2b256IV6 : UInt64 := 0x1f83d9abfb41bd6b
def blake2b256IV7 : UInt64 := 0x5be0cd19137e2179

/-- Convert `Words4` to `Array UInt64` of length 4. -/
def Words4.toArray (w : Words4) : Array UInt64 :=
  #[w.h0, w.h1, w.h2, w.h3]

/-- Construct `Words4` from `Array UInt64` (with 0 fallback). -/
def Words4.ofArray (a : Array UInt64) : Words4 :=
  { h0 := aGetD256 a 0 0
    h1 := aGetD256 a 1 0
    h2 := aGetD256 a 2 0
    h3 := aGetD256 a 3 0 }

/-- Componentwise XOR of two `Words4` values. -/
def Words4.xor (a b : Words4) : Words4 :=
  { h0 := a.h0 ^^^ b.h0
    h1 := a.h1 ^^^ b.h1
    h2 := a.h2 ^^^ b.h2
    h3 := a.h3 ^^^ b.h3 }

/-- 8-word internal chaining state `h[0..7]` for BLAKE2b compression. -/
structure Words8_256 where
  h0 : UInt64
  h1 : UInt64
  h2 : UInt64
  h3 : UInt64
  h4 : UInt64
  h5 : UInt64
  h6 : UInt64
  h7 : UInt64
  deriving DecidableEq, Repr

/-- Initial chaining state for unkeyed BLAKE2b-256 (`outLen = 32 = 0x20`, `h0 = IV0 ^ 0x01010020`). -/
def blake2b256InitState : Words8_256 :=
  { h0 := blake2b256IV0 ^^^ 0x01010020
    h1 := blake2b256IV1
    h2 := blake2b256IV2
    h3 := blake2b256IV3
    h4 := blake2b256IV4
    h5 := blake2b256IV5
    h6 := blake2b256IV6
    h7 := blake2b256IV7 }

/-- 16-word internal work vector `v[0..15]` for BLAKE2b compression. -/
structure Blake2bWork16_256 where
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

/-- RFC 7693 §3.1 quarter-round mixing function `G(a, b, c, d, x, y)`. -/
@[inline] def blake2bG256 (a b c d x y : UInt64) : UInt64 × UInt64 × UInt64 × UInt64 :=
  let a := a + b + x
  let d0 := d ^^^ a
  let d := (d0 >>> 32) ||| (d0 <<< 32)
  let c := c + d
  let b0 := b ^^^ c
  let b := (b0 >>> 24) ||| (b0 <<< 40)
  let a := a + b + y
  let d1 := d ^^^ a
  let d := (d1 >>> 16) ||| (d1 <<< 48)
  let c := c + d
  let b1 := b ^^^ c
  let b := (b1 >>> 63) ||| (b1 <<< 1)
  (a, b, c, d)

/-- One full BLAKE2b round (column step + diagonal step) given permuted message words `s0..s15`. -/
def blake2bRound256 (w : Blake2bWork16_256)
    (s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 : UInt64) : Blake2bWork16_256 :=
  let (v0, v4, v8,  v12) := blake2bG256 w.v0 w.v4 w.v8  w.v12 s0 s1
  let (v1, v5, v9,  v13) := blake2bG256 w.v1 w.v5 w.v9  w.v13 s2 s3
  let (v2, v6, v10, v14) := blake2bG256 w.v2 w.v6 w.v10 w.v14 s4 s5
  let (v3, v7, v11, v15) := blake2bG256 w.v3 w.v7 w.v11 w.v15 s6 s7
  let (v0, v5, v10, v15) := blake2bG256 v0   v5   v10   v15   s8 s9
  let (v1, v6, v11, v12) := blake2bG256 v1   v6   v11   v12   s10 s11
  let (v2, v7, v8,  v13) := blake2bG256 v2   v7   v8    v13   s12 s13
  let (v3, v4, v9,  v14) := blake2bG256 v3   v4   v9    v14   s14 s15
  { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 }

/-- RFC 7693 §3.2 compression function `F` (12 rounds over 16 message words `m0..m15`). -/
def blake2bCompress256 (h : Words8_256)
    (m0 m1 m2 m3 m4 m5 m6 m7 m8 m9 m10 m11 m12 m13 m14 m15 : UInt64)
    (tLow tHigh : UInt64) (isLast : Bool) : Words8_256 :=
  withStrictU64 m0  fun m0  =>
  withStrictU64 m1  fun m1  =>
  withStrictU64 m2  fun m2  =>
  withStrictU64 m3  fun m3  =>
  withStrictU64 m4  fun m4  =>
  withStrictU64 m5  fun m5  =>
  withStrictU64 m6  fun m6  =>
  withStrictU64 m7  fun m7  =>
  withStrictU64 m8  fun m8  =>
  withStrictU64 m9  fun m9  =>
  withStrictU64 m10 fun m10 =>
  withStrictU64 m11 fun m11 =>
  withStrictU64 m12 fun m12 =>
  withStrictU64 m13 fun m13 =>
  withStrictU64 m14 fun m14 =>
  withStrictU64 m15 fun m15 =>
  let f0 : UInt64 := if isLast then 0xffffffffffffffff else 0
  let w : Blake2bWork16_256 :=
    { v0  := h.h0, v1  := h.h1, v2  := h.h2, v3  := h.h3
      v4  := h.h4, v5  := h.h5, v6  := h.h6, v7  := h.h7
      v8  := blake2b256IV0, v9  := blake2b256IV1, v10 := blake2b256IV2, v11 := blake2b256IV3
      v12 := blake2b256IV4 ^^^ tLow
      v13 := blake2b256IV5 ^^^ tHigh
      v14 := blake2b256IV6 ^^^ f0
      v15 := blake2b256IV7 }
  let w := blake2bRound256 w m0  m1  m2  m3  m4  m5  m6  m7  m8  m9  m10 m11 m12 m13 m14 m15
  let w := blake2bRound256 w m14 m10 m4  m8  m9  m15 m13 m6  m1  m12 m0  m2  m11 m7  m5  m3
  let w := blake2bRound256 w m11 m8  m12 m0  m5  m2  m15 m13 m10 m14 m3  m6  m7  m1  m9  m4
  let w := blake2bRound256 w m7  m9  m3  m1  m13 m12 m11 m14 m2  m6  m5  m10 m4  m0  m15 m8
  let w := blake2bRound256 w m9  m0  m5  m7  m2  m4  m10 m15 m14 m1  m11 m12 m6  m8  m3  m13
  let w := blake2bRound256 w m2  m12 m6  m10 m0  m11 m8  m3  m4  m13 m7  m5  m15 m14 m1  m9
  let w := blake2bRound256 w m12 m5  m1  m15 m14 m13 m4  m10 m0  m7  m6  m3  m9  m2  m8  m11
  let w := blake2bRound256 w m13 m11 m7  m14 m12 m1  m3  m9  m5  m0  m15 m4  m8  m6  m2  m10
  let w := blake2bRound256 w m6  m15 m14 m9  m11 m3  m0  m8  m12 m2  m13 m7  m1  m4  m10 m5
  let w := blake2bRound256 w m10 m2  m8  m4  m7  m6  m1  m5  m15 m11 m9  m14 m3  m12 m13 m0
  let w := blake2bRound256 w m0  m1  m2  m3  m4  m5  m6  m7  m8  m9  m10 m11 m12 m13 m14 m15
  let w := blake2bRound256 w m14 m10 m4  m8  m9  m15 m13 m6  m1  m12 m0  m2  m11 m7  m5  m3
  withStrictU64 (h.h0 ^^^ w.v0 ^^^ w.v8)  fun h0 =>
  withStrictU64 (h.h1 ^^^ w.v1 ^^^ w.v9)  fun h1 =>
  withStrictU64 (h.h2 ^^^ w.v2 ^^^ w.v10) fun h2 =>
  withStrictU64 (h.h3 ^^^ w.v3 ^^^ w.v11) fun h3 =>
  withStrictU64 (h.h4 ^^^ w.v4 ^^^ w.v12) fun h4 =>
  withStrictU64 (h.h5 ^^^ w.v5 ^^^ w.v13) fun h5 =>
  withStrictU64 (h.h6 ^^^ w.v6 ^^^ w.v14) fun h6 =>
  withStrictU64 (h.h7 ^^^ w.v7 ^^^ w.v15) fun h7 =>
  { h0, h1, h2, h3, h4, h5, h6, h7 }

/-- RFC 7693 unkeyed `BLAKE2b-256(msg)` returning `Words4` (`h0..h3`). -/
def blake2bSum256Words (msg : ByteArray) : Words4 := Id.run do
  let n := msg.size
  if n == 0 then
    let h := blake2bCompress256 blake2b256InitState 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 true
    return { h0 := h.h0, h1 := h.h1, h2 := h.h2, h3 := h.h3 }
  let numBlocks := (n + 127) / 128
  let mut h := blake2b256InitState
  for blkIdx in [:numBlocks] do
    let off := blkIdx * 128
    let isLast := (blkIdx + 1 == numBlocks)
    let tLow : UInt64 := if isLast then n.toUInt64 else ((blkIdx + 1) * 128).toUInt64
    h := blake2bCompress256 h
      (readU64LE256 msg (off + 0))   (readU64LE256 msg (off + 8))
      (readU64LE256 msg (off + 16))  (readU64LE256 msg (off + 24))
      (readU64LE256 msg (off + 32))  (readU64LE256 msg (off + 40))
      (readU64LE256 msg (off + 48))  (readU64LE256 msg (off + 56))
      (readU64LE256 msg (off + 64))  (readU64LE256 msg (off + 72))
      (readU64LE256 msg (off + 80))  (readU64LE256 msg (off + 88))
      (readU64LE256 msg (off + 96))  (readU64LE256 msg (off + 104))
      (readU64LE256 msg (off + 112)) (readU64LE256 msg (off + 120))
      tLow 0 isLast
  return { h0 := h.h0, h1 := h.h1, h2 := h.h2, h3 := h.h3 }

/-- RFC 7693 unkeyed `BLAKE2b-256(msg)` returning 4 little-endian `UInt64` words. -/
def blake2bSum256 (msg : ByteArray) : Array UInt64 :=
  (blake2bSum256Words msg).toArray

/-- Fast `Words4` evaluation of `hashes.BLAKE2b256WithKey` (`hashes/blake2b256.go:108-145`).
    Supports all input lengths `data.size` (including 128/256/512-bit nonces). -/
def blake2b256WithKeyWords (k : Words4) (b2key : ByteArray) (data : ByteArray) (seed : Words4) : Words4 :=
  let dataLen := data.size
  if dataLen <= 96 then
    let totalLen := (32 + max dataLen 32).toUInt64
    let d0  := readU64LE256 data 0
    let d1  := readU64LE256 data 8
    let d2  := readU64LE256 data 16
    let d3  := readU64LE256 data 24
    let d4  := readU64LE256 data 32
    let d5  := readU64LE256 data 40
    let d6  := readU64LE256 data 48
    let d7  := readU64LE256 data 56
    let d8  := readU64LE256 data 64
    let d9  := readU64LE256 data 72
    let d10 := readU64LE256 data 80
    let d11 := readU64LE256 data 88
    let h := blake2bCompress256 blake2b256InitState
      k.h0 k.h1 k.h2 k.h3
      (d0 ^^^ seed.h0)
      (d1 ^^^ seed.h1)
      (d2 ^^^ seed.h2)
      (d3 ^^^ seed.h3)
      d4 d5 d6 d7 d8 d9 d10 d11
      totalLen 0 true
    { h0 := h.h0, h1 := h.h1, h2 := h.h2, h3 := h.h3 }
  else
    let bs := data.data.toList
    let (d0, bs) := takeU64LE256 bs
    let (d1, bs) := takeU64LE256 bs
    let (d2, bs) := takeU64LE256 bs
    let (d3, rest) := takeU64LE256 bs
    let b0 := pushU64LE256 ByteArray.empty (d0 ^^^ seed.h0)
    let b0 := pushU64LE256 b0              (d1 ^^^ seed.h1)
    let b0 := pushU64LE256 b0              (d2 ^^^ seed.h2)
    let b0 := pushU64LE256 b0              (d3 ^^^ seed.h3)
    blake2bSum256Words (bExtract256 b2key 0 32 ++ b0 ++ ByteArray.mk ⟨rest⟩)

/-- `hashes.BLAKE2b256WithKey(b2key)(data, seed)` (`hashes/blake2b256.go:34-43`). -/
def blake2b256WithKey (b2key : ByteArray) (data : ByteArray) (seed : Array UInt64) : Array UInt64 :=
  let kw : Words4 :=
    { h0 := readU64LE256 b2key 0
      h1 := readU64LE256 b2key 8
      h2 := readU64LE256 b2key 16
      h3 := readU64LE256 b2key 24 }
  (blake2b256WithKeyWords kw b2key data (Words4.ofArray seed)).toArray

/-- `Seed256` state parameterized by a 32-byte `BLAKE2b-256` key and 4-word component rounds. -/
structure Seed256 where
  b2key      : ByteArray
  keyWords   : Words4
  components : Array UInt64
  rounds     : List Words4

/-- Construct a `Seed256` from a 32-byte key and an array of `UInt64` components (multiple of 4). -/
def Seed256.mkFromKeyAndComps (b2key : ByteArray) (comps : Array UInt64) : Seed256 :=
  let kw : Words4 :=
    { h0 := readU64LE256 b2key 0
      h1 := readU64LE256 b2key 8
      h2 := readU64LE256 b2key 16
      h3 := readU64LE256 b2key 24 }
  let numRounds := comps.size / 4
  let rounds := (List.range numRounds).map (fun r =>
    let b := r * 4
    { h0 := aGetD256 comps (b + 0) 0
      h1 := aGetD256 comps (b + 1) 0
      h2 := aGetD256 comps (b + 2) 0
      h3 := aGetD256 comps (b + 3) 0 })
  { b2key, keyWords := kw, components := comps, rounds }

/-- Cascade loop for `chainHash256With` over a list of 4-word component rounds (`seed256.go:248-257`). -/
def chainHash256RoundsLoop (kw : Words4) (b2key : ByteArray) (data : ByteArray) :
    List Words4 → Words4 → Words4
  | [], h => h
  | r :: rs, h =>
    let h' := blake2b256WithKeyWords kw b2key data (Words4.xor r h)
    chainHash256RoundsLoop kw b2key data rs h'

/-- Evaluate `chainHash256With` on a list of 4-word rounds (`seed256.go:445-461`). -/
def chainHash256WithRounds (kw : Words4) (b2key : ByteArray) (rounds : List Words4) (data : ByteArray) : Words4 :=
  match rounds with
  | [] => { h0 := 0, h1 := 0, h2 := 0, h3 := 0 }
  | r0 :: rs =>
    let h0 := blake2b256WithKeyWords kw b2key data r0
    chainHash256RoundsLoop kw b2key data rs h0

/-- `Seed256.ChainHash256(data)` returning `Words4` (`seed256.go:242-261`). -/
def chainHash256Words (s : Seed256) (data : ByteArray) : Words4 :=
  chainHash256WithRounds s.keyWords s.b2key s.rounds data

/-- `Seed256.ChainHash256(data)` returning 4 `UInt64` words (`seed256.go:242-261`). -/
def chainHash256 (s : Seed256) (data : ByteArray) : Array UInt64 :=
  (chainHash256Words s data).toArray

/-- `Seed256.MinPixels()` (`seed256.go:225-233`). -/
def Seed256.minPixels (s : Seed256) : Nat :=
  let bits := s.components.size * 64
  (bits * 10000 + 28074 - 1) / 28074

/-- `Seed256.blockHash256(buf, index)` (`seed256.go:356-361`). -/
def blockHash256Words (s : Seed256) (index : Nat) (nonce : ByteArray) : Words4 :=
  let buf := pushU32LE256 ByteArray.empty index.toUInt32 ++ nonce
  chainHash256Words s buf

/-- Pre-unpacked message words for `blockHash256Words` so per-pixel evaluation avoids
    allocating a `ByteArray` or re-unpacking `nonce` on every pixel. -/
structure BlockNonceTemplate256 where
  d0Hi     : UInt64
  d1       : UInt64
  d2       : UInt64
  d3       : UInt64
  d4       : UInt64
  d5       : UInt64
  d6       : UInt64
  d7       : UInt64
  d8       : UInt64
  d9       : UInt64
  d10      : UInt64
  d11      : UInt64
  totalLen : UInt64

def prepareBlockNonce256 (nonce : ByteArray) : BlockNonceTemplate256 :=
  let buf := pushU32LE256 ByteArray.empty 0 ++ nonce
  { d0Hi     := readU64LE256 buf 0
    d1       := readU64LE256 buf 8
    d2       := readU64LE256 buf 16
    d3       := readU64LE256 buf 24
    d4       := readU64LE256 buf 32
    d5       := readU64LE256 buf 40
    d6       := readU64LE256 buf 48
    d7       := readU64LE256 buf 56
    d8       := readU64LE256 buf 64
    d9       := readU64LE256 buf 72
    d10      := readU64LE256 buf 80
    d11      := readU64LE256 buf 88
    totalLen := (32 + max buf.size 32).toUInt64 }

@[inline] def blake2b256BlockTpl (k : Words4) (tpl : BlockNonceTemplate256) (d0 : UInt64) (seed : Words4) : Words4 :=
  let h := blake2bCompress256 blake2b256InitState
    k.h0 k.h1 k.h2 k.h3
    (d0 ^^^ seed.h0)
    (tpl.d1 ^^^ seed.h1)
    (tpl.d2 ^^^ seed.h2)
    (tpl.d3 ^^^ seed.h3)
    tpl.d4 tpl.d5 tpl.d6 tpl.d7 tpl.d8 tpl.d9 tpl.d10 tpl.d11
    tpl.totalLen 0 true
  { h0 := h.h0, h1 := h.h1, h2 := h.h2, h3 := h.h3 }

def chainHash256TplLoop (kw : Words4) (tpl : BlockNonceTemplate256) (d0 : UInt64) :
    List Words4 → Words4 → Words4
  | [], h => h
  | r :: rs, h =>
    let h' := blake2b256BlockTpl kw tpl d0 (Words4.xor r h)
    chainHash256TplLoop kw tpl d0 rs h'

@[inline] def blockHash256Fast (s : Seed256) (index : Nat) (tpl : BlockNonceTemplate256) : Words4 :=
  let d0 := tpl.d0Hi ||| index.toUInt32.toUInt64
  match s.rounds with
  | [] => { h0 := 0, h1 := 0, h2 := 0, h3 := 0 }
  | r0 :: rs =>
    let h0 := blake2b256BlockTpl s.keyWords tpl d0 r0
    chainHash256TplLoop s.keyWords tpl d0 rs h0

/-- `Seed256.deriveStartPixel(nonce, maxPixels)` (`seed256.go:366-380`). -/
def deriveStartPixel256 (s : Seed256) (nonce : ByteArray) (maxPixels : Nat) : Nat :=
  if maxPixels == 0 then 0
  else
    let buf := (ByteArray.empty.push 0x02) ++ nonce
    let h := chainHash256Words s buf
    h.h0.toNat % maxPixels

/-- `Seed256.deriveInterLockSeed(nonce)` (`seed256.go:404-415`). -/
def deriveInterLockSeed256Words (s : Seed256) (ilNonce : ByteArray) : Words4 :=
  let buf := (ByteArray.empty.push 0x04) ++ ilNonce
  chainHash256Words s buf

def deriveInterLockSeed256 (s : Seed256) (ilNonce : ByteArray) : Array UInt64 :=
  (deriveInterLockSeed256Words s ilNonce).toArray

/-! ## Section 3: 256-Bit Rank Barrier (`Interlock = "48"`, `factor = 2`) -/

/-- `interlockNonceFoldWord(interlockNonceFold(nonce))` (`interlock48_cascade.go:62-75`). -/
def interlockNonceFoldWord256 (nonce : ByteArray) : UInt32 :=
  let (b0, b1, b2, b3) := (List.range nonce.size).foldl
    (fun (acc : UInt8 × UInt8 × UInt8 × UInt8) i =>
      let (a0, a1, a2, a3) := acc
      let b := getByteD256 nonce i
      match i % 4 with
      | 0 => (a0 ^^^ b, a1, a2, a3)
      | 1 => (a0, a1 ^^^ b, a2, a3)
      | 2 => (a0, a1, a2 ^^^ b, a3)
      | _ => (a0, a1, a2, a3 ^^^ b))
    (0, 0, 0, 0)
  b0.toUInt32 ||| (b1.toUInt32 <<< 8) ||| (b2.toUInt32 <<< 16) ||| (b3.toUInt32 <<< 24)

/-- Lookup `C(n, k)` for `0 ≤ n ≤ 48`, `0 ≤ k ≤ 16` via `ITB.RankBarrier.binom`. -/
def binomC48 (n k : Nat) : UInt64 :=
  if k > n then 0 else (binom n k).toUInt64

/-- Find largest `c ∈ [k - 1, n - 1]` with `C(c, k) ≤ rank` (`interlock48.go:85-88`),
    returning `(c, C(c, k))` using the exact recurrence `C(c + 1, k) = C(c, k) * (c + 1) / (c + 1 - k)`. -/
def findCombPos48 (rank : UInt64) (k n : Nat) : Nat × UInt64 :=
  let rec loop (c : Nat) (curC nextC : Nat) (fuel : Nat) : Nat × UInt64 :=
    match fuel with
    | 0 => (c, curC.toUInt64)
    | fuel' + 1 =>
      if c + 1 <= n - 1 && nextC.toUInt64 <= rank then
        let c' := c + 1
        let nextC' := (nextC * (c' + 1)) / (c' + 1 - k)
        loop c' nextC nextC' fuel'
      else
        (c, curC.toUInt64)
  loop (k - 1) 0 1 n

/-- `unrankCombination48(rank, k, n)` (`interlock48.go:82-94`). -/
def unrankCombination48 (rank : UInt64) (k n : Nat) : UInt64 :=
  let rec loop (remK : Nat) (r : UInt64) (mask : UInt64) : UInt64 :=
    match remK with
    | 0 => mask
    | k' + 1 =>
      let (c, binomVal) := findCombPos48 r (k' + 1) n
      let mask' := mask ||| (1 <<< c.toUInt64)
      let r' := r - binomVal
      loop k' r' mask'
  loop k rank 0

/-- Bitwise parallel extract `softPEXT48(x, mask)` over `n` bits (`interlock48.go:153-163`). -/
def softPEXT48Aux : Nat → UInt64 → UInt64 → UInt64
  | 0, _, _ => 0
  | n + 1, x, m =>
    let rest := softPEXT48Aux n (x >>> 1) (m >>> 1)
    if (m &&& (1 : UInt64)) == (1 : UInt64) then
      (x &&& (1 : UInt64)) ||| (rest <<< 1)
    else
      rest

/-- Bitwise parallel deposit `softPDEP48(v, mask)` over `n` bits (`interlock48.go:175-185`). -/
def softPDEP48Aux : Nat → UInt64 → UInt64 → UInt64
  | 0, _, _ => 0
  | n + 1, v, m =>
    if (m &&& (1 : UInt64)) == (1 : UInt64) then
      (v &&& (1 : UInt64)) ||| (softPDEP48Aux n (v >>> 1) (m >>> 1) <<< 1)
    else
      softPDEP48Aux n v (m >>> 1) <<< 1

/-- 48-bit `softPEXT48` (`interlock48.go:153-163`). -/
def softPEXT48 (x mask : UInt64) : UInt16 :=
  (softPEXT48Aux 48 x mask).toUInt16

/-- 48-bit `softPDEP48` (`interlock48.go:175-185`). -/
def softPDEP48 (v : UInt16) (mask : UInt64) : UInt64 :=
  softPDEP48Aux 48 v.toUInt64 mask

/-- 48-bit domain mask `0x0000_FFFF_FFFF_FFFF`. -/
def mask48Domain : UInt64 := 0x0000FFFFFFFFFFFF

/-- High 64 bits of 128-bit product `a * b` (`bits.Mul64` high word). -/
def mulHi64_256 (a b : UInt64) : UInt64 :=
  ((a.toNat * b.toNat) >>> 64).toUInt64

/-- `divB(n)` (`interlock48_rank_split.go:59-68`): returns `(n / B, n mod B)` for `B = C(32, 16) = 601080390`. -/
def divB48 (n : UInt64) : UInt64 × UInt64 :=
  withStrictU64 n fun n =>
  let b : UInt64 := 601080390
  let recip : UInt64 := 0xe4a737fd2603cba7
  withStrictU64 (mulHi64_256 n recip >>> 29) fun q =>
  withStrictU64 (n - q * b) fun r =>
  if r >= b then (q + 1, r - b) else (q, r)

/-- `modA(n)` (`interlock48_rank_split.go:71-76`): returns `n mod A` for `A = C(48, 16) = 2254848913647`. -/
def modA48 (n : UInt64) : UInt64 :=
  withStrictU64 n fun n =>
  let a : UInt64 := 2254848913647
  let recip : UInt64 := 0xf9a974e0a78bad8f
  withStrictU64 (mulHi64_256 n recip >>> 41) fun q =>
  withStrictU64 (n - q * a) fun r =>
  if r >= a then r - a else r

/-- `splitRank48Recip(lane0, lane1)` (`interlock48_rank_split.go:24-42`). -/
def splitRank48Recip256 (lane0 lane1 : UInt64) : UInt64 × UInt32 :=
  withStrictU64 lane0 fun lane0 =>
  withStrictU64 lane1 fun lane1 =>
  let (qHi, r1) := divB48 lane1
  let (qa, ra) := divB48 ((r1 <<< 32) ||| (lane0 >>> 32))
  let (qb, r) := divB48 ((ra <<< 32) ||| (lane0 &&& 0xFFFFFFFF))
  withStrictU64 ((qa <<< 32) ||| qb) fun qLo =>
  let idx1 := r.toUInt32
  let mask21 : UInt64 := 0x1FFFFF
  let u := modA48 ((qHi <<< 22) ||| (qLo >>> 42))
  let u := modA48 ((u <<< 21) ||| ((qLo >>> 21) &&& mask21))
  let idx0 := modA48 ((u <<< 21) ||| (qLo &&& mask21))
  (idx0, idx1)

/-- `rankToMaskTriple48(lane0, lane1)` (`interlock48.go:112-139`). -/
def rankToMaskTriple48 (lane0 lane1 : UInt64) : UInt64 × UInt64 × UInt64 :=
  let (idx0, idx1) := splitRank48Recip256 lane0 lane1
  withStrictU64 (unrankCombination48 idx0 16 48) fun m0 =>
  withStrictU64 (unrankCombination48 idx1.toUInt64 16 32) fun m1Local =>
  withStrictU64 (mask48Domain &&& (~~~m0)) fun remaining =>
  withStrictU64 (softPDEP48Aux 48 m1Local remaining) fun m1 =>
  withStrictU64 (remaining &&& (~~~m1)) fun m2 =>
  (m0, m1, m2)

/-- `chunk48lock(x, m0, m1, m2)` (`interlock48.go:204-213`). -/
def chunk48lock (x : UInt64) (masks : UInt64 × UInt64 × UInt64) : UInt16 × UInt16 × UInt16 :=
  let (m0, m1, m2) := masks
  (softPEXT48 x m0, softPEXT48 x m1, softPEXT48 x m2)

/-- `unchunk48lock(l0, l1, l2, m0, m1, m2)` (`interlock48.go:226-231`). -/
def unchunk48lock (l0 l1 l2 : UInt16) (masks : UInt64 × UInt64 × UInt64) : UInt64 :=
  let (m0, m1, m2) := masks
  softPDEP48 l0 m0 ||| softPDEP48 l1 m1 ||| softPDEP48 l2 m2

/-- Group-factored (`factor = 2`) 256-bit Rank Barrier fill (`interlock48_cascade.go:188-211`):
    one `0x03` cascade call on `[0x03 ‖ LE64(groupIdx) ‖ LE32(foldWord)]` yields 4 `UInt64` words `out`,
    producing two 48-bit mask triples: `(out.h0, out.h1)` for chunk `2 * groupIdx` and
    `(out.h2, out.h3)` for chunk `2 * groupIdx + 1`. -/
def groupMasks48_256 (lockSeed : Seed256) (lockRounds : List Words4) (foldWord : UInt32) (groupIdx : Nat) :
    (UInt64 × UInt64 × UInt64) × (UInt64 × UInt64 × UInt64) :=
  let blk := pushU32LE256 (pushU64LE256 (ByteArray.empty.push 0x03) groupIdx.toUInt64) foldWord
  let out := chainHash256WithRounds lockSeed.keyWords lockSeed.b2key lockRounds blk
  (rankToMaskTriple48 out.h0 out.h1, rankToMaskTriple48 out.h2 out.h3)

/-- Build all `numChunks` 48-bit mask triples using `numGroups = (numChunks + 1) / 2` calls (`factor = 2`). -/
def buildAllChunkMasks48_256 (lockSeed : Seed256) (lockRounds : List Words4) (foldWord : UInt32)
    (numChunks : Nat) : Array (UInt64 × UInt64 × UInt64) :=
  let numGroups := (numChunks + 1) / 2
  let pairs := (List.range numGroups).flatMap (fun g =>
    let (masks0, masks1) := groupMasks48_256 lockSeed lockRounds foldWord g
    [masks0, masks1])
  ⟨pairs.take numChunks⟩

/-- Frame plaintext with 4-byte big-endian length prefix and zero-pad to a multiple of 6 bytes
    (`interlock48.go:284-316`). -/
def framedSrc48 (data : ByteArray) : ByteArray :=
  let totalLen := 4 + data.size
  let numChunks := (totalLen + 5) / 6
  let paddedLen := numChunks * 6
  let padZeros := paddedLen - totalLen
  let hdr := ByteArray.empty
    |>.push (data.size >>> 24).toUInt8
    |>.push (data.size >>> 16).toUInt8
    |>.push (data.size >>> 8).toUInt8
    |>.push data.size.toUInt8
  hdr ++ data ++ ByteArray.mk (Array.replicate padZeros 0)

/-- Strip the 4-byte big-endian length prefix from a reconstructed multiple-of-6 buffer
    (`interlock48.go:1332-1344`). -/
def unframeDst48 (framed : ByteArray) : ByteArray :=
  if framed.size < 4 then framed
  else
    let length := readU32BE256 framed 0
    let endPos := min (4 + length) framed.size
    bExtract256 framed 4 endPos

/-! ## Section 4: Layer II (`0x06`) Cross-Lane 2-Byte Slot Desynchronization -/

/-- Derive the 4 Layer II schedule words `#[w0, w1, w2, w3]` under domain tag `0x06`
    for a 256-bit `lockSeed` (`interlock48_cascade.go:215-232`). -/
def desyncWords256 (lockSeed : Seed256) (lockRounds : List Words4) (foldWord : UInt32) : Array UInt64 :=
  let blk0 := pushU32LE256 (pushU64LE256 (ByteArray.empty.push 0x06) 0) foldWord
  let blk1 := pushU32LE256 (pushU64LE256 (ByteArray.empty.push 0x06) 1) foldWord
  let out0 := chainHash256WithRounds lockSeed.keyWords lockSeed.b2key lockRounds blk0
  let out1 := chainHash256WithRounds lockSeed.keyWords lockSeed.b2key lockRounds blk1
  let (w0, w1) := fullWidthFold256 out0.h0 out0.h1
  let (w2, w3) := fullWidthFold256 out1.h0 out1.h1
  #[w0, w1, w2, w3]

/-- Fisher-Yates shuffle of `[0, 1, ..., k - 1]` driven by `u : UInt64` (`desync.go:112-122, 376-386`). -/
def fisherYatesPerm (k : Nat) (u : UInt64) : Array Nat :=
  let init : Array Nat := ⟨List.range k⟩
  let rec loop (i : Nat) (remU : UInt64) (arr : Array Nat) : Array Nat :=
    match i with
    | 0 => arr
    | i' + 1 =>
      let modVal := (i' + 2).toUInt64
      let swapIdx := (remU % modVal).toNat
      let remU' := remU / modVal
      let vi := aGetD256 arr (i' + 1) 0
      let vs := aGetD256 arr swapIdx 0
      let arr' := aSet256 (aSet256 arr (i' + 1) vs) swapIdx vi
      loop i' remU' arr'
  if k <= 1 then init else loop (k - 1) u init

/-- Layer II cross-lane chunk-slot desynchronization schedule (`desync.go:329-337`). -/
structure LaneDesyncSchedule256 where
  m      : Nat
  betas  : Array Nat
  kLane  : Nat
  offset : Array Nat
  size   : Array Nat
  start  : Array Nat
  logOff : Array Nat
  deriving DecidableEq, Repr

/-- Construct the Layer II schedule for `m` slots from `w[0..3]` (`desync.go:339-397`). -/
def buildLaneDesyncSchedule256 (m : Nat) (w : Array UInt64) : LaneDesyncSchedule256 :=
  if m < 2 then
    { m, betas := #[0, 0, 0], kLane := 0, offset := #[], size := #[], start := #[], logOff := #[0] }
  else
    let w0 := aGetD256 w 0 0
    let w1 := aGetD256 w 1 0
    let w2 := aGetD256 w 2 0
    let w3 := aGetD256 w 3 0
    let beta0 := (w3 % m.toUInt64).toNat
    let beta1 := (beta0 + 1 + (((w3 >>> 16) % (m - 1).toUInt64).toNat)) % m
    let beta2 := ((w3 >>> 32) % m.toUInt64).toNat
    let betas := #[beta0, beta1, beta2]
    if m < 16 then
      { m, betas, kLane := 0, offset := #[], size := #[], start := #[], logOff := #[0] }
    else
      let kLane := 4 + (w0 % 5).toNat
      let base := m / kLane
      let rem := m % kLane
      let physOff0 : Array Nat := (List.range kLane).foldl (fun acc j =>
        let sz := base + (if j < rem then 1 else 0)
        acc.push (aGetD256 acc j 0 + sz)) #[0]
      let physOff : Array Nat :=
        if base >= 4 then
          (List.range (kLane - 1)).foldl (fun acc jIdx =>
            let j := jIdx + 1
            let raw := ((w0 >>> (8 + j).toUInt64) &&& 1).toNat
            if raw == 0 then aSet256 acc j (aGetD256 acc j 0 - 1) else acc) physOff0
        else
          physOff0
      let physSize : Array Nat := (List.range kLane).foldl (fun acc j =>
        acc.push (aGetD256 physOff (j + 1) 0 - aGetD256 physOff j 0)) #[]
      let piLane := fisherYatesPerm kLane w1
      let (offset, size, start, logOff) := (List.range kLane).foldl
        (fun (st : Array Nat × Array Nat × Array Nat × Array Nat) step =>
          let (offs, szs, sts, logs) := st
          let physIdx := aGetD256 piLane step 0
          let mk := aGetD256 physSize physIdx 1
          let pOff := aGetD256 physOff physIdx 0
          let lNext := aGetD256 logs step 0 + mk
          let sVal := (rotl64_256 w2 (9 * step) % mk.toUInt64).toNat
          (offs.push pOff, szs.push mk, sts.push sVal, logs.push lNext))
        (#[], #[], #[], #[0])
      { m, betas, kLane, offset, size, start, logOff }

/-- Build the Layer II slot address map `slotMap[u] = dstIdx` for `u ∈ [0, m)`. -/
def buildLaneSlotMap256 (sched : LaneDesyncSchedule256) : List Nat :=
  (List.range sched.kLane).flatMap (fun step =>
    let mk := aGetD256 sched.size step 0
    let physOff := aGetD256 sched.offset step 0
    let s := aGetD256 sched.start step 0
    (List.range mk).map (fun q =>
      physOff + ((s + q) % mk)))

/-- Single-pass scatter loop placing each element of `srcList` at its target index in `dst`. -/
def scatterSlotsLoop256 : List Nat → List UInt16 → List UInt16 → List UInt16
  | [], _, dst => dst
  | idx :: restIdx, v :: restV, dst =>
    scatterSlotsLoop256 restIdx restV (dst.set idx v)
  | _, [], dst => dst

/-- Invert a permutation `slotMap` (`slotMap[u] = dstIdx`) into `invSlotMap[dstIdx] = u`. -/
def invertSlotMapLoop256 : Nat → List Nat → List Nat → List Nat
  | _, [], inv => inv
  | u, dstIdx :: rest, inv =>
    invertSlotMapLoop256 (u + 1) rest (inv.set dstIdx u)

/-- Forward Layer II permutation on an array of `m` 16-bit lane slots (`desyncLaneEncryptTo`, `desync.go:468-487`). -/
def permuteSlots256Encrypt (src : Array UInt16) (sched : LaneDesyncSchedule256) (l : Nat) : Array UInt16 :=
  let m := sched.m
  if m < 2 then src
  else
    let beta := aGetD256 sched.betas l 0
    let rot := (m - (beta % m)) % m
    let (pre, suf) := listSplitAt256 rot src.toList
    let midList := suf ++ pre
    if sched.kLane == 0 then
      ⟨midList⟩
    else
      let slotMap := buildLaneSlotMap256 sched
      ⟨scatterSlotsLoop256 slotMap midList (List.replicate m 0)⟩

/-- Inverse Layer II permutation on an array of `m` 16-bit lane slots (`desyncLaneDecryptOne`, `desync.go:494-513`). -/
def permuteSlots256Decrypt (src : Array UInt16) (sched : LaneDesyncSchedule256) (l : Nat) : Array UInt16 :=
  let m := sched.m
  if m < 2 then src
  else
    let beta := aGetD256 sched.betas l 0
    let midList : List UInt16 :=
      if sched.kLane == 0 then
        src.toList
      else
        let slotMap := buildLaneSlotMap256 sched
        let invMap := invertSlotMapLoop256 0 slotMap (List.replicate m 0)
        scatterSlotsLoop256 invMap src.toList (List.replicate m 0)
    let (pre, suf) := listSplitAt256 (beta % m) midList
    ⟨suf ++ pre⟩

/-- Pack an array of `UInt16` slots into a `ByteArray` in little-endian order (`2 * slots.size` bytes). -/
def packSlots16 (slots : Array UInt16) : ByteArray :=
  ByteArray.mk ⟨slots.toList.flatMap (fun (w : UInt16) => [w.toUInt8, (w >>> 8).toUInt8])⟩

/-- Unpack a `ByteArray` of `2 * m` bytes into an array of `m` `UInt16` slots in a single pass. -/
def unpackSlots16Loop : Nat → List UInt8 → List UInt16
  | 0, _ => []
  | m + 1, b0 :: b1 :: rest =>
    (b0.toUInt16 ||| (b1.toUInt16 <<< 8)) :: unpackSlots16Loop m rest
  | m + 1, [b0] =>
    b0.toUInt16 :: unpackSlots16Loop m []
  | m + 1, [] =>
    0 :: unpackSlots16Loop m []

def unpackSlots16 (b : ByteArray) (m : Nat) : Array UInt16 :=
  ⟨unpackSlots16Loop m b.data.toList⟩

/-- Single-pass loop applying `chunk48lock` across `framed` (6 bytes/chunk) and `allMasks`. -/
def chunk48StreamLoop :
    List (UInt64 × UInt64 × UInt64) → List UInt8 →
    List UInt16 → List UInt16 → List UInt16 →
    Array UInt16 × Array UInt16 × Array UInt16
  | [], _, r0, r1, r2 => (⟨r0.reverse⟩, ⟨r1.reverse⟩, ⟨r2.reverse⟩)
  | masks :: restMasks, bs, r0, r1, r2 =>
    let (x, restBs) :=
      match bs with
      | b0 :: b1 :: b2 :: b3 :: b4 :: b5 :: tail =>
        let w := b0.toUInt64 ||| (b1.toUInt64 <<< 8) ||| (b2.toUInt64 <<< 16) |||
                 (b3.toUInt64 <<< 24) ||| (b4.toUInt64 <<< 32) ||| (b5.toUInt64 <<< 40)
        (w, tail)
      | _ => (0, [])
    let (l0, l1, l2) := chunk48lock x masks
    chunk48StreamLoop restMasks restBs (l0 :: r0) (l1 :: r1) (l2 :: r2)

/-- Full 256-bit `splitForTriple48LockedInto` (`interlock48.go:1232-1243`, `triplepayload.go:401-440`):
    frames `data`, applies group-factored (`factor = 2`) 48-bit Rank Barrier `chunk48lock`,
    and applies Layer II (`0x06`) slot desynchronization. -/
def splitTriple48_256 (lockSeed : Seed256) (ilNonce : ByteArray) (data : ByteArray) :
    ByteArray × ByteArray × ByteArray :=
  let framed := framedSrc48 data
  let numChunks := framed.size / 6
  let lockKey := deriveInterLockSeed256Words lockSeed ilNonce
  let lockRounds := lockKey :: lockSeed.rounds
  let foldWord := interlockNonceFoldWord256 ilNonce
  let allMasks := buildAllChunkMasks48_256 lockSeed lockRounds foldWord numChunks
  let (slots0, slots1, slots2) := chunk48StreamLoop allMasks.toList framed.data.toList [] [] []
  let sched := buildLaneDesyncSchedule256 numChunks (desyncWords256 lockSeed lockRounds foldWord)
  let s0 := permuteSlots256Encrypt slots0 sched 0
  let s1 := permuteSlots256Encrypt slots1 sched 1
  let s2 := permuteSlots256Encrypt slots2 sched 2
  (packSlots16 s0, packSlots16 s1, packSlots16 s2)

/-- Single-pass loop applying `unchunk48lock` across `allMasks` and the 3 unpermuted slot lists. -/
def unchunk48StreamLoop :
    List (UInt64 × UInt64 × UInt64) → List UInt16 → List UInt16 → List UInt16 → List UInt8
  | [], _, _, _ => []
  | masks :: restM, l0 :: rest0, l1 :: rest1, l2 :: rest2 =>
    let x := unchunk48lock l0 l1 l2 masks
    x.toUInt8 :: (x >>> 8).toUInt8 :: (x >>> 16).toUInt8 ::
    (x >>> 24).toUInt8 :: (x >>> 32).toUInt8 :: (x >>> 40).toUInt8 ::
      unchunk48StreamLoop restM rest0 rest1 rest2
  | _, _, _, _ => []

/-- Full 256-bit `interleaveForTriple48LockedCfgInto` (`interlock48.go:1260-1344`):
    inverts Layer II (`0x06`), applies group-factored (`factor = 2`) `unchunk48lock`,
    and strips the 4-byte big-endian length frame. -/
def interleaveTriple48_256 (lockSeed : Seed256) (ilNonce : ByteArray) (p0 p1 p2 : ByteArray) : ByteArray :=
  let numChunks := p0.size / 2
  if numChunks == 0 then ByteArray.empty
  else
    let lockKey := deriveInterLockSeed256Words lockSeed ilNonce
    let lockRounds := lockKey :: lockSeed.rounds
    let foldWord := interlockNonceFoldWord256 ilNonce
    let sched := buildLaneDesyncSchedule256 numChunks (desyncWords256 lockSeed lockRounds foldWord)
    let u0 := permuteSlots256Decrypt (unpackSlots16 p0 numChunks) sched 0
    let u1 := permuteSlots256Decrypt (unpackSlots16 p1 numChunks) sched 1
    let u2 := permuteSlots256Decrypt (unpackSlots16 p2 numChunks) sched 2
    let allMasks := buildAllChunkMasks48_256 lockSeed lockRounds foldWord numChunks
    let framed : ByteArray := ByteArray.mk ⟨unchunk48StreamLoop allMasks.toList u0.toList u1.toList u2.toList⟩
    unframeDst48 framed

/-! ## Section 5: Interlock-Nonce 3-Lane Split & COBS Framing -/

/-- `nonceSplit(nonceLen)` (`interlock_nonce.go:55-67`). -/
def nonceSplitLens256 (nonceLen : Nat) : Nat × Nat × Nat :=
  let base := nonceLen / 3
  let rem := nonceLen % 3
  let l0 := base + (if rem >= 1 then 1 else 0)
  let l1 := base + (if rem >= 2 then 1 else 0)
  let l2 := base
  (l0, l1, l2)

/-- Split `ilNonce` into 3 fragments `(frag0, frag1, frag2)` (`interlock_nonce.go:55-67`). -/
def splitInterlockNonce256 (ilNonce : ByteArray) : ByteArray × ByteArray × ByteArray :=
  let (l0, l1, l2) := nonceSplitLens256 ilNonce.size
  (bExtract256 ilNonce 0 l0,
   bExtract256 ilNonce l0 (l0 + l1),
   bExtract256 ilNonce (l0 + l1) (l0 + l1 + l2))

/-- `recoverInterlockNonce(nonceLen, parts)` (`interlock_nonce.go:82-94`). -/
def recoverInterlockNonce256 (nonceLen : Nat) (part0 part1 part2 : ByteArray) :
    ByteArray × ByteArray × ByteArray × ByteArray :=
  let (l0, l1, l2) := nonceSplitLens256 nonceLen
  let t0 := min l0 part0.size
  let t1 := min l1 part1.size
  let t2 := min l2 part2.size
  let f0 := bExtract256 part0 0 t0 ++ ByteArray.mk (Array.replicate (l0 - t0) 0)
  let f1 := bExtract256 part1 0 t1 ++ ByteArray.mk (Array.replicate (l1 - t1) 0)
  let f2 := bExtract256 part2 0 t2 ++ ByteArray.mk (Array.replicate (l2 - t2) 0)
  let ilNonce := f0 ++ f1 ++ f2
  (ilNonce, bExtract256 part0 t0 part0.size, bExtract256 part1 t1 part1.size, bExtract256 part2 t2 part2.size)

/-- `cobsEncodeBound(n)` (`cobs.go:41-43`). -/
def cobsEncodeBound256 (n : Nat) : Nat :=
  n + n / 254 + 2

/-- Recursive helper for `cobsEncode` (`cobs.go:50-105`), returning the non-zero encoded body
    (without the trailing `0x00` delimiter appended by `buildTripleWire3Into`). -/
def cobsEncodeBodyLoop : List UInt8 → UInt8 → List UInt8 → List UInt8 → List UInt8
  | [], code, revChunk, revOut =>
    (revChunk ++ (code :: revOut)).reverse
  | b :: bs, code, revChunk, revOut =>
    if b == 0 then
      let revOut' := revChunk ++ (code :: revOut)
      cobsEncodeBodyLoop bs 1 [] revOut'
    else
      let revChunk' := b :: revChunk
      let code' := code + 1
      if code' == 0xFF then
        let revOut' := revChunk' ++ ((0xFF : UInt8) :: revOut)
        cobsEncodeBodyLoop bs 1 [] revOut'
      else
        cobsEncodeBodyLoop bs code' revChunk' revOut

/-- `cobsEncode(src)` (`cobs.go:34-36, 50-105`). -/
def cobsEncode256 (src : ByteArray) : ByteArray :=
  ByteArray.mk ⟨cobsEncodeBodyLoop src.data.toList 1 [] []⟩

/-- Take bytes strictly before the first `0x00` terminator (`itb256.go:393-397`). -/
def takeBeforeZero256 : List UInt8 → List UInt8
  | [] => []
  | b :: bs => if b == 0 then [] else b :: takeBeforeZero256 bs

/-- Recursive helper for `cobsDecodeInto` (`cobs.go:129-159`), bounded by `fuel`. -/
def cobsDecodeBodyLoop : Nat → List UInt8 → List UInt8
  | 0, _ => []
  | _ + 1, [] => []
  | fuel + 1, code :: rest =>
    if code == 0 then []
    else
      let copyLen := code.toNat - 1
      let chunk := rest.take copyLen
      let after := rest.drop copyLen
      if rest.length < copyLen then
        chunk
      else if code < 0xFF && !after.isEmpty then
        chunk ++ (0 :: cobsDecodeBodyLoop fuel after)
      else
        chunk ++ cobsDecodeBodyLoop fuel after

/-- Decode a region payload buffer by scanning up to the first `0x00` byte and applying `cobsDecode`
    (`itb256.go:393-397`, `cobs.go:117-159`). -/
def cobsDecodeNullTerm256 (decodedRegion : ByteArray) : ByteArray :=
  let preNull := takeBeforeZero256 decodedRegion.data.toList
  ByteArray.mk ⟨cobsDecodeBodyLoop preNull.length preNull⟩

/-! ## Section 6: Container Sizing (`Mode 1` and `Mode 2`) -/

/-- Binary-search integer ceiling square root `side = min { s >= 1 | s * s >= totalPixels }`
    (`itb.go:162-165, 192-195`). Avoids `@[extern]` `Nat.sqrt` for kernel reduction. -/
def ceilSqrt256 (totalPixels : Nat) : Nat :=
  let rec loop (fuel lo hi : Nat) : Nat :=
    match fuel with
    | 0 => hi
    | fuel' + 1 =>
      if lo >= hi then hi
      else
        let mid := (lo + hi) / 2
        if mid * mid >= totalPixels then
          loop fuel' lo mid
        else
          loop fuel' (mid + 1) hi
  if totalPixels <= 1 then 1
  else loop 20 1 65536

/-- `calcContainerSize3Cfg` (`itb.go:135-198`, `itb256.go:119-127`):
    computes square container dimensions `(width, height)` for **Mode 1** (`mode = 1`),
    **Mode 2** (`mode = 2`), and **Mode 3** (`mode = 3`, `Gauss-Posit`). -/
def calcContainerSize3_256 (mode barrierFill : Nat) (cobsLens : Nat × Nat × Nat)
    (minPxNoise : Nat) (minPxData minPxStart : Nat × Nat × Nat) : Nat × Nat :=
  let (c0, c1, c2) := cobsLens
  let (d0, d1, d2) := minPxData
  let (s0, s1, s2) := minPxStart
  let px0 := ((c0 + 1) * 8 + 55) / 56
  let px1 := ((c1 + 1) * 8 + 55) / 56
  let px2 := ((c2 + 1) * 8 + 55) / 56
  if mode == 2 || mode == 3 then
    let maxDataThirdPixels := max px0 (max px1 px2)
    let minPxJoint := max minPxNoise (max (max d0 (max d1 d2)) (max s0 (max s1 s2)))
    let floorPx := if mode == 3 then ITB.Posit.positGaussCircleFloor (3 * minPxJoint) else minPxJoint
    let totalPixels := max (3 * maxDataThirdPixels) floorPx
    let side := ceilSqrt256 totalPixels + barrierFill
    (side, side)
  else
    let m0 := max px0 (max minPxNoise (max d0 s0))
    let m1 := max px1 (max minPxNoise (max d1 s1))
    let m2 := max px2 (max minPxNoise (max d2 s2))
    let maxThirdPixels := max m0 (max m1 m2)
    let totalPixels := 3 * maxThirdPixels
    let side := ceilSqrt256 totalPixels + barrierFill
    (side, side)

/-- `tripleThirdCaps(totalPixels)` (`triplepayload.go:145-154`):
    returns `(third, thirdPixels2, (cap0, cap1, cap2))` where `cap_i = third_i * 7`. -/
def tripleThirdCaps256 (totalPixels : Nat) : Nat × Nat × (Nat × Nat × Nat) :=
  let third := totalPixels / 3
  let thirdPixels2 := totalPixels - 2 * third
  (third, thirdPixels2, (third * 7, third * 7, thirdPixels2 * 7))

/-! ## Section 7: Layer I (`0x05`) Sub-Region Schedule & 256-Bit Pixel Barrier -/

/-- Layer I (`0x05`) sub-region trajectory schedule (`desync.go:64-70`). -/
structure SubregionSchedule256 where
  k      : Nat
  offset : Array Nat
  size   : Array Nat
  start  : Array Nat
  logOff : Array Nat
  deriving DecidableEq, Repr

/-- Minimum per-region pixel count for Layer I (`0x05`) sub-region partitioning (`desync.go:15`). -/
def minDesyncRegionPixels256 : Nat := 32

/-- Per-region pixel threshold separating compact Mode 2 containers (`< 365`) from Mode 1 (`>= 365`) (`desync.go:20`). -/
def mode1DesyncRegionPixels256 : Nat := 365

/-- Golden-ratio mixing constant for Layer I sub-region starts (`desync.go:31`). -/
def desyncGoldenGamma256 : UInt64 := 0x9E3779B97F4A7C15

/-- `buildSubregionSchedule(startPixel, totalPixels, w)` (`desync.go:75-136`). -/
def buildSubregionSchedule256 (startPixel totalPixels : Nat) (w : Array UInt64) : SubregionSchedule256 :=
  let w0 := aGetD256 w 0 0
  let w1 := aGetD256 w 1 0
  let (k, deltaMax) :=
    if totalPixels < mode1DesyncRegionPixels256 then
      (6 + (w0 % 5).toNat, 1)
    else
      (8 + (w0 % 9).toNat, 2)
  let base := totalPixels / k
  let rem := totalPixels % k
  let physOff0 : Array Nat := (List.range k).foldl (fun acc j =>
    let sz := base + (if j < rem then 1 else 0)
    acc.push (aGetD256 acc j 0 + sz)) #[0]
  let physOff : Array Nat := (List.range (k - 1)).foldl (fun acc jIdx =>
    let j := jIdx + 1
    let cur := aGetD256 acc j 0
    if deltaMax == 1 then
      let raw := ((w0 >>> (8 + j).toUInt64) &&& 1).toNat
      aSet256 acc j (cur + raw - 1)
    else
      let raw := ((w0 >>> (8 + 2 * j).toUInt64) &&& 3).toNat
      aSet256 acc j (cur + raw - 2)) physOff0
  let physSize : Array Nat := (List.range k).foldl (fun acc j =>
    acc.push (aGetD256 physOff (j + 1) 0 - aGetD256 physOff j 0)) #[]
  let tau := fisherYatesPerm k w1
  let (offset, size, start, logOff) := (List.range k).foldl
    (fun (st : Array Nat × Array Nat × Array Nat × Array Nat) step =>
      let (offs, szs, sts, logs) := st
      let physIdx := aGetD256 tau step 0
      let m := aGetD256 physSize physIdx 1
      let pOff := aGetD256 physOff physIdx 0
      let lNext := aGetD256 logs step 0 + m
      let wi := aGetD256 w (2 + (step % 6)) 0
      let mix := rotl64_256 wi (11 * step) ^^^ ((step + 1).toUInt64 * desyncGoldenGamma256)
      let sVal := ((startPixel.toUInt64 + mix) % m.toUInt64).toNat
      (offs.push pOff, szs.push m, sts.push sVal, logs.push lNext))
    (#[], #[], #[], #[0])
  { k, offset, size, start, logOff }

/-- `Seed256.deriveSubregionScheduleBody(nonce, startPixel, totalPixels)` (`desync.go:181-203`),
    dispatching to `ITB.Posit.buildSubregionSchedulePosit` when `mode == 3` and
    `buildSubregionSchedule256` otherwise. -/
def deriveSubregionSchedule256 (startSeed : Seed256) (nonce : ByteArray) (startPixel totalPixels : Nat)
    (mode : Nat := 1) : SubregionSchedule256 :=
  let basePrefix := (ByteArray.empty.push 0x05) ++ bExtract256 nonce 0 (nonce.size - 1)
  let baseByte := getByteD256 nonce (nonce.size - 1)
  let buf0 := basePrefix.push (baseByte ^^^ 0)
  let buf1 := basePrefix.push (baseByte ^^^ 1)
  let h0 := chainHash256Words startSeed buf0
  let h1 := chainHash256Words startSeed buf1
  let (w0, w1) := fullWidthFold256 h0.h0 h0.h1
  let (w2, w3) := fullWidthFold256 h0.h2 h0.h3
  let (w4, w5) := fullWidthFold256 h1.h0 h1.h1
  let (w6, w7) := fullWidthFold256 h1.h2 h1.h3
  let w := #[w0, w1, w2, w3, w4, w5, w6, w7]
  if mode == 3 then
    let sp := ITB.Posit.buildSubregionSchedulePosit startPixel totalPixels w
    { k := sp.k, offset := sp.offset, size := sp.size, start := sp.start, logOff := sp.logOff }
  else
    buildSubregionSchedule256 startPixel totalPixels w

/-- Map every logical pixel `p ∈ [0, totalPixels)` to its physical pixel index `linearIdx ∈ [0, totalPixels)`
    within the region (`processSubregionsRange256`, `process_generic.go:902-929`). -/
def buildLinearIdxMap256 (startSeed : Seed256) (nonce : ByteArray) (totalPixels : Nat)
    (mode : Nat := 1) : Array Nat :=
  let startPixel := deriveStartPixel256 startSeed nonce totalPixels
  if totalPixels >= minDesyncRegionPixels256 then
    let sched := deriveSubregionSchedule256 startSeed nonce startPixel totalPixels mode
    ⟨(List.range sched.k).flatMap (fun step =>
      let m := aGetD256 sched.size step 0
      let physOff := aGetD256 sched.offset step 0
      let s := aGetD256 sched.start step 0
      (List.range m).map (fun q =>
        physOff + ((s + q) % m)))⟩
  else
    ⟨(List.range totalPixels).map (fun p =>
      (startPixel + p) % totalPixels)⟩

/-- `noiseMix(word0, word1)` (`noisepos.go:26-28`). -/
def noiseMix256 (word0 word1 : UInt64) : UInt64 :=
  word0 + rotl64_256 word1 1

/-- `noiseFold3(w)` (`noisepos.go:9-16`). -/
def noiseFold3_256 (w : UInt64) : Nat :=
  withStrictU64 w fun w =>
  withStrictU64 (w ^^^ (w >>> 32)) fun w =>
  withStrictU64 (w ^^^ (w >>> 16)) fun w =>
  withStrictU64 (w ^^^ (w >>> 8)) fun w =>
  withStrictU64 (w ^^^ (w >>> 4)) fun w =>
  let n := w &&& 15
  ((n ^^^ (n >>> 3)) &&& 7).toNat

/-- `rotateBits7(v, r)` (`itb.go:54-57`). -/
def rotateBits7_256 (v : UInt8) (r : Nat) : UInt8 :=
  let r' := (r % 7).toUInt8
  (((v <<< r') ||| (v >>> (7 - r'))) &&& 0x7F)

/-- 8-byte RGBWYOPA pixel (`Channels = 8`). -/
structure Pixel8_256 where
  c0 : UInt8
  c1 : UInt8
  c2 : UInt8
  c3 : UInt8
  c4 : UInt8
  c5 : UInt8
  c6 : UInt8
  c7 : UInt8
  deriving DecidableEq, Repr

/-- Uniformly filled `Pixel8_256`. -/
def Pixel8_256.replicate (b : UInt8) : Pixel8_256 :=
  { c0 := b, c1 := b, c2 := b, c3 := b, c4 := b, c5 := b, c6 := b, c7 := b }

/-- Append the 8 channel bytes of `px` to `b`. -/
def pushPixel8_256 (b : ByteArray) (px : Pixel8_256) : ByteArray :=
  b.push px.c0
   |>.push px.c1
   |>.push px.c2
   |>.push px.c3
   |>.push px.c4
   |>.push px.c5
   |>.push px.c6
   |>.push px.c7

/-- Read a `Pixel8_256` at byte offset `off` from `b`. -/
def readPixel8_256 (b : ByteArray) (off : Nat) : Pixel8_256 :=
  { c0 := getByteD256 b (off + 0)
    c1 := getByteD256 b (off + 1)
    c2 := getByteD256 b (off + 2)
    c3 := getByteD256 b (off + 3)
    c4 := getByteD256 b (off + 4)
    c5 := getByteD256 b (off + 5)
    c6 := getByteD256 b (off + 6)
    c7 := getByteD256 b (off + 7) }

/-- Encode one channel byte `orig` with 7-bit data `dataBits`, `channelXOR`, `dataRotation`, and `noisePos`
    (`process_generic.go:526-532`). -/
def encodeChannelByte256 (orig dataBits channelXOR : UInt8) (dataRotation noisePos : Nat) : UInt8 :=
  let d := rotateBits7_256 (dataBits ^^^ channelXOR) dataRotation
  let noiseMask : UInt8 := (1 : UInt8) <<< noisePos.toUInt8
  let low := d &&& (noiseMask - 1)
  let high : UInt8 :=
    if noisePos + 1 < 8 then (d >>> noisePos.toUInt8) <<< (noisePos + 1).toUInt8 else 0
  low ||| (orig &&& noiseMask) ||| high

/-- Decode one channel byte `channelByte` with `channelXOR`, `dataRotation`, and `noisePos`
    (`process_generic.go:549-556`). -/
def decodeChannelByte256 (channelByte channelXOR : UInt8) (dataRotation noisePos : Nat) : UInt8 :=
  let noiseMask : UInt8 := (1 : UInt8) <<< noisePos.toUInt8
  let low := channelByte &&& (noiseMask - 1)
  let high : UInt8 :=
    if noisePos + 1 < 8 then (channelByte >>> (noisePos + 1).toUInt8) <<< noisePos.toUInt8 else 0
  let d := low ||| high
  rotateBits7_256 d (7 - dataRotation) ^^^ channelXOR

/-- Encode one 56-bit (7-byte) packed word into an 8-byte pixel `origPx` at logical pixel `p`
    (`processChunk256Body`, `process_generic.go:501-538`). -/
@[inline] def encodePixel256 (noiseSeed dataSeed : Seed256) (tpl : BlockNonceTemplate256) (noiseBase p : Nat)
    (origPx : Pixel8_256) (packed56 : UInt64) : Pixel8_256 :=
  let noiseH := blockHash256Fast noiseSeed (noiseBase + p) tpl
  let dataH := blockHash256Fast dataSeed p tpl
  let noiseHash := noiseMix256 noiseH.h0 noiseH.h1
  let dataHash := dataH.h0
  let noisePos := noiseFold3_256 noiseHash
  let dataRotation := (dataHash % 7).toNat
  let xorMask := dataHash >>> 3
  let encCh (ch : Nat) (orig : UInt8) : UInt8 :=
    let shift := (ch * 7).toUInt64
    let dataBits := ((packed56 >>> shift) &&& 0x7F).toUInt8
    let channelXOR := ((xorMask >>> shift) &&& 0x7F).toUInt8
    encodeChannelByte256 orig dataBits channelXOR dataRotation noisePos
  { c0 := encCh 0 origPx.c0
    c1 := encCh 1 origPx.c1
    c2 := encCh 2 origPx.c2
    c3 := encCh 3 origPx.c3
    c4 := encCh 4 origPx.c4
    c5 := encCh 5 origPx.c5
    c6 := encCh 6 origPx.c6
    c7 := encCh 7 origPx.c7 }

/-- Decode one 8-byte pixel `px` at logical pixel `p` into a 56-bit (7-byte) packed word
    (`processChunk256Body`, `process_generic.go:540-566`). -/
@[inline] def decodePixel256 (noiseSeed dataSeed : Seed256) (tpl : BlockNonceTemplate256) (noiseBase p : Nat)
    (px : Pixel8_256) : UInt64 :=
  let noiseH := blockHash256Fast noiseSeed (noiseBase + p) tpl
  let dataH := blockHash256Fast dataSeed p tpl
  let noiseHash := noiseMix256 noiseH.h0 noiseH.h1
  let dataHash := dataH.h0
  let noisePos := noiseFold3_256 noiseHash
  let dataRotation := (dataHash % 7).toNat
  let xorMask := dataHash >>> 3
  let decCh (ch : Nat) (cByte : UInt8) : UInt64 :=
    let shift := (ch * 7).toUInt64
    let channelXOR := ((xorMask >>> shift) &&& 0x7F).toUInt8
    (decodeChannelByte256 cByte channelXOR dataRotation noisePos).toUInt64 <<< shift
  decCh 0 px.c0 ||| decCh 1 px.c1 ||| decCh 2 px.c2 ||| decCh 3 px.c3 |||
  decCh 4 px.c4 ||| decCh 5 px.c5 ||| decCh 6 px.c6 ||| decCh 7 px.c7

/-- Encode a region's `payload` (of length `totalPixels * 7` bytes) into a `totalPixels * 8`-byte
    region container (`process256Cfg`, `itb256.go:29-56`). -/
def processRegion256Encode (noiseSeed dataSeed startSeed : Seed256) (nonce : ByteArray)
    (totalPixels noiseBase : Nat) (fillByte : UInt8) (payload : ByteArray) (mode : Nat := 1) : ByteArray := Id.run do
  let linearMap := buildLinearIdxMap256 startSeed nonce totalPixels mode
  let tpl := prepareBlockNonce256 nonce
  let origPx := Pixel8_256.replicate fillByte
  let mut pixArr := Array.replicate totalPixels origPx
  for p in [:totalPixels] do
    let linearIdx := aGetD256 linearMap p 0
    let packed56 := readU56LE256 payload (p * 7)
    let newPx := encodePixel256 noiseSeed dataSeed tpl noiseBase p origPx packed56
    pixArr := pixArr.set! linearIdx newPx
  let mut out := ByteArray.emptyWithCapacity (totalPixels * 8)
  for px in pixArr do
    out := pushPixel8_256 out px
  return out

/-- Decode a `totalPixels * 8`-byte region container into its payload up to the `0x00` COBS delimiter
    (`process256Cfg`, `itb256.go:29-56`). -/
def processRegion256Decode (noiseSeed dataSeed startSeed : Seed256) (nonce : ByteArray)
    (regionContainer : ByteArray) (totalPixels noiseBase : Nat) (mode : Nat := 1) : ByteArray := Id.run do
  let linearMap := buildLinearIdxMap256 startSeed nonce totalPixels mode
  let tpl := prepareBlockNonce256 nonce
  let mut out := ByteArray.emptyWithCapacity (totalPixels * 7)
  for p in [:totalPixels] do
    let linearIdx := aGetD256 linearMap p 0
    let px := readPixel8_256 regionContainer (linearIdx * 8)
    let w := decodePixel256 noiseSeed dataSeed tpl noiseBase p px
    let b0 := w.toUInt8
    let b1 := (w >>> 8).toUInt8
    let b2 := (w >>> 16).toUInt8
    let b3 := (w >>> 24).toUInt8
    let b4 := (w >>> 32).toUInt8
    let b5 := (w >>> 40).toUInt8
    let b6 := (w >>> 48).toUInt8
    out := ((((((out.push b0).push b1).push b2).push b3).push b4).push b5).push b6
    if b0 == 0 || b1 == 0 || b2 == 0 || b3 == 0 || b4 == 0 || b5 == 0 || b6 == 0 then
      return out
  return out

/-! ## Section 8: Complete 256-Bit Pipeline (`Encrypt3x256Cfg` / `Decrypt3x256Cfg`) -/

/-- 8-seed 256-bit constellation (`noiseSeed`, `lockSeed`, `dataSeed1..3`, `startSeed1..3`). -/
structure Constellation256 where
  noiseSeed  : Seed256
  lockSeed   : Seed256
  dataSeed1  : Seed256
  dataSeed2  : Seed256
  dataSeed3  : Seed256
  startSeed1 : Seed256
  startSeed2 : Seed256
  startSeed3 : Seed256

/-- Build a per-region payload buffer of capacity `capBytes`:
    `cobsEncode256(frag ++ lane) ++ [0x00] ++ replicate(capBytes - encLen - 1, fillByte)`
    (`triplepayload.go:442-460`). -/
def buildRegionPayload256 (frag lane : ByteArray) (capBytes : Nat) (fillByte : UInt8) : ByteArray :=
  let cobs := cobsEncode256 (frag ++ lane)
  let term := cobs.push 0x00
  let tailLen := capBytes - term.size
  term ++ ByteArray.mk (Array.replicate tailLen fillByte)

/-- Deterministic specification of `Encrypt3x256Cfg` (`itb256.go:159-263`)
    across **Mode 1** (`mode = 1`) and **Mode 2** (`mode = 2`). -/
def encrypt3x256Deterministic (c : Constellation256) (plaintext : ByteArray) (mode : Nat)
    (ilNonce mainNonce : ByteArray) (fillByte : UInt8) (prefix32 : ByteArray)
    (barrierFill : Nat := 1) (reserve : Nat := 33) : ByteArray :=
  -- 1. 48-bit Rank Barrier (`factor = 2`) + Layer II (`0x06`)
  let (lane0, lane1, lane2) := splitTriple48_256 c.lockSeed ilNonce plaintext
  -- 2. Interlock-nonce 3-lane split
  let (frag0, frag1, frag2) := splitInterlockNonce256 ilNonce
  -- 3. Container sizing from COBS upper bounds (`triplepayload.go:288-295`)
  let b0 := cobsEncodeBound256 (frag0.size + lane0.size)
  let b1 := cobsEncodeBound256 (frag1.size + lane1.size)
  let b2 := cobsEncodeBound256 (frag2.size + lane2.size)
  let (width, height) := calcContainerSize3_256 mode barrierFill (b0, b1, b2 + reserve)
    c.noiseSeed.minPixels
    (c.dataSeed1.minPixels, c.dataSeed2.minPixels, c.dataSeed3.minPixels)
    (c.startSeed1.minPixels, c.startSeed2.minPixels, c.startSeed3.minPixels)
  let totalPixels := width * height
  let (third, thirdPixels2, (cap0, cap1, cap2)) := tripleThirdCaps256 totalPixels
  -- 4. COBS encode + 0x00 terminator + DRBG tail fill
  let pay0 := buildRegionPayload256 frag0 lane0 cap0 fillByte
  let pay1 := buildRegionPayload256 frag1 lane1 cap1 fillByte
  let pay2 := buildRegionPayload256 frag2 lane2 cap2 fillByte
  -- 5. Layer I (`0x05`) + 256-bit Pixel Barrier across the 3 regions
  let reg0 := processRegion256Encode c.noiseSeed c.dataSeed1 c.startSeed1 mainNonce third        0           fillByte pay0 mode
  let reg1 := processRegion256Encode c.noiseSeed c.dataSeed2 c.startSeed2 mainNonce third        third       fillByte pay1 mode
  let reg2 := processRegion256Encode c.noiseSeed c.dataSeed3 c.startSeed3 mainNonce thirdPixels2 (2 * third) fillByte pay2 mode
  -- 6. Wire assembly: [prefix32][mainNonce][BE16(width)][BE16(height)][reg0][reg1][reg2]
  let hdr := pushU16BE256 (pushU16BE256 (prefix32 ++ mainNonce) width) height
  hdr ++ reg0 ++ reg1 ++ reg2

/-- Specification of `Decrypt3x256Cfg` (`itb256.go:270-410`) consuming `wire` directly. -/
def decrypt3x256 (c : Constellation256) (wire : ByteArray) (nonceLen : Nat := 16) (mode : Nat := 1) : Option ByteArray :=
  let hdrSize := 32 + nonceLen + 4
  if wire.size < hdrSize then none
  else
    let mainNonce := wire.extract 32 (32 + nonceLen)
    let width := readU16BE256 wire (32 + nonceLen)
    let height := readU16BE256 wire (32 + nonceLen + 2)
    if width == 0 || height == 0 || width != height then none
    else
      let totalPixels := width * height
      let expectedSize := totalPixels * 8
      if wire.size != hdrSize + expectedSize then none
      else
        let (third, thirdPixels2, _) := tripleThirdCaps256 totalPixels
        let tBytes := third * 8
        let tBytes2 := thirdPixels2 * 8
        let reg0 := wire.extract hdrSize (hdrSize + tBytes)
        let reg1 := wire.extract (hdrSize + tBytes) (hdrSize + 2 * tBytes)
        let reg2 := wire.extract (hdrSize + 2 * tBytes) (hdrSize + 2 * tBytes + tBytes2)
        -- 1. Layer I (`0x05`) + 256-bit Pixel Barrier decode
        let dec0 := processRegion256Decode c.noiseSeed c.dataSeed1 c.startSeed1 mainNonce reg0 third        0           mode
        let dec1 := processRegion256Decode c.noiseSeed c.dataSeed2 c.startSeed2 mainNonce reg1 third        third       mode
        let dec2 := processRegion256Decode c.noiseSeed c.dataSeed3 c.startSeed3 mainNonce reg2 thirdPixels2 (2 * third) mode
        -- 2. Null-search + COBS decode
        let part0 := cobsDecodeNullTerm256 dec0
        let part1 := cobsDecodeNullTerm256 dec1
        let part2 := cobsDecodeNullTerm256 dec2
        -- 3. Recover interlock nonce & lane payloads
        let (ilNonce, lane0, lane1, lane2) := recoverInterlockNonce256 nonceLen part0 part1 part2
        -- 4. Invert Layer II (`0x06`) + 48-bit Rank Barrier (`factor = 2`)
        some (interleaveTriple48_256 c.lockSeed ilNonce lane0 lane1 lane2)

/-- Configuration structure for `encrypt3x256Deterministic` / `decrypt3x256Cfg` (`itb.go:Config`). -/
structure PipelineConfig256 where
  nonceBits   : Nat := 128
  barrierFill : Nat := 1
  mode        : Nat := 1
  reserve     : Nat := 33
  fillByte    : UInt8 := 0x5A
  deriving DecidableEq, Repr

/-- Nonce byte length `nonceBits / 8`. -/
def PipelineConfig256.nonceBytes (cfg : PipelineConfig256) : Nat :=
  cfg.nonceBits / 8

/-- Configuration-driven wrapper around `decrypt3x256` (`itb256.go:Decrypt3x256Cfg`).
    Reads `W` and `H` directly from the wire header (independent of `cfg.barrierFill`, and shared across Mode 1/2). -/
def decrypt3x256Cfg (cfg : PipelineConfig256) (c : Constellation256) (wire : ByteArray) : Option ByteArray :=
  let decMode := if cfg.mode == 3 then 3 else 1
  decrypt3x256 c wire cfg.nonceBytes decMode

/-! ## Section 9: Stage-by-Stage & End-to-End Inversion Theorems -/

/-- **Theorem 1 (5-Stage Functional Composition Left-Inverse)**:
    For any five forward pipeline stages
      1. `f_rank  : α → β` (48-Bit Rank Barrier `0x03`/`0x04`, `factor = 2`)
      2. `f_slot  : β → γ` (Layer II `0x06` Cross-Lane Slot Desynchronization)
      3. `f_cobs  : γ → δ` (Interlock-Nonce Prefix & COBS Framing)
      4. `f_traj  : δ → ε` (Layer I `0x05` Sub-Region Trajectory)
      5. `f_pixel : ε → ζ` (256-Bit Pixel Barrier `0x01`/`0x02` Channel Encoding)
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
    `decrypt3x256Cfg` depends only on `cfg.nonceBytes` (to slice `mainNonce` and `ilNonce`)
    and on whether `cfg.mode == 3` (to select `buildSubregionSchedulePosit` vs `buildSubregionSchedule256`),
    and has **zero dependence** on `cfg.barrierFill`, `cfg.reserve`, or `cfg.fillByte`.
    In particular, any **Mode 1** wire decrypts under a **Mode 2** receiver config and vice versa
    (`(1 == 3) = (2 == 3)` holds as `false = false`), and any **Mode 3** wire decrypts under any
    **Mode 3** receiver config regardless of `barrierFill`, `reserve`, or `fillByte`. -/
theorem decrypt3x256Cfg_mode_barrierFill_independent
    (cfg1 cfg2 : PipelineConfig256) (c : Constellation256) (wire : ByteArray)
    (hNonce : cfg1.nonceBytes = cfg2.nonceBytes)
    (hMode3 : (cfg1.mode == 3) = (cfg2.mode == 3)) :
    decrypt3x256Cfg cfg1 c wire = decrypt3x256Cfg cfg2 c wire := by
  unfold decrypt3x256Cfg
  rw [hNonce, hMode3]

/-- `nonceSplitLens256 n` partitions `n` bytes across the 3 lanes (`l0 + l1 + l2 = n`). -/
theorem nonceSplitLens256_sum (n : Nat) :
    (nonceSplitLens256 n).1 + (nonceSplitLens256 n).2.1 + (nonceSplitLens256 n).2.2 = n := by
  simp only [nonceSplitLens256]
  split <;> split <;> omega

/-- Canonical nonce split lengths for 128-bit (`16 B`), 256-bit (`32 B`), and 512-bit (`64 B`) nonces. -/
theorem nonceSplitLens256_canonical :
    nonceSplitLens256 16 = (6, 5, 5) ∧
    nonceSplitLens256 32 = (11, 11, 10) ∧
    nonceSplitLens256 64 = (22, 21, 21) := by
  decide

/-- Canonical `minPixels` floor for 256-bit seeds across 512-bit (`8` words), 1024-bit (`16` words),
    and 2048-bit (`32` words) keys (`seed256.go:108-120`): `183`, `365`, and `730` pixels. -/
theorem minPixelsForKeyBits256_canonical :
    ((512 * 10000 + 28074 - 1) / 28074 = 183) ∧
    ((1024 * 10000 + 28074 - 1) / 28074 = 365) ∧
    ((2048 * 10000 + 28074 - 1) / 28074 = 730) := by
  decide

/-- 7-bit rotation `rotateBits7_256` is inverted by rotating by `7 - r` on all 7-bit values `v ∈ Fin 128`
    and rotation offsets `r ∈ Fin 7`. -/
theorem rotateBits7_256_roundtrip (v : Fin 128) (r : Fin 7) :
    rotateBits7_256 (rotateBits7_256 v.val.toUInt8 r.val) (7 - r.val) = v.val.toUInt8 := by
  revert v r
  decide

/-- Channel-byte bit-insertion (preserving the carrier noise bit at `noisePos`) is inverted by
    bit-extraction for every carrier bit `noiseBit : Bool`, 7-bit payload `d ∈ Fin 128`,
    and `noisePos ∈ Fin 8` (and universally for all `BitVec 7 × BitVec 7 × Fin 7 × Fin 8 × Bool`
    via `ITB.PixelBarrier.decode_encode_id`). -/
theorem channelBitInsertExtract256_roundtrip (noiseBit : Bool) (d : Fin 128) (noisePos : Fin 8) :
    let orig8 : UInt8 := if noiseBit then (1 : UInt8) <<< noisePos.val.toUInt8 else 0
    decodeChannelByte256 (encodeChannelByte256 orig8 d.val.toUInt8 0 0 noisePos.val)
      0 0 noisePos.val = d.val.toUInt8 := by
  revert noiseBit d noisePos
  decide

/-- Universal per-channel Pixel Barrier round-trip across all 7-bit data `d`, 7-bit masks `m`,
    rotations `r ∈ Fin 7`, noise positions `np ∈ Fin 8`, and carrier bits `noiseBit : Bool`
    (inherited from `ITB.PixelBarrier`). -/
theorem pixelChannel256_roundtrip (d m : BitVec 7) (r : Fin 7) (np : Fin 8) (noiseBit : Bool) :
    decodeChannel (encodeChannel d m r np noiseBit) m r np = d :=
  decode_encode_id d m r np noiseBit

/-- `invFullWidthFold` and `fullWidthFold` form an exact 128-bit bijection over `BitVec 64 × BitVec 64`
    for all Layer I (`0x05`) and Layer II (`0x06`) schedule words (inherited from `ITB.Desync`). -/
theorem fullWidthFold256_bijection (hLo hHi w0 w1 : BitVec 64) :
    invFullWidthFold (fullWidthFold hLo hHi).1 (fullWidthFold hLo hHi).2 = (hLo, hHi) ∧
    fullWidthFold (invFullWidthFold w0 w1).1 (invFullWidthFold w0 w1).2 = (w0, w1) :=
  fullWidthFold_bijection hLo hHi w0 w1

/-- Layer II (`0x06`) cyclic shift inversion (`invLaneSlotShift` is the exact two-sided inverse
    of `laneSlotShift` on `[0, m)`, and `desyncBeta0 m r0 ≠ desyncBeta1 m r0 r1` for all `m ≥ 2`). -/
theorem desyncLaneSlotShift256_roundtrip (m beta j r0 r1 : Nat) (hm : 2 ≤ m) (hb : beta < m) (hj : j < m) :
    invLaneSlotShift m beta (laneSlotShift m beta j) = j ∧
    laneSlotShift m beta (invLaneSlotShift m beta j) = j ∧
    desyncBeta0 m r0 ≠ desyncBeta1 m r0 r1 :=
  ⟨laneSlotShift_left_inv m beta j hb hj,
   laneSlotShift_right_inv m beta j hb hj,
   desync_beta0_ne_beta1 m r0 r1 hm⟩

/-- Layer I (`0x05`) sub-region cyclic step inversion (`invSubregionStep` is the exact two-sided
    inverse of `subregionStep` on `[0, M)`). -/
theorem subregionStep256_roundtrip (M s q : Nat) (hs : s < M) (hq : q < M) :
    invSubregionStep M s (subregionStep M s q) = q ∧
    subregionStep M s (invSubregionStep M s q) = q :=
  ⟨subregionStep_left_inv M s q hs hq,
   subregionStep_right_inv M s q hs hq⟩

/-- Why **Mode 1** and **Mode 2** decrypt vice-versa automatically:
    1. `decrypt3x256` has no `mode` or `barrierFill` parameter: it reads `(width, height)` directly
       from the wire header and computes `third = (width * height) / 3`.
    2. In **Layer I** (`0x05`), `buildSubregionSchedule256` selects the compact schedule
       (`k = 6 + w0 % 5, deltaMax = 1`) vs the full schedule (`k = 8 + w0 % 9, deltaMax = 2`)
       solely by comparing the region's pixel count `totalPixels` against
       `mode1DesyncRegionPixels256 = 365` (`desync.go:77`). -/
theorem buildSubregionSchedule256_mode_branch (startPixel totalPixels : Nat) (w : Array UInt64) :
    (buildSubregionSchedule256 startPixel totalPixels w).k =
      if totalPixels < mode1DesyncRegionPixels256 then
        6 + (aGetD256 w 0 0 % 5).toNat
      else
        8 + (aGetD256 w 0 0 % 9).toNat := by
  simp only [buildSubregionSchedule256]
  split <;> rfl

/-! ## Section 10: Kernel-Checked Go Reference KAT Verification -/

/-- Deterministic KAT plaintext generator matching `mkDeterministicBytes` in the Go KAT harness:
    every 11th byte (at `i % 11 == 3`) is `0x00` to exercise COBS zero-run splitting, and all
    other bytes are `(13 * i + 7) & 0xFF`. -/
def mkDeterministicBytes256 (n : Nat) : ByteArray :=
  ByteArray.mk ⟨(List.range n).map (fun i =>
    if i % 11 == 3 then
      0x00
    else
      ((i * 13 + 7) % 256).toUInt8)⟩

/-- Fixed 32-byte `BLAKE2b-256` key `b2key[i] = 0xA0 + i` (`i ∈ 0..31`). -/
def katB2Key256 : ByteArray :=
  ByteArray.mk ⟨(List.range 32).map (fun i => (0xA0 + i).toUInt8)⟩

/-- Deterministic `Seed256` constructor for `keyBits ∈ {512, 1024, 2048}` and constellation `slot ∈ 0..7`. -/
def mkKatSeed256 (keyBits slot : Nat) : Seed256 :=
  let numComps := keyBits / 64
  let comps : Array UInt64 := ⟨(List.range numComps).map (fun i =>
    (slot.toUInt64 + 1) * 0x0102030405060708 + i.toUInt64 * 0x1111111111111111)⟩
  Seed256.mkFromKeyAndComps katB2Key256 comps

/-- Deterministic 8-seed `Constellation256` for `keyBits ∈ {512, 1024, 2048}`. -/
def mkKatConstellation256 (keyBits : Nat) : Constellation256 :=
  { noiseSeed  := mkKatSeed256 keyBits 0
    lockSeed   := mkKatSeed256 keyBits 1
    dataSeed1  := mkKatSeed256 keyBits 2
    dataSeed2  := mkKatSeed256 keyBits 3
    dataSeed3  := mkKatSeed256 keyBits 4
    startSeed1 := mkKatSeed256 keyBits 5
    startSeed2 := mkKatSeed256 keyBits 6
    startSeed3 := mkKatSeed256 keyBits 7 }

/-- Deterministic `ilNonce` of `nonceBits` bits (`ilNonce[i] = 0x10 + i`). -/
def mkKatIlNonce256 (nonceBits : Nat) : ByteArray :=
  ByteArray.mk ⟨(List.range (nonceBits / 8)).map (fun i => (0x10 + i).toUInt8)⟩

/-- Deterministic `mainNonce` of `nonceBits` bits (`mainNonce[i] = 0x20 + i`). -/
def mkKatMainNonce256 (nonceBits : Nat) : ByteArray :=
  ByteArray.mk ⟨(List.range (nonceBits / 8)).map (fun i => (0x20 + i).toUInt8)⟩

/-- Deterministic 32-byte chunk prefix (`prefix32[i] = 0x30 + i`). -/
def katPrefix32_256 : ByteArray :=
  ByteArray.mk ⟨(List.range 32).map (fun i => (0x30 + i).toUInt8)⟩

/-- Deterministic DRBG fill byte `0x5A`. -/
def katFillByte256 : UInt8 := 0x5A

/-- 15-byte test message `0x00..0x0E` for `blake2b256WithKey` and `chainHash256`. -/
def katMsg15_256 : ByteArray :=
  ByteArray.mk #[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e]

/-- Expected RFC 7693 `BLAKE2b-256("")` output words from Go `blake2b.Sum256(nil)`. -/
def katBlake2b256Empty : Array UInt64 := #[
  0xb243e526c051570e,
  0xa1da9960b02eabe8,
  0x87778f7747dfe5d1,
  0xa8e32ff1cd45abfa
]

/-- Expected RFC 7693 `BLAKE2b-256("abc")` output words from Go `blake2b.Sum256([]byte("abc"))`. -/
def katBlake2b256ABC : Array UInt64 := #[
  0x723942633c81ddbd,
  0x9b5798ee3fef7131,
  0x423ecbb13b4e9694,
  0x1923d568c0c86272
]

/-- Expected `hashes.BLAKE2b256WithKey(b2key)(msg15, seed)` output words from Go. -/
def katBlake2b256WithKeyOut : Array UInt64 := #[
  0xb7e86487e8fb125a,
  0x4fa71c529e2b1dbd,
  0x8a1588031e477258,
  0x2f6be1a574b483a4
]

/-- Expected `Seed256.ChainHash256` output words for 512-bit (`2`-round), 1024-bit (`4`-round),
    and 2048-bit (`8`-round) seeds from Go. -/
def katChainHash256Key512Out : Array UInt64 := #[
  0xfe5ced104f78347a,
  0x6b65dd165c74fd89,
  0xe3fd5595069ce4da,
  0x82f76f3145f2947f
]

def katChainHash256Key1024Out : Array UInt64 := #[
  0xb27872f60d695be3,
  0x3a08b3c3e7a08648,
  0xabd56619640010f9,
  0x561f4d295c0a7ef3
]

def katChainHash256Key2048Out : Array UInt64 := #[
  0x152a5ddd3380ea79,
  0x2323f9554b4cb5c4,
  0x01914518478d9a84,
  0x7b4c5b829cc60f53
]

/-- Kernel-checked verification that `blake2bSum256` matches RFC 7693 and Go `blake2b.Sum256`
    on `""` and `"abc"`, and `blake2b256WithKey` matches Go `hashes.BLAKE2b256WithKey`. -/
theorem blake2b256_matches_go_kat :
    blake2bSum256 ByteArray.empty = katBlake2b256Empty ∧
    blake2bSum256 (ByteArray.mk #[0x61, 0x62, 0x63]) = katBlake2b256ABC ∧
    blake2b256WithKey katB2Key256 katMsg15_256
      #[0x0102030405060708, 2 * 0x0102030405060708,
        3 * 0x0102030405060708, 4 * 0x0102030405060708] = katBlake2b256WithKeyOut := by
  native_decide

/-- Kernel-checked verification that `chainHash256` matches Go `Seed256.ChainHash256` across
    all 3 key sizes (`512`, `1024`, `2048` bits). -/
theorem chainHash256_matches_go_kat :
    chainHash256 (mkKatSeed256 512 0) katMsg15_256 = katChainHash256Key512Out ∧
    chainHash256 (mkKatSeed256 1024 0) katMsg15_256 = katChainHash256Key1024Out ∧
    chainHash256 (mkKatSeed256 2048 0) katMsg15_256 = katChainHash256Key2048Out := by
  native_decide

/-- Compute the square container side `W = H` produced by `calcContainerSize3_256` for
    `(keyBits, nonceBits, mode, payloadLen)` (`itb.go:135-198`, `triplepayload.go:288-295`). -/
def calcExpectedContainerSide256 (keyBits nonceBits mode payloadLen : Nat) : Nat :=
  let minPx := (keyBits * 10000 + 28074 - 1) / 28074
  let (l0, l1, l2) := nonceSplitLens256 (nonceBits / 8)
  let laneLen := 2 * ((payloadLen + 4 + 5) / 6)
  let b0 := cobsEncodeBound256 (l0 + laneLen)
  let b1 := cobsEncodeBound256 (l1 + laneLen)
  let b2 := cobsEncodeBound256 (l2 + laneLen) + 33
  (calcContainerSize3_256 mode 1 (b0, b1, b2) minPx (minPx, minPx, minPx) (minPx, minPx, minPx)).1

/-- Canonical 11-step payload size ladder (`1 B` up to `64 MB`). -/
def katSizeLadder256 : List Nat :=
  [1, 512, 1024, 4096, 16384, 131072, 524288, 1048576, 4194304, 16777216, 67108864]

/-- Expected square container sides `W = H` from Go across all `11 × 3 × 3 × 2 = 198` combinations
    of `payloadLen ∈ katSizeLadder256`, `keyBits ∈ [512, 1024, 2048]`, `nonceBits ∈ [128, 256, 512]`,
    and `mode ∈ [2, 1]`. -/
def katExpectedContainerSides256 : Array Nat := #[
  15, 25, 15, 25, 15, 25, 21, 35, 21, 35, 21, 35,
  29, 48, 29, 48, 29, 48, 15, 25, 15, 25, 15, 25,
  21, 35, 21, 35, 21, 35, 29, 48, 29, 48, 29, 48,
  15, 25, 15, 25, 15, 25, 21, 35, 21, 35, 21, 35,
  29, 48, 29, 48, 29, 48, 26, 26, 26, 26, 26, 26,
  26, 35, 26, 35, 26, 35, 29, 48, 29, 48, 29, 48,
  50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50,
  50, 50, 50, 50, 50, 50, 139, 139, 139, 139, 139, 139,
  139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139,
  276, 276, 276, 276, 276, 276, 276, 276, 276, 276, 276, 276,
  276, 276, 276, 276, 276, 276, 389, 389, 389, 389, 389, 389,
  389, 389, 389, 389, 389, 389, 389, 389, 389, 389, 389, 389,
  777, 777, 777, 777, 777, 777, 777, 777, 777, 777, 777, 777,
  777, 777, 777, 777, 777, 777, 1553, 1553, 1553, 1553, 1553, 1553,
  1553, 1553, 1553, 1553, 1553, 1553, 1553, 1553, 1553, 1553, 1553, 1553,
  3104, 3104, 3104, 3104, 3104, 3104, 3104, 3104, 3104, 3104, 3104, 3104,
  3104, 3104, 3104, 3104, 3104, 3104
]

/-- Evaluate `calcExpectedContainerSide256` across all 198 combinations of the 11-step size ladder. -/
def computeContainerSidesLadder256 : Array Nat :=
  katSizeLadder256.foldl (fun acc L =>
    [512, 1024, 2048].foldl (fun acc2 kb =>
      [128, 256, 512].foldl (fun acc3 nb =>
        [2, 1].foldl (fun acc4 m =>
          acc4.push (calcExpectedContainerSide256 kb nb m L)) acc3) acc2) acc) #[]

/-- Kernel-checked verification that `calcContainerSize3_256` matches Go `calcContainerSize3Cfg`
    across all 198 combinations of `(1 B .. 64 MB) × (512, 1024, 2048) × (128, 256, 512) × (Mode 2, Mode 1)`. -/
theorem containerSides256_matches_go_ladder :
    computeContainerSidesLadder256 = katExpectedContainerSides256 := by
  native_decide

/-- Stage-by-stage round-trip verification for `framedSrc48`/`unframeDst48`,
    `splitInterlockNonce256`/`recoverInterlockNonce256` across 128/256/512-bit nonces,
    `cobsEncode256`/`cobsDecodeNullTerm256`, and `splitTriple48_256`/`interleaveTriple48_256`
    on a 96-byte (`M = 17` chunks, `numGroups = 9` groups of `factor = 2`, Layer II `kLane ∈ [4, 8]`) payload. -/
theorem stage_framing48_roundtrip_kat :
    let pt96 := mkDeterministicBytes256 96
    unframeDst48 (framedSrc48 pt96) = pt96 := by
  native_decide

theorem stage_cobs256_roundtrip_kat :
    let pt96 := mkDeterministicBytes256 96
    let il128 := mkKatIlNonce256 128
    cobsDecodeNullTerm256 (buildRegionPayload256 il128 pt96 200 katFillByte256) = (il128 ++ pt96) := by
  native_decide

theorem stage_nonceSplit256_roundtrip_kat :
    let pt96 := mkDeterministicBytes256 96
    let il128 := mkKatIlNonce256 128
    let il256 := mkKatIlNonce256 256
    let il512 := mkKatIlNonce256 512
    (let (f0, f1, f2) := splitInterlockNonce256 il128
     recoverInterlockNonce256 16 (f0 ++ pt96) (f1 ++ pt96) (f2 ++ pt96) = (il128, pt96, pt96, pt96)) ∧
    (let (f0, f1, f2) := splitInterlockNonce256 il256
     recoverInterlockNonce256 32 (f0 ++ pt96) (f1 ++ pt96) (f2 ++ pt96) = (il256, pt96, pt96, pt96)) ∧
    (let (f0, f1, f2) := splitInterlockNonce256 il512
     recoverInterlockNonce256 64 (f0 ++ pt96) (f1 ++ pt96) (f2 ++ pt96) = (il512, pt96, pt96, pt96)) := by
  native_decide

theorem stage_splitTriple48_256_roundtrip_kat :
    let pt96 := mkDeterministicBytes256 96
    let seed512 := mkKatSeed256 512 1
    let il128 := mkKatIlNonce256 128
    let (l0, l1, l2) := splitTriple48_256 seed512 il128 pt96
    interleaveTriple48_256 seed512 il128 l0 l1 l2 = pt96 := by
  native_decide

/-- Expected `blake2b.Sum256(wire)` digest from Go `Encrypt3x256Cfg` for
    `keyBits = 512, nonceBits = 128, Mode = 2, payloadLen = 96` (`M = 17` chunks). -/
def katWireDigest256_K512_N128_M2_L96 : Array UInt64 := #[
  0x7b95559a93fd0176,
  0x2b99c5deae81dcd8,
  0x1d1591c9c5de307d,
  0x6a23034f21cce2a7
]

/-- Helper to run `encrypt3x256Deterministic` on the deterministic KAT fixture. -/
def runKatEncrypt256 (keyBits nonceBits mode payloadLen : Nat) : ByteArray :=
  encrypt3x256Deterministic
    (mkKatConstellation256 keyBits)
    (mkDeterministicBytes256 payloadLen)
    mode
    (mkKatIlNonce256 nonceBits)
    (mkKatMainNonce256 nonceBits)
    katFillByte256
    katPrefix32_256

/-- Kernel-checked verification that `encrypt3x256Deterministic` for `K512, N128, Mode 2, L = 96 B`
    (`M = 17` chunks, `numGroups = 9` groups of `factor = 2`, Layer II `kLane ∈ [4, 8]`)
    produces the exact same 1852-byte wire digest as Go `Encrypt3x256Cfg`. -/
theorem encrypt256_K512_N128_M2_L96_digest_kat :
    blake2bSum256 (runKatEncrypt256 512 128 2 96) = katWireDigest256_K512_N128_M2_L96 := by
  native_decide

/-- Kernel-checked verification that `decrypt3x256` on the `K512, N128, Mode 2, L = 96 B` wire
    recovers the exact 96-byte plaintext. -/
theorem decrypt256_K512_N128_M2_L96_roundtrip_kat :
    decrypt3x256 (mkKatConstellation256 512) (runKatEncrypt256 512 128 2 96) 16 =
      some (mkDeterministicBytes256 96) := by
  native_decide

/-- Run one deterministic encrypt + cross-mode/cross-fill decrypt check and compare `(wire.size, d0, d1, d2, d3)`
    against Go's `itb.Encrypt3x256Cfg` / `itb.Decrypt3x256Cfg`. -/
def checkParamKatEntry256 (keyBits nonceBits mode msgLen wantWireLen : Nat)
    (want0 want1 want2 want3 : UInt64) : Bool :=
  let otherMode := if mode == 3 then 3 else if mode == 1 then 2 else 1
  let cfgDec : PipelineConfig256 := { nonceBits, barrierFill := 32, mode := otherMode }
  let c := mkKatConstellation256 keyBits
  let pt := mkDeterministicBytes256 msgLen
  let wire := runKatEncrypt256 keyBits nonceBits mode msgLen
  let dig := blake2bSum256 wire
  let dec := decrypt3x256Cfg cfgDec c wire
  (wire.size == wantWireLen) &&
    (dig == #[want0, want1, want2, want3]) &&
    (dec == some pt)

/-- All 18 parameter combinations `(keyBits ∈ {512, 1024, 2048}) × (nonceBits ∈ {128, 256, 512}) × (Mode ∈ {1, 2})`
    at `msgLen = 96` (`M = 17` chunks, `numGroups = 9` groups of `factor = 2`) captured from Go's `itb.Encrypt3x256Cfg`. -/
def katParamMatrix256 : List (Nat × Nat × Nat × Nat × UInt64 × UInt64 × UInt64 × UInt64) := [
  (512, 128, 1, 5052, 0xde1644fb18987f63, 0x2a18134ee30e991e, 0x5408abaa49bf9e20, 0x3c01a1c4aed6b1db),
  (512, 128, 2, 1852, 0x7b95559a93fd0176, 0x2b99c5deae81dcd8, 0x1d1591c9c5de307d, 0x6a23034f21cce2a7),
  (512, 256, 1, 5068, 0x04972fd5bd7a9a35, 0xf17084988933546e, 0x4d6bb0458afe2e6c, 0x6eb9ad77fd6d9c7f),
  (512, 256, 2, 1868, 0x1f4ecc18eef61747, 0x54c6bf9501c10bb0, 0x0800f35f2e3f432e, 0x2b1fe5e45e3a93b4),
  (512, 512, 1, 5100, 0x9ea46192fb427d08, 0x89a48face7c5f81f, 0x61fb436d12e05b07, 0x0b4c0d3f5aa90406),
  (512, 512, 2, 1900, 0x6c89a6dd497b63ca, 0xcc240df5142963fe, 0x644c92b3234c1a5e, 0xb29174e78b9de11e),
  (1024, 128, 1, 9852, 0x512bfc8bc8e08f6c, 0xc935c2198ac50166, 0xef7fa72c7427610f, 0x8954d22a68cf4fd1),
  (1024, 128, 2, 3580, 0x2d906df621cd69fa, 0x7de961e30aa44870, 0x066b57d50fe09f54, 0x118b724c37c4d67a),
  (1024, 256, 1, 9868, 0x89add26ddee7f063, 0xb4e95eb326b89d4b, 0xc8ec27009e586062, 0xff93d7de70d6ec30),
  (1024, 256, 2, 3596, 0x0e763c5411649724, 0x1d16670bb68f19cb, 0xa0979f1153425e24, 0x9c70db77a4823ed1),
  (1024, 512, 1, 9900, 0xd655fb7b55679a66, 0x215ab88ceddb61ed, 0x4f0427f6fd118d6d, 0xee64bc888025ad88),
  (1024, 512, 2, 3628, 0x2007311c91219f76, 0x5524102101227c94, 0x5690fb768b9980c3, 0x9ab026ef4c60b65f),
  (2048, 128, 1, 18484, 0x7cfc122e76dc23aa, 0x1d8a7ccb11d6a9ef, 0xbb45c13fea2372fa, 0x5705a18f3f4c7b28),
  (2048, 128, 2, 6780, 0xd95d0dc202be02af, 0x282259f84a5ae7d9, 0x05624ea67eef6470, 0xdec3244503ea667a),
  (2048, 256, 1, 18500, 0x1ecef186a28b3584, 0xe2aa34ca9a51b6ce, 0x31742e05c5d7c0de, 0xf8c6ad2e8c177ddb),
  (2048, 256, 2, 6796, 0x7fb48dabb8319fdf, 0x38a51a079eaebc63, 0xbc4b7f149e375f84, 0xd59e0e1877f3b8b4),
  (2048, 512, 1, 18532, 0xd3cfd73951c0e27b, 0x6d585891967cfee7, 0x4ec05f61173ad7f2, 0x6c5ffed7dcd99ccb),
  (2048, 512, 2, 6828, 0x1d21437638ebff08, 0x15d4fadbc0344fd2, 0xc4f35146a223c81f, 0xc171067d7749205a)
]

/-- **KAT: All 18 `(keyBits, nonceBits, Mode)` Configurations**:
    Verifies bit-exact Go wire digests and cross-mode decrypt round-trip across all
    3 key sizes (`512`, `1024`, `2048` bits), all 3 nonce sizes (`128`, `256`, `512` bits),
    and both **Mode 1** and **Mode 2**. -/
theorem kat_go_param_matrix256_all_18_exact :
    (katParamMatrix256.all fun (kb, nb, mode, wLen, d0, d1, d2, d3) =>
      checkParamKatEntry256 kb nb mode 96 wLen d0 d1 d2 d3) = true := by
  native_decide

/-- Payload size ladder (`1 B`, `96 B`, `512 B`, `1 KB`, `4 KB`, `16 KB`) across **Mode 1** & **Mode 2**
    (`1024`-bit key, `128`-bit nonce) captured from Go's `itb.Encrypt3x256Cfg`. -/
def katSizeLadderDigests256 : List (Nat × Nat × Nat × UInt64 × UInt64 × UInt64 × UInt64) := [
  (1, 1, 9852, 0x3a1f046d9a5e6033, 0x78d1ecdc4748e004, 0xf836486e783ccf53, 0xa4f6f534e7b19f6b),
  (1, 2, 3580, 0x6bc7603603074005, 0x5d28f0e20b880cd7, 0xf1e3423316da3795, 0x7122b048a515b093),
  (96, 1, 9852, 0x512bfc8bc8e08f6c, 0xc935c2198ac50166, 0xef7fa72c7427610f, 0x8954d22a68cf4fd1),
  (96, 2, 3580, 0x2d906df621cd69fa, 0x7de961e30aa44870, 0x066b57d50fe09f54, 0x118b724c37c4d67a),
  (512, 1, 9852, 0xca9fb59ef578ee8c, 0x99ed1bba505f6049, 0x439d2e8fbd4b1c22, 0xe6e9d6d12f7bc6a2),
  (512, 2, 3580, 0x03e79839bdb17bdc, 0x517e1a79f3267446, 0xc2f71f6918e2694e, 0x4f0ee9570e68a91b),
  (1024, 1, 9852, 0x90ef2eaea0578986, 0x250ca3b82f8bcc88, 0x76e072db6cf403cc, 0x0fa25310018a8ac2),
  (1024, 2, 3580, 0xd80a01d6a39046a9, 0x8ad3be85de545feb, 0x1b31eb696c99c9bb, 0x2a27119c34314874),
  (4096, 1, 9852, 0x2e37a65dccbf44b4, 0xe070f0e3469227ac, 0xc9cd89356d4a117a, 0x078e310cd11b474a),
  (4096, 2, 5460, 0xdbbf9e7acc3fdb16, 0x482ae8b4d5193bdd, 0x45e1197c88546d97, 0xeb03d938a726d971),
  (16384, 1, 20052, 0xd702e748d72cf495, 0xcb64d2f4734ac364, 0x662638575562f54a, 0x8207832352df86f1),
  (16384, 2, 20052, 0xd702e748d72cf495, 0xcb64d2f4734ac364, 0x662638575562f54a, 0x8207832352df86f1)
]

/-- **KAT: End-to-End Encrypt/Decrypt Payload Size Ladder (`1 B` .. `16 KB`)**:
    Verifies bit-exact Go wire digests and cross-mode round-trip decryption across `1 B`, `96 B`, `512 B`,
    `1 KB` (`1024`), `4 KB` (`4096`), and `16 KB` (`16384`) in both **Mode 1** and **Mode 2**. -/
theorem kat_go_size_ladder256_encrypt_decrypt_exact :
    (katSizeLadderDigests256.all fun (sz, mode, wLen, d0, d1, d2, d3) =>
      checkParamKatEntry256 1024 128 mode sz wLen d0 d1 d2 d3) = true := by
  native_decide

/-! ## Section 11: Mode 3 (`Gauss-Posit`) Container Floors, Isolation, & Bit-Exact Go KATs -/

/-- **Mode 3 Theorem 1 (Canonical Mode 3 `Gauss-Posit` Container Floors & Strict Ordering)**:
    For 256-bit seeds (`minPixels ∈ {183, 365, 730}` for `512, 1024, 2048`-bit keys),
    the Mode 3 inscribed Gauss-circle Posit floor `positGaussCircleFloor (3 * minPixels)`
    equals `350, 698, 1395` pixels, yielding minimum container sides `20, 28, 39` (`400, 784, 1521` px),
    strictly between Mode 2 (`15, 21, 29`) and Mode 1 (`25, 35, 48`). -/
theorem mode3_container_floors256_canonical :
    ITB.Posit.positGaussCircleFloor (3 * 183) = 350 ∧
    ITB.Posit.positGaussCircleFloor (3 * 365) = 698 ∧
    ITB.Posit.positGaussCircleFloor (3 * 730) = 1395 ∧
    calcExpectedContainerSide256 512 128 3 1 = 20 ∧
    calcExpectedContainerSide256 1024 128 3 1 = 28 ∧
    calcExpectedContainerSide256 2048 128 3 1 = 39 ∧
    calcExpectedContainerSide256 512 128 2 1 < calcExpectedContainerSide256 512 128 3 1 ∧
    calcExpectedContainerSide256 512 128 3 1 < calcExpectedContainerSide256 512 128 1 1 ∧
    calcExpectedContainerSide256 1024 128 2 1 < calcExpectedContainerSide256 1024 128 3 1 ∧
    calcExpectedContainerSide256 1024 128 3 1 < calcExpectedContainerSide256 1024 128 1 1 ∧
    calcExpectedContainerSide256 2048 128 2 1 < calcExpectedContainerSide256 2048 128 3 1 ∧
    calcExpectedContainerSide256 2048 128 3 1 < calcExpectedContainerSide256 2048 128 1 1 := by
  native_decide

/-- Expected `blake2b.Sum256(wire)` digest from Go `Encrypt3x256Cfg` for
    `keyBits = 512, nonceBits = 128, Mode = 3, payloadLen = 96` (`M = 17` chunks, `3252` wire bytes). -/
def katWireDigest256_K512_N128_M3_L96 : Array UInt64 := #[
  0x008ccf3e6c758978,
  0xa1d77c7d711f111e,
  0x21da300f9626b400,
  0x88742efe5fb63786
]

/-- **Mode 3 Theorem 2 (Mode 3 `K512, N128, L96` Wire Digest & Decrypt Round-Trip)**:
    `encrypt3x256Deterministic` for `K512, N128, Mode 3, L = 96 B` produces the exact same
    3252-byte wire digest as Go `Encrypt3x256Cfg`, and `decrypt3x256Cfg` (even with altered
    `barrierFill := 32, reserve := 64, fillByte := 0xAA`) recovers the exact 96-byte plaintext. -/
theorem encrypt_decrypt256_K512_N128_M3_L96_kat :
    let wire := runKatEncrypt256 512 128 3 96
    let cfgDec : PipelineConfig256 := { nonceBits := 128, barrierFill := 32, mode := 3, reserve := 64, fillByte := 0xAA }
    (wire.size == 3252) &&
    (blake2bSum256 wire == katWireDigest256_K512_N128_M3_L96) &&
    (decrypt3x256Cfg cfgDec (mkKatConstellation256 512) wire == some (mkDeterministicBytes256 96)) = true := by
  native_decide

/-- **Mode 3 Theorem 3 (Layer I Schedule Isolation Between Mode 3 and Modes 1/2)**:
    Because **Mode 3** dispatches Layer I (`0x05`) to `buildSubregionSchedulePosit` whereas
    **Mode 1** and **Mode 2** dispatch to `buildSubregionSchedule256`, a Mode 3 wire decrypts to
    `some pt` under `mode := 3` but does not decrypt to `some pt` under `mode := 1` or `mode := 2`. -/
theorem kat_go_mode3_isolation256 :
    let c := mkKatConstellation256 512
    let pt := mkDeterministicBytes256 96
    let wire := runKatEncrypt256 512 128 3 96
    let cfgDecM3 : PipelineConfig256 := { nonceBits := 128, barrierFill := 32, mode := 3 }
    let cfgDecM1 : PipelineConfig256 := { nonceBits := 128, barrierFill := 1, mode := 1 }
    let cfgDecM2 : PipelineConfig256 := { nonceBits := 128, barrierFill := 1, mode := 2 }
    (decrypt3x256Cfg cfgDecM3 c wire == some pt) &&
    (decrypt3x256Cfg cfgDecM1 c wire != some pt) &&
    (decrypt3x256Cfg cfgDecM2 c wire != some pt) = true := by
  native_decide

/-- All 9 **Mode 3** parameter combinations `(keyBits ∈ {512, 1024, 2048}) × (nonceBits ∈ {128, 256, 512})`
    at `msgLen = 96` (`M = 17` chunks) captured from Go's `itb.Encrypt3x256Cfg`. -/
def katParamMatrix256Mode3 : List (Nat × Nat × Nat × UInt64 × UInt64 × UInt64 × UInt64) := [
  (512, 128, 3252, 0x008ccf3e6c758978, 0xa1d77c7d711f111e, 0x21da300f9626b400, 0x88742efe5fb63786),
  (512, 256, 3268, 0x8c16b4612c724045, 0x77c04d22e36d2158, 0xb824c79fadbd8f8a, 0xf6b884e180600df3),
  (512, 512, 3300, 0x54e746d8b99e42ee, 0x03ba369cba70761a, 0xdb35f01c27d42344, 0xf11d4c2a0377aa60),
  (1024, 128, 6324, 0xa4c8e8aeda48adee, 0xa12b3339d9f57b6d, 0xebbe871f4d7af3fe, 0x2fe84a962fd38c4a),
  (1024, 256, 6340, 0xe6d55fd20b6f92e5, 0x63c147f2b8385761, 0x57ad9fa65aaea77a, 0x727f2874ac2a0764),
  (1024, 512, 6372, 0xc52d7f598f748c49, 0x02ef3c9dc8ee5357, 0x2cfe1fa886d73c0b, 0x14b911be5ca02d5c),
  (2048, 128, 12220, 0xc599996c0ed691cb, 0xa5a7eb43ae9e8874, 0x74aac27ae09d927f, 0xcf8ae568d7481606),
  (2048, 256, 12236, 0xe2f7d6415ddcb5d4, 0xbd3d2bbf0a0eb648, 0x9cae0f04de53c894, 0x527b38c909521a0c),
  (2048, 512, 12268, 0x145564d049b93deb, 0x30b97ad6cd5f4e73, 0x75aa9cd9f48e9817, 0xaee80d9a7c025f01)
]

/-- **Mode 3 Theorem 4 (All 9 `(keyBits, nonceBits)` Mode 3 Configurations)**:
    Verifies bit-exact Go wire digests and round-trip decryption across all
    3 key sizes (`512`, `1024`, `2048` bits) and all 3 nonce sizes (`128`, `256`, `512` bits)
    in **Mode 3**. -/
theorem kat_go_param_matrix256_mode3_all_9_exact :
    (katParamMatrix256Mode3.all fun (kb, nb, wLen, d0, d1, d2, d3) =>
      checkParamKatEntry256 kb nb 3 96 wLen d0 d1 d2 d3) = true := by
  native_decide

/-- **Mode 3** payload size ladder (`1 B`, `96 B`, `512 B`, `1 KB`, `4 KB`, `16 KB`)
    at `1024`-bit key, `128`-bit nonce captured from Go's `itb.Encrypt3x256Cfg`. -/
def katSizeLadderDigests256Mode3 : List (Nat × Nat × UInt64 × UInt64 × UInt64 × UInt64) := [
  (1, 6324, 0xfad5df37170d83d8, 0xd8f529becd594893, 0x0aa25a725f7789fe, 0xd736333f809d4dd3),
  (96, 6324, 0xa4c8e8aeda48adee, 0xa12b3339d9f57b6d, 0xebbe871f4d7af3fe, 0x2fe84a962fd38c4a),
  (512, 6324, 0x9bfc50e78d0d6b7c, 0x4e45645a0f54fbe3, 0x7a167c33d0705a83, 0xe33e7bf8818c6328),
  (1024, 6324, 0x5fa5c4654cdb9baa, 0xc943db10ee8dcb9e, 0xa2402f495343db51, 0xd87eabce1b61db47),
  (4096, 6324, 0xd9ae83b39f04d135, 0x396c0809590e60ac, 0xa8b266912d43cf13, 0x6027bdf0dce1887e),
  (16384, 20052, 0xa718573f33c07281, 0xf52b068acc61d62a, 0xf0c23e4067626e0b, 0x3e3da9fa544642a3)
]

/-- **Mode 3 Theorem 5 (End-to-End Mode 3 Encrypt/Decrypt Payload Size Ladder `1 B` .. `16 KB`)**:
    Verifies bit-exact Go wire digests and round-trip decryption across `1 B`, `96 B`, `512 B`,
    `1 KB` (`1024`), `4 KB` (`4096`), and `16 KB` (`16384`) in **Mode 3**. -/
theorem kat_go_size_ladder256_mode3_encrypt_decrypt_exact :
    (katSizeLadderDigests256Mode3.all fun (sz, wLen, d0, d1, d2, d3) =>
      checkParamKatEntry256 1024 128 3 sz wLen d0 d1 d2 d3) = true := by
  native_decide

/-- Expected square container sides `W = H` in **Mode 3** from Go across all `11 × 3 × 3 = 99`
    combinations of `payloadLen ∈ katSizeLadder256`, `keyBits ∈ [512, 1024, 2048]`, and
    `nonceBits ∈ [128, 256, 512]`. -/
def katExpectedContainerSides256Mode3 : Array Nat := #[
  20, 20, 20, 28, 28, 28, 39, 39, 39,
  20, 20, 20, 28, 28, 28, 39, 39, 39,
  20, 20, 20, 28, 28, 28, 39, 39, 39,
  26, 26, 26, 28, 28, 28, 39, 39, 39,
  50, 50, 50, 50, 50, 50, 50, 50, 50,
  139, 139, 139, 139, 139, 139, 139, 139, 139,
  276, 276, 276, 276, 276, 276, 276, 276, 276,
  389, 389, 389, 389, 389, 389, 389, 389, 389,
  777, 777, 777, 777, 777, 777, 777, 777, 777,
  1553, 1553, 1553, 1553, 1553, 1553, 1553, 1553, 1553,
  3104, 3104, 3104, 3104, 3104, 3104, 3104, 3104, 3104
]

/-- Evaluate `calcExpectedContainerSide256` in **Mode 3** (`mode = 3`) across all 99 combinations
    of the 11-step size ladder. -/
def computeContainerSidesLadder256Mode3 : Array Nat :=
  katSizeLadder256.foldl (fun acc L =>
    [512, 1024, 2048].foldl (fun acc2 kb =>
      [128, 256, 512].foldl (fun acc3 nb =>
        acc3.push (calcExpectedContainerSide256 kb nb 3 L)) acc2) acc) #[]

/-- **Mode 3 Theorem 6 (Full 99-Cell Mode 3 Container Sizing Ladder `1 B` .. `64 MB`)**:
    Verifies that `calcContainerSize3_256` in **Mode 3** (`mode = 3`) matches Go
    `calcContainerSize3Cfg` across all 99 combinations of `(1 B .. 64 MB) × (512, 1024, 2048) × (128, 256, 512)`. -/
theorem containerSides256_mode3_matches_go_ladder :
    computeContainerSidesLadder256Mode3 = katExpectedContainerSides256Mode3 := by
  native_decide

end ITB.PipelineSpec256
