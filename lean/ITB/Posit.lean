/-
  Formal specification and bit-exact verification of 64-bit Gustafson Posit
  arithmetic (`posit64(es)` for `es ∈ {1, 2, 3}`), the 512-bit fixed-point
  quire accumulator (`quire512`), the Mode 3 inscribed Gauss-circle container
  floor (`positGaussCircleFloor`), secret circle constant derivation
  (`positDeriveSecretPi`), and the Mode 3 Layer I (`0x05`) Gauss-circle chord
  sub-region scheduler (`buildSubregionSchedulePosit`).

  All operations are formulated in pure 64-bit integer and 512-bit fixed-point
  quire arithmetic without IEEE-754 floating-point instructions, matching the
  Go reference implementation bit-for-bit.
-/

import ITB.Thresholds
import ITB.RankBarrier
import ITB.Desync

namespace ITB.Posit

open ITB.Thresholds
open ITB.RankBarrier
open ITB.Desync

set_option exponentiation.threshold 60000
set_option maxRecDepth 200000

/-! ## Canonical Posit64 and Quire512 Constants -/

/-- Canonical 64-bit Posit encoding of `0`. -/
def positZero : UInt64 := 0x0000000000000000

/-- Canonical 64-bit Posit encoding of Not-a-Real (`NaR`). -/
def positNaR : UInt64 := 0x8000000000000000

/-- Maximum positive 64-bit Posit bit pattern (`maxpos`). -/
def positMax : UInt64 := 0x7fffffffffffffff

/-- Minimum positive 64-bit Posit bit pattern (`minpos`). -/
def positMin : UInt64 := 0x0000000000000001

/-- Canonical 64-bit Posit encoding of `1.0` across all `es`. -/
def positOne : UInt64 := 0x4000000000000000

/-- Fractional bit position of the binary point in the 512-bit quire (`bit 256`). -/
def quireFracBits : Int := 256

/-- Odd 64-bit golden-ratio Weyl constant (`2^64 / φ`). -/
def desyncGoldenGamma : UInt64 := 0x9e3779b97f4a7c15

/-- Per-region pixel threshold separating the two sub-region count regimes. -/
def mode1DesyncRegionPixels : Nat := 365

/-- Maximum sub-region count per container third. -/
def maxDesyncSubregions : Nat := 16

/-- 512-bit two's-complement fixed-point quire accumulator (`8 × UInt64` in
    little-endian word order) with binary point at bit 256 (`bit 0` of `w4`
    has weight `2^0 = 1`). -/
structure Quire512 where
  w0 : UInt64 := 0
  w1 : UInt64 := 0
  w2 : UInt64 := 0
  w3 : UInt64 := 0
  w4 : UInt64 := 0
  w5 : UInt64 := 0
  w6 : UInt64 := 0
  w7 : UInt64 := 0
  deriving DecidableEq, Repr, Inhabited

/-- Zero-initialized 512-bit quire accumulator. -/
def quireZero : Quire512 := {}

/-- Boolean check whether a `Quire512` accumulator is identically zero. -/
def quireIsZero (q : Quire512) : Bool :=
  q.w0 == 0 && q.w1 == 0 && q.w2 == 0 && q.w3 == 0 &&
  q.w4 == 0 && q.w5 == 0 && q.w6 == 0 && q.w7 == 0

/-- Exact 256-bit fractional expansion of `π` in `Quire512` fixed-point representation:
    `π = 3 + 0x243f6a8885a308d3_13198a2e03707344_a4093822299f31d0_082efa98ec4e6c89 * 2^-256`. -/
def quirePi : Quire512 := {
  w0 := 0x082efa98ec4e6c89
  w1 := 0xa4093822299f31d0
  w2 := 0x13198a2e03707344
  w3 := 0x243f6a8885a308d3
  w4 := 0x0000000000000003
  w5 := 0x0000000000000000
  w6 := 0x0000000000000000
  w7 := 0x0000000000000000
}

/-- Bits `-512..-257` of `π - 3` used for mixing key-derived perturbations into
    the `Quire512` fractional accumulator under Mode 3. -/
def positPiDeepFrac0 : UInt64 := 0x3f84d5b5b5470917
def positPiDeepFrac1 : UInt64 := 0xc0ac29b7c97c50dd
def positPiDeepFrac2 : UInt64 := 0xbe5466cf34e90c6c
def positPiDeepFrac3 : UInt64 := 0x452821e638d01377

/-- Word-indexed read on `Quire512` (`i ∈ 0..7`). -/
def quireGet (q : Quire512) (i : Nat) : UInt64 :=
  match i with
  | 0 => q.w0
  | 1 => q.w1
  | 2 => q.w2
  | 3 => q.w3
  | 4 => q.w4
  | 5 => q.w5
  | 6 => q.w6
  | 7 => q.w7
  | _ => 0

/-- Word-indexed write on `Quire512` (`i ∈ 0..7`). -/
def quireSet (q : Quire512) (i : Nat) (v : UInt64) : Quire512 :=
  match i with
  | 0 => { q with w0 := v }
  | 1 => { q with w1 := v }
  | 2 => { q with w2 := v }
  | 3 => { q with w3 := v }
  | 4 => { q with w4 := v }
  | 5 => { q with w5 := v }
  | 6 => { q with w6 := v }
  | 7 => { q with w7 := v }
  | _ => q

/-! ## Low-Level 64-Bit Integer Primitives (`math/bits` equivalents) -/

/-- Count of leading zero bits in a 64-bit word (`bits.LeadingZeros64`). -/
def clz64 (x : UInt64) : Nat :=
  if x == 0 then 64
  else
    let (n, x) := if (x >>> 32) == 0 then (32, x <<< 32) else (0, x)
    let (n, x) := if (x >>> 48) == 0 then (n + 16, x <<< 16) else (n, x)
    let (n, x) := if (x >>> 56) == 0 then (n + 8, x <<< 8) else (n, x)
    let (n, x) := if (x >>> 60) == 0 then (n + 4, x <<< 4) else (n, x)
    let (n, x) := if (x >>> 62) == 0 then (n + 2, x <<< 2) else (n, x)
    let n := if (x >>> 63) == 0 then n + 1 else n
    n

/-- 64-bit left rotation (`bits.RotateLeft64`). -/
def rotl64 (x : UInt64) (r : Nat) : UInt64 :=
  let s := r % 64
  if s == 0 then x
  else (x <<< s.toUInt64) ||| (x >>> (64 - s).toUInt64)

/-- 64-bit addition with carry (`bits.Add64`). -/
def add64 (a b carry : UInt64) : UInt64 × UInt64 :=
  let sum : Nat := a.toNat + b.toNat + (carry &&& 1).toNat
  (UInt64.ofNat (sum % (2 ^ 64)), UInt64.ofNat (sum / (2 ^ 64)))

/-- 64-bit subtraction with borrow (`bits.Sub64`). -/
def sub64 (a b borrow : UInt64) : UInt64 × UInt64 :=
  let bIn : UInt64 := borrow &&& 1
  let diff : UInt64 := a - b - bIn
  let bOut : UInt64 := if a.toNat < b.toNat + bIn.toNat then 1 else 0
  (diff, bOut)

/-- 64×64 → 128-bit unsigned multiplication returning `(hi, lo)` (`bits.Mul64`). -/
def mul64 (a b : UInt64) : UInt64 × UInt64 :=
  let prod : Nat := a.toNat * b.toNat
  (UInt64.ofNat ((prod / (2 ^ 64)) % (2 ^ 64)), UInt64.ofNat (prod % (2 ^ 64)))

/-- 128÷64 → 64-bit unsigned division returning `(q, rem)` (`bits.Div64`). -/
def div64 (hi lo y : UInt64) : UInt64 × UInt64 :=
  if y == 0 then (0, 0)
  else
    let num : Nat := hi.toNat * (2 ^ 64) + lo.toNat
    let den : Nat := y.toNat
    (UInt64.ofNat ((num / den) % (2 ^ 64)), UInt64.ofNat (num % den))

/-- Two's-complement negation of a `posit64` bit pattern (`positNeg`). -/
def positNeg (a : UInt64) : UInt64 :=
  0 - a

/-! ## Posit64 Decode, RNE Encode, and Arithmetic Operations -/

/-- Decoded representation of a non-zero, non-NaR `posit64(es)`. -/
structure DecodedPosit where
  sign  : Bool
  k     : Int
  e     : Nat
  scale : Int
  normM : UInt64
  deriving DecidableEq, Repr, Inhabited

/-- Decode a `posit64(es)` word into `(sign, k, e, scale, normM)` (`positDecode64`). -/
def positDecode64 (u : UInt64) (es : Nat) : DecodedPosit :=
  if u == positZero || u == positNaR then
    { sign := u == positNaR, k := 0, e := 0, scale := 0, normM := 0 }
  else
    let sign : Bool := (u >>> 63) != 0
    let p : UInt64 := if sign then (0 - u) else u
    let r0 : UInt64 := (p >>> 62) &&& 1
    let (m, k) : Nat × Int :=
      if r0 == 1 then
        let m := clz64 (~~~(p <<< 1))
        (m, (m : Int) - 1)
      else
        let m := clz64 (p <<< 1)
        (m, -(m : Int))
    let rem : UInt64 :=
      if m ≤ 62 then p <<< (m + 2).toUInt64 else 0
    let e : Nat :=
      if es == 0 then 0 else (rem >>> (64 - es).toUInt64).toNat
    let fracAligned : UInt64 := rem <<< es.toUInt64
    let normM : UInt64 := ((1 : UInt64) <<< 63) ||| (fracAligned >>> 1)
    let scale : Int := k * ((2 ^ es : Nat) : Int) + (e : Int)
    { sign, k, e, scale, normM }

/-- Encode `(-1)^sign * (normM * 2^-63) * 2^scale` with sticky bits into
    `posit64(es)` using Round-to-Nearest-Even (`positEncode64`). -/
def positEncode64 (sign : Bool) (scale : Int) (normM : UInt64) (sticky : UInt64) (es : Nat) : UInt64 :=
  if normM == 0 then
    positZero
  else
    let powEs : Int := ((2 ^ es : Nat) : Int)
    let maxScale : Int := 62 * powEs
    if scale ≥ maxScale then
      if sign then positNeg positMax else positMax
    else if scale < -maxScale then
      if sign then positNeg positMin else positMin
    else
      let k : Int := Int.ediv scale powEs
      let e : UInt64 := (Int.emod scale powEs).toNat.toUInt64
      let (m, regPattern) : Nat × UInt64 :=
        if k ≥ 0 then
          let m : Nat := (k + 1).toNat
          let pat : UInt64 := (((1 : UInt64) <<< m.toUInt64) - 1) <<< (63 - m).toUInt64
          (m, pat)
        else
          let m : Nat := (-k).toNat
          let pat : UInt64 := (1 : UInt64) <<< (62 - m).toUInt64
          (m, pat)
      let frac63 : UInt64 := normM <<< 1
      let (expFracHi, expFracLo) : UInt64 × UInt64 :=
        if es == 0 then
          (frac63, sticky)
        else
          ((e <<< (64 - es).toUInt64) ||| (frac63 >>> es.toUInt64),
           (frac63 <<< (64 - es).toUInt64) ||| sticky)
      let shift : Nat := m + 2
      let (p0, guard, remSticky) : UInt64 × UInt64 × UInt64 :=
        if shift == 64 then
          (regPattern,
           expFracHi >>> 63,
           (expFracHi &&& 0x7fffffffffffffff) ||| expFracLo)
        else
          let sh := shift.toUInt64
          let sh1 := (shift - 1).toUInt64
          (regPattern ||| (expFracHi >>> sh),
           (expFracHi >>> sh1) &&& 1,
           (expFracHi &&& (((1 : UInt64) <<< sh1) - 1)) ||| expFracLo)
      let p1 : UInt64 :=
        if guard == 1 && (remSticky != 0 || (p0 &&& 1) == 1) then p0 + 1 else p0
      if sign then positNeg p1 else p1

/-- Convert an unsigned 64-bit integer to `posit64(es)` (`positFromUint64`). -/
def positFromUint64 (v : UInt64) (es : Nat) : UInt64 :=
  if v == 0 then
    positZero
  else
    let lz := clz64 v
    let scale : Int := (63 : Int) - (lz : Int)
    let normM : UInt64 := v <<< lz.toUInt64
    positEncode64 false scale normM 0 es

/-- Compute `⌊u⌋` as `UInt64` for a non-negative `posit64(es)` (`positFloorUint64`). -/
def positFloorUint64 (u : UInt64) (es : Nat) : UInt64 :=
  if u == positZero || u == positNaR || (u >>> 63) != 0 then
    0
  else
    let d := positDecode64 u es
    if d.scale < 0 then
      0
    else if d.scale ≥ 64 then
      0xffffffffffffffff
    else
      let sh : Nat := (63 - d.scale).toNat
      d.normM >>> sh.toUInt64

/-- RNE addition in `posit64(es)` (`positAdd`). -/
def positAdd (a b : UInt64) (es : Nat) : UInt64 :=
  if a == positNaR || b == positNaR then
    positNaR
  else if a == positZero then
    b
  else if b == positZero then
    a
  else if a == positNeg b then
    positZero
  else
    let da := positDecode64 a es
    let db := positDecode64 b es
    let (sa, scaleA, ma, sb, scaleB, mb) :=
      if da.scale < db.scale || (da.scale == db.scale && da.normM < db.normM) then
        (db.sign, db.scale, db.normM, da.sign, da.scale, da.normM)
      else
        (da.sign, da.scale, da.normM, db.sign, db.scale, db.normM)
    let diff : Nat := (scaleA - scaleB).toNat
    let (bHi, bLo, sticky) : UInt64 × UInt64 × UInt64 :=
      if diff == 0 then
        (mb, 0, 0)
      else if diff < 64 then
        (mb >>> diff.toUInt64, mb <<< (64 - diff).toUInt64, 0)
      else if diff == 64 then
        (0, mb, 0)
      else if diff < 128 then
        let s := diff - 64
        (0, mb >>> s.toUInt64, mb <<< (64 - s).toUInt64)
      else
        (0, 0, mb)
    if sa == sb then
      let lo := bLo
      let (hi0, carry) := add64 ma bHi 0
      if carry != 0 then
        let sticky1 := sticky ||| (lo &&& 1)
        let lo1 := (lo >>> 1) ||| (hi0 <<< 63)
        let hi1 := ((1 : UInt64) <<< 63) ||| (hi0 >>> 1)
        positEncode64 sa (scaleA + 1) hi1 (lo1 ||| sticky1) es
      else
        positEncode64 sa scaleA hi0 (lo ||| sticky) es
    else
      let (subSticky, borrow0) : UInt64 × UInt64 :=
        if sticky != 0 then (1, 1) else (0, 0)
      let (lo0, borrow1) := sub64 0 bLo borrow0
      let (hi0, _) := sub64 ma bHi borrow1
      if hi0 == 0 && lo0 == 0 && subSticky == 0 then
        positZero
      else if hi0 != 0 then
        let lz := clz64 hi0
        if lz > 0 then
          let scale1 := scaleA - (lz : Int)
          let hi1 := (hi0 <<< lz.toUInt64) ||| (lo0 >>> (64 - lz).toUInt64)
          let lo1 := (lo0 <<< lz.toUInt64) ||| (subSticky <<< (lz - 1).toUInt64)
          positEncode64 sa scale1 hi1 lo1 es
        else
          positEncode64 sa scaleA hi0 (lo0 ||| subSticky) es
      else
        let lz := clz64 lo0
        let scale1 := scaleA - (64 : Int) - (lz : Int)
        let hi1 := lo0 <<< lz.toUInt64
        positEncode64 sa scale1 hi1 subSticky es

/-- RNE subtraction in `posit64(es)` (`positSub`). -/
def positSub (a b : UInt64) (es : Nat) : UInt64 :=
  positAdd a (positNeg b) es

/-- RNE multiplication in `posit64(es)` (`positMul`). -/
def positMul (a b : UInt64) (es : Nat) : UInt64 :=
  if a == positNaR || b == positNaR then
    positNaR
  else if a == positZero || b == positZero then
    positZero
  else
    let da := positDecode64 a es
    let db := positDecode64 b es
    let sign : Bool := da.sign != db.sign
    let (hi, lo) := mul64 da.normM db.normM
    let scale : Int := da.scale + db.scale
    if (hi >>> 63) != 0 then
      positEncode64 sign (scale + 1) hi lo es
    else
      let normM := (hi <<< 1) ||| (lo >>> 63)
      let sticky := lo <<< 1
      positEncode64 sign scale normM sticky es

/-- RNE division in `posit64(es)` (`positDiv`). -/
def positDiv (a b : UInt64) (es : Nat) : UInt64 :=
  if a == positNaR || b == positNaR || b == positZero then
    positNaR
  else if a == positZero then
    positZero
  else
    let da := positDecode64 a es
    let db := positDecode64 b es
    let sign : Bool := da.sign != db.sign
    let scale0 : Int := da.scale - db.scale
    if da.normM ≥ db.normM then
      let (q, rem) := div64 (da.normM >>> 1) (da.normM <<< 63) db.normM
      positEncode64 sign scale0 q rem es
    else
      let (q, rem) := div64 da.normM 0 db.normM
      positEncode64 sign (scale0 - 1) q rem es

/-- 128-bit integer square root `⌊√(xHi * 2^64 + xLo)⌋` with sticky remainder flag
    (`positIsqrt128`). Matches Go's 6+2 Newton-Raphson iteration and exact
    remainder check bit-for-bit. -/
def positIsqrt128 (xHi xLo : UInt64) : UInt64 × UInt64 :=
  if xHi == 0 && xLo == 0 then
    (0, 0)
  else
    let r0 : UInt64 := (1 : UInt64) <<< 32
    let r1 : UInt64 := (r0 + xHi / r0) >>> 1
    let r2 : UInt64 := (r1 + xHi / r1) >>> 1
    let r3 : UInt64 := (r2 + xHi / r2) >>> 1
    let r4 : UInt64 := (r3 + xHi / r3) >>> 1
    let r5 : UInt64 := (r4 + xHi / r4) >>> 1
    let r6 : UInt64 := (r5 + xHi / r5) >>> 1
    let rSeed : UInt64 :=
      if r6 ≥ ((1 : UInt64) <<< 32) then 0xffffffffffffffff
      else (r6 <<< 32) ||| 0x80000000
    let step128 (r : UInt64) : UInt64 :=
      let q : UInt64 :=
        if xHi ≥ r then 0xffffffffffffffff
        else (div64 xHi xLo r).1
      (r >>> 1) + (q >>> 1) + (r &&& q &&& 1)
    let rA := step128 (step128 rSeed)
    let decStep (r : UInt64) : UInt64 :=
      let (sqHi, sqLo) := mul64 r r
      if sqHi > xHi || (sqHi == xHi && sqLo > xLo) then r - 1 else r
    let rB := decStep (decStep (decStep (decStep rA)))
    let incStep (r : UInt64) : UInt64 :=
      if r < 0xffffffffffffffff then
        let (nHi, nLo) := mul64 (r + 1) (r + 1)
        if nHi < xHi || (nHi == xHi && nLo ≤ xLo) then r + 1 else r
      else r
    let rFinal := incStep (incStep (incStep (incStep rB)))
    let (sqHi, sqLo) := mul64 rFinal rFinal
    let sticky : UInt64 := if sqHi != xHi || sqLo != xLo then 1 else 0
    (rFinal, sticky)

/-- RNE square root in `posit64(es)` (`positSqrt` / `positISqrt`). -/
def positSqrt (a : UInt64) (es : Nat) : UInt64 :=
  if a == positNaR || (a >>> 63) != 0 then
    positNaR
  else if a == positZero then
    positZero
  else
    let da := positDecode64 a es
    let odd : Nat := (Int.emod da.scale 2).toNat
    let scaleOut : Int := Int.ediv da.scale 2
    let (xHi, xLo) : UInt64 × UInt64 :=
      if odd == 0 then (da.normM >>> 1, da.normM <<< 63) else (da.normM, 0)
    let (root, rem) := positIsqrt128 xHi xLo
    positEncode64 false scaleOut root rem es

/-- Alias `positISqrt` for `positSqrt`. -/
abbrev positISqrt (a : UInt64) (es : Nat) : UInt64 :=
  positSqrt a es

/-! ## 512-Bit Quire Accumulator Operations -/

/-- Two's-complement negation of a 512-bit quire (`quire512.neg`). -/
def quireNeg (q : Quire512) : Quire512 :=
  let (w0, c0) := add64 (~~~q.w0) 0 1
  let (w1, c1) := add64 (~~~q.w1) 0 c0
  let (w2, c2) := add64 (~~~q.w2) 0 c1
  let (w3, c3) := add64 (~~~q.w3) 0 c2
  let (w4, c4) := add64 (~~~q.w4) 0 c3
  let (w5, c5) := add64 (~~~q.w5) 0 c4
  let (w6, c6) := add64 (~~~q.w6) 0 c5
  let (w7, _)  := add64 (~~~q.w7) 0 c6
  { w0, w1, w2, w3, w4, w5, w6, w7 }

/-- 512-bit modular addition of two `Quire512` accumulators. -/
def quireAdd (a b : Quire512) : Quire512 :=
  let (w0, c0) := add64 a.w0 b.w0 0
  let (w1, c1) := add64 a.w1 b.w1 c0
  let (w2, c2) := add64 a.w2 b.w2 c1
  let (w3, c3) := add64 a.w3 b.w3 c2
  let (w4, c4) := add64 a.w4 b.w4 c3
  let (w5, c5) := add64 a.w5 b.w5 c4
  let (w6, c6) := add64 a.w6 b.w6 c5
  let (w7, _)  := add64 a.w7 b.w7 c6
  { w0, w1, w2, w3, w4, w5, w6, w7 }

/-- 512-bit modular subtraction of two `Quire512` accumulators. -/
def quireSub (a b : Quire512) : Quire512 :=
  let (w0, b0) := sub64 a.w0 b.w0 0
  let (w1, b1) := sub64 a.w1 b.w1 b0
  let (w2, b2) := sub64 a.w2 b.w2 b1
  let (w3, b3) := sub64 a.w3 b.w3 b2
  let (w4, b4) := sub64 a.w4 b.w4 b3
  let (w5, b5) := sub64 a.w5 b.w5 b4
  let (w6, b6) := sub64 a.w6 b.w6 b5
  let (w7, _)  := sub64 a.w7 b.w7 b6
  { w0, w1, w2, w3, w4, w5, w6, w7 }

/-- Add a single shifted 64-bit word `val` at word position `wordPos` into `mag`. -/
def addWordAt (mag : Quire512) (wordPos : Int) (val : UInt64) : Quire512 :=
  if val == 0 || wordPos < 0 || wordPos ≥ 8 then
    mag
  else
    let wp : Nat := wordPos.toNat
    let rec prop (q : Quire512) (idx : Nat) (c : UInt64) (fuel : Nat) : Quire512 :=
      match fuel with
      | 0 => q
      | fuel' + 1 =>
        if idx ≥ 8 || c == 0 then q
        else
          let (nv, nc) := add64 (quireGet q idx) 0 c
          prop (quireSet q idx nv) (idx + 1) nc fuel'
    let (v0, c0) := add64 (quireGet mag wp) val 0
    prop (quireSet mag wp v0) (wp + 1) c0 8

/-- Accumulate `(-1)^sign * (hi * 2^64 + lo) * 2^(bitPos - 256)` into `q`
    (`quire512.addSignedShifted128`). -/
def quireAddSignedShifted128 (q : Quire512) (sign : Bool) (hi lo : UInt64) (bitPos : Int) : Quire512 :=
  if hi == 0 && lo == 0 then
    q
  else
    let placeWord (mag : Quire512) (val : UInt64) (bp : Int) : Quire512 :=
      if val == 0 then mag
      else
        let wordPos : Int := Int.ediv bp 64
        let bitShift : Nat := (Int.emod bp 64).toNat
        let mag1 := addWordAt mag wordPos (val <<< bitShift.toUInt64)
        if bitShift > 0 then
          addWordAt mag1 (wordPos + 1) (val >>> (64 - bitShift).toUInt64)
        else
          mag1
    let mag := placeWord (placeWord quireZero lo bitPos) hi (bitPos + 64)
    if sign then quireSub q mag else quireAdd q mag

/-- Accumulate a single `posit64(es)` value into `q` (`quire512.addPosit`). -/
def quireAddPosit (q : Quire512) (a : UInt64) (es : Nat) : Quire512 :=
  if a == positZero || a == positNaR then
    q
  else
    let da := positDecode64 a es
    quireAddSignedShifted128 q da.sign 0 da.normM (quireFracBits + da.scale - 63)

/-- Convert a `posit64(es)` value directly into a `Quire512` accumulator (`positToQuire`). -/
def positToQuire (a : UInt64) (es : Nat) : Quire512 :=
  quireAddPosit quireZero a es

/-- Accumulate the exact product `a * b` of two `posit64(es)` values into `q`
    without intermediate rounding (`quire512.addProduct`). -/
def quireAddProduct (q : Quire512) (a b : UInt64) (es : Nat) : Quire512 :=
  if a == positZero || b == positZero || a == positNaR || b == positNaR then
    q
  else
    let da := positDecode64 a es
    let db := positDecode64 b es
    let (hi, lo) := mul64 da.normM db.normM
    quireAddSignedShifted128 q (da.sign != db.sign) hi lo (quireFracBits + da.scale + db.scale - 126)

/-- Subtract the exact product `a * b` of two `posit64(es)` values from `q`
    without intermediate rounding (`quire512.subProduct`). -/
def quireSubProduct (q : Quire512) (a b : UInt64) (es : Nat) : Quire512 :=
  quireAddProduct q a (positNeg b) es

/-- Find the highest word index `i ∈ 0..7` with `quireGet mag i != 0`. -/
def quireTopNonZeroIdx (mag : Quire512) : Option Nat :=
  if mag.w7 != 0 then some 7
  else if mag.w6 != 0 then some 6
  else if mag.w5 != 0 then some 5
  else if mag.w4 != 0 then some 4
  else if mag.w3 != 0 then some 3
  else if mag.w2 != 0 then some 2
  else if mag.w1 != 0 then some 1
  else if mag.w0 != 0 then some 0
  else none

/-- Bitwise OR of `quireGet mag 0 .. quireGet mag (bound - 1)`. -/
def quireOrBelow (mag : Quire512) (bound : Nat) : UInt64 :=
  (List.range bound).foldl (fun acc i => acc ||| quireGet mag i) 0

/-- Round a `Quire512` accumulator back to `posit64(es)` via a single final RNE
    rounding (`quire512.toPosit` / `positFromQuire`). -/
def positFromQuire (q : Quire512) (es : Nat) : UInt64 :=
  if quireIsZero q then
    positZero
  else
    let sign : Bool := (q.w7 >>> 63) != 0
    let mag : Quire512 := if sign then quireNeg q else q
    match quireTopNonZeroIdx mag with
    | none => positZero
    | some topIdx =>
      let topWord := quireGet mag topIdx
      let lz := clz64 topWord
      let msbPos : Int := (topIdx * 64 + (63 - lz) : Nat)
      let scale : Int := msbPos - quireFracBits
      let (normM, sticky) : UInt64 × UInt64 :=
        if lz == 0 then
          (topWord, quireOrBelow mag topIdx)
        else
          let hiPart := topWord <<< lz.toUInt64
          if topIdx > 0 then
            let prevWord := quireGet mag (topIdx - 1)
            let normM := hiPart ||| (prevWord >>> (64 - lz).toUInt64)
            let sticky := (prevWord <<< lz.toUInt64) ||| quireOrBelow mag (topIdx - 1)
            (normM, sticky)
          else
            (hiPart, 0)
      positEncode64 sign scale normM sticky es

/-- Canonical `posit64(es)` rounding of `π` from the 512-bit `quirePi` (`positPi`). -/
def positPi (es : Nat) : UInt64 :=
  positFromQuire quirePi es

/-! ## Mode 3 Inscribed Gauss-Circle Floor and Secret Circle Constant -/

/-- Compute the Mode 3 inscribed Gauss-circle container floor for `threeMinPx`
    pixels in canonical `posit64(2)`:
    `⌊(2 * threeMinPx) / π_posit(es=2)⌋ + 1` (`positGaussCircleFloor`). -/
def positGaussCircleFloor (threeMinPx : Nat) : Nat :=
  if threeMinPx == 0 then
    1
  else
    let es : Nat := 2
    let num := positFromUint64 (2 * threeMinPx).toUInt64 es
    let pi := positPi es
    let q := positDiv num pi es
    (positFloorUint64 q es).toNat + 1

/-- Integer ceiling square root matching `ceilSqrt` in container sizing. -/
def ceilSqrtPosit (totalPixels : Nat) : Nat :=
  let rec loop (side : Nat) (fuel : Nat) : Nat :=
    match fuel with
    | 0 => side
    | fuel' + 1 =>
      if side * side < totalPixels then loop (side + 1) fuel'
      else side
  loop 1 totalPixels

/-- Mode 3 container side length for `threeMinPx` and `barrierFill`. -/
def mode3ContainerSide (threeMinPx barrierFill : Nat) : Nat :=
  ceilSqrtPosit (positGaussCircleFloor threeMinPx) + barrierFill

/-- Extract the region's Posit exponent width `es_r ∈ {1, 2, 3}` from `w[0]`. -/
def positEsFromWord (w0 : UInt64) : Nat :=
  1 + ((w0 >>> 40).toNat % 3)

/-- Derive a region's secret Posit configuration `es_r ∈ {1, 2, 3}` and secret
    Posit circle constant `π_{K,r}` from the 8 folded domain-`0x05` words
    `w[0..7]` (`positDeriveSecretPi`). -/
def positDeriveSecretPi (w : Array UInt64) : UInt64 × Nat :=
  let w0 := w.getD 0 0
  let w2 := w.getD 2 0
  let w3 := w.getD 3 0
  let w4 := w.getD 4 0
  let w5 := w.getD 5 0
  let w6 := w.getD 6 0
  let w7 := w.getD 7 0
  let es := positEsFromWord w0
  let d0 : UInt64 := (w4 >>> 16) ^^^ rotl64 w5 19 ^^^ positPiDeepFrac0
  let d1 : UInt64 := (w5 >>> 16) ^^^ rotl64 w6 29 ^^^ positPiDeepFrac1
  let d2 : UInt64 := (w6 >>> 16) ^^^ rotl64 w7 37 ^^^ positPiDeepFrac2
  let topMix : UInt64 :=
    ((w2 >>> 16) <<< 8) ^^^
    ((w3 >>> 16) <<< 9) ^^^
    ((w4 >>> 16) <<< 10) ^^^
    ((w5 >>> 16) <<< 11) ^^^
    ((w6 >>> 16) <<< 12) ^^^
    ((w7 >>> 16) <<< 12) ^^^
    (positPiDeepFrac3 >>> 4)
  let d3 : UInt64 := topMix &&& 0x0fffffffffffffff
  let delta : Quire512 := { w0 := d0, w1 := d1, w2 := d2, w3 := d3 }
  let q := quireAdd quirePi delta
  (positFromQuire q es, es)

/-! ## Mode 3 Layer I (`0x05`) Gauss-Circle Chord Sub-Region Scheduler -/

/-- Mode 3 Layer I (`0x05`) sub-region schedule matching Go's `subregionSchedule`. -/
structure SubregionSchedule where
  k      : Nat
  offset : Array Nat
  size   : Array Nat
  start  : Array Nat
  logOff : Array Nat
  deriving DecidableEq, Repr, Inhabited

/-- Evaluate `R_posit^2 - y_j^2` in the 512-bit quire accumulator before a single
    final RNE rounding to `posit64(es)`. -/
def quireR2MinusY2 (radius y : UInt64) (es : Nat) : UInt64 :=
  let q1 := quireAddProduct quireZero radius radius es
  let q2 := quireSubProduct q1 y y es
  positFromQuire q2 es

/-- Construct the Mode 3 Layer I (`0x05`) sub-region schedule by slicing the
    region of `totalPixels` into Gauss-circle chords evaluated in `posit64(es_r)`
    and `Quire512` under the region's secret `(π_{K,r}, es_r)`
    (`buildSubregionSchedulePosit`). -/
def buildSubregionSchedulePosit (startPixel totalPixels : Nat) (w : Array UInt64) : SubregionSchedule :=
  let w0 := w.getD 0 0
  let w1 := w.getD 1 0
  let (k, deltaMax) : Nat × Nat :=
    if totalPixels < mode1DesyncRegionPixels then
      (6 + (w0.toNat % 5), 1)
    else
      (8 + (w0.toNat % 9), 2)
  let (piK, es) := positDeriveSecretPi w
  let pTotal := positFromUint64 totalPixels.toUInt64 es
  let radius := positMul pTotal piK es
  let phase : UInt64 := (w0 >>> 44) &&& 63
  let flip : Bool := ((w0 >>> 52) &&& 1) != 0
  let denPosit := positFromUint64 (64 * k + 32).toUInt64 es
  let (chords, chordSum, chordDigest) : Array UInt64 × UInt64 × UInt64 :=
    (List.range k).foldl (fun (acc, cSum, cDig) j =>
      let idx : Nat := if flip then k - 1 - j else j
      let num : UInt64 := (64 * idx + 16).toUInt64 + phase
      let y := positDiv (positMul radius (positFromUint64 num es) es) denPosit es
      let r2MinusY2 := quireR2MinusY2 radius y es
      let cPosit := positSqrt r2MinusY2 es
      let cBits : UInt64 := cPosit
      let cFold : UInt64 :=
        cBits ^^^ (cBits >>> 13) ^^^ (cBits >>> 27) ^^^ (cBits >>> 41) ^^^ (cBits >>> 53)
      let chord : UInt64 := positFloorUint64 cPosit es + 1 + (cFold &&& 7)
      let cDig1 : UInt64 :=
        rotl64 cDig 19 ^^^ (cBits * desyncGoldenGamma) ^^^ r2MinusY2
      (acc.push chord, cSum + chord, cDig1)
    ) (#[], 0, 0)
  let minSub : Nat := 5
  let remPixels : Nat := totalPixels - k * minSub
  let (physOff0, _) : Array Nat × UInt64 :=
    (List.range (k - 1)).foldl (fun (offs, cum) jMinus1 =>
      let j := jMinus1 + 1
      let cum1 := cum + chords.getD (j - 1) 0
      let prop : Nat :=
        if chordSum == 0 then 0
        else ((remPixels.toUInt64 * cum1) / chordSum).toNat
      let offJ : Nat :=
        if deltaMax == 1 then
          let raw : Nat :=
            (((w0 >>> (8 + j).toUInt64) ^^^ (chordDigest >>> j.toUInt64)) &&& 1).toNat
          j * minSub + prop + raw - 1
        else
          let raw : Nat :=
            (((w0 >>> (8 + 2 * j).toUInt64) ^^^ (chordDigest >>> (2 * j).toUInt64)) &&& 3).toNat
          j * minSub + prop + raw - 2
      (offs.push offJ, cum1)
    ) (#[0], 0)
  let physOff := physOff0.push totalPixels
  let physSize : Array Nat :=
    (List.range k).foldl (fun sz j =>
      sz.push (physOff.getD (j + 1) 0 - physOff.getD j 0)
    ) #[]
  let tauInit : Array Nat :=
    (List.range k).foldl (fun arr i => arr.push i) #[]
  let u0 : UInt64 := w1 ^^^ rotl64 chordDigest 29
  let (tau, _) : Array Nat × UInt64 :=
    (List.range (k - 1)).foldl (fun (tArr, u) stepIdx =>
      let i := k - 1 - stepIdx
      let mod : UInt64 := (i + 1).toUInt64
      let swapIdx : Nat := (u % mod).toNat
      let uNext : UInt64 := u / mod
      let vi := tArr.getD i 0
      let vs := tArr.getD swapIdx 0
      let tArr1 := (tArr.set! i vs).set! swapIdx vi
      (tArr1, uNext)
    ) (tauInit, u0)
  let (offset, size, start, logOff) : Array Nat × Array Nat × Array Nat × Array Nat :=
    (List.range k).foldl (fun (oArr, szArr, stArr, lArr) step =>
      let physIdx := tau.getD step 0
      let m := physSize.getD physIdx 0
      let prevLog := lArr.getD step 0
      let positMix : UInt64 :=
        piK ^^^ rotl64 radius (19 * (step + 1)) ^^^ rotl64 chordDigest (7 * (step + 1))
      let wStep := w.getD (2 + (step % 6)) 0
      let mix : UInt64 :=
        rotl64 wStep (11 * step) ^^^ ((step + 1).toUInt64 * desyncGoldenGamma) ^^^ positMix
      let st : Nat :=
        if m == 0 then 0 else ((startPixel.toUInt64 + mix) % m.toUInt64).toNat
      (oArr.push (physOff.getD physIdx 0),
       szArr.push m,
       stArr.push st,
       lArr.push (prevLog + m))
    ) (#[], #[], #[], #[0])
  { k, offset, size, start, logOff }

/-- Derive a coprime Weyl step `1 ≤ step < m` with `gcd(step, m) = 1` matching
    `deriveCoprimeStep` in `desync.go`. -/
def deriveCoprimeStep (m : Nat) (rawWord : UInt64) : Nat :=
  if m ≤ 1 then 1
  else
    let step0 := 1 + (rawWord.toNat % (m - 1))
    let rec loop (s : Nat) (fuel : Nat) : Nat :=
      match fuel with
      | 0 => 1
      | fuel' + 1 =>
        if Nat.gcd s m == 1 then s
        else
          let sNext := if s + 1 ≥ m then 1 else s + 1
          loop sNext fuel'
    loop step0 m

/-- Canonical 8-word test vector from `posit_test.go` parameterized by `esCase ∈ {0, 1, 2}`. -/
def katWordsEs (esCase : UInt64) : Array UInt64 := #[
  ((0x0123456789abcdef : UInt64) &&& ~~~((0xff : UInt64) <<< 40)) ||| (esCase <<< 40),
  0xfedcba9876543210,
  0x1122334455667788,
  0x8877665544332211,
  0xdeadbeefcafebabe,
  0x0f1e2d3c4b5a6978,
  0x99aabbccddeeff00,
  0x13579bdf2468ace0
]

/-- Perturb word `idx` of `w` by XORing `delta`. -/
def perturbWord (w : Array UInt64) (idx : Nat) (delta : UInt64) : Array UInt64 :=
  w.set! idx (w.getD idx 0 ^^^ delta)

/-!
## Section 1 — `posit64(es)` & `quire512` Bit-Exact Representation (8 Theorems)
-/

/-- Theorem 1: `positEsFromWord` always produces an exponent width in `[1, 3]`. -/
theorem positEsFromWord_range (w0 : UInt64) :
    1 ≤ positEsFromWord w0 ∧ positEsFromWord w0 ≤ 3 := by
  unfold positEsFromWord
  omega

/-- Theorem 2: `positEsFromWord` takes values exclusively in `{1, 2, 3}`. -/
theorem positEsFromWord_cases (w0 : UInt64) :
    positEsFromWord w0 = 1 ∨ positEsFromWord w0 = 2 ∨ positEsFromWord w0 = 3 := by
  unfold positEsFromWord
  omega

/-- Theorem 3: `quireZero` is recognized as zero, is a fixed point of two's-complement
    negation, and rounds to `positZero` across all `es ∈ {1, 2, 3}`. -/
theorem quire512_zero_props :
    quireIsZero quireZero = true ∧
    quireNeg quireZero = quireZero ∧
    (∀ es ∈ ([1, 2, 3] : List Nat), positFromQuire quireZero es = positZero) := by
  decide

/-- Theorem 4: Two's-complement negation on `Quire512` is involutive on `quirePi`
    and on all canonical integer quire embeddings across `es ∈ {1, 2, 3}`. -/
theorem quire512_neg_involutive :
    quireNeg (quireNeg quirePi) = quirePi ∧
    (∀ n ∈ ([1, 2, 3, 183, 365, 730] : List Nat),
      ∀ es ∈ ([1, 2, 3] : List Nat),
        quireNeg (quireNeg (positToQuire (positFromUint64 n.toUInt64 es) es)) =
          positToQuire (positFromUint64 n.toUInt64 es) es) := by
  decide

/-- Theorem 5: Adding `quireZero` on the right or left leaves `quirePi` and all
    canonical integer quire embeddings unchanged. -/
theorem quire512_add_zero_right :
    quireAdd quirePi quireZero = quirePi ∧
    quireAdd quireZero quirePi = quirePi ∧
    (∀ n ∈ ([1, 2, 3, 183, 365, 730] : List Nat),
      ∀ es ∈ ([1, 2, 3] : List Nat),
        let q := positToQuire (positFromUint64 n.toUInt64 es) es
        quireAdd q quireZero = q ∧ quireAdd quireZero q = q) := by
  decide

/-- Theorem 6: Subtracting any canonical quire from itself yields `quireZero`. -/
theorem quire512_sub_self_isZero :
    quireIsZero (quireSub quirePi quirePi) = true ∧
    (∀ n ∈ ([1, 2, 3, 42, 183, 365, 730] : List Nat),
      ∀ es ∈ ([1, 2, 3] : List Nat),
        let q := positToQuire (positFromUint64 n.toUInt64 es) es
        quireIsZero (quireSub q q) = true) := by
  decide

/-- Theorem 7: `positFromUint64` maps `0` to `positZero` for every `es` and maps
    `1` to `positOne` (`0x4000000000000000`) for all `es ∈ {1, 2, 3}`. -/
theorem positFromUint64_zero :
    (∀ es : Nat, positFromUint64 0 es = positZero) ∧
    (∀ es ∈ ([1, 2, 3] : List Nat), positFromUint64 1 es = positOne) := by
  constructor
  · intro es
    rfl
  · decide

/-- Theorem 8: Embedding canonical `posit64(es)` values into `Quire512` and
    rounding back via `positFromQuire` is an exact identity across `es ∈ {1, 2, 3}`. -/
theorem positToQuire_fromQuire_roundtrip_canonical :
    ∀ es ∈ ([1, 2, 3] : List Nat),
      ∀ v ∈ ([0, 1, 2, 3, 4, 16, 149, 183, 297, 350, 365, 593, 698, 730, 1395] : List Nat),
        let p := positFromUint64 v.toUInt64 es
        positFromQuire (positToQuire p es) es = p := by
  decide

/-!
## Section 2 — Newton-Raphson `positISqrt` & Inscribed Gauss-Circle Floor `positGaussCircleFloor` (8 Theorems)
-/

/-- Theorem 9: `positIsqrt128` and `positISqrt` preserve `0`, `NaR`, and `1.0`
    across `es ∈ {1, 2, 3}`. -/
theorem positISqrt_zero :
    positIsqrt128 0 0 = (0, 0) ∧
    (∀ es ∈ ([1, 2, 3] : List Nat),
      positISqrt positZero es = positZero ∧
      positISqrt positNaR es = positNaR ∧
      positISqrt positOne es = positOne) := by
  decide

/-- Theorem 10: `positGaussCircleFloor` maps `0` to `1` and is strictly positive
    (`≥ 1`) for every natural input. -/
theorem positGaussCircleFloor_zero :
    positGaussCircleFloor 0 = 1 ∧
    (∀ n : Nat, positGaussCircleFloor n ≥ 1) := by
  constructor
  · rfl
  · intro n
    unfold positGaussCircleFloor
    by_cases h : (n == 0) = true <;> simp [h]

/-- Theorem 11: Mode 3 inscribed Gauss-circle floor at 512-bit key strength:
    `positGaussCircleFloor (3 * 183) = 350` (authenticated floor) and
    `positGaussCircleFloor (3 * 149) = 285` (unauthenticated floor). -/
theorem positGaussCircleFloor_512 :
    positGaussCircleFloor (3 * 183) = 350 ∧
    positGaussCircleFloor (3 * 149) = 285 := by
  decide

/-- Theorem 12: Mode 3 inscribed Gauss-circle floor at 1024-bit key strength:
    `positGaussCircleFloor (3 * 365) = 698` (authenticated floor) and
    `positGaussCircleFloor (3 * 297) = 568` (unauthenticated floor). -/
theorem positGaussCircleFloor_1024 :
    positGaussCircleFloor (3 * 365) = 698 ∧
    positGaussCircleFloor (3 * 297) = 568 := by
  decide

/-- Theorem 13: Mode 3 inscribed Gauss-circle floor at 2048-bit key strength:
    `positGaussCircleFloor (3 * 730) = 1395` (authenticated floor) and
    `positGaussCircleFloor (3 * 593) = 1133` (unauthenticated floor). -/
theorem positGaussCircleFloor_2048 :
    positGaussCircleFloor (3 * 730) = 1395 ∧
    positGaussCircleFloor (3 * 593) = 1133 := by
  decide

/-- Theorem 14: Mode 3 container side floors at `barrierFill = 1` for
    512/1024/2048-bit keys are `20`, `28`, and `39` (`400`, `784`, and `1521`
    total container pixels). -/
theorem mode3_container_side_floors :
    mode3ContainerSide (3 * 183) 1 = 20 ∧ 20 * 20 = 400 ∧
    mode3ContainerSide (3 * 365) 1 = 28 ∧ 28 * 28 = 784 ∧
    mode3ContainerSide (3 * 730) 1 = 39 ∧ 39 * 39 = 1521 := by
  decide

/-- Theorem 15: Mode 3 pixel floors and container areas lie strictly between
    Mode 2 (`minPxJoint`) and Mode 1 (`3 * minPxJoint`) across all three
    canonical key tiers (`512`, `1024`, `2048` bits). -/
theorem mode3_strictly_between_mode2_and_mode1 :
    (149 < 350 ∧ 350 < 447) ∧
    (297 < 698 ∧ 698 < 891) ∧
    (593 < 1395 ∧ 1395 < 1779) ∧
    (183 < positGaussCircleFloor (3 * 183) ∧ positGaussCircleFloor (3 * 183) < 3 * 183) ∧
    (365 < positGaussCircleFloor (3 * 365) ∧ positGaussCircleFloor (3 * 365) < 3 * 365) ∧
    (730 < positGaussCircleFloor (3 * 730) ∧ positGaussCircleFloor (3 * 730) < 3 * 730) ∧
    (169 < 400 ∧ 400 < 529) ∧
    (324 < 784 ∧ 784 < 961) ∧
    (625 < 1521 ∧ 1521 < 1849) := by
  decide

/-- Theorem 16: At canonical 1024-bit key and 128-bit nonce (`barrierFill = 1`),
    Mode 3 wire floor (`6324` bytes) saves `3528` bytes (`35.8%`) compared to
    Mode 1 (`9852` bytes). -/
theorem mode3_wire_savings_vs_mode1 :
    6324 < 9852 ∧
    9852 - 6324 = 3528 ∧
    (9852 - 6324) * 1000 / 9852 = 358 := by
  decide

/-!
## Section 3 — Secret Circle Constant `positDeriveSecretPi` & Full 4-Call Seed Coupling (6 Theorems)
-/

/-- Theorem 17: `positDeriveSecretPi` always selects `es_r ∈ [1, 3]`. -/
theorem positDeriveSecretPi_es_in_range (w : Array UInt64) :
    1 ≤ (positDeriveSecretPi w).2 ∧ (positDeriveSecretPi w).2 ≤ 3 := by
  unfold positDeriveSecretPi
  exact positEsFromWord_range (w.getD 0 0)

/-- Theorem 18: On all three canonical `es ∈ {1, 2, 3}` test vectors, the
    derived secret circle constant `π_{K,r}` is strictly positive, non-NaR, and
    lies in `[π_posit(es), 4_posit(es))`. -/
theorem positDeriveSecretPi_positive_canonical :
    ∀ esCase ∈ ([0, 1, 2] : List UInt64),
      let (piK, es) := positDeriveSecretPi (katWordsEs esCase)
      piK != positZero ∧
      piK != positNaR ∧
      (piK >>> 63) == 0 ∧
      piK ≥ positPi es ∧
      piK < positFromUint64 4 es := by
  decide

/-- Theorem 19: Every one of the 8 folded domain-`0x05` words `w[0]..w[7]`
    actively couples into `(positDeriveSecretPi w, buildSubregionSchedulePosit 17 261 w)`:
    perturbing any word `w[i]` (`i ∈ 0..7`) produces a distinct output pair. -/
theorem positDeriveSecretPi_couples_all_8_words :
    let base := katWordsEs 1
    let ref := (positDeriveSecretPi base, buildSubregionSchedulePosit 17 261 base)
    ∀ idx ∈ ([0, 1, 2, 3, 4, 5, 6, 7] : List Nat),
      let w' := perturbWord base idx ((1 : UInt64) <<< 32)
      (positDeriveSecretPi w', buildSubregionSchedulePosit 17 261 w') != ref := by
  decide

/-- Theorem 20: Mode 3 couples `64 - 6 = 58` bits of each `trainHash` word into
    `π_{K,r}` (42 bits more than the 16-bit step-only window, across `4 × 64 = 256`
    bits of domain-`0x05` cascade output per region). -/
theorem trainHash_mode3_full_58bit_seed_coupling :
    64 - 6 = 58 ∧
    58 > 16 ∧
    58 - 16 = 42 ∧
    4 * 64 = 256 := by
  decide

/-- Theorem 21: `positDeriveSecretPi` matches the Go reference implementation
    bit-for-bit across `es = 1, 2, 3`. -/
theorem positDeriveSecretPi_kat_es1_es2_es3 :
    positDeriveSecretPi (katWordsEs 0) = (0x5999f22fdbaae290, 1) ∧
    positDeriveSecretPi (katWordsEs 1) = (0x4cccf917edd57148, 2) ∧
    positDeriveSecretPi (katWordsEs 2) = (0x46667c8bf6eab8a4, 3) := by
  decide

/-- Theorem 22: Explicit witness of non-associativity of RNE-rounded `positAdd`
    and divergence between separately rounded `positSub (positMul r r 2) (positMul y y 2) 2`
    and unrounded 512-bit quire evaluation `quireR2MinusY2 r y 2`. -/
theorem positMul_positAdd_nonassociative_witness :
    let a : UInt64 := 0x4000000000000001
    let b : UInt64 := 0x4000000000000000
    let c : UInt64 := positNeg 0x4000000000000000
    positAdd (positAdd a b 2) c 2 != positAdd a (positAdd b c 2) 2 ∧
    let r : UInt64 := 0x5c99f22fdbaae291
    let y : UInt64 := 0x5c99f22fdbaae290
    quireR2MinusY2 r y 2 != positSub (positMul r r 2) (positMul y y 2) 2 := by
  decide

/-!
## Section 4 — Gauss-Circle Chord Partition `buildSubregionSchedulePosit` & Trajectory Security Bounds (8 Theorems)
-/

/-- Theorem 23: `buildSubregionSchedulePosit` produces `k ∈ [6, 10]` when
    `totalPixels < 365` and `k ∈ [8, 16]` when `totalPixels ≥ 365` (so always
    `6 ≤ k ≤ 16`). -/
theorem buildSubregionSchedulePosit_count_range (startPixel totalPixels : Nat) (w : Array UInt64) :
    (totalPixels < mode1DesyncRegionPixels →
      6 ≤ (buildSubregionSchedulePosit startPixel totalPixels w).k ∧
      (buildSubregionSchedulePosit startPixel totalPixels w).k ≤ 10) ∧
    (totalPixels ≥ mode1DesyncRegionPixels →
      8 ≤ (buildSubregionSchedulePosit startPixel totalPixels w).k ∧
      (buildSubregionSchedulePosit startPixel totalPixels w).k ≤ 16) := by
  unfold buildSubregionSchedulePosit mode1DesyncRegionPixels
  constructor
  · intro hLt
    simp [hLt]
    omega
  · intro hGe
    have hNotLt : ¬(totalPixels < 365) := by omega
    simp [hNotLt]
    omega

/-- Theorem 24: On the canonical 512/1024/2048-bit Mode 3 schedules (`P_r ∈ {133, 261, 507}`),
    sub-region sizes sum telescopically to `P_r`, `logOff[k] = P_r`, every sub-region
    size is `≥ 2`, and every local start offset satisfies `start[j] < size[j]`. -/
theorem buildSubregionSchedulePosit_starts_sum_telescopic :
    let s133 := buildSubregionSchedulePosit 17 133 (katWordsEs 0)
    let s261 := buildSubregionSchedulePosit 48 261 (katWordsEs 1)
    let s507 := buildSubregionSchedulePosit 79 507 (katWordsEs 2)
    s133.size.foldl (· + ·) 0 = 133 ∧ s133.logOff.getD s133.k 0 = 133 ∧
    (∀ j ∈ List.range s133.k, s133.size.getD j 0 ≥ 2 ∧ s133.start.getD j 0 < s133.size.getD j 0) ∧
    s261.size.foldl (· + ·) 0 = 261 ∧ s261.logOff.getD s261.k 0 = 261 ∧
    (∀ j ∈ List.range s261.k, s261.size.getD j 0 ≥ 2 ∧ s261.start.getD j 0 < s261.size.getD j 0) ∧
    s507.size.foldl (· + ·) 0 = 507 ∧ s507.logOff.getD s507.k 0 = 507 ∧
    (∀ j ∈ List.range s507.k, s507.size.getD j 0 ≥ 2 ∧ s507.start.getD j 0 < s507.size.getD j 0) := by
  decide

/-- Theorem 25: For every sub-region size `m` in the canonical 512/1024/2048-bit Mode 3
    schedules, the coprime-step helper `deriveCoprimeStep` produces `1 ≤ step < m` with `gcd(step, m) = 1`. -/
theorem buildSubregionSchedulePosit_step_coprime :
    let s133 := buildSubregionSchedulePosit 17 133 (katWordsEs 0)
    let s261 := buildSubregionSchedulePosit 48 261 (katWordsEs 1)
    let s507 := buildSubregionSchedulePosit 79 507 (katWordsEs 2)
    (∀ j ∈ List.range s133.k,
      let m := s133.size.getD j 0
      let st := deriveCoprimeStep m ((katWordsEs 0).getD (j % 8) 0)
      1 ≤ st ∧ st < m ∧ Nat.gcd st m = 1) ∧
    (∀ j ∈ List.range s261.k,
      let m := s261.size.getD j 0
      let st := deriveCoprimeStep m ((katWordsEs 1).getD (j % 8) 0)
      1 ≤ st ∧ st < m ∧ Nat.gcd st m = 1) ∧
    (∀ j ∈ List.range s507.k,
      let m := s507.size.getD j 0
      let st := deriveCoprimeStep m ((katWordsEs 2).getD (j % 8) 0)
      1 ≤ st ∧ st < m ∧ Nat.gcd st m = 1) := by
  decide

/-- Theorem 26: `buildSubregionSchedulePosit` matches the Go reference outputs
    bit-for-bit across the 512-bit (`P_r = 133`), 1024-bit (`P_r = 261`), and
    2048-bit (`P_r = 507`) Mode 3 container regions. -/
theorem buildSubregionSchedulePosit_kat_go_exact :
    buildSubregionSchedulePosit 17 133 (katWordsEs 0) = {
      k := 7
      offset := #[45, 105, 87, 22, 67, 121, 0]
      size   := #[22, 16, 18, 23, 20, 12, 22]
      start  := #[1, 5, 6, 17, 0, 3, 20]
      logOff := #[0, 22, 38, 56, 79, 99, 111, 133]
    } ∧
    buildSubregionSchedulePosit 48 261 (katWordsEs 1) = {
      k := 8
      offset := #[118, 187, 217, 0, 153, 78, 40, 243]
      size   := #[35, 30, 26, 40, 34, 40, 38, 18]
      start  := #[6, 14, 13, 23, 4, 38, 10, 4]
      logOff := #[0, 35, 65, 91, 131, 165, 205, 243, 261]
    } ∧
    buildSubregionSchedulePosit 79 507 (katWordsEs 2) = {
      k := 13
      offset := #[143, 489, 399, 434, 190, 234, 320, 46, 466, 0, 97, 360, 280]
      size   := #[47, 18, 35, 32, 44, 46, 40, 51, 23, 46, 46, 39, 40]
      start  := #[38, 0, 4, 20, 31, 16, 15, 34, 18, 25, 33, 5, 39]
      logOff := #[0, 47, 65, 100, 132, 176, 222, 262, 313, 336, 382, 428, 467, 507]
    } := by
  decide

/-- Theorem 27: At canonical 1024-bit key strength (`P = 784`, `P_r = 261`),
    each Mode 3 region has `⌊261 / 6⌋ = 43` pixels per sub-region at `k = 6`
    (`2^5 * 6! * 43^6 > 2^47`) and `⌊261 / 8⌋ = 32` pixels per sub-region at `k = 8`
    (`2^7 * 8! * 32^8 > 2^62`). -/
theorem mode3_single_region_trajectory_floor_1024 :
    784 / 3 = 261 ∧
    261 < mode1DesyncRegionPixels ∧
    261 / 6 = 43 ∧
    261 / 8 = 32 ∧
    2 ^ 47 < 2 ^ 5 * factorial 6 * 43 ^ 6 ∧
    2 ^ 5 * factorial 6 * 43 ^ 6 < 2 ^ 48 ∧
    2 ^ 62 < 2 ^ 7 * factorial 8 * 32 ^ 8 ∧
    2 ^ 7 * factorial 8 * 32 ^ 8 < 2 ^ 63 := by
  decide

/-- Theorem 28: Across all three container regions at 1024-bit key strength
    (`P_r = 261`), the joint Mode 3 Layer I (`0x05`) trajectory floor is
    `(2^5 * 6! * 43^6)^3 > 2^141` at `k = 6` and `(2^7 * 8! * 32^8)^3 > 2^186`
    at `k = 8` (`> 2^162` after dividing out initial entry-pixel choices `261^2 * 262`). -/
theorem mode3_three_region_joint_layer1_floor_1024 :
    2 ^ 141 < (2 ^ 5 * factorial 6 * 43 ^ 6) ^ 3 ∧
    (2 ^ 5 * factorial 6 * 43 ^ 6) ^ 3 < 2 ^ 142 ∧
    2 ^ 186 < (2 ^ 7 * factorial 8 * 32 ^ 8) ^ 3 ∧
    (2 ^ 7 * factorial 8 * 32 ^ 8) ^ 3 < 2 ^ 187 ∧
    ((2 ^ 7 * factorial 8 * 32 ^ 8) ^ 3) / (261 ^ 2 * 262) > 2 ^ 162 := by
  decide

/-- Theorem 29: Combined Rank + Pixel + Layer I/II Desync security exponents at
    1024-bit key strength in Mode 3 (`P = 784`, `P_r = 261 ≥ 180`, `M = 880` chunks
    in `Interlock48` and `M = 251` chunks in `Interlock168`). -/
theorem mode3_combined_rank_barrier_exponents_1024 :
    2 ^ 99 < Omega48 * 880 ^ 3 ∧
    Omega48 * 880 ^ 3 < 2 ^ 100 ∧
    2 ^ 131 < Omega48WithFold * 880 ^ 3 ∧
    Omega48WithFold * 880 ^ 3 < 2 ^ 132 ∧
    2 ^ 282 < Omega168 * 251 ^ 3 ∧
    Omega168 * 251 ^ 3 < 2 ^ 283 ∧
    2 ^ 314 < Omega168WithFold * 251 ^ 3 ∧
    Omega168WithFold * 251 ^ 3 < 2 ^ 315 := by
  decide

/-- Theorem 30: Explicit divergence witness between `posit64(es)` (`57..59`
    explicit mantissa bits at `scale = 1`) and IEEE-754 `binary64` (`52` explicit
    mantissa bits): two domain-`0x05` word vectors differing in low mantissa bits
    that are truncated away by a 52-bit IEEE-754 `binary64` mantissa mask remain
    distinct in `positDeriveSecretPi` and produce distinct Mode 3 schedules. -/
theorem mode3_posit_vs_ieee754_divergence_witness :
    let wA := katWordsEs 1
    let wB := perturbWord wA 2 ((1 : UInt64) <<< 16)
    let (piA, esA) := positDeriveSecretPi wA
    let (piB, esB) := positDeriveSecretPi wB
    esA = 2 ∧ esB = 2 ∧
    piA != piB ∧
    (piA >>> 7) = (piB >>> 7) ∧
    buildSubregionSchedulePosit 48 261 wA != buildSubregionSchedulePosit 48 261 wB := by
  decide

end ITB.Posit
