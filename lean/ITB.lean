/-
  Root entry point for the ITB Lean 4 formal verification suite.
  Imports all six verification modules covering Proofs 1 through 12
  (including 3a, 3b, 4a, and both 48-bit and 168-bit Rank Barrier modes),
  Byte-Splitting (`gcd(7, 8) = 1`), MAC-Inside-Encrypt Composition,
  Nonce Uniqueness, and Two-Layer Sub-Region & Lane Desynchronization (`ITB.Desync`).
-/
import ITB.Thresholds
import ITB.RankBarrier
import ITB.PixelBarrier
import ITB.SplitRank
import ITB.SeedIsolation
import ITB.Desync
