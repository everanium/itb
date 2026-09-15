//go:build arm64 && !purego && !noitbasm

// arm64 arm of package interlock: the NEON batched rank-unrank kernel
// for the 48-bit interlock mask derivation. The per-chunk PEXT / PDEP
// entry points (Chunk48Lock / Unchunk48Lock) stay on the pure-Go
// softPEXT48 / softPDEP48 path of the parent package on arm64
// (HasBMI2 is false here); the batched chunk-apply lives in
// interlockasm48_batch_arm64.go.
package interlock

// HasNEONInterlock selects the NEON 8-lane batched rank-unrank kernel
// ([RankToMaskTripleUnrank48NEON]). Advanced SIMD is mandatory in
// ARMv8-A, so the flag is true on every arm64 host; it exists so
// ITB_FORCE_INTERLOCK_TIER=scalar can clear it for cross-tier parity
// runs.
var HasNEONInterlock = true

// crow48Table holds C(p, 0..16) in lanes 0..16 — the canonical binomial
// rows of the combinatorial-number-system unrank. Init source for the
// kernel-facing [crow48PackedNEON] repack and the independent oracle
// for this package's parity tests; the kernel itself reads only
// crow48PackedNEON.
var crow48Table [49][17]uint64

func init() {
	var c [49][17]uint64
	for n := 0; n <= 48; n++ {
		c[n][0] = 1
		for k := 1; k <= 16 && k <= n; k++ {
			c[n][k] = c[n-1][k-1] + c[n-1][k]
		}
	}
	crow48Table = c
}

// crow48PackedNEON is the binomial table repacked for the NEON kernel's
// byte-index TBX gather: row p, slot s (s = 0..15, 8 bytes each) holds
// C(p, 16 - s), i.e. the row is indexed by the number of positions
// already picked rather than by the remaining count. Slot 16 (C(p, 0))
// is deliberately absent: an index past the 128-byte row falls outside
// both TBX table windows, and the all-ones seed the kernel loads into
// the gather destination survives as the "no further pick" sentinel
// (rank >= 0xFFFF_FFFF_FFFF_FFFF is false for every rank < C(48, 16)).
var crow48PackedNEON [49][16]uint64

func init() {
	for n := 0; n <= 48; n++ {
		for s := 0; s < 16; s++ {
			crow48PackedNEON[n][s] = crow48Table[n][16-s]
		}
	}
}

// RankToMaskTripleUnrank48NEON derives 8 balanced (m0, m1, m2) 48-bit
// mask triples from 8 precomputed combinadic index pairs — the same
// contract as the amd64 RankToMaskTripleUnrank48: idx0[j] in
// [0, C(48,16)) selects the 16-of-48 mask m0, idx1[j] in [0, C(32,16))
// selects the 16-of-32 mask remapped onto the positions m0 leaves free
// (m1), and m2 is the complement. Output: out[0] = m0 lanes, out[1] =
// m1, out[2] = m2. Caller gates on [HasNEONInterlock].
//
// Constant-time: the binomial row address depends only on the public
// loop position; the secret per-lane pick count is consumed by
// register-only, data-oblivious operations (TBX register permute, CMHS
// predicates, AND-masked updates), so neither the memory-access pattern
// nor the control flow depends on the secret indices — the invariant the
// amd64 kernels establish for VPERMT2Q / VPERMD. The remap stage is a
// fixed 48-step vector walk with per-lane variable shifts (USHL), also
// data-oblivious.
func RankToMaskTripleUnrank48NEON(idx0 *[8]uint64, idx1 *[8]uint32, out *[3][8]uint64) {
	rankToMaskTripleUnrank48NEON(idx0, idx1, &crow48PackedNEON, out)
}

//go:noescape
func rankToMaskTripleUnrank48NEON(idx0 *[8]uint64, idx1 *[8]uint32, crow *[49][16]uint64, out *[3][8]uint64)
