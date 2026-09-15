//go:build amd64 && !purego && !noitbasm

package interlock

// UseUnrank16 selects the 16-lane AVX-512 rank-unrank kernel
// ([RankToMaskTripleUnrank48x16]) for a 16-chunk superblock; when false
// the superblock runs as two 8-lane [RankToMaskTripleUnrank48] passes.
// Both arms are bit-exact; the flag is a dispatch choice. It defaults to
// the AVX-512 capability flag and exists so the geometry can be pinned
// per microarchitecture or forced in tests.
var UseUnrank16 = HasAVX512RankMask

// RankToMaskTripleUnrank48x16 derives 16 balanced (m0, m1, m2) 48-bit
// mask triples from 16 precomputed combinadic index pairs — the
// [RankToMaskTripleUnrank48] contract over two batches of 8 lanes,
// evaluated in one interleaved pass. Output: out[0] = m0 lanes, out[1]
// = m1, out[2] = m2, lane j in [0, 16). Constant-time under the same
// invariants as the 8-lane kernel (see interlockasm48_x16_amd64.s).
// Caller gates on [HasAVX512RankMask].
func RankToMaskTripleUnrank48x16(idx0 *[16]uint64, idx1 *[16]uint32, out *[3][16]uint64) {
	rankToMaskTripleUnrank48x16AVX512(idx0, idx1, crow48Packed, out)
}

//go:noescape
func rankToMaskTripleUnrank48x16AVX512(idx0 *[16]uint64, idx1 *[16]uint32, crow *[49][16]uint64, out *[3][16]uint64)
