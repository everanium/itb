//go:build !amd64 || purego || noitbasm

package interlock

// Chunk168Lock should never be called on non-amd64 builds — the parent
// package's dispatch routes to the portable Go fallback when HasBMI2 is
// false. Kept as a callable stub so the import resolves cleanly.
func Chunk168Lock(src *[21]byte, m0, m1, m2 [3]uint64, out *[3][7]byte) {
	panic("interlock: Chunk168Lock unavailable on non-amd64 build")
}

// Unchunk168Lock — same stubbed behaviour as Chunk168Lock.
func Unchunk168Lock(p0, p1, p2 *[7]byte, m0, m1, m2 [3]uint64, dst *[21]byte) {
	panic("interlock: Unchunk168Lock unavailable on non-amd64 build")
}

// RankToMaskTripleUnrank168 should never be called when
// HasAVX512RankMask is false — the parent package's dispatch routes to
// the scalar rankToMaskTriple168. Kept as a callable stub so the import
// resolves cleanly.
func RankToMaskTripleUnrank168(idx0 *[3][8]uint64, idx1 *[2][8]uint64, out *[3][3][8]uint64) {
	panic("interlock: RankToMaskTripleUnrank168 unavailable on this build")
}

// RankToMaskTripleUnrank168AVX2 should never be called when
// HasAVX2RankMask is false — the parent package's dispatch routes to
// the scalar rankToMaskTriple168. Kept as a callable stub so the import
// resolves cleanly.
func RankToMaskTripleUnrank168AVX2(idx0 *[3][8]uint64, idx1 *[2][8]uint64, out *[3][3][8]uint64) {
	panic("interlock: RankToMaskTripleUnrank168AVX2 unavailable on this build")
}
