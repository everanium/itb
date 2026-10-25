//go:build !arm64 || purego || noitbasm

package interlock

// RankToMaskTripleUnrank168NEON should never be called when
// HasNEONInterlock is false — the parent package's dispatch routes to
// the scalar rankToMaskTriple168. Kept as a callable stub so the import
// resolves cleanly.
func RankToMaskTripleUnrank168NEON(idx0 *[3][8]uint64, idx1 *[2][8]uint64, out *[3][3][8]uint64) {
	panic("interlock: RankToMaskTripleUnrank168NEON unavailable on this build")
}
