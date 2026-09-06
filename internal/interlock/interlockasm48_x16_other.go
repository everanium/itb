//go:build !amd64 || purego || noitbasm

package interlock

// UseUnrank16 is always false on non-amd64 / purego / noitbasm builds.
var UseUnrank16 = false

// RankToMaskTripleUnrank48x16 should never be called on these builds —
// the parent package dispatches to the scalar path when
// HasAVX512RankMask is false. Kept as a callable stub so the import
// resolves cleanly.
func RankToMaskTripleUnrank48x16(idx0 *[16]uint64, idx1 *[16]uint32, out *[3][16]uint64) {
	panic("interlock: RankToMaskTripleUnrank48x16 unavailable on this build")
}
