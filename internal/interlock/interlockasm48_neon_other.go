//go:build !arm64 || purego || noitbasm

package interlock

// HasNEONInterlock is always false on non-arm64 / purego / noitbasm.
const HasNEONInterlock = false

// HasSVE2Interlock is always false on non-arm64 / purego / noitbasm.
const HasSVE2Interlock = false

// RankToMaskTripleUnrank48NEON should never be called when
// HasNEONInterlock is false — the parent package's dispatch routes to
// the scalar rankToMaskTriple48. Kept as a callable stub so the import
// resolves cleanly.
func RankToMaskTripleUnrank48NEON(idx0 *[8]uint64, idx1 *[8]uint32, out *[3][8]uint64) {
	panic("interlock: RankToMaskTripleUnrank48NEON unavailable on this build")
}
