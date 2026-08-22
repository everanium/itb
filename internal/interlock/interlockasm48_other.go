//go:build !amd64 || purego || noitbasm

// Stub package on platforms where the BMI2 PEXTQ / PDEPQ assembly
// path does not apply. The parent `itb` package always uses its
// portable Go softPEXT48 / softPDEP48 fallback in this case; nothing
// here is exercised.
package interlock

// HasBMI2 is always false on non-amd64 builds.
const HasBMI2 = false

// Chunk48Lock should never be called on non-amd64 builds — the parent
// package's dispatch routes to the portable Go fallback when HasBMI2
// is false. Kept as a callable stub so the import resolves cleanly.
func Chunk48Lock(x, m0, m1, m2 uint64) (l0, l1, l2 uint64) {
	panic("interlock: Chunk48Lock unavailable on non-amd64 build")
}

// Unchunk48Lock — same stubbed behaviour as Chunk48Lock.
func Unchunk48Lock(l0, l1, l2, m0, m1, m2 uint64) (x uint64) {
	panic("interlock: Unchunk48Lock unavailable on non-amd64 build")
}

// HasAVX512RankMask is always false on non-amd64 / purego / noitbasm.
const HasAVX512RankMask = false

// RankToMaskTripleUnrank48 should never be called when
// HasAVX512RankMask is false — the parent package's dispatch routes
// to the scalar rankToMaskTriple48. Kept as a callable stub so the
// import resolves cleanly.
func RankToMaskTripleUnrank48(idx0 *[8]uint64, idx1 *[8]uint32, out *[3][8]uint64) {
	panic("interlock: RankToMaskTripleUnrank48 unavailable on this build")
}
