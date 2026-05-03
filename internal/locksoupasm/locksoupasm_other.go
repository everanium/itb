//go:build !amd64 || purego || noitbasm

// Stub package on platforms where the BMI2 PEXT/PDEP assembly path does
// not apply. The parent `itb` package always uses its portable Go
// softPEXT24 / softPDEP24 fallback in this case; nothing here is
// exercised.
package locksoupasm

// HasBMI2 is always false on non-amd64 builds.
const HasBMI2 = false

// Chunk24Lock should never be called on non-amd64 builds — the parent
// package's dispatch routes to the portable Go fallback when HasBMI2
// is false. Kept as a callable stub so the import resolves cleanly.
func Chunk24Lock(x, m0, m1, m2 uint32) (l0, l1, l2 uint32) {
	panic("locksoupasm: Chunk24Lock unavailable on non-amd64 build")
}

// Unchunk24Lock — same stubbed behaviour as Chunk24Lock.
func Unchunk24Lock(l0, l1, l2, m0, m1, m2 uint32) (x uint32) {
	panic("locksoupasm: Unchunk24Lock unavailable on non-amd64 build")
}

// HasAVX512Permute is always false on non-amd64 builds.
const HasAVX512Permute = false

// Permute24Avx512 should never be called on non-amd64 builds — the parent
// package's dispatch routes to softPermute24 when HasAVX512Permute is
// false. Kept as a callable stub so the import resolves cleanly.
func Permute24Avx512(x uint32, perm *[32]byte) (y uint32) {
	panic("locksoupasm: Permute24Avx512 unavailable on non-amd64 build")
}
