//go:build !amd64 || purego || noitbasm

// Stub arm of the keccakasm package on platforms (or build modes)
// where the AVX-512 kernel does not apply. The parent macs/ package
// keeps using the stdlib-backed x/crypto cSHAKE256 in this case; the
// portable permutation here only serves tests.
package keccakasm

// HasAVX512Fused is always false on non-amd64 / purego / noitbasm
// builds.
var HasAVX512Fused = false

// asmCompiled reports whether this build carries the AVX-512 kernel
// at all (build-tag arm).
const asmCompiled = false

// keccakF1600 applies the Keccak-f[1600] permutation in place via the
// portable scalar implementation.
func keccakF1600(a *[25]uint64) {
	keccakF1600Generic(a)
}

// absorbBlock absorbs one full rate block via the portable arm.
func absorbBlock(a *[25]uint64, block []byte) {
	absorbBlockGeneric(a, block)
}
