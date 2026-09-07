//go:build !amd64 || purego || noitbasm

package aesitbasm

// No eight-lane kernel applies on this build; the eight-lane dispatchers
// run two four-lane calls of the build's x4 dispatcher (NEON on arm64
// hosts with the AES extension, the pure-Go cascade elsewhere).
var FusedHasVAESAVX512X8 = false

// FusedX8Active is always false on this build.
func FusedX8Active() bool { return false }

func FusedChain20x8(key *[16]byte, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	fusedChainX8ViaX4(FusedChain20x4, key, components, dataPtrs, out)
}
func FusedChain36x8(key *[16]byte, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	fusedChainX8ViaX4(FusedChain36x4, key, components, dataPtrs, out)
}
func FusedChain68x8(key *[16]byte, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	fusedChainX8ViaX4(FusedChain68x4, key, components, dataPtrs, out)
}
