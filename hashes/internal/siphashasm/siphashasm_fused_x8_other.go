//go:build !amd64 || purego || noitbasm

package siphashasm

// No eight-lane kernel applies on this build; the eight-lane dispatchers
// run two four-lane calls of the build's x4 dispatcher (NEON on arm64,
// the pure-Go cascade elsewhere).
var FusedHasAVX512X8 = false

// FusedX8Active is always false on this build.
func FusedX8Active() bool { return false }

func FusedChain20x8(components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	fusedChainX8ViaX4(20, components, dataPtrs, out)
}
func FusedChain36x8(components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	fusedChainX8ViaX4(36, components, dataPtrs, out)
}
func FusedChain68x8(components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	fusedChainX8ViaX4(68, components, dataPtrs, out)
}
