//go:build (!amd64 && !arm64) || purego || noitbasm

package siphashasm

// No assembly tier applies on this build; the fused dispatchers run the
// pure-Go cascade.
var (
	FusedHasAVX512 = false
	FusedHasAVX2   = false
	FusedHasNEON   = false
)

// FusedAvailable is always false on this build.
func FusedAvailable() bool { return false }

func FusedChain13x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarFusedBatch(components, dataPtrs, 13, out)
}
func FusedChain20x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarFusedBatch(components, dataPtrs, 20, out)
}
func FusedChain36x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarFusedBatch(components, dataPtrs, 36, out)
}
func FusedChain68x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarFusedBatch(components, dataPtrs, 68, out)
}
func FusedChain13x1(components []uint64, data *byte, out *[2]uint64) {
	scalarFusedSingle(components, data, 13, out)
}
func FusedChain20x1(components []uint64, data *byte, out *[2]uint64) {
	scalarFusedSingle(components, data, 20, out)
}
func FusedChain36x1(components []uint64, data *byte, out *[2]uint64) {
	scalarFusedSingle(components, data, 36, out)
}
func FusedChain68x1(components []uint64, data *byte, out *[2]uint64) {
	scalarFusedSingle(components, data, 68, out)
}
func FusedChain13x16(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	scalarFusedX16(components, groupIdxBase, out)
}
