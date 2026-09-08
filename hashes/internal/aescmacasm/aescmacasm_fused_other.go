//go:build (!amd64 && !arm64) || purego || noitbasm

package aescmacasm

// No assembly tier applies on this build; the fused dispatchers run the
// pure-Go cascade.
var (
	FusedHasVAESAVX512 = false
	FusedHasVAESAVX2   = false
	FusedHasAVXAESNI   = false
	FusedHasAESNI      = false
	FusedHasARMAES     = false
)

// FusedAvailable is always false on this build.
func FusedAvailable() bool { return false }

func FusedChain13x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarFusedBatch(s, components, dataPtrs, 13, out)
}
func FusedChain20x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarFusedBatch(s, components, dataPtrs, 20, out)
}
func FusedChain36x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarFusedBatch(s, components, dataPtrs, 36, out)
}
func FusedChain68x4(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	scalarFusedBatch(s, components, dataPtrs, 68, out)
}
func FusedChain13x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	scalarFusedSingle(s, components, data, 13, out)
}
func FusedChain20x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	scalarFusedSingle(s, components, data, 20, out)
}
func FusedChain36x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	scalarFusedSingle(s, components, data, 36, out)
}
func FusedChain68x1(s *Schedule, components []uint64, data *byte, out *[2]uint64) {
	scalarFusedSingle(s, components, data, 68, out)
}
func FusedChain13x16(s *Schedule, components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	scalarFusedX16(s, components, groupIdxBase, out)
}
