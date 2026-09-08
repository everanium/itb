//go:build (!amd64 && !arm64) || purego || noitbasm

package chacha20asm

// No fused kernel on this build: every flag is false and every entry
// point runs the pure-Go cascade.
var (
	FusedHasAVX512 = false
	FusedHasAVX2   = false
	FusedHasNEON   = false
	HasAVX512X16   = false
	HasAVX2X16     = false
	HasNEONX16     = false
)

// FusedAvailable is always false on this build.
func FusedAvailable() bool { return false }

func Fused256Chain13x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	scalarFused256X4(fixedKey, components, dataPtrs, 13, out)
}
func Fused256Chain13x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 13))
}

func Fused256Chain20x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	scalarFused256X4(fixedKey, components, dataPtrs, 20, out)
}
func Fused256Chain20x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 20))
}

func Fused256Chain36x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	scalarFused256X4(fixedKey, components, dataPtrs, 36, out)
}
func Fused256Chain36x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 36))
}

func Fused256Chain68x4(fixedKey *[32]byte, components []uint64, dataPtrs *[4]*byte, out *[4][4]uint64) {
	scalarFused256X4(fixedKey, components, dataPtrs, 68, out)
}
func Fused256Chain68x1(fixedKey *[32]byte, components []uint64, data *byte, out *[4]uint64) {
	*out = ScalarFusedChain256(fixedKey, components, lanePtr(data, 68))
}

func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	scalarFill256X8(fixedKey, components, groupIdxBase, out)
}

// Eight-lane per-pixel arm: absent on this build.
var FusedHasAVX512X8 = false

// FusedX8Active is always false on this build.
func FusedX8Active() bool { return false }

func Fused256Chain20x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	scalarFused256X8(fixedKey, components, dataPtrs, 20, out)
}
func Fused256Chain36x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	scalarFused256X8(fixedKey, components, dataPtrs, 36, out)
}
func Fused256Chain68x8(fixedKey *[32]byte, components []uint64, dataPtrs *[8]*byte, out *[8][4]uint64) {
	scalarFused256X8(fixedKey, components, dataPtrs, 68, out)
}
