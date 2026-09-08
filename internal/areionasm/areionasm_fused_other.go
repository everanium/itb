//go:build (!amd64 && !arm64) || purego || noitbasm

package areionasm

// No fused kernel applies on this build; every dispatcher runs the
// pure-Go cascade.
var (
	FusedHasVAESAVX512 = false
	FusedHasVAESAVX2   = false
	FusedHasAESNI      = false
	FusedHasARMAES     = false
	HasVAESAVX512X16   = false
	HasVAESAVX2X16     = false
	HasAESNIX16        = false
	HasARMAESX16       = false
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

func Fused512Chain13x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	scalarFused512X4(fixedKey, components, dataPtrs, 13, out)
}
func Fused512Chain13x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 13))
}

func Fused512Chain20x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	scalarFused512X4(fixedKey, components, dataPtrs, 20, out)
}
func Fused512Chain20x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 20))
}

func Fused512Chain36x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	scalarFused512X4(fixedKey, components, dataPtrs, 36, out)
}
func Fused512Chain36x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 36))
}

func Fused512Chain68x4(fixedKey *[64]byte, components []uint64, dataPtrs *[4]*byte, out *[4][8]uint64) {
	scalarFused512X4(fixedKey, components, dataPtrs, 68, out)
}
func Fused512Chain68x1(fixedKey *[64]byte, components []uint64, data *byte, out *[8]uint64) {
	*out = ScalarFusedChain512(fixedKey, components, lanePtr(data, 68))
}

func Fused256Fill13x8(fixedKey *[32]byte, components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
	scalarFill256X8(fixedKey, components, groupIdxBase, out)
}
func Fused512Fill13x4(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[4][8]uint64) {
	scalarFill512X4(fixedKey, components, groupIdxBase, out)
}

// Eight-lane per-pixel arm: absent on this build.
var FusedHasVAESAVX512X8 = false

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
func Fused512Chain20x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	scalarFused512X8(fixedKey, components, dataPtrs, 20, out)
}
func Fused512Chain36x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	scalarFused512X8(fixedKey, components, dataPtrs, 36, out)
}
func Fused512Chain68x8(fixedKey *[64]byte, components []uint64, dataPtrs *[8]*byte, out *[8][8]uint64) {
	scalarFused512X8(fixedKey, components, dataPtrs, 68, out)
}
func Fused512Fill13x8(fixedKey *[64]byte, components []uint64, groupIdxBase uint64, out *[8][8]uint64) {
	scalarFill512X8(fixedKey, components, groupIdxBase, out)
}
