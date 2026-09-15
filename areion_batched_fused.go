package itb

import "github.com/everanium/itb/internal/areionasm"

// areionSoEM256BatchedFused evaluates the four lanes of the Areion-SoEM-256
// batched arm through the single-lane fused cascade kernel of
// internal/areionasm when an assembly tier is selected and the common
// lane length (the caller guards the equal-length contract) is one of
// the kernel shapes: one component
// group per lane is exactly one SoEM chain absorb keyed
// fixedKey ‖ seed, so the result is bit-exact with the single arm (the
// invariant the areionasm parity tests and the hashes known-answer
// vectors pin). false sends the caller to the four-way permutation
// path.
func areionSoEM256BatchedFused(fixedKey *[32]byte, seeds *[4][4]uint64, data *[4][]byte, commonLen int) (out [4][4]uint64, ok bool) {
	if !areionasm.FusedAvailable() {
		return out, false
	}
	switch commonLen {
	case 13:
		for lane := range out {
			areionasm.Fused256Chain13x1(fixedKey, seeds[lane][:], &data[lane][0], &out[lane])
		}
	case 20:
		for lane := range out {
			areionasm.Fused256Chain20x1(fixedKey, seeds[lane][:], &data[lane][0], &out[lane])
		}
	case 36:
		for lane := range out {
			areionasm.Fused256Chain36x1(fixedKey, seeds[lane][:], &data[lane][0], &out[lane])
		}
	case 68:
		for lane := range out {
			areionasm.Fused256Chain68x1(fixedKey, seeds[lane][:], &data[lane][0], &out[lane])
		}
	default:
		return out, false
	}
	return out, true
}

// areionSoEM512BatchedFused is the width-512 form of
// [areionSoEM256BatchedFused].
func areionSoEM512BatchedFused(fixedKey *[64]byte, seeds *[4][8]uint64, data *[4][]byte, commonLen int) (out [4][8]uint64, ok bool) {
	if !areionasm.FusedAvailable() {
		return out, false
	}
	switch commonLen {
	case 13:
		for lane := range out {
			areionasm.Fused512Chain13x1(fixedKey, seeds[lane][:], &data[lane][0], &out[lane])
		}
	case 20:
		for lane := range out {
			areionasm.Fused512Chain20x1(fixedKey, seeds[lane][:], &data[lane][0], &out[lane])
		}
	case 36:
		for lane := range out {
			areionasm.Fused512Chain36x1(fixedKey, seeds[lane][:], &data[lane][0], &out[lane])
		}
	case 68:
		for lane := range out {
			areionasm.Fused512Chain68x1(fixedKey, seeds[lane][:], &data[lane][0], &out[lane])
		}
	default:
		return out, false
	}
	return out, true
}
