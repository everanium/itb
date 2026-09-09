//go:build arm64 && !purego && !noitbasm

package siphashasm

var (
	// FusedHasNEON selects the NEON four-lane kernels and the GPR
	// single-lane kernel on arm64. NEON is part of the ARMv8-A baseline,
	// so the flag is true unless ITB_FORCE_HASH_TIER=scalar clears it.
	FusedHasNEON = true

	FusedHasAVX512 = false
	FusedHasAVX2   = false
)

// FusedHasGPR arms the single-lane general-purpose-register kernels, the
// single-lane arm of every tier: true on every arm64 build, cleared by
// ITB_FORCE_HASH_TIER=scalar.
var FusedHasGPR = true

// HasGPRX16 is the general-purpose-register arm of the batch-16 fill
// hook; cleared by ITB_FORCE_INTERLOCK_PRF_FILL_TIER=scalar and by
// ITB_FORCE_HASH_TIER=scalar.
var HasGPRX16 = true

// FusedAvailable reports whether the NEON tier or the GPR arm is selected.
func FusedAvailable() bool { return FusedHasNEON || FusedHasGPR }

func FusedChain13x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(components, dataPtrs, 13, out)
		return
	}
	c, np := &components[0], len(components)/2
	switch {
	case FusedHasNEON:
		sipHash24FusedChain13x4NeonAsm(c, np, dataPtrs, out)
	case FusedHasGPR:
		for l := range dataPtrs {
			sipHash24FusedChain13x1GprAsm(c, np, dataPtrs[l], &out[l])
		}
	default:
		scalarFusedBatch(components, dataPtrs, 13, out)
	}
}
func FusedChain20x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(components, dataPtrs, 20, out)
		return
	}
	c, np := &components[0], len(components)/2
	switch {
	case FusedHasNEON:
		sipHash24FusedChain20x4NeonAsm(c, np, dataPtrs, out)
	case FusedHasGPR:
		for l := range dataPtrs {
			sipHash24FusedChain20x1GprAsm(c, np, dataPtrs[l], &out[l])
		}
	default:
		scalarFusedBatch(components, dataPtrs, 20, out)
	}
}
func FusedChain36x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(components, dataPtrs, 36, out)
		return
	}
	c, np := &components[0], len(components)/2
	switch {
	case FusedHasNEON:
		sipHash24FusedChain36x4NeonAsm(c, np, dataPtrs, out)
	case FusedHasGPR:
		for l := range dataPtrs {
			sipHash24FusedChain36x1GprAsm(c, np, dataPtrs[l], &out[l])
		}
	default:
		scalarFusedBatch(components, dataPtrs, 36, out)
	}
}
func FusedChain68x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if !validComponents(components) {
		scalarFusedBatch(components, dataPtrs, 68, out)
		return
	}
	c, np := &components[0], len(components)/2
	switch {
	case FusedHasNEON:
		sipHash24FusedChain68x4NeonAsm(c, np, dataPtrs, out)
	case FusedHasGPR:
		for l := range dataPtrs {
			sipHash24FusedChain68x1GprAsm(c, np, dataPtrs[l], &out[l])
		}
	default:
		scalarFusedBatch(components, dataPtrs, 68, out)
	}
}
func FusedChain13x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasGPR && validComponents(components) {
		sipHash24FusedChain13x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 13, out)
}
func FusedChain20x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasGPR && validComponents(components) {
		sipHash24FusedChain20x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 20, out)
}
func FusedChain36x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasGPR && validComponents(components) {
		sipHash24FusedChain36x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 36, out)
}
func FusedChain68x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasGPR && validComponents(components) {
		sipHash24FusedChain68x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 68, out)
}

// FusedChain13x16 runs the batch-16 fill as two calls of the NEON
// eight-lane fill kernel (lanes 0..7 at groupIdxBase, lanes 8..15 at
// groupIdxBase + 8; the blocks are synthesised in-register) under
// HasNEONX16, else the pure-Go cascade.
func FusedChain13x16(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	if HasNEONX16 && validComponents(components) {
		sipHash24FusedChain13x8NeonAsm(&components[0], len(components)/2, groupIdxBase, x16Half(out, 0))
		sipHash24FusedChain13x8NeonAsm(&components[0], len(components)/2, groupIdxBase+8, x16Half(out, 1))
		return
	}
	scalarFusedX16(components, groupIdxBase, out)
}

// NEON four-lane kernels (siphash_fusedchain128_<shape>x4_neon_arm64.s)
// and GPR single-lane kernels (siphash_fusedchain128_<shape>x1_gpr_arm64.s).
//
//go:noescape
func sipHash24FusedChain13x4NeonAsm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain20x4NeonAsm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain36x4NeonAsm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain68x4NeonAsm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24FusedChain13x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func sipHash24FusedChain20x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func sipHash24FusedChain36x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)

//go:noescape
func sipHash24FusedChain68x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)

// Eight-lane fused fill kernel (siphash_fusedchain128_13x8_neon_arm64.s).
//
//go:noescape
func sipHash24FusedChain13x8NeonAsm(comps *uint64, nPairs int, groupIdxBase uint64, out *[8][2]uint64)
