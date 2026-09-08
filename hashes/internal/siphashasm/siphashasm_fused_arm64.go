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

// FusedAvailable reports whether the NEON fused cascade tier is selected.
func FusedAvailable() bool { return FusedHasNEON }

func FusedChain13x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasNEON && validComponents(components) {
		sipHash24FusedChain13x4NeonAsm(&components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(components, dataPtrs, 13, out)
}
func FusedChain20x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasNEON && validComponents(components) {
		sipHash24FusedChain20x4NeonAsm(&components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(components, dataPtrs, 20, out)
}
func FusedChain36x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasNEON && validComponents(components) {
		sipHash24FusedChain36x4NeonAsm(&components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(components, dataPtrs, 36, out)
}
func FusedChain68x4(components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64) {
	if FusedHasNEON && validComponents(components) {
		sipHash24FusedChain68x4NeonAsm(&components[0], len(components)/2, dataPtrs, out)
		return
	}
	scalarFusedBatch(components, dataPtrs, 68, out)
}
func FusedChain13x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasNEON && validComponents(components) {
		sipHash24FusedChain13x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 13, out)
}
func FusedChain20x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasNEON && validComponents(components) {
		sipHash24FusedChain20x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 20, out)
}
func FusedChain36x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasNEON && validComponents(components) {
		sipHash24FusedChain36x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 36, out)
}
func FusedChain68x1(components []uint64, data *byte, out *[2]uint64) {
	if FusedHasNEON && validComponents(components) {
		sipHash24FusedChain68x1GprAsm(&components[0], len(components)/2, data, out)
		return
	}
	scalarFusedSingle(components, data, 68, out)
}

// FusedChain13x16 runs the batch-16 fill as four NEON x4 calls over
// Go-synthesised fill blocks under HasNEONX16, else the pure-Go cascade.
func FusedChain13x16(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
	if HasNEONX16 && validComponents(components) {
		blocks := fillBlocks16(groupIdxBase)
		for q := 0; q < 4; q++ {
			ptrs := x16Quarter(&blocks, q)
			sipHash24FusedChain13x4NeonAsm(&components[0], len(components)/2, &ptrs, x16Out(out, q))
		}
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
