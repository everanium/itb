//go:build amd64 && !purego && !noitbasm

package blake2sasm

// Blake2s256ChainAbsorb20x4 is the public 4-pixel-batched entry point
// for the BLAKE2s-256 chain-absorb at the 20-byte data shape (ITB
// SetNonceBits(128) buf shape).
//
// On amd64 + AVX-512 + VL hosts (HasAVX512Fused == true), dispatches
// to the fused ZMM-batched ASM kernel which holds four lane-isolated
// BLAKE2s states in 16 ZMM registers (one ZMM per v[k], 4 of 16 dword
// lanes used) across all 10 internal mixing rounds. No DIAG/UNDIAG
// permutations are required since the four states are lane-parallel
// rather than shuffled-into-one. On hosts without AVX-512+VL, falls
// through to the scalar batched reference path, which loops the
// per-lane scalar reference (delegating to upstream
// golang.org/x/crypto/blake2s).
//
// Buffer construction is identical between the two paths and matches
// the bit-exact behaviour of the existing hashes.BLAKE2s256 closure
// applied to each of the four pixel inputs:
//
//	per lane:
//	  buf[0:32]   = b2key
//	  buf[32:52]  = data[lane]
//	  buf[52:64]  = zero
//	  then for i in 0..3: buf[32+i*8 : 40+i*8] ^= seeds[lane][i] (LE uint64)
//
// One BLAKE2s compression with t=64, f=^0 (final). Output is the
// 8 × uint32 BLAKE2s state per lane (32 bytes of digest).
//
// h0 selects the parameter-block-XOR'd initial state (digestLength=32
// for hashes.BLAKE2s256). Pass &Blake2sIV256Param.
func Blake2s256ChainAbsorb20x4(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	if HasAVX512Fused {
		blake2s256ChainAbsorb20x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb20(h0, b2key, seeds, dataPtrs, out)
}

// blake2s256ChainAbsorb20x4Asm is the AVX-512 ZMM-batched fused
// chain-absorb kernel implemented in blake2s_chain256_20_amd64.s.
// State across four lane-isolated BLAKE2s compressions is held in
// 16 ZMM registers across all 10 mixing rounds; one 64-byte BLAKE2s
// compression per lane with t=64, f=^0 (final). Bit-exact parity
// against the scalar reference is verified by the x4 parity tests in
// blake2sasm_chain_test.go.
//
//go:noescape
func blake2s256ChainAbsorb20x4Asm(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
)

// Blake2s256ChainAbsorb36x4 — 36-byte BLAKE2s-256 batched dispatcher
// (ITB SetNonceBits(256) buf shape). Two compression blocks per lane:
//
//	Block 1 (t=64,  f=0):  buf[0:64]   = b2key + (data[0:32] ⊕ seed)
//	Block 2 (t=68,  f=^0): buf[64:128] = data[32:36] + 60 zero pad
//
// The ASM kernel holds all four lanes' BLAKE2s states in ZMM
// registers across both compressions; the inter-block fold runs
// in-register lane-parallel, with the block-1 chaining hash spilled
// to stack so the block-2 final fold can reload it.
func Blake2s256ChainAbsorb36x4(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	if HasAVX512Fused {
		blake2s256ChainAbsorb36x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb36(h0, b2key, seeds, dataPtrs, out)
}

//go:noescape
func blake2s256ChainAbsorb36x4Asm(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
)

// Blake2s256ChainAbsorb68x4 — 68-byte BLAKE2s-256 batched dispatcher
// (ITB SetNonceBits(512) buf shape). Two compression blocks per lane:
//
//	Block 1 (t=64,  f=0):  buf[0:64]   = b2key + (data[0:32] ⊕ seed)
//	Block 2 (t=100, f=^0): buf[64:128] = data[32:68] + 28 zero pad
//
// Same structure as the 36-byte two-block kernel; only the block-2
// data fill is wider (36 bytes instead of 4), populating m[0..8]
// instead of m[0] alone.
func Blake2s256ChainAbsorb68x4(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	if HasAVX512Fused {
		blake2s256ChainAbsorb68x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb68(h0, b2key, seeds, dataPtrs, out)
}

//go:noescape
func blake2s256ChainAbsorb68x4Asm(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
)
