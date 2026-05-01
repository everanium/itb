//go:build amd64 && !purego

package blake2basm

// Blake2b512ChainAbsorb20x4 is the public 4-pixel-batched entry point
// for the BLAKE2b-512 chain-absorb at the 20-byte data shape (ITB
// SetNonceBits(128) buf shape).
//
// On amd64 + AVX-512 + VL hosts (HasAVX512Fused == true), dispatches
// to the fused ZMM-batched ASM kernel which holds four lane-isolated
// BLAKE2b states in 16 ZMM registers (one ZMM per v[k], 4 of 8 qword
// lanes used) across all 12 internal mixing rounds. No DIAG/UNDIAG
// permutations are required since the four states are lane-parallel
// rather than shuffled-into-one. On hosts without AVX-512+VL, falls
// through to the scalar batched reference path, which loops the
// per-lane scalar reference (delegating to upstream
// golang.org/x/crypto/blake2b).
//
// Buffer construction is identical between the two paths and matches
// the bit-exact behaviour of the existing hashes.BLAKE2b512 closure
// applied to each of the four pixel inputs:
//
//	per lane:
//	  buf[0:64]   = b2key
//	  buf[64:84]  = data[lane]
//	  buf[84:128] = zero
//	  then for i in 0..7: buf[64+i*8 : 72+i*8] ^= seeds[lane][i] (LE)
//
// One BLAKE2b compression with t=128, f=^0 (final). Output is the
// 8 × uint64 BLAKE2b state per lane. For -256 callers, only
// out[lane][0:4] is meaningful (32-byte digest); the closure
// truncates accordingly.
//
// h0 selects digest width via paramBlock pre-XOR'd into h[0]:
// pass &Blake2bIV512Param for hashes.BLAKE2b512 callers,
// &Blake2bIV256Param for hashes.BLAKE2b256 callers (though for -256
// the dedicated Blake2b256ChainAbsorbN x4 entry points are preferred —
// they use the narrower 32-byte key prefix and 4 seed components).
func Blake2b512ChainAbsorb20x4(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	if HasAVX512Fused {
		blake2b512ChainAbsorb20x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch512ChainAbsorb20(h0, b2key, seeds, dataPtrs, out)
}

// blake2b512ChainAbsorb20x4Asm is the AVX-512 ZMM-batched fused
// chain-absorb kernel implemented in blake2b_chain512_20_amd64.s.
// State across four lane-isolated BLAKE2b compressions is held in
// 16 ZMM registers across all 12 mixing rounds; one 128-byte BLAKE2b
// compression per lane with t=128, f=^0 (final). Bit-exact parity
// against the scalar reference is verified by the x4 parity tests in
// blake2basm_chain_test.go.
//
//go:noescape
func blake2b512ChainAbsorb20x4Asm(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Blake2b512ChainAbsorb36x4 — 36-byte BLAKE2b-512 batched dispatcher
// (ITB SetNonceBits(256) buf shape). Same single-compression structure
// as the 20-byte path; only the data-region length differs.
func Blake2b512ChainAbsorb36x4(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	if HasAVX512Fused {
		blake2b512ChainAbsorb36x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch512ChainAbsorb36(h0, b2key, seeds, dataPtrs, out)
}

//go:noescape
func blake2b512ChainAbsorb36x4Asm(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Blake2b512ChainAbsorb68x4 — 68-byte BLAKE2b-512 batched dispatcher
// (ITB SetNonceBits(512) buf shape). Two compression blocks per lane:
//
//	Block 1 (t=128, f=0): buf[0:128]   = b2key + (data[0:64] ⊕ seed)
//	Block 2 (t=132, f=^0): buf[128:132] = data[64:68] + 124 zero pad
//
// The ASM kernel holds all four lanes' BLAKE2b states in ZMM
// registers across both compressions; the inter-block fold runs
// in-register lane-parallel, with the block-1 chaining hash spilled
// to stack so the block-2 final fold can reload it.
func Blake2b512ChainAbsorb68x4(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	if HasAVX512Fused {
		blake2b512ChainAbsorb68x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch512ChainAbsorb68(h0, b2key, seeds, dataPtrs, out)
}

//go:noescape
func blake2b512ChainAbsorb68x4Asm(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Blake2b256ChainAbsorb20x4 — BLAKE2b-256 batched dispatcher for the
// 20-byte data shape (ITB SetNonceBits(128) buf shape). The 256-bit
// kernels use a 32-byte prefix-MAC key and 4 seed components (vs 64 /
// 8 in the 512-bit kernels). One BLAKE2b compression per lane with
// t = key_len + max(data_len, 32) (= 64 for 20-byte data), f=^0.
// Output in out[lane][0:4] holds the 32-byte digest; out[lane][4:8]
// is undefined (the kernel does not zero it; the public closure
// truncates the result to [4]uint64).
func Blake2b256ChainAbsorb20x4(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	if HasAVX512Fused {
		blake2b256ChainAbsorb20x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb20(h0, b2key, seeds, dataPtrs, out)
}

//go:noescape
func blake2b256ChainAbsorb20x4Asm(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Blake2b256ChainAbsorb36x4 — 36-byte BLAKE2b-256 batched dispatcher
// (SetNonceBits(256)). t=68, single compression block per lane.
func Blake2b256ChainAbsorb36x4(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	if HasAVX512Fused {
		blake2b256ChainAbsorb36x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb36(h0, b2key, seeds, dataPtrs, out)
}

//go:noescape
func blake2b256ChainAbsorb36x4Asm(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// Blake2b256ChainAbsorb68x4 — 68-byte BLAKE2b-256 batched dispatcher
// (SetNonceBits(512)). t=100, single compression block per lane (the
// per-lane buf is 100 bytes ≤ 128, so no inter-block fold like the
// 512-bit counterpart's two-block kernel).
func Blake2b256ChainAbsorb68x4(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	if HasAVX512Fused {
		blake2b256ChainAbsorb68x4Asm(h0, b2key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb68(h0, b2key, seeds, dataPtrs, out)
}

//go:noescape
func blake2b256ChainAbsorb68x4Asm(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)
