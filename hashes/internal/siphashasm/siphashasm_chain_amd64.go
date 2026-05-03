//go:build amd64 && !purego && !noitbasm

package siphashasm

// SipHash24Chain128Absorb20x4 is the public 4-pixel-batched entry
// point for the SipHash-2-4-128 chain-absorb at the 20-byte data
// shape (ITB SetNonceBits(128) buf shape — the default config).
//
// On amd64 + AVX-512 + VL hosts (HasAVX512Fused == true), dispatches
// to the fused ZMM-batched ASM kernel; otherwise falls through to
// the scalar batched reference path (which delegates to upstream
// github.com/dchest/siphash).
//
// Buffer construction is identical between the two paths and matches
// the bit-exact behaviour of the existing hashes.SipHash24 closure
// applied to each of the four pixel inputs:
//
//	per lane:
//	  K0, K1 = seeds[lane][0], seeds[lane][1]
//	  v0..v3 init from K0/K1 ^ SipHash constants (v1 also ^ 0xee
//	         for the 128-bit output variant)
//	  for each 8-byte data word m at offsets 0, 8 + a 4-byte
//	         tail block at offset 16 with lenTag(20) in top byte:
//	    v3 ^= m; SipRound × 2; v0 ^= m
//	  finalization: v2 ^= 0xee; SipRound × 4; out0 = v0^v1^v2^v3
//	  finalization: v1 ^= 0xdd; SipRound × 4; out1 = v0^v1^v2^v3
//	  out[lane] = (out0, out1)
//
// 20-byte buf shape: 2 full + 1 padded compression block + 2-half
// finalization = 14 SipRounds total per pixel.
func SipHash24Chain128Absorb20x4(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	if HasAVX512Fused {
		sipHash24Chain128Absorb20x4Asm(seeds, dataPtrs, out)
		return
	}
	scalarBatch128ChainAbsorb20(seeds, dataPtrs, out)
}

// sipHash24Chain128Absorb20x4Asm is the AVX-512 ZMM-batched fused
// chain-absorb kernel implemented in siphash_chain128_20_amd64.s.
// Bit-exact parity against the scalar reference is verified by
// the x4 parity tests in siphashasm_chain_test.go.
//
//go:noescape
func sipHash24Chain128Absorb20x4Asm(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)

// SipHash24Chain128Absorb36x4 — 36-byte SipHash-2-4-128 batched
// dispatcher (ITB SetNonceBits(256) buf shape). 4 full + 1 padded
// compression blocks + 2-half finalization = 18 SipRounds total.
func SipHash24Chain128Absorb36x4(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	if HasAVX512Fused {
		sipHash24Chain128Absorb36x4Asm(seeds, dataPtrs, out)
		return
	}
	scalarBatch128ChainAbsorb36(seeds, dataPtrs, out)
}

//go:noescape
func sipHash24Chain128Absorb36x4Asm(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)

// SipHash24Chain128Absorb68x4 — 68-byte SipHash-2-4-128 batched
// dispatcher (ITB SetNonceBits(512) buf shape). 8 full + 1 padded
// compression blocks + 2-half finalization = 26 SipRounds total.
func SipHash24Chain128Absorb68x4(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	if HasAVX512Fused {
		sipHash24Chain128Absorb68x4Asm(seeds, dataPtrs, out)
		return
	}
	scalarBatch128ChainAbsorb68(seeds, dataPtrs, out)
}

//go:noescape
func sipHash24Chain128Absorb68x4Asm(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)
