//go:build amd64 && !purego && !noitbasm

package blake3asm

// Blake3256ChainAbsorb20x4 is the public 4-pixel-batched entry
// point for the BLAKE3-256 chain-absorb at the 20-byte data shape
// (ITB SetNonceBits(128) buf shape).
//
// On amd64 + AVX-512 + VL hosts (HasAVX512Fused == true), dispatches
// to the fused ZMM-batched ASM kernel; otherwise falls through to
// the scalar batched reference path (which delegates to upstream
// github.com/zeebo/blake3).
//
// Buffer construction is identical between the two paths and
// matches the bit-exact behaviour of the existing hashes.BLAKE3
// closure applied to each of the four pixel inputs:
//
//	per lane:
//	  mixed[0:20]  = data[lane]            (per-lane, 20 bytes)
//	  mixed[20:32] = zero pad
//	  then for i in 0..3:
//	    mixed[i*8 : i*8+8] ^= seeds[lane][i]   (LE uint64; straddles
//	                                            two BLAKE3 message
//	                                            words m[2i], m[2i+1])
//
// The keyed-hash mode key (32 bytes shared across all 4 lanes) is
// consumed by BLAKE3's state init (v[0..7] = KEY broadcast), NOT
// written into the mixed buffer. One BLAKE3 compression with
// block_len=32, flags=0x1B (KEYED_HASH|CHUNK_START|CHUNK_END|ROOT).
func Blake3256ChainAbsorb20x4(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	if HasAVX512Fused {
		blake3256ChainAbsorb20x4Asm(key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb20(key, seeds, dataPtrs, out)
}

// blake3256ChainAbsorb20x4Asm is the AVX-512 ZMM-batched fused
// chain-absorb kernel implemented in blake3_chain256_20_amd64.s.
// Bit-exact parity against the scalar reference is verified by the
// x4 parity tests in blake3asm_chain_test.go.
//
//go:noescape
func blake3256ChainAbsorb20x4Asm(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
)

// Blake3256ChainAbsorb36x4 — 36-byte BLAKE3-256 batched dispatcher
// (ITB SetNonceBits(256) buf shape). Single compression block per
// lane (mixed=36 ≤ 64-byte BLAKE3 block size); same flag set as
// the 20-byte case but block_len=36 and the m-pack covers 9 dwords
// of data (m[0..8]) instead of 5.
func Blake3256ChainAbsorb36x4(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	if HasAVX512Fused {
		blake3256ChainAbsorb36x4Asm(key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb36(key, seeds, dataPtrs, out)
}

//go:noescape
func blake3256ChainAbsorb36x4Asm(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
)

// Blake3256ChainAbsorb68x4 — 68-byte BLAKE3-256 batched dispatcher
// (ITB SetNonceBits(512) buf shape). Two compression blocks per
// lane (mixed=68 > 64):
//
//	Block 1 (block_len=64, flags=KEYED_HASH|CHUNK_START):
//	    m[0..7]  = data[0:32] ⊕ seed
//	    m[8..15] = data[32:64]
//	    Output cv1 = v[k] ⊕ v[k+8] (k in 0..7) becomes block 2's v[0..7].
//
//	Block 2 (block_len=4, flags=KEYED_HASH|CHUNK_END|ROOT):
//	    m[0]     = data[64:68]
//	    m[1..15] = 0
//	    Final out[k] = v[k] ⊕ v[k+8] (no ⊕ chaining_value; BLAKE3's
//	                                   output mixing differs from
//	                                   BLAKE2's h0 ⊕ v[k] ⊕ v[k+8]).
func Blake3256ChainAbsorb68x4(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	if HasAVX512Fused {
		blake3256ChainAbsorb68x4Asm(key, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb68(key, seeds, dataPtrs, out)
}

//go:noescape
func blake3256ChainAbsorb68x4Asm(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
)
