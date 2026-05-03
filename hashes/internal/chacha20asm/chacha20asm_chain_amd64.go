//go:build amd64 && !purego && !noitbasm

package chacha20asm

// ChaCha20256ChainAbsorb20x4 is the public 4-pixel-batched entry
// point for the ChaCha20-256 chain-absorb at the 20-byte data shape
// (ITB SetNonceBits(128) buf shape — the default config).
//
// On amd64 + AVX-512 + VL hosts (HasAVX512Fused == true), dispatches
// to the fused ZMM-batched ASM kernel; otherwise falls through to
// the scalar batched reference path (which delegates to upstream
// golang.org/x/crypto/chacha20).
//
// Buffer construction is identical between the two paths and
// matches the bit-exact behaviour of the existing hashes.ChaCha20
// closure applied to each of the four pixel inputs:
//
//	per lane:
//	  key  = fixedKey                                (32 bytes, shared)
//	  for i in 0..3:
//	    key[i*8:(i+1)*8] ^= seeds[lane][i] (LE uint64)
//	  c    = chacha20.NewUnauthenticatedCipher(key, zero_nonce)
//	  state[0:8]  = uint64(20) (LE)
//	  state[8:28] = data[lane][0:20]
//	  state[28:32] = 0
//	  c.XORKeyStream(state, state)   // consumes ks_lo of block 0
//	  out[lane] = state[0:32] (4 × LE uint64)
//
// The 20-byte case takes one ChaCha20 compression (one ks_lo half
// XOR'd over state[0:32]); the kernel computes the full 64-byte
// keystream block and uses only the lower 8 dwords.
func ChaCha20256ChainAbsorb20x4(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
) {
	if HasAVX512Fused {
		chaCha20256ChainAbsorb20x4Asm(fixedKey, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb20(fixedKey, seeds, dataPtrs, out)
}

// chaCha20256ChainAbsorb20x4Asm is the AVX-512 ZMM-batched fused
// chain-absorb kernel implemented in chacha20_chain256_20_amd64.s.
// Bit-exact parity against the scalar reference is verified by the
// x4 parity tests in chacha20asm_chain_test.go.
//
//go:noescape
func chaCha20256ChainAbsorb20x4Asm(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// ChaCha20256ChainAbsorb36x4 — 36-byte ChaCha20-256 batched
// dispatcher (ITB SetNonceBits(256) buf shape). Two CBC-MAC absorb
// rounds per lane; both consume halves of the same compression
// block (counter=0):
//
//	state[0:8]  = uint64(36) (LE)
//	state[8:32] = data[lane][0:24]
//	c.XORKeyStream(state, state)               // consumes ks_lo of block 0
//	state[8:20] ^= data[lane][24:36]           // 12-byte tail
//	c.XORKeyStream(state, state)               // consumes ks_hi of block 0
//
// One ChaCha20 compression is performed in the kernel; the 16-dword
// keystream is split into ks_lo (dwords 0..7) and ks_hi (dwords 8..15).
func ChaCha20256ChainAbsorb36x4(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
) {
	if HasAVX512Fused {
		chaCha20256ChainAbsorb36x4Asm(fixedKey, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb36(fixedKey, seeds, dataPtrs, out)
}

//go:noescape
func chaCha20256ChainAbsorb36x4Asm(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)

// ChaCha20256ChainAbsorb68x4 — 68-byte ChaCha20-256 batched
// dispatcher (ITB SetNonceBits(512) buf shape). Three CBC-MAC absorb
// rounds per lane; the first two consume halves of compression
// block 0 (counter=0), the third consumes ks_lo of compression block
// 1 (counter=1):
//
//	state[0:8]  = uint64(68) (LE)
//	state[8:32] = data[lane][0:24]
//	c.XORKeyStream(state, state)               // ks_lo of block 0
//	state[8:32] ^= data[lane][24:48]           // 24-byte chunk
//	c.XORKeyStream(state, state)               // ks_hi of block 0
//	state[8:28] ^= data[lane][48:68]           // 20-byte tail
//	c.XORKeyStream(state, state)               // ks_lo of block 1 (counter=1)
//
// Two ChaCha20 compressions are performed in the kernel — the first
// at counter=0 (yields ks_lo/ks_hi for absorb rounds 1 + 2) and the
// second at counter=1 (yields ks_lo for absorb round 3).
func ChaCha20256ChainAbsorb68x4(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
) {
	if HasAVX512Fused {
		chaCha20256ChainAbsorb68x4Asm(fixedKey, seeds, dataPtrs, out)
		return
	}
	scalarBatch256ChainAbsorb68(fixedKey, seeds, dataPtrs, out)
}

//go:noescape
func chaCha20256ChainAbsorb68x4Asm(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
)
