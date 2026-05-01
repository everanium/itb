//go:build amd64 && !purego

package aescmacasm

// AESCMAC128ChainAbsorb20x4 is the public 4-pixel-batched entry
// point for the AES-CMAC-128 chain-absorb at the 20-byte data shape
// (ITB SetNonceBits(128) buf shape — the default config).
//
// On amd64 + VAES + AVX-512 hosts (HasVAESAVX512 == true), dispatches
// to the fused ZMM-batched ASM kernel; otherwise falls through to
// the scalar batched reference path (which delegates to upstream
// crypto/aes — itself AES-NI accelerated on capable amd64 hosts).
//
// Buffer construction is identical between the two paths and matches
// the bit-exact behaviour of the existing hashes.AESCMAC closure
// applied to each of the four pixel inputs:
//
//	per lane:
//	  state[0:8]  = seeds[lane][0] ^ uint64(20)  (LE)
//	  state[8:16] = seeds[lane][1] ^ uint64(20)  (LE)
//	  state[0:16] ^= data[lane][0:16]
//	  state = AES_K(state)                       (CBC-MAC round 1)
//	  state[0:4] ^= data[lane][16:20]            (4-byte tail XOR)
//	  state = AES_K(state)                       (CBC-MAC round 2)
//	  out[lane][0] = LE uint64 of state[0:8]
//	  out[lane][1] = LE uint64 of state[8:16]
//
// The 20-byte case takes 2 AES-CMAC rounds (= 2 full AES-128
// permutations); the kernel runs both in-place on a single ZMM
// register holding all 4 lanes.
func AESCMAC128ChainAbsorb20x4(
	roundKeys *[176]byte,
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	if HasVAESAVX512 {
		aesCMAC128ChainAbsorb20x4Asm(roundKeys, seeds, dataPtrs, out)
		return
	}
	scalarBatch128ChainAbsorb20(key, seeds, dataPtrs, out)
}

// aesCMAC128ChainAbsorb20x4Asm is the VAES + AVX-512 ZMM-batched
// fused chain-absorb kernel implemented in
// aescmac_chain128_20_amd64.s. Bit-exact parity against the scalar
// reference is verified by the x4 parity tests in
// aescmacasm_chain_test.go.
//
//go:noescape
func aesCMAC128ChainAbsorb20x4Asm(
	roundKeys *[176]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)

// AESCMAC128ChainAbsorb36x4 — 36-byte AES-CMAC-128 batched
// dispatcher (ITB SetNonceBits(256) buf shape). Three CBC-MAC
// absorb rounds per lane:
//
//	state[0:16]  = (seed0 ^ 36) || (seed1 ^ 36)
//	state       ^= data[lane][0:16]
//	state        = AES_K(state)                  (round 1)
//	state       ^= data[lane][16:32]
//	state        = AES_K(state)                  (round 2)
//	state[0:4]  ^= data[lane][32:36]             (4-byte tail XOR)
//	state        = AES_K(state)                  (round 3)
func AESCMAC128ChainAbsorb36x4(
	roundKeys *[176]byte,
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	if HasVAESAVX512 {
		aesCMAC128ChainAbsorb36x4Asm(roundKeys, seeds, dataPtrs, out)
		return
	}
	scalarBatch128ChainAbsorb36(key, seeds, dataPtrs, out)
}

//go:noescape
func aesCMAC128ChainAbsorb36x4Asm(
	roundKeys *[176]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)

// AESCMAC128ChainAbsorb68x4 — 68-byte AES-CMAC-128 batched
// dispatcher (ITB SetNonceBits(512) buf shape). Five CBC-MAC absorb
// rounds per lane:
//
//	state[0:16]  = (seed0 ^ 68) || (seed1 ^ 68)
//	state       ^= data[lane][0:16];   state = AES_K(state)   (round 1)
//	state       ^= data[lane][16:32];  state = AES_K(state)   (round 2)
//	state       ^= data[lane][32:48];  state = AES_K(state)   (round 3)
//	state       ^= data[lane][48:64];  state = AES_K(state)   (round 4)
//	state[0:4]  ^= data[lane][64:68];  state = AES_K(state)   (round 5)
func AESCMAC128ChainAbsorb68x4(
	roundKeys *[176]byte,
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	if HasVAESAVX512 {
		aesCMAC128ChainAbsorb68x4Asm(roundKeys, seeds, dataPtrs, out)
		return
	}
	scalarBatch128ChainAbsorb68(key, seeds, dataPtrs, out)
}

//go:noescape
func aesCMAC128ChainAbsorb68x4Asm(
	roundKeys *[176]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
)
