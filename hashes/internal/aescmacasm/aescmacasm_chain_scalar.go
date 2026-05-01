package aescmacasm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"unsafe"
)

// scalar128ChainAbsorb is the pure-Go reference implementation of
// the AES-CMAC-128 chain-absorb closure for a single pixel. The
// construction is bit-exact equivalent to the closure body in
// hashes/aescmac.go — any divergence here would observably change
// the digest emitted by hashes.AESCMAC:
//
//	state[0:8]  = seed0 ^ lenTag (LE uint64)
//	state[8:16] = seed1 ^ lenTag (LE uint64)
//	state[0:min(16, len(data))] ^= data[0:min(16, len(data))]
//	state = AES_K(state)
//	for off in 16, 32, ...; off < len(data); off += 16:
//	  state[0:end-off] ^= data[off:end]   (end = min(off+16, len(data)))
//	  state = AES_K(state)
//	output:  (LE uint64 of state[0:8], LE uint64 of state[8:16])
//
// Used as the production fallback on hosts without VAES + AVX-512
// and as the parity baseline for the ZMM-batched ASM kernels.
// crypto/aes.cipher.Block is itself AES-NI-accelerated on amd64
// hosts that expose the AES round instructions, so the fallback
// path remains fast on all but the slowest silicon.
func scalar128ChainAbsorb(
	block cipher.Block,
	data []byte,
	seed0, seed1 uint64,
) (uint64, uint64) {
	lenTag := uint64(len(data))
	var b1 [16]byte
	binary.LittleEndian.PutUint64(b1[0:], seed0^lenTag)
	binary.LittleEndian.PutUint64(b1[8:], seed1^lenTag)
	firstBlockLen := len(data)
	if firstBlockLen > 16 {
		firstBlockLen = 16
	}
	for i := 0; i < firstBlockLen; i++ {
		b1[i] ^= data[i]
	}
	block.Encrypt(b1[:], b1[:])
	for off := 16; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		for i := 0; i < end-off; i++ {
			b1[i] ^= data[off+i]
		}
		block.Encrypt(b1[:], b1[:])
	}
	return binary.LittleEndian.Uint64(b1[:8]), binary.LittleEndian.Uint64(b1[8:])
}

// newScalarBlock builds a crypto/aes.cipher.Block from a 16-byte
// AES key. Used by the scalar reference path; the ZMM kernel path
// pre-expands the key schedule via ExpandKeyAES128 instead and
// passes the 176-byte schedule directly to the kernel.
func newScalarBlock(key *[16]byte) cipher.Block {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	return block
}

// scalarBatch128ChainAbsorb20 is the scalar 4-lane reference for the
// AES-CMAC-128 batched chain-absorb at the 20-byte data shape. Loops
// the per-lane scalar reference; each lane is bit-exact equivalent
// to the public hashes.AESCMAC closure on the same input. Used as
// the production fallback on hosts without VAES + AVX-512 and as
// the parity baseline for the ZMM-batched ASM kernel.
func scalarBatch128ChainAbsorb20(
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	block := newScalarBlock(key)
	for lane := 0; lane < 4; lane++ {
		data := (*[20]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane][0], out[lane][1] = scalar128ChainAbsorb(block, data[:], seeds[lane][0], seeds[lane][1])
	}
}

// scalarBatch128ChainAbsorb36 — 36-byte counterpart.
func scalarBatch128ChainAbsorb36(
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	block := newScalarBlock(key)
	for lane := 0; lane < 4; lane++ {
		data := (*[36]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane][0], out[lane][1] = scalar128ChainAbsorb(block, data[:], seeds[lane][0], seeds[lane][1])
	}
}

// scalarBatch128ChainAbsorb68 — 68-byte counterpart.
func scalarBatch128ChainAbsorb68(
	key *[16]byte,
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	block := newScalarBlock(key)
	for lane := 0; lane < 4; lane++ {
		data := (*[68]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane][0], out[lane][1] = scalar128ChainAbsorb(block, data[:], seeds[lane][0], seeds[lane][1])
	}
}
