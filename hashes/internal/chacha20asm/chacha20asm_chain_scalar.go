package chacha20asm

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/crypto/chacha20"
)

// scalar256ChainAbsorb is the pure-Go reference implementation of
// the ChaCha20-256 chain-absorb closure for a single pixel. The
// construction is bit-exact equivalent to the closure body in
// hashes/chacha20.go — any divergence here would observably change
// the digest emitted by hashes.ChaCha20:
//
//	per-call key:  key[i*8:(i+1)*8] ^= seed[i]   (LE uint64, i in 0..3)
//	cipher:        chacha20.NewUnauthenticatedCipher(key, zero_nonce)
//	state init:    state[0:8]   = uint64(len(data)) (LE)
//	               state[8:32]  = 0
//	absorb (chunkSize = 24, CBC-MAC-style):
//	  if len(data) <= 24:
//	    copy state[8:8+len(data)], data
//	    c.XORKeyStream(state, state)
//	  else:
//	    copy state[8:32], data[0:24]
//	    c.XORKeyStream(state, state)
//	    for off in 24, 48, ...:
//	      end = min(off+24, len(data))
//	      state[8:8+(end-off)] ^= data[off:end]
//	      c.XORKeyStream(state, state)
//	output:        state[0:32] split into 4 LE uint64
//
// On non-amd64 / purego builds and on amd64 hosts without
// AVX-512+VL, this serves as the production fallback. On AVX-512+VL
// hosts it is the parity baseline for the ZMM-batched ASM kernels —
// divergence between scalar and ASM output would observably change
// the digest emitted by hashes.ChaCha20256.
func scalar256ChainAbsorb(
	fixedKey *[32]byte,
	data []byte,
	seed *[4]uint64,
) [4]uint64 {
	var key [32]byte
	copy(key[:], fixedKey[:])
	for i := 0; i < 4; i++ {
		off := i * 8
		v := binary.LittleEndian.Uint64(key[off:])
		binary.LittleEndian.PutUint64(key[off:], v^seed[i])
	}
	var nonce [12]byte
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		panic(err)
	}
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))

	const chunkSize = 24
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		c.XORKeyStream(state[:], state[:])
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		c.XORKeyStream(state[:], state[:])
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			for i := 0; i < end-off; i++ {
				state[8+i] ^= data[off+i]
			}
			c.XORKeyStream(state[:], state[:])
			off = end
		}
	}
	return [4]uint64{
		binary.LittleEndian.Uint64(state[0:]),
		binary.LittleEndian.Uint64(state[8:]),
		binary.LittleEndian.Uint64(state[16:]),
		binary.LittleEndian.Uint64(state[24:]),
	}
}

// scalarBatch256ChainAbsorb20 is the scalar 4-lane reference for the
// ChaCha20-256 batched chain-absorb at the 20-byte data shape. Loops
// the per-lane scalar reference; each lane is bit-exact equivalent
// to the public hashes.ChaCha20 closure on the same input. Used as
// the production fallback on hosts without AVX-512+VL and as the
// parity baseline for the ZMM-batched ASM kernel.
func scalarBatch256ChainAbsorb20(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[20]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane] = scalar256ChainAbsorb(fixedKey, data[:], &seeds[lane])
	}
}

// scalarBatch256ChainAbsorb36 — 36-byte counterpart.
func scalarBatch256ChainAbsorb36(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[36]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane] = scalar256ChainAbsorb(fixedKey, data[:], &seeds[lane])
	}
}

// scalarBatch256ChainAbsorb68 — 68-byte counterpart.
func scalarBatch256ChainAbsorb68(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][4]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[68]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane] = scalar256ChainAbsorb(fixedKey, data[:], &seeds[lane])
	}
}
