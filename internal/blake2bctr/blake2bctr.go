// Package blake2bctr implements RFC 7693 Keyed BLAKE2b-256 and BLAKE2b-512
// single-input PRF evaluation, 4-lane batched PRF evaluation, and direct
// multi-block counter-mode keystream XOR with precomputed key-block chaining
// state and SIMD-accelerated kernels on amd64 (AVX-512VL / AVX2) and arm64
// (NEON).
package blake2bctr

import (
	"encoding/binary"
	"math/bits"
	"runtime"

	"github.com/everanium/itb/internal/wipe"
)

const (
	// KeySize is the RFC 7693 Keyed BLAKE2b key size in bytes used by ITB.
	KeySize = 32
	// NonceSize is the PRF-CTR nonce size in bytes.
	NonceSize = 16
	// BlockSize256 is the BLAKE2b-256 output block size in bytes.
	BlockSize256 = 32
	// BlockSize512 is the BLAKE2b-512 output block size in bytes.
	BlockSize512 = 64

	iv0 uint64 = 0x6a09e667f3bcc908
	iv1 uint64 = 0xbb67ae8584caa73b
	iv2 uint64 = 0x3c6ef372fe94f82b
	iv3 uint64 = 0xa54ff53a5f1d36f1
	iv4 uint64 = 0x510e527fade682d1
	iv5 uint64 = 0x9b05688c2b3e6c1f
	iv6 uint64 = 0x1f83d9abfb41bd6b
	iv7 uint64 = 0x5be0cd19137e2179

	// param256 and param512 encode fanout=1, depth=1, keyLen=32, and digest
	// byte length 32 or 64 in the low 32 bits of parameter word 0.
	param256 uint64 = 0x01012020
	param512 uint64 = 0x01012040
)

var sigma = [12][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

// InitKey256 loads the 32-byte key into keyBlock and precomputes the 8-word
// chaining state hKey produced by compressing the 128-byte zero-padded key
// block as a non-final block for BLAKE2b-256.
func InitKey256(key []byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	initKey(key, hKey, keyBlock, param256)
}

// InitKey512 loads the 32-byte key into keyBlock and precomputes the 8-word
// chaining state hKey produced by compressing the 128-byte zero-padded key
// block as a non-final block for BLAKE2b-512.
func InitKey512(key []byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	initKey(key, hKey, keyBlock, param512)
}

//go:noinline
func initKey(key []byte, hKey *[8]uint64, keyBlock *[4]uint64, param uint64) {
	if len(key) != KeySize {
		panic("blake2bctr: invalid key length")
	}
	keyBlock[0] = binary.LittleEndian.Uint64(key[0:8])
	keyBlock[1] = binary.LittleEndian.Uint64(key[8:16])
	keyBlock[2] = binary.LittleEndian.Uint64(key[16:24])
	keyBlock[3] = binary.LittleEndian.Uint64(key[24:32])

	hKey[0] = iv0 ^ param
	hKey[1] = iv1
	hKey[2] = iv2
	hKey[3] = iv3
	hKey[4] = iv4
	hKey[5] = iv5
	hKey[6] = iv6
	hKey[7] = iv7

	var m [16]uint64
	m[0] = keyBlock[0]
	m[1] = keyBlock[1]
	m[2] = keyBlock[2]
	m[3] = keyBlock[3]
	compressBlock(hKey, &m, 128, 0, 0, 0)
	clear(m[:])
	runtime.KeepAlive(&m)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

// Eval256 evaluates RFC 7693 Keyed BLAKE2b-256 on in using the precomputed
// non-final key-block state hKey (and keyBlock when len(in) == 0), writing the
// 32-byte digest to dst[:32] with zero heap allocations.
func Eval256(dst, in []byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	if len(dst) < BlockSize256 {
		panic("blake2bctr: dst smaller than BlockSize256")
	}
	eval(dst[:BlockSize256], in, hKey, keyBlock, param256, 4)
}

// Eval512 evaluates RFC 7693 Keyed BLAKE2b-512 on in using the precomputed
// non-final key-block state hKey (and keyBlock when len(in) == 0), writing the
// 64-byte digest to dst[:64] with zero heap allocations.
func Eval512(dst, in []byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	if len(dst) < BlockSize512 {
		panic("blake2bctr: dst smaller than BlockSize512")
	}
	eval(dst[:BlockSize512], in, hKey, keyBlock, param512, 8)
}

//go:noinline
func eval(dst, in []byte, hKey *[8]uint64, keyBlock *[4]uint64, param uint64, outWords int) {
	var h [8]uint64
	var m [16]uint64
	if len(in) == 0 {
		h[0] = iv0 ^ param
		h[1] = iv1
		h[2] = iv2
		h[3] = iv3
		h[4] = iv4
		h[5] = iv5
		h[6] = iv6
		h[7] = iv7
		m[0] = keyBlock[0]
		m[1] = keyBlock[1]
		m[2] = keyBlock[2]
		m[3] = keyBlock[3]
		compressBlock(&h, &m, 128, 0, ^uint64(0), 0)
	} else {
		h = *hKey
		t0 := uint64(128)
		t1 := uint64(0)
		rem := in
		for len(rem) > 128 {
			for i := 0; i < 16; i++ {
				m[i] = binary.LittleEndian.Uint64(rem[i*8:])
			}
			var carry uint64
			t0, carry = bits.Add64(t0, 128, 0)
			t1 += carry
			compressBlock(&h, &m, t0, t1, 0, 0)
			rem = rem[128:]
		}
		loadPaddedBlock(&m, rem)
		var carry uint64
		t0, carry = bits.Add64(t0, uint64(len(rem)), 0)
		t1 += carry
		compressBlock(&h, &m, t0, t1, ^uint64(0), 0)
	}
	for i := 0; i < outWords; i++ {
		binary.LittleEndian.PutUint64(dst[i*8:], h[i])
	}
	clear(h[:])
	clear(m[:])
	runtime.KeepAlive(&h)
	runtime.KeepAlive(&m)
	wipeCompressFrame()
	wipe.ClobberRegs()
}

func loadPaddedBlock(m *[16]uint64, rem []byte) {
	clear(m[:])
	fullWords := len(rem) >> 3
	for i := 0; i < fullWords; i++ {
		m[i] = binary.LittleEndian.Uint64(rem[i*8:])
	}
	if tail := len(rem) & 7; tail > 0 {
		var w uint64
		base := fullWords * 8
		for b := 0; b < tail; b++ {
			w |= uint64(rem[base+b]) << (8 * b)
		}
		m[fullWords] = w
	}
}

//go:noinline
func wipeCompressFrame() {
	var pad [64]uint64
	clear(pad[:])
	runtime.KeepAlive(&pad)
}

func gMix(a, b, c, d, mx, my uint64) (uint64, uint64, uint64, uint64) {
	a = a + b + mx
	d = bits.RotateLeft64(d^a, -32)
	c = c + d
	b = bits.RotateLeft64(b^c, -24)
	a = a + b + my
	d = bits.RotateLeft64(d^a, -16)
	c = c + d
	b = bits.RotateLeft64(b^c, -63)
	return a, b, c, d
}

//go:noinline
func compressBlock(h *[8]uint64, m *[16]uint64, t0, t1, f0, f1 uint64) {
	v0, v1, v2, v3 := h[0], h[1], h[2], h[3]
	v4, v5, v6, v7 := h[4], h[5], h[6], h[7]
	v8, v9, v10, v11 := iv0, iv1, iv2, iv3
	v12 := iv4 ^ t0
	v13 := iv5 ^ t1
	v14 := iv6 ^ f0
	v15 := iv7 ^ f1

	for r := 0; r < 12; r++ {
		s := &sigma[r]
		v0, v4, v8, v12 = gMix(v0, v4, v8, v12, m[s[0]], m[s[1]])
		v1, v5, v9, v13 = gMix(v1, v5, v9, v13, m[s[2]], m[s[3]])
		v2, v6, v10, v14 = gMix(v2, v6, v10, v14, m[s[4]], m[s[5]])
		v3, v7, v11, v15 = gMix(v3, v7, v11, v15, m[s[6]], m[s[7]])
		v0, v5, v10, v15 = gMix(v0, v5, v10, v15, m[s[8]], m[s[9]])
		v1, v6, v11, v12 = gMix(v1, v6, v11, v12, m[s[10]], m[s[11]])
		v2, v7, v8, v13 = gMix(v2, v7, v8, v13, m[s[12]], m[s[13]])
		v3, v4, v9, v14 = gMix(v3, v4, v9, v14, m[s[14]], m[s[15]])
	}

	h[0] ^= v0 ^ v8
	h[1] ^= v1 ^ v9
	h[2] ^= v2 ^ v10
	h[3] ^= v3 ^ v11
	h[4] ^= v4 ^ v12
	h[5] ^= v5 ^ v13
	h[6] ^= v6 ^ v14
	h[7] ^= v7 ^ v15
}

// compress24Block compresses a 24-byte final message block (nonce[0], nonce[1],
// m2, with m[3..15] == 0, t0 = 152, f0 = ^uint64(0)) starting from hKey into out.
//
//go:noinline
func compress24Block(out *[8]uint64, hKey *[8]uint64, nonce *[2]uint64, m2 uint64) {
	v0, v1, v2, v3 := hKey[0], hKey[1], hKey[2], hKey[3]
	v4, v5, v6, v7 := hKey[4], hKey[5], hKey[6], hKey[7]
	v8, v9, v10, v11 := iv0, iv1, iv2, iv3
	v12 := iv4 ^ 152
	v13 := iv5
	v14 := iv6 ^ ^uint64(0)
	v15 := iv7

	var m [16]uint64
	m[0] = nonce[0]
	m[1] = nonce[1]
	m[2] = m2

	for r := 0; r < 12; r++ {
		s := &sigma[r]
		v0, v4, v8, v12 = gMix(v0, v4, v8, v12, m[s[0]], m[s[1]])
		v1, v5, v9, v13 = gMix(v1, v5, v9, v13, m[s[2]], m[s[3]])
		v2, v6, v10, v14 = gMix(v2, v6, v10, v14, m[s[4]], m[s[5]])
		v3, v7, v11, v15 = gMix(v3, v7, v11, v15, m[s[6]], m[s[7]])
		v0, v5, v10, v15 = gMix(v0, v5, v10, v15, m[s[8]], m[s[9]])
		v1, v6, v11, v12 = gMix(v1, v6, v11, v12, m[s[10]], m[s[11]])
		v2, v7, v8, v13 = gMix(v2, v7, v8, v13, m[s[12]], m[s[13]])
		v3, v4, v9, v14 = gMix(v3, v4, v9, v14, m[s[14]], m[s[15]])
	}

	out[0] = hKey[0] ^ v0 ^ v8
	out[1] = hKey[1] ^ v1 ^ v9
	out[2] = hKey[2] ^ v2 ^ v10
	out[3] = hKey[3] ^ v3 ^ v11
	out[4] = hKey[4] ^ v4 ^ v12
	out[5] = hKey[5] ^ v5 ^ v13
	out[6] = hKey[6] ^ v6 ^ v14
	out[7] = hKey[7] ^ v7 ^ v15

	m2 = 0
	runtime.KeepAlive(&m2)
	clear(m[:])
	runtime.KeepAlive(&m)
}

//go:noinline
func scalarXORKeyStreamBlocks256(dst, src []byte, hKey *[8]uint64, nonce *[2]uint64, counter uint64) {
	var out [8]uint64
	ctr := counter
	for i := 0; i < len(src); i += BlockSize256 {
		compress24Block(&out, hKey, nonce, ctr)
		s := src[i : i+BlockSize256 : i+BlockSize256]
		d := dst[i : i+BlockSize256 : i+BlockSize256]
		for j := 0; j < 4; j++ {
			binary.LittleEndian.PutUint64(d[j*8:], binary.LittleEndian.Uint64(s[j*8:])^out[j])
		}
		ctr++
	}
	ctr = 0
	runtime.KeepAlive(&ctr)
	clear(out[:])
	runtime.KeepAlive(&out)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

//go:noinline
func scalarXORKeyStreamBlocks512(dst, src []byte, hKey *[8]uint64, nonce *[2]uint64, counter uint64) {
	var out [8]uint64
	ctr := counter
	for i := 0; i < len(src); i += BlockSize512 {
		compress24Block(&out, hKey, nonce, ctr)
		s := src[i : i+BlockSize512 : i+BlockSize512]
		d := dst[i : i+BlockSize512 : i+BlockSize512]
		for j := 0; j < 8; j++ {
			binary.LittleEndian.PutUint64(d[j*8:], binary.LittleEndian.Uint64(s[j*8:])^out[j])
		}
		ctr++
	}
	ctr = 0
	runtime.KeepAlive(&ctr)
	clear(out[:])
	runtime.KeepAlive(&out)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

//go:noinline
func scalarBatchPRF256x4(dst, in *[4][]byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	for lane := 0; lane < 4; lane++ {
		Eval256(dst[lane], in[lane], hKey, keyBlock)
	}
}

//go:noinline
func scalarBatchPRF512x4(dst, in *[4][]byte, hKey *[8]uint64, keyBlock *[4]uint64) {
	for lane := 0; lane < 4; lane++ {
		Eval512(dst[lane], in[lane], hKey, keyBlock)
	}
}
