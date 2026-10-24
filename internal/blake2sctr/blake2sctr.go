// Package blake2sctr implements RFC 7693 Keyed BLAKE2s-256 single-input PRF
// evaluation, 4-lane batched PRF evaluation, and counter-mode keystream XOR
// with precomputed key-block chaining state and SIMD-accelerated kernels on
// amd64 (AVX-512VL / AVX2) and arm64 (NEON).
package blake2sctr

import (
	"encoding/binary"
	"math/bits"
	"runtime"
	"unsafe"

	"github.com/everanium/itb/internal/wipe"
)

const (
	// KeySize is the RFC 7693 Keyed BLAKE2s-256 key size in bytes.
	KeySize = 32
	// NonceSize is the counter-mode nonce size in bytes.
	NonceSize = 16
	// BlockSize is the BLAKE2s-256 digest and keystream block size in bytes.
	BlockSize = 32

	iv0 uint32 = 0x6a09e667
	iv1 uint32 = 0xbb67ae85
	iv2 uint32 = 0x3c6ef372
	iv3 uint32 = 0xa54ff53a
	iv4 uint32 = 0x510e527f
	iv5 uint32 = 0x9b05688c
	iv6 uint32 = 0x1f83d9ab
	iv7 uint32 = 0x5be0cd19

	// paramIV0 is iv0 ^ 0x01010000 ^ (KeySize << 8) ^ BlockSize.
	paramIV0 uint32 = iv0 ^ 0x01012020
)

var sigma = [10][16]uint8{
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
}

// InitKey parses the 32-byte key into keyWords and precomputes the 8-word
// chaining state hKey produced by compressing the 64-byte zero-padded key
// block (block 0) as a non-final BLAKE2s block (t0 = 64, f0 = 0).
func InitKey(key []byte, hKey *[8]uint32, keyWords *[8]uint32) {
	if len(key) != KeySize {
		panic("blake2sctr: wrong key size")
	}
	initKeyBody(key, hKey, keyWords)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

//go:noinline
func initKeyBody(key []byte, hKey *[8]uint32, keyWords *[8]uint32) {
	var m [16]uint32
	for i := 0; i < 8; i++ {
		w := binary.LittleEndian.Uint32(key[4*i:])
		keyWords[i] = w
		m[i] = w
	}
	*hKey = [8]uint32{paramIV0, iv1, iv2, iv3, iv4, iv5, iv6, iv7}
	compressBlock(hKey, &m, 64, 0, 0, 0)
	clear(m[:])
	runtime.KeepAlive(&m)
}

// Eval computes the 32-byte RFC 7693 Keyed BLAKE2s-256 digest of in into
// dst[:32] using the precomputed non-final key-block state hKey (for
// len(in) > 0) or keyWords (for len(in) == 0) with zero heap allocations.
func Eval(dst, in []byte, hKey *[8]uint32, keyWords *[8]uint32) {
	if len(dst) < BlockSize {
		panic("blake2sctr: dst smaller than BlockSize")
	}
	evalBody(dst[:BlockSize], in, hKey, keyWords)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

//go:noinline
func evalBody(dst, in []byte, hKey *[8]uint32, keyWords *[8]uint32) {
	var h [8]uint32
	var m [16]uint32
	var b [64]byte

	if len(in) == 0 {
		h = [8]uint32{paramIV0, iv1, iv2, iv3, iv4, iv5, iv6, iv7}
		for i := 0; i < 8; i++ {
			m[i] = keyWords[i]
		}
		compressBlock(&h, &m, 64, 0, 0xffffffff, 0)
	} else {
		h = *hKey
		t := uint64(64)
		for len(in) > 64 {
			for i := 0; i < 16; i++ {
				m[i] = binary.LittleEndian.Uint32(in[4*i:])
			}
			t += 64
			compressBlock(&h, &m, uint32(t), uint32(t>>32), 0, 0)
			in = in[64:]
		}
		for i := 0; i < 64; i++ {
			b[i] = 0
		}
		for i := 0; i < len(in); i++ {
			b[i] = in[i]
		}
		for i := 0; i < 16; i++ {
			m[i] = binary.LittleEndian.Uint32(b[4*i:])
		}
		t += uint64(len(in))
		compressBlock(&h, &m, uint32(t), uint32(t>>32), 0xffffffff, 0)
	}

	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(dst[4*i:], h[i])
	}
	clear(b[:])
	clear(m[:])
	clear(h[:])
	runtime.KeepAlive(&b)
	runtime.KeepAlive(&m)
	runtime.KeepAlive(&h)
}

func gFunction(a, b, c, d, x, y uint32) (uint32, uint32, uint32, uint32) {
	a = a + b + x
	d = bits.RotateLeft32(d^a, -16)
	c = c + d
	b = bits.RotateLeft32(b^c, -12)
	a = a + b + y
	d = bits.RotateLeft32(d^a, -8)
	c = c + d
	b = bits.RotateLeft32(b^c, -7)
	return a, b, c, d
}

func compressBlock(h *[8]uint32, m *[16]uint32, t0, t1, f0, f1 uint32) {
	v0, v1, v2, v3 := h[0], h[1], h[2], h[3]
	v4, v5, v6, v7 := h[4], h[5], h[6], h[7]
	v8, v9, v10, v11 := iv0, iv1, iv2, iv3
	v12 := iv4 ^ t0
	v13 := iv5 ^ t1
	v14 := iv6 ^ f0
	v15 := iv7 ^ f1

	for r := 0; r < 10; r++ {
		s := &sigma[r]
		v0, v4, v8, v12 = gFunction(v0, v4, v8, v12, m[s[0]], m[s[1]])
		v1, v5, v9, v13 = gFunction(v1, v5, v9, v13, m[s[2]], m[s[3]])
		v2, v6, v10, v14 = gFunction(v2, v6, v10, v14, m[s[4]], m[s[5]])
		v3, v7, v11, v15 = gFunction(v3, v7, v11, v15, m[s[6]], m[s[7]])
		v0, v5, v10, v15 = gFunction(v0, v5, v10, v15, m[s[8]], m[s[9]])
		v1, v6, v11, v12 = gFunction(v1, v6, v11, v12, m[s[10]], m[s[11]])
		v2, v7, v8, v13 = gFunction(v2, v7, v8, v13, m[s[12]], m[s[13]])
		v3, v4, v9, v14 = gFunction(v3, v4, v9, v14, m[s[14]], m[s[15]])
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

func transposeMsg4x(m *[16][4]uint32, in *[4][]byte, commonLen int) {
	var b [64]byte
	for lane := 0; lane < 4; lane++ {
		src := in[lane]
		for i := 0; i < 64; i++ {
			b[i] = 0
		}
		for i := 0; i < commonLen; i++ {
			b[i] = src[i]
		}
		for w := 0; w < 16; w++ {
			m[w][lane] = binary.LittleEndian.Uint32(b[4*w:])
		}
	}
	clear(b[:])
	runtime.KeepAlive(&b)
}

func scalarBatchPRFx4(dst, in *[4][]byte, hKey *[8]uint32, keyWords *[8]uint32) {
	for lane := 0; lane < 4; lane++ {
		if len(dst[lane]) < BlockSize {
			panic("blake2sctr: dst smaller than BlockSize")
		}
		evalBody(dst[lane][:BlockSize], in[lane], hKey, keyWords)
	}
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

//go:noinline
func scalarXORKeyStreamBlocks(dst, src []byte, hKey *[8]uint32, nonce *[4]uint32, counter uint64) {
	var h [8]uint32
	var m [16]uint32
	m[0] = nonce[0]
	m[1] = nonce[1]
	m[2] = nonce[2]
	m[3] = nonce[3]

	ctr := counter
	for i := 0; i < len(src); i += BlockSize {
		m[4] = uint32(ctr)
		m[5] = uint32(ctr >> 32)
		h = *hKey
		compressBlock(&h, &m, 64+24, 0, 0xffffffff, 0)

		s := src[i : i+BlockSize : i+BlockSize]
		d := dst[i : i+BlockSize : i+BlockSize]
		for j := 0; j < 8; j++ {
			binary.LittleEndian.PutUint32(d[j*4:], binary.LittleEndian.Uint32(s[j*4:])^h[j])
		}
		ctr++
	}

	clear(h[:])
	clear(m[:])
	runtime.KeepAlive(&h)
	runtime.KeepAlive(&m)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	xp := uintptr(unsafe.Pointer(&x[0]))
	yp := uintptr(unsafe.Pointer(&y[0]))
	return xp < yp+uintptr(len(y)) && yp < xp+uintptr(len(x))
}
