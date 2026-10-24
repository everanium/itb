// Package blake3ctr implements Keyed BLAKE3 single-input PRF evaluation,
// 4-lane batched PRF evaluation, and counter-mode keystream XOR with
// pre-decoded key words and SIMD-accelerated kernels on amd64
// (AVX-512VL / AVX2) and arm64 (NEON).
package blake3ctr

import (
	"encoding/binary"
	"math/bits"
	"runtime"
	"unsafe"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb/internal/wipe"
)

const (
	// KeySize is the Keyed BLAKE3 key size in bytes.
	KeySize = 32
	// NonceSize is the counter-mode nonce size in bytes.
	NonceSize = 16
	// BlockSize is the BLAKE3 digest and keystream block size in bytes.
	BlockSize = 32

	iv0 uint32 = 0x6a09e667
	iv1 uint32 = 0xbb67ae85
	iv2 uint32 = 0x3c6ef372
	iv3 uint32 = 0xa54ff53a
	iv4 uint32 = 0x510e527f
	iv5 uint32 = 0x9b05688c
	iv6 uint32 = 0x1f83d9ab
	iv7 uint32 = 0x5be0cd19

	// flagsKeyedSingleChunk is CHUNK_START(0x01) | CHUNK_END(0x02) | ROOT(0x08) | KEYED_HASH(0x10).
	flagsKeyedSingleChunk uint32 = 0x1b
)

var msgSchedule = [7][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
	{3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
	{10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
	{12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
	{9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
	{11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
}

// InitKey parses the 32-byte key into 8 little-endian uint32 words.
func InitKey(key []byte, keyWords *[8]uint32) {
	if len(key) != KeySize {
		panic("blake3ctr: wrong key size")
	}
	for i := 0; i < 8; i++ {
		keyWords[i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	wipe.ClobberRegs()
}

// Eval computes the 32-byte Keyed BLAKE3 digest of in into dst[:32].
// Inputs with len(in) <= 64 are evaluated in a single 7-round block
// compression with zero heap allocations; longer inputs delegate to
// github.com/zeebo/blake3.NewKeyed.
func Eval(dst, in []byte, keyWords *[8]uint32, keyBytes *[32]byte) {
	if len(dst) < BlockSize {
		panic("blake3ctr: dst smaller than BlockSize")
	}
	if len(in) <= 64 {
		evalSingleBlock(dst[:BlockSize], in, keyWords)
		wipe.CallStack512B()
		wipe.ClobberRegs()
		return
	}
	evalLong(dst[:BlockSize], in, keyBytes)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

//go:noinline
func evalSingleBlock(dst, in []byte, keyWords *[8]uint32) {
	var b [64]byte
	var m [16]uint32
	var out [8]uint32

	for i := 0; i < len(in); i++ {
		b[i] = in[i]
	}
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	compressSingleBlock(&out, keyWords, &m, uint32(len(in)))
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(dst[4*i:], out[i])
	}

	clear(b[:])
	clear(m[:])
	clear(out[:])
	runtime.KeepAlive(&b)
	runtime.KeepAlive(&m)
	runtime.KeepAlive(&out)
}

//go:noinline
func evalLong(dst, in []byte, keyBytes *[32]byte) {
	h, err := blake3.NewKeyed(keyBytes[:])
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(in)
	h.Sum(dst[:0])
	wipe.StructPtr(h)
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

func compressSingleBlock(out *[8]uint32, keyWords *[8]uint32, m *[16]uint32, blockLen uint32) {
	v0, v1, v2, v3 := keyWords[0], keyWords[1], keyWords[2], keyWords[3]
	v4, v5, v6, v7 := keyWords[4], keyWords[5], keyWords[6], keyWords[7]
	v8, v9, v10, v11 := iv0, iv1, iv2, iv3
	v12 := uint32(0)
	v13 := uint32(0)
	v14 := blockLen
	v15 := flagsKeyedSingleChunk

	for r := 0; r < 7; r++ {
		s := &msgSchedule[r]
		v0, v4, v8, v12 = gFunction(v0, v4, v8, v12, m[s[0]], m[s[1]])
		v1, v5, v9, v13 = gFunction(v1, v5, v9, v13, m[s[2]], m[s[3]])
		v2, v6, v10, v14 = gFunction(v2, v6, v10, v14, m[s[4]], m[s[5]])
		v3, v7, v11, v15 = gFunction(v3, v7, v11, v15, m[s[6]], m[s[7]])
		v0, v5, v10, v15 = gFunction(v0, v5, v10, v15, m[s[8]], m[s[9]])
		v1, v6, v11, v12 = gFunction(v1, v6, v11, v12, m[s[10]], m[s[11]])
		v2, v7, v8, v13 = gFunction(v2, v7, v8, v13, m[s[12]], m[s[13]])
		v3, v4, v9, v14 = gFunction(v3, v4, v9, v14, m[s[14]], m[s[15]])
	}

	out[0] = v0 ^ v8
	out[1] = v1 ^ v9
	out[2] = v2 ^ v10
	out[3] = v3 ^ v11
	out[4] = v4 ^ v12
	out[5] = v5 ^ v13
	out[6] = v6 ^ v14
	out[7] = v7 ^ v15
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

func scalarBatchPRFx4(dst, in *[4][]byte, keyWords *[8]uint32, keyBytes *[32]byte) {
	for lane := 0; lane < 4; lane++ {
		if len(dst[lane]) < BlockSize {
			panic("blake3ctr: dst smaller than BlockSize")
		}
		if len(in[lane]) <= 64 {
			evalSingleBlock(dst[lane][:BlockSize], in[lane], keyWords)
		} else {
			evalLong(dst[lane][:BlockSize], in[lane], keyBytes)
		}
	}
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

//go:noinline
func scalarXORKeyStreamBlocks(dst, src []byte, keyWords *[8]uint32, nonce *[4]uint32, counter uint64) {
	var out [8]uint32
	var m [16]uint32
	m[0] = nonce[0]
	m[1] = nonce[1]
	m[2] = nonce[2]
	m[3] = nonce[3]

	ctr := counter
	for i := 0; i < len(src); i += BlockSize {
		m[4] = uint32(ctr)
		m[5] = uint32(ctr >> 32)
		compressSingleBlock(&out, keyWords, &m, 24)

		s := src[i : i+BlockSize : i+BlockSize]
		d := dst[i : i+BlockSize : i+BlockSize]
		for j := 0; j < 8; j++ {
			binary.LittleEndian.PutUint32(d[j*4:], binary.LittleEndian.Uint32(s[j*4:])^out[j])
		}
		ctr++
	}

	clear(out[:])
	clear(m[:])
	runtime.KeepAlive(&out)
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
