// Package chacha20ctr implements RFC 8439 ChaCha20 and draft-irtf-cfrg-xchacha
// XChaCha20 counter-mode stream encryption with zero-allocation counter
// reset, immediate partial-block keystream scrubbing, and SIMD-accelerated
// multi-block XOR kernels on amd64 (AVX-512 / AVX2) and arm64 (NEON).
package chacha20ctr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"unsafe"

	"github.com/everanium/itb/internal/wipe"
)

const (
	// KeySize is the ChaCha20 and XChaCha20 key size in bytes.
	KeySize = 32
	// NonceSize is the RFC 8439 ChaCha20 nonce size in bytes.
	NonceSize = 12
	// NonceSizeX is the XChaCha20 extended nonce size in bytes.
	NonceSizeX = 24
	// BlockSize is the ChaCha20 block size in bytes.
	BlockSize = 64

	j0 uint32 = 0x61707865
	j1 uint32 = 0x3320646e
	j2 uint32 = 0x79622d32
	j3 uint32 = 0x6b206574
)

// Cipher is a stateful RFC 8439 ChaCha20 or XChaCha20 stream cipher instance
// stored entirely by value so callers can embed or stack-allocate it without
// heap allocations or reflection-based zeroization.
type Cipher struct {
	key      [8]uint32
	nonce    [3]uint32
	counter  uint32
	buf      [BlockSize]byte
	bufOff   int
	overflow bool
}

// Init initializes c with a 32-byte key and a 12-byte (ChaCha20) or 24-byte
// (XChaCha20) nonce at counter 0.
func (c *Cipher) Init(key, nonce []byte) error {
	return c.InitWithCounter(key, nonce, 0)
}

// InitWithCounter initializes c with a 32-byte key, a 12-byte or 24-byte
// nonce, and an initial 32-bit block counter.
func (c *Cipher) InitWithCounter(key, nonce []byte, counter uint32) error {
	if len(key) != KeySize {
		return errors.New("chacha20: wrong key size")
	}
	switch len(nonce) {
	case NonceSize:
		for i := range c.key {
			c.key[i] = binary.LittleEndian.Uint32(key[4*i:])
		}
		c.nonce[0] = binary.LittleEndian.Uint32(nonce[0:4])
		c.nonce[1] = binary.LittleEndian.Uint32(nonce[4:8])
		c.nonce[2] = binary.LittleEndian.Uint32(nonce[8:12])
	case NonceSizeX:
		var k [8]uint32
		for i := range k {
			k[i] = binary.LittleEndian.Uint32(key[4*i:])
		}
		hchacha20(&c.key, &k, nonce[0:16])
		clear(k[:])
		runtime.KeepAlive(&k)
		c.nonce[0] = 0
		c.nonce[1] = binary.LittleEndian.Uint32(nonce[16:20])
		c.nonce[2] = binary.LittleEndian.Uint32(nonce[20:24])
		wipe.CallStack512B()
		wipe.ClobberRegs()
	default:
		return errors.New("chacha20: wrong nonce size")
	}
	c.counter = counter
	clear(c.buf[:])
	c.bufOff = BlockSize
	c.overflow = false
	return nil
}

// SetCounter sets the 32-bit block counter and discards any buffered partial
// block, zeroing the internal keystream buffer.
func (c *Cipher) SetCounter(counter uint32) {
	if c.bufOff < BlockSize {
		clear(c.buf[:])
		c.bufOff = BlockSize
	}
	c.counter = counter
	c.overflow = false
}

// ResetCounter repositions the stream to byteOffset from the start of the
// keystream (counter 0, byte 0) without allocating on the heap.
func (c *Cipher) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byte offset %d", byteOffset)
	}
	blockCounter := uint64(byteOffset / BlockSize)
	if blockCounter > math.MaxUint32 {
		return fmt.Errorf("ctr: chacha20 block counter %d overflows uint32", blockCounter)
	}
	rem := byteOffset % BlockSize
	if rem == 0 {
		if c.bufOff < BlockSize {
			clear(c.buf[:])
			c.bufOff = BlockSize
		}
		c.counter = uint32(blockCounter)
		c.overflow = false
		return nil
	}
	clear(c.buf[:])
	XORKeyStreamBlocks(c.buf[:], c.buf[:], &c.key, &c.nonce, uint32(blockCounter))
	clear(c.buf[:rem])
	c.bufOff = rem
	if uint32(blockCounter) == math.MaxUint32 {
		c.counter = 0
		c.overflow = true
	} else {
		c.counter = uint32(blockCounter) + 1
		c.overflow = false
	}
	return nil
}

// XORKeyStream XORs each byte in src with the keystream and writes the result
// to dst. Any consumed keystream bytes in the internal partial-block buffer
// are zeroed immediately upon use.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("chacha20: output smaller than input")
	}
	dst = dst[:len(src)]
	if inexactOverlap(dst, src) {
		panic("chacha20: invalid buffer overlap")
	}

	if c.bufOff < BlockSize {
		avail := BlockSize - c.bufOff
		if len(src) < avail {
			avail = len(src)
		}
		ks := c.buf[c.bufOff : c.bufOff+avail]
		for i := 0; i < avail; i++ {
			dst[i] = src[i] ^ ks[i]
		}
		clear(ks)
		c.bufOff += avail
		dst = dst[avail:]
		src = src[avail:]
		if len(src) == 0 {
			return
		}
	}

	numBlocks := (uint64(len(src)) + BlockSize - 1) / BlockSize
	if c.overflow || uint64(c.counter)+numBlocks > 1<<32 {
		panic("chacha20: counter overflow")
	} else if uint64(c.counter)+numBlocks == 1<<32 {
		c.overflow = true
	}

	full := len(src) &^ (BlockSize - 1)
	if full > 0 {
		XORKeyStreamBlocks(dst[:full], src[:full], &c.key, &c.nonce, c.counter)
		c.counter += uint32(full / BlockSize)
		dst = dst[full:]
		src = src[full:]
	}

	if len(src) > 0 {
		clear(c.buf[:])
		XORKeyStreamBlocks(c.buf[:], c.buf[:], &c.key, &c.nonce, c.counter)
		c.counter++
		rem := len(src)
		for i := 0; i < rem; i++ {
			dst[i] = src[i] ^ c.buf[i]
		}
		clear(c.buf[:rem])
		c.bufOff = rem
	}
}

// Wipe zeroes all key material, nonces, and buffered keystream bytes in c.
func (c *Cipher) Wipe() {
	*c = Cipher{bufOff: BlockSize}
	runtime.KeepAlive(c)
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	xp := uintptr(unsafe.Pointer(&x[0]))
	yp := uintptr(unsafe.Pointer(&y[0]))
	return xp < yp+uintptr(len(y)) && yp < xp+uintptr(len(x))
}

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

// hchacha20 derives a 256-bit subkey from key and a 16-byte nonce without heap
// allocations, zeroing its working state before return.
//
//go:noinline
func hchacha20(out *[8]uint32, key *[8]uint32, nonce []byte) {
	var x [16]uint32
	x[0], x[1], x[2], x[3] = j0, j1, j2, j3
	for i := 0; i < 8; i++ {
		x[4+i] = key[i]
	}
	x[12] = binary.LittleEndian.Uint32(nonce[0:4])
	x[13] = binary.LittleEndian.Uint32(nonce[4:8])
	x[14] = binary.LittleEndian.Uint32(nonce[8:12])
	x[15] = binary.LittleEndian.Uint32(nonce[12:16])

	for i := 0; i < 10; i++ {
		x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = quarterRound(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = quarterRound(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = quarterRound(x[3], x[7], x[11], x[15])
		x[0], x[5], x[10], x[15] = quarterRound(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = quarterRound(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = quarterRound(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = quarterRound(x[3], x[4], x[9], x[14])
	}

	out[0], out[1], out[2], out[3] = x[0], x[1], x[2], x[3]
	out[4], out[5], out[6], out[7] = x[12], x[13], x[14], x[15]
	clear(x[:])
	runtime.KeepAlive(&x)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}

// scalarXORKeyStreamBlocks XORs full 64-byte blocks of ChaCha20 keystream
// from src into dst starting at counter. len(src) must be a multiple of 64.
//
//go:noinline
func scalarXORKeyStreamBlocks(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter uint32) {
	var x [16]uint32
	ctr := counter
	for i := 0; i < len(src); i += BlockSize {
		x[0], x[1], x[2], x[3] = j0, j1, j2, j3
		for j := 0; j < 8; j++ {
			x[4+j] = key[j]
		}
		x[12] = ctr
		x[13] = nonce[0]
		x[14] = nonce[1]
		x[15] = nonce[2]

		for r := 0; r < 10; r++ {
			x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
			x[1], x[5], x[9], x[13] = quarterRound(x[1], x[5], x[9], x[13])
			x[2], x[6], x[10], x[14] = quarterRound(x[2], x[6], x[10], x[14])
			x[3], x[7], x[11], x[15] = quarterRound(x[3], x[7], x[11], x[15])

			x[0], x[5], x[10], x[15] = quarterRound(x[0], x[5], x[10], x[15])
			x[1], x[6], x[11], x[12] = quarterRound(x[1], x[6], x[11], x[12])
			x[2], x[7], x[8], x[13] = quarterRound(x[2], x[7], x[8], x[13])
			x[3], x[4], x[9], x[14] = quarterRound(x[3], x[4], x[9], x[14])
		}

		x[0] += j0
		x[1] += j1
		x[2] += j2
		x[3] += j3
		for j := 0; j < 8; j++ {
			x[4+j] += key[j]
		}
		x[12] += ctr
		x[13] += nonce[0]
		x[14] += nonce[1]
		x[15] += nonce[2]

		s := src[i : i+BlockSize : i+BlockSize]
		d := dst[i : i+BlockSize : i+BlockSize]
		for j := 0; j < 16; j++ {
			binary.LittleEndian.PutUint32(d[j*4:], binary.LittleEndian.Uint32(s[j*4:])^x[j])
		}

		ctr++
	}
	clear(x[:])
	runtime.KeepAlive(&x)
	wipe.CallStack512B()
	wipe.ClobberRegs()
}
