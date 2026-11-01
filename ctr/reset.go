package ctr

import (
	"encoding/binary"
	"fmt"
	"io"
	"runtime"

	"github.com/everanium/areion"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/chacha20ctr"
)

// ResettableKeystream is a Keystream whose internal counter can be
// repositioned to any byte offset of its (name, key, nonce) stream after
// construction. The byte at any offset is byte-identical to a sequential
// consume from the start; ResetCounter is functionally equivalent to a
// fresh New() call followed by an advance, but reuses the per-primitive
// setup state — notably the AES round-key schedule — so the cost of
// repositioning is dominated by the intra-block discard rather than by
// repeated key expansion.
type ResettableKeystream interface {
	Keystream
	ResetCounter(byteOffset int) error
}

// NewResettable returns a ResettableKeystream for the named cipher,
// honouring the same key and nonce length contract as New. The keystream
// it produces is byte-identical to New(name, key, nonce); the only
// difference is the cached state that backs ResetCounter.
func NewResettable(name string, key, nonce []byte) (ResettableKeystream, error) {
	switch name {
	case hashes.CipherAreion256, hashes.CipherAreion512, hashes.CipherBLAKE2b256, hashes.CipherBLAKE2b512, hashes.CipherBLAKE2s, hashes.CipherBLAKE3:
		ks, err := newPrfHashCTR(name, key, nonce)
		if err != nil {
			return nil, err
		}
		switch v := ks.(type) {
		case *prfHashCTR:
			return v, nil
		case *prfHashCTRBatch:
			return v, nil
		default:
			return nil, fmt.Errorf("ctr: %s keystream is not resettable", name)
		}
	case hashes.CipherAES128CTR:
		return newAESResettable(key, nonce)
	case hashes.CipherSipHash24:
		ks, err := newSipHashCTR(key, nonce)
		if err != nil {
			return nil, err
		}
		return ks.(*sipCTR), nil
	case hashes.CipherChaCha20:
		return newChaCha20Resettable(key, nonce)
	default:
		return nil, fmt.Errorf("ctr: unknown cipher %q", name)
	}
}

// NewResettableAt is NewResettable repositioned at byteOffset. A zero
// byteOffset is equivalent to NewResettable; negative values are an error.
func NewResettableAt(name string, key, nonce []byte, byteOffset int) (ResettableKeystream, error) {
	if byteOffset < 0 {
		return nil, fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	if name == hashes.CipherAES128CTR {
		return newAESResettableAt(key, nonce, byteOffset)
	}
	ks, err := NewResettable(name, key, nonce)
	if err != nil {
		return nil, err
	}
	if byteOffset == 0 {
		return ks, nil
	}
	if err := ks.ResetCounter(byteOffset); err != nil {
		if c, ok := ks.(io.Closer); ok {
			_ = c.Close()
		}
		return nil, err
	}
	return ks, nil
}

const aesBlockSize = 16

// aesResettable implements NIST SP 800-38A AES-128 in counter mode over
// the pre-expanded 11-round key schedule using areion.AES128CTRXOR.
// ResetCounter repositions the 128-bit big-endian block counter in O(1)
// and pre-populates the intra-block remainder without re-running key
// expansion or allocating heap state.
type aesResettable struct {
	nonce      [aesBlockSize]byte
	rk         [11][16]byte
	blockOff   uint64
	keystrm    [aesBlockSize]byte
	keystrmOff int
	keystrmLen int
}

func newAESResettable(key, nonce []byte) (*aesResettable, error) {
	return newAESResettableAt(key, nonce, 0)
}

func newAESResettableAt(key, nonce []byte, byteOffset int) (*aesResettable, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("ctr: aes-128-ctr key must be 16 bytes, got %d", len(key))
	}
	if len(nonce) != aesBlockSize {
		return nil, fmt.Errorf("ctr: aes-128-ctr nonce must be %d bytes, got %d", aesBlockSize, len(nonce))
	}
	a := &aesResettable{}
	copy(a.nonce[:], nonce)
	var k [16]byte
	copy(k[:], key)
	areion.ExpandKey128(&k, &a.rk)
	clear(k[:])
	runtime.KeepAlive(&k)
	if byteOffset != 0 {
		if err := a.ResetCounter(byteOffset); err != nil {
			_ = a.Close()
			return nil, err
		}
	}
	return a, nil
}

func (a *aesResettable) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ctr/aes: short dst")
	}
	if len(src) == 0 {
		return
	}
	if a.keystrmLen > 0 {
		take := a.keystrmLen
		if take > len(src) {
			take = len(src)
		}
		ksSlice := a.keystrm[a.keystrmOff : a.keystrmOff+take]
		for i := 0; i < take; i++ {
			dst[i] = src[i] ^ ksSlice[i]
		}
		clear(ksSlice)
		a.keystrmOff += take
		a.keystrmLen -= take
		src = src[take:]
		dst = dst[take:]
	}
	if nBlocks := len(src) / aesBlockSize; nBlocks > 0 {
		adv := nBlocks * aesBlockSize
		areion.AES128CTRXOR(&a.rk, dst[:adv], src[:adv], &a.nonce, a.blockOff)
		a.blockOff += uint64(nBlocks)
		src = src[adv:]
		dst = dst[adv:]
	}
	if rem := len(src); rem > 0 {
		a.keystrm = [aesBlockSize]byte{}
		areion.AES128CTRXOR(&a.rk, a.keystrm[:], a.keystrm[:], &a.nonce, a.blockOff)
		a.blockOff++
		for i := 0; i < rem; i++ {
			dst[i] = src[i] ^ a.keystrm[i]
		}
		clear(a.keystrm[:rem])
		a.keystrmOff = rem
		a.keystrmLen = aesBlockSize - rem
	}
}

func (a *aesResettable) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	clear(a.keystrm[:])
	a.blockOff = uint64(byteOffset / aesBlockSize)
	a.keystrmOff = 0
	a.keystrmLen = 0
	if intra := byteOffset % aesBlockSize; intra > 0 {
		areion.AES128CTRXOR(&a.rk, a.keystrm[:], a.keystrm[:], &a.nonce, a.blockOff)
		a.blockOff++
		clear(a.keystrm[:intra])
		a.keystrmOff = intra
		a.keystrmLen = aesBlockSize - intra
	}
	return nil
}

func (a *aesResettable) Close() error {
	*a = aesResettable{}
	runtime.KeepAlive(a)
	return nil
}

// chaCha20Resettable implements RFC 8439 ChaCha20 in counter mode with
// zero-allocation ResetCounter repositioning and SIMD-accelerated block XOR.
type chaCha20Resettable struct {
	key     [8]uint32
	nonce   [3]uint32
	counter uint64
	skip    int
	buf     [64]byte
	bufOff  int
	bufLen  int
}

func newChaCha20Resettable(key, nonce []byte) (*chaCha20Resettable, error) {
	if len(key) != chacha20ctr.KeySize {
		return nil, fmt.Errorf("ctr: chacha20 key must be %d bytes, got %d", chacha20ctr.KeySize, len(key))
	}
	if len(nonce) != chacha20ctr.NonceSize {
		return nil, fmt.Errorf("ctr: chacha20 nonce must be %d bytes, got %d", chacha20ctr.NonceSize, len(nonce))
	}
	c := &chaCha20Resettable{}
	for i := range c.key {
		c.key[i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	for i := range c.nonce {
		c.nonce[i] = binary.LittleEndian.Uint32(nonce[4*i:])
	}
	return c, nil
}

func (c *chaCha20Resettable) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ctr/chacha20: short dst")
	}
	if len(src) == 0 {
		return
	}
	if c.skip > 0 {
		if c.counter >= 1<<32 {
			panic("ctr/chacha20: counter overflow")
		}
		c.buf = [64]byte{}
		chacha20ctr.XORKeyStreamBlocks(c.buf[:], c.buf[:], &c.key, &c.nonce, uint32(c.counter))
		c.counter++
		clear(c.buf[:c.skip])
		c.bufOff = c.skip
		c.bufLen = 64 - c.skip
		c.skip = 0
	}
	if c.bufLen > 0 {
		take := c.bufLen
		if take > len(src) {
			take = len(src)
		}
		bufSlice := c.buf[c.bufOff : c.bufOff+take]
		for i := 0; i < take; i++ {
			dst[i] = src[i] ^ bufSlice[i]
		}
		clear(bufSlice)
		c.bufOff += take
		c.bufLen -= take
		src = src[take:]
		dst = dst[take:]
	}
	if nBlocks := len(src) / 64; nBlocks > 0 {
		if c.counter+uint64(nBlocks) > 1<<32 {
			panic("ctr/chacha20: counter overflow")
		}
		adv := nBlocks * 64
		chacha20ctr.XORKeyStreamBlocks(dst[:adv], src[:adv], &c.key, &c.nonce, uint32(c.counter))
		c.counter += uint64(nBlocks)
		src = src[adv:]
		dst = dst[adv:]
	}
	if rem := len(src); rem > 0 {
		if c.counter >= 1<<32 {
			panic("ctr/chacha20: counter overflow")
		}
		c.buf = [64]byte{}
		chacha20ctr.XORKeyStreamBlocks(c.buf[:], c.buf[:], &c.key, &c.nonce, uint32(c.counter))
		c.counter++
		for i := 0; i < rem; i++ {
			dst[i] = src[i] ^ c.buf[i]
		}
		clear(c.buf[:rem])
		c.bufOff = rem
		c.bufLen = 64 - rem
	}
}

func (c *chaCha20Resettable) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	const blockSize = 64
	blockOff := uint64(byteOffset / blockSize)
	if blockOff >= 1<<32 {
		return fmt.Errorf("ctr: chacha20 counter overflow — byteOffset %d requires block index %d ≥ 2^32 (~256 GiB per (key, nonce)); outer-layer format deniability weakens past this seek point, inner ITB confidentiality unaffected. Choose AES-128-CTR outer cipher for streams above this cap", byteOffset, blockOff)
	}
	clear(c.buf[:])
	c.counter = blockOff
	c.bufOff = 0
	c.bufLen = 0
	c.skip = byteOffset % blockSize
	return nil
}

func (c *chaCha20Resettable) Close() error {
	*c = chaCha20Resettable{}
	runtime.KeepAlive(c)
	return nil
}

// ResetCounter on sipCTR drops the partial-block buffer, positions the
// 64-bit block counter at the block containing byteOffset, and advances
// past the intra-block remainder without escaping a scratch slice so the
// next XORKeyStream starts at the byte at byteOffset.
func (c *sipCTR) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	const blockSize = 16
	c.counter = uint64(byteOffset / blockSize)
	clear(c.keystrm[:])
	c.keystrmN = 0
	if rem := byteOffset % blockSize; rem > 0 {
		c.refill()
		clear(c.keystrm[:rem])
		c.keystrmN = blockSize - rem
	}
	return nil
}

// ResetCounter on prfHashCTR mirrors the sipCTR variant for the
// fixed-output-width PRF-counter primitives.
func (c *prfHashCTR) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	c.counter = uint64(byteOffset / c.blockSize)
	clear(c.keystrm)
	c.keystrmN = 0
	if rem := byteOffset % c.blockSize; rem > 0 {
		c.refill()
		clear(c.keystrm[:rem])
		c.keystrmN = c.blockSize - rem
	}
	return nil
}

// ResetCounter on prfHashCTRBatch positions the next refill at the
// 4-block group containing byteOffset (refill writes blocks
// counter..counter+3 and advances by 4), drops the partial buffer, and
// advances past the intra-group remainder without escaping a scratch
// slice so the next XORKeyStream starts at byteOffset.
func (c *prfHashCTRBatch) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	c.counter = uint64(byteOffset / c.blockSize)
	clear(c.keystrm)
	c.keystrmN = 0
	if rem := byteOffset % c.blockSize; rem > 0 {
		c.refill()
		clear(c.keystrm[:rem])
		c.keystrmN = 4*c.blockSize - rem
	}
	return nil
}
