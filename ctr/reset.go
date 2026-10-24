package ctr

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/chacha20ctr"
	"github.com/everanium/itb/internal/wipe"
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

// aesResettable wraps a crypto/cipher.Stream over AES-128 alongside the
// cached cipher.Block and the original 16-byte nonce. ResetCounter
// rebuilds the inner Stream at the IV positioned by blockOff blocks past
// the nonce, then discards the intra-block remainder; the cipher.Block
// is reused so AES key expansion runs once per construction.
type aesResettable struct {
	block            cipher.Block
	nonce            [aes.BlockSize]byte
	nonceHi          uint64
	nonceLo          uint64
	iv               [aes.BlockSize]byte
	scratch          [aes.BlockSize]byte
	stream           cipher.Stream
	streamAlt        cipher.Stream
	streamDirectSize int
	fastReset        bool
}

func detectStreamDirectSize(s *cipher.Stream) int {
	if s == nil || *s == nil {
		return 0
	}
	rv := reflect.ValueOf(*s)
	if rv.Kind() != reflect.Struct || rv.NumField() != 1 {
		return 0
	}
	f := rv.Field(0)
	if f.Kind() != reflect.Pointer || f.IsNil() {
		return 0
	}
	elem := f.Type().Elem()
	if elem.Kind() != reflect.Struct {
		return 0
	}
	for i := 0; i < elem.NumField(); i++ {
		switch elem.Field(i).Type.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Interface, reflect.Map, reflect.Chan, reflect.Func:
			return 0
		}
	}
	ifaceWords := (*[2]unsafe.Pointer)(unsafe.Pointer(s))
	if ifaceWords[1] != f.UnsafePointer() {
		return 0
	}
	return int(elem.Size())
}

var (
	aesCTRDirectSize int
	aesCTRFastReset  bool
)

func init() {
	var zeroKey [16]byte
	block, err := aes.NewCipher(zeroKey[:])
	if err != nil {
		return
	}
	const (
		probeHi = uint64(0x0102030405060708)
		probeLo = uint64(0x090a0b0c0d0e0f10)
	)
	var probeIV [aes.BlockSize]byte
	binary.BigEndian.PutUint64(probeIV[0:8], probeHi)
	binary.BigEndian.PutUint64(probeIV[8:16], probeLo)
	s := cipher.NewCTR(block, probeIV[:])
	sz := detectStreamDirectSize(&s)
	aesCTRDirectSize = sz
	if sz >= 24 && sz <= 512+24 {
		p := (*[2]unsafe.Pointer)(unsafe.Pointer(&s))[1]
		if p != nil {
			schedLen := sz - 24
			tail := (*[3]uint64)(unsafe.Add(p, schedLen))
			if tail[0] == probeLo && tail[1] == probeHi && tail[2] == 0 {
				var z [5]byte
				s.XORKeyStream(z[:], z[:])
				clear(z[:])
				if tail[0] == probeLo && tail[1] == probeHi && tail[2] == 5 {
					aesCTRFastReset = true
				}
			}
			b := unsafe.Slice((*byte)(p), sz)
			clear(b)
			runtime.KeepAlive(b)
		}
	}
	wipe.StructPtr(s)
	wipe.StructPtr(block)
}

func (a *aesResettable) wipeStream() {
	if a.stream == nil {
		return
	}
	if a.streamDirectSize > 0 {
		p := (*[2]unsafe.Pointer)(unsafe.Pointer(&a.stream))[1]
		if p != nil {
			b := unsafe.Slice((*byte)(p), a.streamDirectSize)
			clear(b)
			runtime.KeepAlive(b)
			return
		}
	}
	wipe.StructPtr(a.stream)
}

func newAESResettable(key, nonce []byte) (*aesResettable, error) {
	return newAESResettableAt(key, nonce, 0)
}

func newAESResettableAt(key, nonce []byte, byteOffset int) (*aesResettable, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("ctr: aes-128-ctr key must be 16 bytes, got %d", len(key))
	}
	if len(nonce) != aes.BlockSize {
		return nil, fmt.Errorf("ctr: aes-128-ctr nonce must be %d bytes, got %d", aes.BlockSize, len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a := &aesResettable{
		block:            block,
		nonceHi:          binary.BigEndian.Uint64(nonce[0:8]),
		nonceLo:          binary.BigEndian.Uint64(nonce[8:16]),
		streamDirectSize: aesCTRDirectSize,
	}
	copy(a.nonce[:], nonce)

	s0 := cipher.NewCTR(block, a.nonce[:])
	if aesCTRFastReset {
		p0 := (*[2]unsafe.Pointer)(unsafe.Pointer(&s0))[1]
		if p0 != nil {
			schedLen := aesCTRDirectSize - 24
			a.fastReset = true
			tail0 := (*[3]uint64)(unsafe.Add(p0, schedLen))
			tail0[0] = a.nonceLo
			tail0[1] = a.nonceHi
			tail0[2] = uint64(byteOffset)
			a.stream = s0
			return a, nil
		}
	}

	if byteOffset == 0 {
		a.stream = s0
		return a, nil
	}
	a.stream = s0
	a.wipeStream()
	blockOff := uint64(byteOffset / aes.BlockSize)
	intra := byteOffset % aes.BlockSize
	ivAtInto(&a.iv, a.nonce[:], blockOff)
	a.stream = cipher.NewCTR(block, a.iv[:])
	clear(a.iv[:])
	if intra > 0 {
		z := a.scratch[:intra]
		a.stream.XORKeyStream(z, z)
		clear(z)
	}
	return a, nil
}

func (a *aesResettable) XORKeyStream(dst, src []byte) {
	a.stream.XORKeyStream(dst, src)
}

func (a *aesResettable) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	if a.fastReset {
		if a.streamAlt == nil {
			s1 := cipher.NewCTR(a.block, a.nonce[:])
			a.wipeStream()
			a.streamAlt = s1
			a.stream = s1
		}
		p := (*[2]unsafe.Pointer)(unsafe.Pointer(&a.stream))[1]
		schedLen := a.streamDirectSize - 24
		tail := (*[3]uint64)(unsafe.Add(p, schedLen))
		tail[0] = a.nonceLo
		tail[1] = a.nonceHi
		tail[2] = uint64(byteOffset)
		return nil
	}
	blockOff := uint64(byteOffset / aes.BlockSize)
	intra := byteOffset % aes.BlockSize
	ivAtInto(&a.iv, a.nonce[:], blockOff)
	a.wipeStream()
	a.stream = cipher.NewCTR(a.block, a.iv[:])
	clear(a.iv[:])
	if intra > 0 {
		z := a.scratch[:intra]
		a.stream.XORKeyStream(z, z)
		clear(z)
	}
	return nil
}

func (a *aesResettable) Close() error {
	clear(a.nonce[:])
	a.nonceHi = 0
	a.nonceLo = 0
	clear(a.iv[:])
	clear(a.scratch[:])
	a.wipeStream()
	if a.streamAlt != nil {
		a.stream = a.streamAlt
		a.wipeStream()
		a.streamAlt = nil
	}
	wipe.StructPtr(a.block)
	a.stream = nil
	a.block = nil
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
