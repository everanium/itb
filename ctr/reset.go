package ctr

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20"
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
	case CipherSipHash24:
		ks, err := newSipHashCTR(key, nonce)
		if err != nil {
			return nil, err
		}
		return ks.(*sipCTR), nil
	case CipherAES128CTR:
		return newAESResettable(key, nonce)
	case CipherChaCha20:
		return newChaCha20Resettable(key, nonce)
	case CipherAreion256, CipherAreion512, CipherBLAKE2b256, CipherBLAKE2b512, CipherBLAKE2s, CipherBLAKE3:
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
	ks, err := NewResettable(name, key, nonce)
	if err != nil {
		return nil, err
	}
	if byteOffset == 0 {
		return ks, nil
	}
	if err := ks.ResetCounter(byteOffset); err != nil {
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
	block  cipher.Block
	nonce  [aes.BlockSize]byte
	stream cipher.Stream
}

func newAESResettable(key, nonce []byte) (*aesResettable, error) {
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
	a := &aesResettable{block: block}
	copy(a.nonce[:], nonce)
	a.stream = cipher.NewCTR(block, a.nonce[:])
	return a, nil
}

func (a *aesResettable) XORKeyStream(dst, src []byte) {
	a.stream.XORKeyStream(dst, src)
}

func (a *aesResettable) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	blockOff := uint64(byteOffset / aes.BlockSize)
	intra := byteOffset % aes.BlockSize
	a.stream = cipher.NewCTR(a.block, ivAt(a.nonce[:], blockOff))
	discard(a.stream, intra)
	return nil
}

// chaCha20Resettable wraps *chacha20.Cipher (RFC 8439). The upstream
// SetCounter refuses to move the block counter backwards (it panics to
// prevent counter reuse across distinct messages), so ResetCounter
// rebuilds the cipher from the original key and nonce on every call,
// then SetCounter takes the always-fresh counter forward to the target
// block. The intra-block remainder is then discarded so the next
// XORKeyStream starts at the byte at byteOffset. The RFC 8439 block
// counter is 32 bits wide, so byteOffset must satisfy
// byteOffset/64 <= 2^32 − 1.
type chaCha20Resettable struct {
	cipher *chacha20.Cipher
	key    []byte
	nonce  []byte
}

func newChaCha20Resettable(key, nonce []byte) (*chaCha20Resettable, error) {
	if len(key) != chacha20.KeySize {
		return nil, fmt.Errorf("ctr: chacha20 key must be %d bytes, got %d", chacha20.KeySize, len(key))
	}
	if len(nonce) != chacha20.NonceSize {
		return nil, fmt.Errorf("ctr: chacha20 nonce must be %d bytes, got %d", chacha20.NonceSize, len(nonce))
	}
	keyCopy := append([]byte(nil), key...)
	nonceCopy := append([]byte(nil), nonce...)
	c, err := chacha20.NewUnauthenticatedCipher(keyCopy, nonceCopy)
	if err != nil {
		return nil, err
	}
	return &chaCha20Resettable{
		cipher: c,
		key:    keyCopy,
		nonce:  nonceCopy,
	}, nil
}

func (c *chaCha20Resettable) XORKeyStream(dst, src []byte) {
	c.cipher.XORKeyStream(dst, src)
}

func (c *chaCha20Resettable) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	const blockSize = 64
	blockOff := uint64(byteOffset / blockSize)
	if blockOff > uint64(^uint32(0)) {
		return fmt.Errorf("ctr: chacha20 byteOffset %d overflows 32-bit block counter", byteOffset)
	}
	fresh, err := chacha20.NewUnauthenticatedCipher(c.key, c.nonce)
	if err != nil {
		return err
	}
	fresh.SetCounter(uint32(blockOff))
	c.cipher = fresh
	discard(c.cipher, byteOffset%blockSize)
	return nil
}

// ResetCounter on sipCTR drops the partial-block buffer, positions the
// 64-bit block counter at the block containing byteOffset, and discards
// the intra-block remainder so the next XORKeyStream starts at the byte
// at byteOffset.
func (c *sipCTR) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	const blockSize = 16
	c.counter = uint64(byteOffset / blockSize)
	c.keystrmN = 0
	discard(c, byteOffset%blockSize)
	return nil
}

// ResetCounter on prfHashCTR mirrors the sipCTR variant for the
// fixed-output-width PRF-counter primitives.
func (c *prfHashCTR) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	c.counter = uint64(byteOffset / c.blockSize)
	c.keystrmN = 0
	discard(c, byteOffset%c.blockSize)
	return nil
}

// ResetCounter on prfHashCTRBatch positions the next refill at the
// 4-block group containing byteOffset (refill writes blocks
// counter..counter+3 and advances by 4), drops the partial buffer, and
// discards the intra-group remainder so the next XORKeyStream starts at
// byteOffset.
func (c *prfHashCTRBatch) ResetCounter(byteOffset int) error {
	if byteOffset < 0 {
		return fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	groupSize := 4 * c.blockSize
	c.counter = uint64(byteOffset/groupSize) * 4
	c.keystrmN = 0
	discard(c, byteOffset%groupSize)
	return nil
}
