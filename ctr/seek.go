package ctr

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20"

	"github.com/everanium/itb/internal/hashprf"
)

// streamBlockSize returns the keystream block granularity of the named cipher,
// the unit the counter advances by. Used to split a byte offset into a whole-
// block counter jump plus an intra-block remainder.
func streamBlockSize(name string) (int, error) {
	switch name {
	case CipherAES128CTR, CipherSipHash24:
		return 16, nil
	case CipherChaCha20:
		return 64, nil
	case CipherAreion256, CipherAreion512, CipherBLAKE2b256, CipherBLAKE2b512, CipherBLAKE2s, CipherBLAKE3:
		return hashprf.BlockSize(name)
	default:
		return 0, fmt.Errorf("ctr: unknown cipher %q", name)
	}
}

// ivAt returns the 16-byte AES-CTR IV positioned blockOff blocks past nonce,
// i.e. nonce interpreted as a big-endian 128-bit counter plus blockOff. This
// matches crypto/cipher CTR's whole-IV big-endian increment, so the keystream
// from cipher.NewCTR(block, ivAt(nonce, b)) equals the original stream's block b.
func ivAt(nonce []byte, blockOff uint64) []byte {
	iv := make([]byte, 16)
	copy(iv, nonce)
	carry := blockOff
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(iv[i]) + (carry & 0xff)
		iv[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
	return iv
}

// discard advances a keystream by n bytes (n < one block) by XORing a scratch
// buffer through it. Used to skip the intra-block remainder after a whole-block
// counter jump; n is bounded by the cipher block size, so this is O(1).
func discard(ks Keystream, n int) {
	if n <= 0 {
		return
	}
	z := make([]byte, n)
	ks.XORKeyStream(z, z)
}

// NewAt returns a keystream positioned so its first output byte is the byte at
// byteOffset of the (name, key, nonce) stream produced by New. It lets one
// logical stream be XORed in parallel: each worker seeks to its chunk's byte
// offset and emits only its slice. The seek is O(1) — a whole-block counter
// jump plus an intra-block remainder skip of fewer than one block's bytes —
// never an O(byteOffset) discard.
//
// byteOffset must be >= 0; byteOffset == 0 is exactly New.
func NewAt(name string, key, nonce []byte, byteOffset int) (Keystream, error) {
	if byteOffset < 0 {
		return nil, fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	if byteOffset == 0 {
		return New(name, key, nonce)
	}
	bs, err := streamBlockSize(name)
	if err != nil {
		return nil, err
	}
	blockOff := uint64(byteOffset / bs)
	intra := byteOffset % bs

	// AES-CTR cannot be re-seeked after construction; build it with an
	// offset IV instead.
	if name == CipherAES128CTR {
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
		ks := cipher.NewCTR(block, ivAt(nonce, blockOff))
		discard(ks, intra)
		return ks, nil
	}

	// All other ciphers expose a counter the constructor leaves at 0; jump it
	// to blockOff, then skip the intra-block remainder.
	ks, err := New(name, key, nonce)
	if err != nil {
		return nil, err
	}
	switch c := ks.(type) {
	case *sipCTR:
		c.counter = blockOff
	case *prfHashCTR:
		c.counter = blockOff
	case *prfHashCTRBatch:
		c.counter = blockOff
	case *chacha20.Cipher:
		c.SetCounter(uint32(blockOff))
	default:
		return nil, fmt.Errorf("ctr: %s keystream is not seekable", name)
	}
	discard(ks, intra)
	return ks, nil
}
