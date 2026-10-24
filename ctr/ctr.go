package ctr

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"runtime"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/chacha20ctr"
	"github.com/everanium/itb/internal/hashprf"
	"github.com/everanium/itb/internal/siphash24"
)

// Keystream is the minimal interface a counter-mode cipher exposes. The
// contract matches crypto/cipher.Stream — XORKeyStream xors a keystream
// segment over src into dst, advancing the internal counter.
//
// Every concrete implementation — the native AES-128-CTR and ChaCha20 and the
// PRF-counter-mode constructions — satisfies this signature. The interface
// stays decoupled from crypto/cipher.Stream so the PRF-counter constructions
// do not have to pretend to be a stdlib type.
type Keystream interface {
	XORKeyStream(dst, src []byte)
}

// KeySize returns the byte length of the key for the named cipher.
func KeySize(name string) (int, error) {
	switch name {
	case hashes.CipherAES128CTR:
		return 16, nil
	case hashes.CipherSipHash24:
		return 16, nil
	case hashes.CipherChaCha20:
		return chacha20ctr.KeySize, nil // 32
	case hashes.CipherAreion256, hashes.CipherAreion512, hashes.CipherBLAKE2b256, hashes.CipherBLAKE2b512, hashes.CipherBLAKE2s, hashes.CipherBLAKE3:
		return hashprf.KeySize(name)
	default:
		return 0, fmt.Errorf("ctr: unknown cipher %q", name)
	}
}

// NonceSize returns the nonce length for the named cipher.
func NonceSize(name string) (int, error) {
	switch name {
	case hashes.CipherAES128CTR:
		return aes.BlockSize, nil // 16
	case hashes.CipherSipHash24:
		return 16, nil
	case hashes.CipherChaCha20:
		return chacha20ctr.NonceSize, nil // 12
	case hashes.CipherAreion256, hashes.CipherAreion512, hashes.CipherBLAKE2b256, hashes.CipherBLAKE2b512, hashes.CipherBLAKE2s, hashes.CipherBLAKE3:
		return hashCTRNonceSize, nil // 16
	default:
		return 0, fmt.Errorf("ctr: unknown cipher %q", name)
	}
}

// New constructs a Keystream from the named cipher, the caller-provided key,
// and a per-stream nonce. The key length must equal KeySize(name); the nonce
// length must equal NonceSize(name).
//
// Names outside PRF-grade registry primitives yield an
// unknown-cipher error.
func New(name string, key, nonce []byte) (Keystream, error) {
	switch name {
	case hashes.CipherAES128CTR:
		ks, err := newAESResettable(key, nonce)
		if err != nil {
			return nil, err
		}
		return ks, nil
	case hashes.CipherSipHash24:
		return newSipHashCTR(key, nonce)
	case hashes.CipherChaCha20:
		c, err := newChaCha20Resettable(key, nonce)
		if err != nil {
			return nil, err
		}
		return c, nil
	case hashes.CipherAreion256, hashes.CipherAreion512, hashes.CipherBLAKE2b256, hashes.CipherBLAKE2b512, hashes.CipherBLAKE2s, hashes.CipherBLAKE3:
		return newPrfHashCTR(name, key, nonce)
	default:
		return nil, fmt.Errorf("ctr: unknown cipher %q", name)
	}
}

// SipHash-2-4 in CTR mode.
//
// SipHash-2-4 is a 128-bit-keyed PRF / MAC; the 128-bit-output variant
// (SipHash-2-4-128) drives the keystream. Building a keystream from a PRF is
// the standard CTR construction:
//
//	keystream_block_i = SipHash128(K, nonce_hi || (nonce_lo XOR counter_i))   (16 bytes per call)
//
// The combined PRF input is 16 bytes (a 16-byte nonce split into two 8-byte
// halves, counter increments folded into the lower half). The construction is
// sound under the same PRF assumption that justifies AES-CTR — XORing PRF
// output with plaintext is the canonical PRF-secure stream. The 128-bit
// output places the keystream-block collision birthday at 2^64.
type sipCTR struct {
	k0, k1   uint64
	nonceHi  uint64
	nonceLo  uint64
	vInit    [4]uint64
	counter  uint64
	keystrm  [16]byte
	keystrmN int // number of unconsumed bytes in keystrm[16-keystrmN:]
}

func newSipHashCTR(key, nonce []byte) (Keystream, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("ctr: siphash key must be 16 bytes, got %d", len(key))
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("ctr: siphash nonce must be 16 bytes, got %d", len(nonce))
	}
	c := &sipCTR{
		k0:      binary.LittleEndian.Uint64(key[:8]),
		k1:      binary.LittleEndian.Uint64(key[8:]),
		nonceHi: binary.LittleEndian.Uint64(nonce[:8]),
		nonceLo: binary.LittleEndian.Uint64(nonce[8:]),
	}
	siphash24.InitCTRState(&c.vInit, c.k0, c.k1, c.nonceHi)
	return c, nil
}

func (c *sipCTR) Close() error {
	*c = sipCTR{}
	runtime.KeepAlive(c)
	return nil
}

func (c *sipCTR) refill() {
	siphash24.Block128Into(&c.keystrm, c.k0, c.k1, c.nonceHi, c.nonceLo^c.counter)
	c.counter++
	c.keystrmN = 16
}

func (c *sipCTR) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ctr/siphash: short dst")
	}
	n := len(src)
	i := 0

	// Drain leftover bytes from a previous partial refill, byte by byte.
	if c.keystrmN > 0 {
		off := 16 - c.keystrmN
		take := c.keystrmN
		if take > n {
			take = n
		}
		for j := 0; j < take; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[off+j]
			c.keystrm[off+j] = 0
		}
		i += take
		c.keystrmN -= take
	}

	// Bulk path: evaluate full 16-byte blocks via SIMD / register-ABI CTR kernel.
	if nBlocks := (n - i) / 16; nBlocks > 0 {
		adv := nBlocks * 16
		siphash24.XORKeyStreamBlocksWithState(dst[i:i+adv], src[i:i+adv], &c.vInit, c.nonceLo, c.counter)
		c.counter += uint64(nBlocks)
		i += adv
	}

	// Tail (<16 bytes): refill keystrm buffer and consume the leading bytes.
	if i < n {
		c.refill()
		rem := n - i
		for j := 0; j < rem; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[j]
			c.keystrm[j] = 0
		}
		c.keystrmN -= rem
	}
}
