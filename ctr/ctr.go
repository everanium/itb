// Package ctr provides counter-mode keystream constructions over the nine
// PRF-grade ITB registry primitives. AES-128-CTR ("aescmac") and ChaCha20
// ("chacha20") use their native cipher modes; the other seven ("areion256",
// "areion512", "siphash24", "blake2b256", "blake2b512", "blake2s", "blake3")
// run in PRF-counter mode, where a keystream block is the primitive's
// keyed-PRF output over the nonce concatenated with the block counter.
//
// The package is the single source of truth for cipher key and nonce sizes.
// Each keystream satisfies the Keystream interface, whose XORKeyStream method
// matches the crypto/cipher.Stream contract: the keystream segment is XORed
// over src into dst while the internal counter advances.
package ctr

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/dchest/siphash"
	"golang.org/x/crypto/chacha20"

	"github.com/everanium/itb/internal/hashprf"
)

// Cipher names for the native-mode primitives, matching the ITB registry
// identifiers. The remaining PRF-counter-mode names are defined alongside
// their construction.
const (
	CipherSipHash24 = "siphash24"
	CipherAES128CTR = "aescmac"
	CipherChaCha20  = "chacha20"
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
//
// aescmac uses a 16-byte AES-128 key; chacha20 uses a 32-byte key;
// siphash24 uses a 16-byte SipHash key.
func KeySize(name string) (int, error) {
	switch name {
	case CipherSipHash24:
		return 16, nil
	case CipherAES128CTR:
		return 16, nil
	case CipherChaCha20:
		return chacha20.KeySize, nil // 32
	case CipherAreion256, CipherAreion512, CipherBLAKE2b256, CipherBLAKE2b512, CipherBLAKE2s, CipherBLAKE3:
		return hashprf.KeySize(name)
	default:
		return 0, fmt.Errorf("ctr: unknown cipher %q", name)
	}
}

// NonceSize returns the nonce length for the named cipher.
//
// aescmac uses a 16-byte block-sized IV; chacha20 (RFC8439) uses a 12-byte
// nonce; siphash24 uses a 16-byte construction-defined nonce (the SipHash key
// is the cipher key; the nonce is mixed with the 64-bit counter under the PRF).
func NonceSize(name string) (int, error) {
	switch name {
	case CipherSipHash24:
		return 16, nil
	case CipherAES128CTR:
		return aes.BlockSize, nil // 16
	case CipherChaCha20:
		return chacha20.NonceSize, nil // 12
	case CipherAreion256, CipherAreion512, CipherBLAKE2b256, CipherBLAKE2b512, CipherBLAKE2s, CipherBLAKE3:
		return hashCTRNonceSize, nil // 16
	default:
		return 0, fmt.Errorf("ctr: unknown cipher %q", name)
	}
}

// New constructs a Keystream from the named cipher, the caller-provided key,
// and a per-stream nonce. The key length must equal KeySize(name); the nonce
// length must equal NonceSize(name).
//
// Names outside the nine PRF-grade registry primitives yield an
// unknown-cipher error.
func New(name string, key, nonce []byte) (Keystream, error) {
	switch name {
	case CipherSipHash24:
		return newSipHashCTR(key, nonce)
	case CipherAES128CTR:
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
		return cipher.NewCTR(block, nonce), nil
	case CipherChaCha20:
		if len(key) != chacha20.KeySize {
			return nil, fmt.Errorf("ctr: chacha20 key must be %d bytes, got %d", chacha20.KeySize, len(key))
		}
		if len(nonce) != chacha20.NonceSize {
			return nil, fmt.Errorf("ctr: chacha20 nonce must be %d bytes, got %d", chacha20.NonceSize, len(nonce))
		}
		c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			return nil, err
		}
		return c, nil
	case CipherAreion256, CipherAreion512, CipherBLAKE2b256, CipherBLAKE2b512, CipherBLAKE2s, CipherBLAKE3:
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
//	keystream_block_i = SipHash128(K, nonce || counter_i)   (16 bytes per call)
//
// The combined PRF input is 16 bytes (a 16-byte nonce split into two 8-byte
// halves, counter increments folded into the lower half). The construction is
// sound under the same PRF assumption that justifies AES-CTR — XORing PRF
// output with plaintext is the canonical PRF-secure stream. The 128-bit
// output places the keystream-block collision birthday at 2^64.
//
// The nonce is 16 bytes wide, partitioned as (nonce_hi||nonce_lo). Each
// keystream block hashes a 16-byte input formed from
// (nonce_hi || nonce_lo XOR counter_le). This binds every block to the
// stream's nonce while injecting unique 64-bit counter material per block.

type sipCTR struct {
	k0, k1   uint64
	nonceHi  uint64
	nonceLo  uint64
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
	return c, nil
}

func (c *sipCTR) refill() {
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[:8], c.nonceHi)
	binary.LittleEndian.PutUint64(buf[8:], c.nonceLo^c.counter)
	lo, hi := siphash.Hash128(c.k0, c.k1, buf[:])
	binary.LittleEndian.PutUint64(c.keystrm[:8], lo)
	binary.LittleEndian.PutUint64(c.keystrm[8:], hi)
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
		}
		i += take
		c.keystrmN -= take
	}

	// Bulk path: hash one 16-byte input per 16-byte keystream block, XOR
	// directly via two uint64 — skips the keystrm[16]byte buffer entirely.
	var nonceBuf [16]byte
	binary.LittleEndian.PutUint64(nonceBuf[:8], c.nonceHi)
	for n-i >= 16 {
		binary.LittleEndian.PutUint64(nonceBuf[8:], c.nonceLo^c.counter)
		ksLo, ksHi := siphash.Hash128(c.k0, c.k1, nonceBuf[:])
		srcLo := binary.LittleEndian.Uint64(src[i:])
		srcHi := binary.LittleEndian.Uint64(src[i+8:])
		binary.LittleEndian.PutUint64(dst[i:], srcLo^ksLo)
		binary.LittleEndian.PutUint64(dst[i+8:], srcHi^ksHi)
		c.counter++
		i += 16
	}

	// Tail (<16 bytes): refill keystrm buffer and consume the leading bytes.
	if i < n {
		c.refill()
		rem := n - i
		for j := 0; j < rem; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[j]
		}
		c.keystrmN -= rem
	}
}
