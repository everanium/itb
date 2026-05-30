// Package kdf derives length-flexible subkeys from a key-derivation key
// using a per-primitive construction selected by registry cipher name.
//
// The intended source of the master key-derivation key is a high-entropy,
// uniformly distributed secret such as an ML-KEM shared secret. Each
// supported registry primitive maps to a standard, separately analysable
// construction:
//
//   - "areion256", "areion512" — SP 800-108 KDF in Counter Mode, PRF = the
//     registry Areion-SoEM keyed hash. areion512 needs a
//     64-byte PRF key; a 32-byte master is deterministically
//     stretched to 64 bytes via areion256 first.
//   - "siphash24" — NIST SP 800-108 KDF in Counter Mode, PRF =
//     SipHash-2-4 with 128-bit output.
//   - "aescmac"   — NIST SP 800-108 KDF in Counter Mode, PRF = AES-CMAC
//     over AES-128.
//   - "blake2b256", "blake2b512", "blake2s", "blake3" — SP 800-108 KDF in
//     Counter Mode, PRF = the primitive's native keyed hash.
//   - "chacha20"  — XChaCha20 keystream KDF with the public label as the
//     24-byte nonce.
//
// Derive returns an error for any other name.
//
// A public domain-separation label keeps independent derivations from the
// same master distinct. Labels need only be unique per intended subkey;
// they carry no secrecy requirement.
package kdf

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"

	"github.com/dchest/siphash"
	"golang.org/x/crypto/chacha20"
)

// Key sizes per supported primitive, in bytes.
const (
	aescmacKeySize   = 16 // AES-128
	siphash24KeySize = 16 // (k0, k1) little-endian halves
	chacha20KeySize  = 32 // XChaCha20 key
)

// chacha20NonceSize is the XChaCha20 nonce length. A 24-byte nonce
// selects the XChaCha20 variant of chacha20.NewUnauthenticatedCipher.
const chacha20NonceSize = 24

// maxOutLen caps the requested output length. The SP 800-108 counter-mode
// constructions encode the output length in bits as a 32-bit big-endian L
// field, so outLen*8 must fit in a uint32; the cap keeps every construction
// well within that bound (real subkeys are a few dozen bytes).
const maxOutLen = (1<<32)/8 - 1

// Derive produces an outLen-byte subkey from master under the public
// domain-separation label, using the construction selected by name.
//
// name selects the construction; supported values are "areion256",
// "areion512", "blake2b256", "blake2b512", "blake2s", "blake3",
// "aescmac", "siphash24", "chacha20". Any other value is an error.
//
// master is the key-derivation key. When master is longer than the
// selected primitive's key size it is truncated to that size (a uniform
// master remains uniform under truncation). When master is shorter than
// the required key size Derive returns an error rather than fabricate
// key entropy.
//
// label is a public domain-separation string. For "aescmac" and
// "siphash24" it is the SP 800-108 Label field and may be any length.
// For "chacha20" it becomes the XChaCha20 nonce and must be at most 24
// bytes; longer labels are an error.
//
// outLen is the exact number of subkey bytes returned. It must be
// non-negative.
func Derive(name string, master []byte, label string, outLen int) ([]byte, error) {
	if outLen < 0 {
		return nil, fmt.Errorf("kdf: negative output length %d", outLen)
	}
	if outLen > maxOutLen {
		return nil, fmt.Errorf("kdf: output length %d exceeds maximum %d", outLen, maxOutLen)
	}
	switch name {
	case "aescmac":
		return deriveAESCMAC(master, label, outLen)
	case "siphash24":
		return deriveSipHash24(master, label, outLen)
	case "chacha20":
		return deriveChaCha20(master, label, outLen)
	case hashAreion256, hashBLAKE2b256, hashBLAKE2b512, hashBLAKE2s, hashBLAKE3:
		return deriveHashPRF(name, master, label, outLen)
	case hashAreion512:
		return deriveAreion512(master, label, outLen)
	default:
		return nil, fmt.Errorf("kdf: unsupported primitive %q", name)
	}
}

// deriveAESCMAC implements SP 800-108 Counter Mode with PRF = AES-CMAC
// over AES-128. master is truncated to 16 bytes; a shorter master is an
// error.
func deriveAESCMAC(master []byte, label string, outLen int) ([]byte, error) {
	if len(master) < aescmacKeySize {
		return nil, fmt.Errorf("kdf: aescmac master must be at least %d bytes, got %d", aescmacKeySize, len(master))
	}
	block, err := aes.NewCipher(master[:aescmacKeySize])
	if err != nil {
		return nil, fmt.Errorf("kdf: aescmac key setup: %w", err)
	}
	mac := newCMAC(block)
	prf := func(in []byte) []byte {
		return mac.sum(in)
	}
	return sp800108CounterMode(prf, aes.BlockSize, []byte(label), outLen), nil
}

// deriveSipHash24 implements SP 800-108 Counter Mode with PRF =
// SipHash-2-4-128. The 16-byte master is the (k0, k1) SipHash key; a
// shorter master is an error.
func deriveSipHash24(master []byte, label string, outLen int) ([]byte, error) {
	if len(master) < siphash24KeySize {
		return nil, fmt.Errorf("kdf: siphash24 master must be at least %d bytes, got %d", siphash24KeySize, len(master))
	}
	k0 := binary.LittleEndian.Uint64(master[:8])
	k1 := binary.LittleEndian.Uint64(master[8:16])
	prf := func(in []byte) []byte {
		lo, hi := siphash.Hash128(k0, k1, in)
		out := make([]byte, 16)
		binary.LittleEndian.PutUint64(out[:8], lo)
		binary.LittleEndian.PutUint64(out[8:], hi)
		return out
	}
	return sp800108CounterMode(prf, 16, []byte(label), outLen), nil
}

// deriveChaCha20 implements the XChaCha20 keystream KDF. The 32-byte
// master is the XChaCha20 key; a shorter master is an error. The label
// is right-zero-padded to a 24-byte nonce and must be at most 24 bytes.
// The subkey is the leading outLen bytes of the XChaCha20 keystream at
// counter 0.
func deriveChaCha20(master []byte, label string, outLen int) ([]byte, error) {
	if len(master) < chacha20KeySize {
		return nil, fmt.Errorf("kdf: chacha20 master must be at least %d bytes, got %d", chacha20KeySize, len(master))
	}
	if len(label) > chacha20NonceSize {
		return nil, fmt.Errorf("kdf: chacha20 label must be at most %d bytes, got %d", chacha20NonceSize, len(label))
	}
	var nonce [chacha20NonceSize]byte
	copy(nonce[:], label)
	c, err := chacha20.NewUnauthenticatedCipher(master[:chacha20KeySize], nonce[:])
	if err != nil {
		return nil, fmt.Errorf("kdf: chacha20 cipher setup: %w", err)
	}
	out := make([]byte, outLen)
	// XORing the keystream into a zero buffer extracts the raw keystream.
	c.XORKeyStream(out, out)
	return out, nil
}

// sp800108CounterMode runs the NIST SP 800-108 KDF in Counter Mode
// (representation r1) over a fixed-output-length PRF. For each block
// index i = 1, 2, ... the PRF input is
//
//	[i]_32be || Label || 0x00 || Context || [L]_32be
//
// with empty Context and L the requested output length in bits. The
// returned slice is the leftmost outLen bytes of the concatenated PRF
// outputs K(1) || K(2) || ...
//
// Because L is bound into every block input, the output is specific to
// outLen: deriving a different outLen under the same key and label yields
// entirely different bytes, so a longer derivation truncated to a shorter
// length does NOT equal the shorter derivation. Derivations sharing the
// same (key, label, outLen) are deterministic and identical.
//
// prf returns exactly prfLen bytes per call.
func sp800108CounterMode(prf func([]byte) []byte, prfLen int, label []byte, outLen int) []byte {
	out := make([]byte, outLen)
	if outLen == 0 {
		return out
	}

	// Fixed-input layout per block: 4-byte counter prefix, then Label,
	// the 0x00 separator, the (empty) Context, and the 4-byte L suffix.
	// Only the leading 4 counter bytes change between blocks, so the
	// suffix is built once and reused.
	suffix := make([]byte, 0, len(label)+1+4)
	suffix = append(suffix, label...)
	suffix = append(suffix, 0x00)
	var lbits [4]byte
	binary.BigEndian.PutUint32(lbits[:], uint32(outLen)*8)
	suffix = append(suffix, lbits[:]...)

	in := make([]byte, 4+len(suffix))
	copy(in[4:], suffix)

	written := 0
	for i := uint32(1); written < outLen; i++ {
		binary.BigEndian.PutUint32(in[:4], i)
		block := prf(in)
		n := copy(out[written:], block[:prfLen])
		written += n
	}
	return out
}
