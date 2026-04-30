package macs

import (
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/everanium/itb"
)

// KMAC256 returns a cached KMAC256 itb.MACFunc keyed by key.
//
// KMAC256 is defined in NIST SP 800-185 Section 4 as
//
//	KMAC256(K, X, L, S) = cSHAKE256(newX, L, "KMAC", S)
//
// where newX = bytepad(encode_string(K), 136) || X || right_encode(L)
// and L is the requested output length in bits (256 here, 32 bytes).
//
// The shipped factory uses an empty customization string S; pass a
// non-empty S via [KMAC256WithCustomization] when domain separation
// across multiple distinct usages of the same key is required.
//
// Caching strategy: cSHAKE256 carries internal sponge state, and
// the absorb phase up through bytepad(encode_string(K), 136) is
// keyspecific. The factory absorbs that prefix into a template
// cSHAKE256 once, then clones the template per call to absorb the
// message and emit 32 output bytes. Cloning is cheap (sponge state
// copy) and concurrent goroutines may invoke the closure in
// parallel.
//
// Key length must be at least 16 bytes (NIST SP 800-185 places no
// hard lower bound, but ITB enforces 16-byte minimum to stay aligned
// with its own keying discipline).
func KMAC256(key []byte) (itb.MACFunc, error) {
	return KMAC256WithCustomization(key, nil)
}

// KMAC256WithCustomization is KMAC256 with a non-empty customization
// string S, intended for callers that need domain separation across
// multiple distinct usages of the same key.
func KMAC256WithCustomization(key, customization []byte) (itb.MACFunc, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("macs: kmac256 key too short: %d bytes (min 16)", len(key))
	}
	const rate = 136 // KMAC256 underlying cSHAKE256 rate in bytes (1088 bits)
	const outputBits = 256

	prefix := bytepad(encodeString(key), rate)
	suffix := rightEncode(uint64(outputBits))

	custom := append([]byte(nil), customization...)

	// Pre-absorb the keyed prefix into a template cSHAKE256.
	// NewCShake256 takes function-name N = "KMAC" and customization S;
	// per NIST SP 800-185, the cSHAKE256 padding bookkeeping happens
	// inside the constructor.
	template := sha3.NewCShake256([]byte("KMAC"), custom)
	if _, err := template.Write(prefix); err != nil {
		return nil, fmt.Errorf("macs: cshake256.Write(prefix): %w", err)
	}

	return func(data []byte) []byte {
		h := template.Clone()
		_, _ = h.Write(data)
		_, _ = h.Write(suffix)
		var out [32]byte
		_, _ = h.Read(out[:])
		return append([]byte(nil), out[:]...)
	}, nil
}

// leftEncode implements NIST SP 800-185 Algorithm 5: the variable-
// length integer encoding used as a length prefix. Returns
// `n || big-endian(x)` where n is the byte length of the
// representation.
func leftEncode(x uint64) []byte {
	var buf [9]byte
	// Find the most-significant non-zero byte (n bytes total).
	n := 8
	for n > 1 && (x>>(uint(n-1)*8))&0xFF == 0 {
		n--
	}
	buf[0] = byte(n)
	for i := 0; i < n; i++ {
		buf[1+i] = byte(x >> (uint(n-1-i) * 8))
	}
	return buf[:1+n]
}

// rightEncode is leftEncode with the length byte at the end. NIST
// SP 800-185 Algorithm 6.
func rightEncode(x uint64) []byte {
	var buf [9]byte
	n := 8
	for n > 1 && (x>>(uint(n-1)*8))&0xFF == 0 {
		n--
	}
	for i := 0; i < n; i++ {
		buf[i] = byte(x >> (uint(n-1-i) * 8))
	}
	buf[n] = byte(n)
	return buf[:n+1]
}

// encodeString implements NIST SP 800-185 Algorithm 3: encodes a
// byte string as `left_encode(len(s) * 8) || s`.
func encodeString(s []byte) []byte {
	enc := leftEncode(uint64(len(s)) * 8)
	out := make([]byte, len(enc)+len(s))
	copy(out, enc)
	copy(out[len(enc):], s)
	return out
}

// bytepad implements NIST SP 800-185 Algorithm 4: prepends
// `left_encode(w)` to z and pads with zero bytes so that the total
// length is a positive multiple of w.
func bytepad(z []byte, w int) []byte {
	enc := leftEncode(uint64(w))
	total := len(enc) + len(z)
	if rem := total % w; rem != 0 {
		total += w - rem
	}
	out := make([]byte, total)
	copy(out, enc)
	copy(out[len(enc):], z)
	return out
}
