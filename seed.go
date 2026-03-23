package itb

import (
	"crypto/rand"
	"fmt"
	"runtime"
)

// NonceSize is the per-message nonce size in bytes (128 bits).
// Birthday collision after ~2^64 messages; negligible up to ~2^48 messages.
const NonceSize = 16

// MaxKeyBits is the maximum supported key size in bits.
// Effective security depends on hash function's internal state width.
const MaxKeyBits = 2048

// generateNonce returns a fresh 128-bit cryptographic nonce.
func generateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return nonce, nil
}

// secureWipe zeroes a byte slice to minimize sensitive data exposure in memory.
// runtime.KeepAlive prevents the compiler from optimizing away the zero-fill.
func secureWipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// generateRandomBytes returns n cryptographically random bytes.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return b, nil
}
