package itb

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
)

// testNonceOverride is set only by test code (see setTestNonce in *_test.go).
// Production callers never set this — generateNonceCfg falls through to
// crypto/rand. One atomic load per encryption in the hot path; negligible
// overhead in production, critical for nonce-reuse attack simulation in
// Probe 1 of the red-team plan.
var testNonceOverride atomic.Pointer[[]byte]

// NonceSize is the default per-message nonce size in bytes (128 bits).
// The compile-in default surfaces through [DefaultNonceBits]. Birthday
// collision at ~2^(nonceBits/2) messages.
const NonceSize = 16

// MaxKeyBits is the maximum supported key size in bits.
// Effective security depends on hash function's internal state width.
const MaxKeyBits = 2048

// secureWipe zeroes a byte slice to minimize sensitive data exposure in memory.
// clear() lowers to runtime.memclrNoHeapPointers — an observable side-effect
// the compiler cannot elide, replacing the prior manual-loop + KeepAlive
// pattern with a single intrinsic that widens to vector stores on amd64.
func secureWipe(b []byte) {
	clear(b)
}

// generateRandomBytes returns n cryptographically random bytes.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return b, nil
}
