package itb

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
)

// testNonceOverride is set only by test code (see setTestNonce in *_test.go).
// Production callers never set this — generateNonce falls through to crypto/rand.
// One atomic load per encryption in the hot path; negligible overhead in
// production, critical for nonce-reuse attack simulation in Probe 1 of the
// red-team plan.
var testNonceOverride atomic.Pointer[[]byte]

// NonceSize is the default per-message nonce size in bytes (128 bits).
// Use SetNonceBits to change. Birthday collision at ~2^(nonceBits/2) messages.
const NonceSize = 16

// nonceSizeOverride stores the configured nonce size in bytes (0 = use default NonceSize).
var nonceSizeOverride atomic.Int32

// SetNonceBits sets the nonce size in bits. Valid values: 128, 256, 512.
// Panics on invalid input — nonce misconfiguration is a security-critical bug.
// Both sender and receiver must use the same value.
// Thread-safe (atomic). Affects all subsequent Encrypt calls.
func SetNonceBits(n int) {
	switch n {
	case 128:
		nonceSizeOverride.Store(16)
	case 256:
		nonceSizeOverride.Store(32)
	case 512:
		nonceSizeOverride.Store(64)
	default:
		panic(fmt.Sprintf("itb: SetNonceBits(%d): valid values are 128, 256, 512", n))
	}
}

// GetNonceBits returns the current nonce size in bits.
func GetNonceBits() int {
	return currentNonceSize() * 8
}

// currentNonceSize returns the current nonce size in bytes.
func currentNonceSize() int {
	if n := int(nonceSizeOverride.Load()); n > 0 {
		return n
	}
	return NonceSize
}

// barrierFillOverride stores the configured barrier fill value (0 = use default 1).
var barrierFillOverride atomic.Int32

// SetBarrierFill sets the CSPRNG barrier fill margin added to the container side.
// Valid values: 1, 2, 4, 8, 16, 32. Default is 1.
// Panics on invalid input — barrier misconfiguration is a security-critical bug.
// Asymmetric: the receiver does not need the same value as the sender.
// Thread-safe (atomic). Affects all subsequent Encrypt calls.
func SetBarrierFill(n int) {
	switch n {
	case 1, 2, 4, 8, 16, 32:
		barrierFillOverride.Store(int32(n))
	default:
		panic(fmt.Sprintf("itb: SetBarrierFill(%d): valid values are 1, 2, 4, 8, 16, 32", n))
	}
}

// GetBarrierFill returns the current barrier fill value.
// Returns 1 if no override is set (default).
func GetBarrierFill() int {
	return currentBarrierFill()
}

// currentBarrierFill returns the current barrier fill value.
func currentBarrierFill() int {
	if n := int(barrierFillOverride.Load()); n > 0 {
		return n
	}
	return 1
}

// MaxKeyBits is the maximum supported key size in bits.
// Effective security depends on hash function's internal state width.
const MaxKeyBits = 2048

// generateNonce returns a fresh cryptographic nonce of current configured size.
// If a test has installed a fixed nonce via setTestNonce, returns a copy of
// that instead — used for nonce-reuse attack simulation. Production callers
// never hit the override branch (the setter is in *_test.go only).
func generateNonce() ([]byte, error) {
	if p := testNonceOverride.Load(); p != nil {
		return append([]byte(nil), *p...), nil
	}
	nonce := make([]byte, currentNonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return nonce, nil
}

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
