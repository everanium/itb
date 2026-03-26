package itb

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"sync/atomic"
)

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
func generateNonce() ([]byte, error) {
	nonce := make([]byte, currentNonceSize())
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
