package macs

import (
	"fmt"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb"
)

// HMACBLAKE3 returns a cached BLAKE3-keyed itb.MACFunc.
//
// BLAKE3 has a native keyed mode (`blake3.NewKeyed(key32)`) that
// derives the per-message hashing state from a 32-byte key once;
// this is the recommended construction for "HMAC-BLAKE3" (no nested
// HMAC wrapper is required because BLAKE3-keyed is itself a sound
// keyed PRF — see the BLAKE3 spec, section 6).
//
// Caching strategy: the keyed template hasher is built once at
// factory construction. Each call clones the template (cheap —
// internal state copy), writes the data, finalizes to 32 bytes,
// and is discarded. Concurrent goroutines may invoke the returned
// closure in parallel since each holds its own clone.
//
// Key length must be exactly 32 bytes. Shorter keys are rejected.
func HMACBLAKE3(key []byte) (itb.MACFunc, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("macs: hmac-blake3 key must be exactly 32 bytes, got %d", len(key))
	}
	template, err := blake3.NewKeyed(key)
	if err != nil {
		return nil, fmt.Errorf("macs: blake3.NewKeyed: %w", err)
	}
	return func(data []byte) []byte {
		h := template.Clone()
		h.Write(data)
		var out [32]byte
		h.Sum(out[:0])
		return append([]byte(nil), out[:]...)
	}, nil
}
