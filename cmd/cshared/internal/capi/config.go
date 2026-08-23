package capi

import "github.com/everanium/itb"

// MaxKeyBits returns the maximum supported ITB key width in bits
// (build-time constant, currently 2048). Read-only.
func MaxKeyBits() int { return itb.MaxKeyBits }

// Channels returns the number of channels per pixel in the RGBWYOPA
// container layout (build-time constant, currently 8). Read-only.
func Channels() int { return itb.Channels }

// DefaultNonceBits returns the compile-in default nonce width in bits
// used when a Config leaves NonceBits at zero. Bindings that need to
// stream-parse without threading a Config value can pass this to
// [HeaderSize] / [ParseChunkLen].
func DefaultNonceBits() int { return itb.DefaultNonceBits }

// HeaderSize returns the ciphertext-chunk header size in bytes for
// the supplied nonceBytes (nonce + 2-byte width + 2-byte height).
// nonceBytes must be 16, 32, or 64; other values yield StatusBadInput
// via the caller-provided out-parameter contract of the FFI shim.
//
// Callers driving the streaming decrypt path pass the nonceBytes
// their Pipeline / Config selected (16 for 128-bit nonces, 32 for
// 256-bit, 64 for 512-bit). Passing the wrong value produces a header
// size that misaligns the parser and every subsequent chunk parse
// fails — the parameter is deliberately explicit rather than latent.
func HeaderSize(nonceBytes int) (int, Status) {
	switch nonceBytes {
	case 16, 32, 64:
		return nonceBytes + 4, StatusOK
	}
	setLastErr(StatusBadInput)
	return 0, StatusBadInput
}
