package capi

// Status is the integer error code returned by every capi entry
// point. Mirrors the ITB_OK / ITB_ERR_* constants exposed through
// the C ABI surface and must stay numerically stable across releases.
type Status int

const (
	StatusOK             Status = 0
	StatusBadHash        Status = 1
	StatusBadKeyBits     Status = 2
	StatusBadHandle      Status = 3
	StatusBadInput       Status = 4
	StatusBufferTooSmall Status = 5
	StatusEncryptFailed  Status = 6
	StatusDecryptFailed  Status = 7
	StatusSeedWidthMix   Status = 8
	StatusBadMAC         Status = 9
	StatusMACFailure     Status = 10
	StatusInternal       Status = 99
)

// String returns a short human-readable label for the status code.
// Used by the FFI ITB_LastError() entry point and by test failure
// messages.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusBadHash:
		return "unknown hash name"
	case StatusBadKeyBits:
		return "invalid key bits (must be 512..2048, multiple of width)"
	case StatusBadHandle:
		return "invalid seed handle"
	case StatusBadInput:
		return "invalid input"
	case StatusBufferTooSmall:
		return "output buffer too small"
	case StatusEncryptFailed:
		return "encrypt failed"
	case StatusDecryptFailed:
		return "decrypt failed"
	case StatusSeedWidthMix:
		return "seed width mismatch (all three handles must share the same hash width)"
	case StatusBadMAC:
		return "unknown MAC name or invalid MAC handle"
	case StatusMACFailure:
		return "MAC verification failed (tampered ciphertext or wrong key)"
	case StatusInternal:
		return "internal error"
	}
	return "unknown status"
}
