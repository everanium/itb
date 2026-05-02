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

	// Easy encryptor (itb/easy sub-package) sentinel codes. The
	// numeric block 11..18 is dedicated to the Encryptor surface so
	// the lower codes 0..10 remain reserved for the low-level
	// Encrypt / Decrypt path. Bindings translate each code into a
	// distinct exception class (or sentinel attribute) on the
	// language-side wrapper.
	StatusEasyClosed               Status = 11
	StatusEasyMalformed            Status = 12
	StatusEasyVersionTooNew        Status = 13
	StatusEasyUnknownPrimitive     Status = 14
	StatusEasyUnknownMAC           Status = 15
	StatusEasyBadKeyBits           Status = 16
	StatusEasyMismatch             Status = 17
	StatusEasyLockSeedAfterEncrypt Status = 18

	// Native Blob (itb.Blob128 / Blob256 / Blob512) sentinel codes.
	// The numeric block 19..22 is dedicated to the low-level state-
	// blob surface so the lower codes 0..18 remain reserved for
	// the seed-handle / Encrypt / Decrypt / Encryptor paths.
	// Bindings translate each code into a distinct exception class
	// on the language-side wrapper.
	StatusBlobModeMismatch  Status = 19
	StatusBlobMalformed     Status = 20
	StatusBlobVersionTooNew Status = 21
	StatusBlobTooManyOpts   Status = 22

	StatusInternal Status = 99
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
	case StatusEasyClosed:
		return "encryptor is closed"
	case StatusEasyMalformed:
		return "malformed state blob"
	case StatusEasyVersionTooNew:
		return "state blob version too new"
	case StatusEasyUnknownPrimitive:
		return "unknown primitive in state blob"
	case StatusEasyUnknownMAC:
		return "unknown MAC in state blob"
	case StatusEasyBadKeyBits:
		return "invalid key_bits in state blob"
	case StatusEasyMismatch:
		return "state blob disagrees with encryptor configuration (read field via ITB_Easy_LastMismatchField)"
	case StatusEasyLockSeedAfterEncrypt:
		return "SetLockSeed after first Encrypt is not allowed"
	case StatusBlobModeMismatch:
		return "blob mode mismatch (Single Import on Triple blob, or vice versa)"
	case StatusBlobMalformed:
		return "malformed state blob"
	case StatusBlobVersionTooNew:
		return "blob version too new"
	case StatusBlobTooManyOpts:
		return "Export accepts at most one options struct"
	case StatusInternal:
		return "internal error"
	}
	return "unknown status"
}
