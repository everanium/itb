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

	// Reserved sentinel block 11..17 — previously carried the
	// retired Easy encryptor surface's per-facade sentinel codes.
	// The numeric slots stay reserved so no future addition
	// re-uses them and shifts a wire-numeric error identifier
	// bindings may still be reading from a legacy log.
	StatusReserved11 Status = 11
	StatusReserved12 Status = 12
	StatusReserved13 Status = 13
	StatusReserved14 Status = 14
	StatusReserved15 Status = 15
	StatusReserved16 Status = 16
	StatusReserved17 Status = 17

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

	// Streaming AEAD end-of-stream signals raised by the binding-side
	// stream-loop helpers when the input transcript is malformed at
	// the terminator boundary. Returned by the binding's wrapper, not
	// by the per-chunk ABI handlers.
	StatusStreamTruncated  Status = 23
	StatusStreamAfterFinal Status = 24

	// Triple Pipeline (itb/triple) sentinel — returned by every
	// [TripleEncryptStream] / [TripleDecryptStream] /
	// [TripleEncryptMessage] / [TripleDecryptMessage] / [TripleRekey]
	// call after [TripleClose] has run. Distinct from
	// StatusEasyClosed so bindings can map the two facades to
	// distinct language-side exception classes.
	StatusTripleClosed Status = 25

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
	case StatusReserved11,
		StatusReserved12,
		StatusReserved13,
		StatusReserved14,
		StatusReserved15,
		StatusReserved16,
		StatusReserved17:
		return "reserved status (retired Easy facade)"
	case StatusBlobModeMismatch:
		return "blob mode mismatch (Single Import on Triple blob, or vice versa)"
	case StatusBlobMalformed:
		return "malformed state blob"
	case StatusBlobVersionTooNew:
		return "blob version too new"
	case StatusBlobTooManyOpts:
		return "Export accepts at most one options struct"
	case StatusStreamTruncated:
		return "Streaming AEAD transcript truncated before terminator"
	case StatusStreamAfterFinal:
		return "Streaming AEAD chunk after terminator"
	case StatusTripleClosed:
		return "Triple Pipeline is closed"
	case StatusInternal:
		return "internal error"
	}
	return "unknown status"
}
