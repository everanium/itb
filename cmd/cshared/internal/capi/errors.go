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

	// Triple sentinel block 11..13. These slots previously carried the
	// retired Easy encryptor surface's per-facade codes; the numeric
	// values are reassigned to the triple-side blob-record sentinels
	// (see triple.ErrBlobMalformedRecipe and
	// triple.ErrRecipePrimitiveUnknown) and to the registry miss
	// (triple.ErrUnknownProfile, returned by [TripleInit] and
	// [TripleLookup]). 14..17 remain unassigned for future use.
	StatusBlobMalformedRecipe    Status = 11
	StatusRecipePrimitiveUnknown Status = 12
	StatusUnknownProfile         Status = 13
	StatusReserved14             Status = 14
	StatusReserved15             Status = 15
	StatusReserved16             Status = 16
	StatusReserved17             Status = 17

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
	// call after [TripleClose] has run. Bindings map it to a
	// language-side exception class distinct from the generic
	// bad-handle path so the caller sees a clear "already closed"
	// signal rather than "invalid handle".
	StatusTripleClosed Status = 25

	// [TripleRegister] sentinel — returned when the caller attempts
	// to register a name that is already in the profile catalogue
	// (either from the shipped set installed at package init or a
	// prior [TripleRegister] call). Distinct from
	// StatusBadInput so bindings can map the duplicate-name path to
	// a language-idiomatic "already exists" exception without
	// conflating it with the validation-failure surface.
	StatusProfileExists Status = 26

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
		return "seed width mismatch (all eight seed handles must share the same hash width)"
	case StatusBadMAC:
		return "unknown MAC name or invalid MAC handle"
	case StatusMACFailure:
		return "MAC verification failed (tampered ciphertext or wrong key)"
	case StatusBlobMalformedRecipe:
		return "blob profile record invalid"
	case StatusRecipePrimitiveUnknown:
		return "blob profile record names a primitive absent from the local registries"
	case StatusUnknownProfile:
		return "unknown profile name"
	case StatusReserved14,
		StatusReserved15,
		StatusReserved16,
		StatusReserved17:
		return "reserved status"
	case StatusBlobModeMismatch:
		return "blob mode mismatch (expected mode=3 Triple)"
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
	case StatusProfileExists:
		return "profile name already registered"
	case StatusInternal:
		return "internal error"
	}
	return "unknown status"
}
