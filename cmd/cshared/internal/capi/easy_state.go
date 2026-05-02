package capi

import (
	"errors"

	"github.com/everanium/itb/easy"
)

// EasyExport serialises the encryptor's full state (PRF keys, seed
// components, MAC key, dedicated lockSeed material when active) as a
// JSON blob into the caller-allocated buffer. Same caller-allocated-
// buffer convention as Encrypt / Decrypt: the returned n carries the
// bytes written on success or the required capacity on
// StatusBufferTooSmall, so callers can probe with a zero-capacity
// pass to discover the size, then resize and retry.
//
// The blob shape is documented in easy/state.go (stateBlobV1). v1
// carries the structural state (primitive / key_bits / mode / mac /
// seeds / prf_keys / mac_key / lock_seed); per-instance configuration
// knobs (NonceBits, BarrierFill, BitSoup, LockSoup, ChunkSize) are
// not serialised — both sides communicate them via deployment config.
func EasyExport(id EasyHandleID, out []byte) (n int, st Status) {
	defer recoverEasyPanic(&st, StatusInternal)

	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	blob := h.enc.Export()
	if len(blob) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(blob), StatusBufferTooSmall
	}
	copy(out, blob)
	return len(blob), StatusOK
}

// EasyImport replaces the encryptor's PRF keys, seed components, MAC
// key, and (optionally) dedicated lockSeed material with the values
// carried in a JSON blob produced by a prior EasyExport call.
// Returns StatusOK on success or one of the StatusEasy* / StatusInternal
// codes on failure; on error the encryptor's pre-Import state is
// unchanged (Encryptor.Import is transactional on the easy side).
//
// The state blob carries the authoritative LockSeed setting — a blob
// with lock_seed:true elevates a default-LockSeed=0 receiver to
// LockSeed=1, and a blob without lock_seed demotes a pre-Import
// LockSeed=1 receiver to LockSeed=0 (the receiver's pre-Import
// dedicated-lockSeed material is zeroed and discarded). The four
// other configuration dimensions (primitive, key_bits, mode, mac) are
// rejected on mismatch via StatusEasyMismatch — the receiver's hash
// / MAC factories were bound at New / New3 time and cannot be
// rewired by Import. The offending field is captured in
// lastMismatchField for retrieval via EasyLastMismatchField.
func EasyImport(id EasyHandleID, blob []byte) (st Status) {
	defer recoverEasyPanic(&st, StatusInternal)

	h, st := resolveEasy(id)
	if st != StatusOK {
		return st
	}
	if err := h.enc.Import(blob); err != nil {
		s := mapImportError(err)
		setLastErr(s)
		return s
	}
	return StatusOK
}

// EasyPeekConfig parses a state blob's metadata (primitive, key_bits,
// mode, mac) without performing full validation, allowing a caller to
// inspect a saved blob before constructing a matching encryptor.
//
// Returns StatusOK with the parsed fields on success;
// StatusEasyMalformed (and on bindings the LastError text) on JSON
// parse failure / kind mismatch / too-new version / unknown mode value.
// The deferred recover translates the easy package's panic policy
// (PeekConfig panics on malformed input) into a Status return.
func EasyPeekConfig(blob []byte) (primitive string, keyBits int, mode int, mac string, st Status) {
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusEasyMalformed)
			primitive, keyBits, mode, mac = "", 0, 0, ""
			st = StatusEasyMalformed
		}
	}()
	primitive, keyBits, mode, mac = easy.PeekConfig(blob)
	return primitive, keyBits, mode, mac, StatusOK
}

// mapImportError translates an Encryptor.Import error onto the matching
// FFI Status code. The four sentinel errors map 1:1; *easy.ErrMismatch
// is captured into lastMismatchField so bindings can read the offending
// JSON field via EasyLastMismatchField, and any unknown error type is
// treated as an internal bug rather than silently swallowed.
//
// The errors.Is path covers wrapped sentinels (the easy package does
// not currently wrap them, but a future revision might — better to
// be defensive than rely on identity comparison).
func mapImportError(err error) Status {
	if err == nil {
		return StatusOK
	}
	switch {
	case errors.Is(err, easy.ErrMalformed):
		return StatusEasyMalformed
	case errors.Is(err, easy.ErrVersionTooNew):
		return StatusEasyVersionTooNew
	case errors.Is(err, easy.ErrUnknownPrimitive):
		return StatusEasyUnknownPrimitive
	case errors.Is(err, easy.ErrUnknownMAC):
		return StatusEasyUnknownMAC
	case errors.Is(err, easy.ErrBadKeyBits):
		return StatusEasyBadKeyBits
	}
	var mismatch *easy.ErrMismatch
	if errors.As(err, &mismatch) {
		setMismatchField(mismatch.Field)
		return StatusEasyMismatch
	}
	return StatusInternal
}
