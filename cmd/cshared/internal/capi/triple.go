package capi

import (
	"bytes"
	"errors"
	"runtime/cgo"

	itb "github.com/everanium/itb"
	"github.com/everanium/itb/triple"
)

// TripleInit constructs a fresh Triple Ouroboros [triple.Pipeline]
// against the named profile and returns both a stable handle and the
// exported blob bytes carrying the full session bundle.
//
// The opts argument is a URL-query-encoded string parsed by
// [parseTripleOpts]. Every field in [triple.Opts] has a corresponding
// query key; unknown keys are rejected with StatusBadInput so a
// typoed override surfaces immediately rather than silently having
// no effect.
//
// The returned blob bytes carry the caller-visible session state —
// distribute them to the receiver, which reconstructs an equivalent
// Pipeline via [TripleOpen]. Same caller-allocated-buffer convention
// as the Encrypt / Decrypt families: the returned n reports bytes
// written on success or the required capacity on
// StatusBufferTooSmall.
func TripleInit(profile string, opts string, blobOut []byte) (id TripleHandleID, n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	parsed, err := parseTripleOpts(opts)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, 0, StatusBadInput
	}
	pipe, blob, err := triple.Init(profile, parsed)
	if err != nil {
		s := mapTripleError(err)
		setLastErr(s)
		return 0, 0, s
	}
	if len(blob) > len(blobOut) {
		// Pipeline already exists but the caller's blob buffer is
		// too small — close the Pipeline before returning so the
		// caller does not have to chase a handle it never received.
		_ = pipe.Close()
		setLastErr(StatusBufferTooSmall)
		return 0, len(blob), StatusBufferTooSmall
	}
	copy(blobOut, blob)
	h := &TripleHandle{pipe: pipe}
	return TripleHandleID(cgo.NewHandle(h)), len(blob), StatusOK
}

// TripleOpen reconstructs a [triple.Pipeline] from a blob produced by
// [TripleInit] or [TripleRekey] and returns a stable handle.
//
// The masters argument carries either zero or two byte slices in the
// (PermMaster, WrapMaster) order — zero to use the blob-embedded
// masters as-is, two to override them (the rekey-on-import path).
// Any other arity is rejected via StatusBadInput.
func TripleOpen(profile string, blob []byte, opts string, masters ...[]byte) (id TripleHandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)

	parsed, err := parseTripleOpts(opts)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(masters) != 0 && len(masters) != 2 {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	pipe, err := triple.Open(profile, blob, parsed, masters...)
	if err != nil {
		s := mapTripleError(err)
		setLastErr(s)
		return 0, s
	}
	h := &TripleHandle{pipe: pipe}
	return TripleHandleID(cgo.NewHandle(h)), StatusOK
}

// TripleRekey swaps the Pipeline's parallax + wrapper masters and
// returns a fresh blob carrying the rotated wrap-layer + unchanged
// inner session state. Rekey mutates Pipeline state; the caller is
// responsible for serialising this against every concurrent cipher
// path call on the same handle (see [triple.Pipeline.Rekey]).
func TripleRekey(id TripleHandleID, permMaster, wrapMaster []byte, blobOut []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	blob, err := h.pipe.Rekey(permMaster, wrapMaster)
	if err != nil {
		s := mapTripleError(err)
		setLastErr(s)
		return 0, s
	}
	if len(blob) > len(blobOut) {
		setLastErr(StatusBufferTooSmall)
		return len(blob), StatusBufferTooSmall
	}
	copy(blobOut, blob)
	return len(blob), StatusOK
}

// TripleClose zeroes the Pipeline's secret material (seed components,
// PRF keys, wrapper key, MAC key, parallax subkeys) and marks the
// Pipeline closed. Subsequent cipher-path calls on the same handle
// return StatusTripleClosed. Idempotent — multiple Close calls return
// StatusOK without panic. The handle itself remains valid until
// [FreeTriple] is called.
func TripleClose(id TripleHandleID) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return st
	}
	if err := h.pipe.Close(); err != nil {
		setLastErr(StatusInternal)
		return StatusInternal
	}
	return StatusOK
}

// FreeTriple releases the cgo.Handle backing a TripleHandleID after
// calling Close on the underlying Pipeline (which zeroes seed
// components, PRF keys, wrapper key, MAC key, and drops parallax
// handles before releasing them to GC). The double-zero — Close from
// FreeTriple AND the explicit TripleClose entry — is intentional:
// bindings that forget the explicit Close still get key material
// zeroed when they release the handle, while bindings that DO call
// Close hit Close's idempotent fast path here.
func FreeTriple(id TripleHandleID) (st Status) {
	if id == 0 {
		setLastErr(StatusBadHandle)
		return StatusBadHandle
	}
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadHandle)
			st = StatusBadHandle
		}
	}()
	if h, ok := cgo.Handle(id).Value().(*TripleHandle); ok && h != nil && h.pipe != nil {
		_ = h.pipe.Close()
	}
	cgo.Handle(id).Delete()
	return StatusOK
}

// TripleEncryptStream drives one Streaming AEAD / Non-AEAD encrypt
// pass across the Pipeline's full chain: parallax encrypt-Reader → itb
// Triple 8-seed Streaming AEAD (or Non-AEAD) → wrapper wrap-Writer.
//
// Buffer convention mirrors the low-level ITB_EncryptStream* family:
// the caller supplies a plaintext src slice + a wire destination
// buffer with capacity; the returned n reports bytes written on
// success or the required capacity on StatusBufferTooSmall.
//
// The destination-buffer capacity is measured by feeding the
// Pipeline's chain through a [bytes.Buffer]; the growth budget is
// bounded by the plaintext length plus the fixed per-stream + per-
// chunk envelope overheads. Bindings sizing their buffer via
// max(plain_len * 2, 65536) hit the fast path in practice.
func TripleEncryptStream(id TripleHandleID, plainSrc, wireDst []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	var wire bytes.Buffer
	// Pre-size to the ciphertext-expansion upper bound so the wire
	// accumulation never re-grows mid-encrypt.
	wire.Grow(len(plainSrc) + len(plainSrc)/4 + 65536)
	if err := h.pipe.EncryptStream(bytes.NewReader(plainSrc), &wire); err != nil {
		s := mapTripleError(err)
		setLastErr(s)
		return 0, s
	}
	if wire.Len() > len(wireDst) {
		setLastErr(StatusBufferTooSmall)
		return wire.Len(), StatusBufferTooSmall
	}
	copy(wireDst, wire.Bytes())
	return wire.Len(), StatusOK
}

// TripleDecryptStream is the receive-side counterpart of
// [TripleEncryptStream]. Reverses the Pipeline chain: wrapper
// unwrap-Reader → itb Triple 8-seed Streaming AEAD (or Non-AEAD)
// decrypt → parallax decrypt-Writer. Same caller-allocated-buffer
// convention.
func TripleDecryptStream(id TripleHandleID, wireSrc, plainDst []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	var plain bytes.Buffer
	// Pre-size to the wire length — plaintext is always ≤ wire.
	plain.Grow(len(wireSrc))
	if err := h.pipe.DecryptStream(bytes.NewReader(wireSrc), &plain); err != nil {
		s := mapTripleError(err)
		setLastErr(s)
		return 0, s
	}
	if plain.Len() > len(plainDst) {
		setLastErr(StatusBufferTooSmall)
		return plain.Len(), StatusBufferTooSmall
	}
	copy(plainDst, plain.Bytes())
	return plain.Len(), StatusOK
}

// TripleEncryptMessage runs a Single Message encrypt across the
// Pipeline's chain — buffer-in, buffer-out. Same caller-allocated-
// buffer convention as [TripleEncryptStream]; the difference is
// intent: [Pipeline.EncryptMessage] is the naming for callers without
// an [io.Reader] / [io.Writer] at hand, while [Pipeline.EncryptStream]
// is the naming for callers who do. The byte shape produced by the
// two paths is identical when the plaintext fits in one chunk.
func TripleEncryptMessage(id TripleHandleID, plain, wireDst []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	wire, err := h.pipe.EncryptMessage(plain)
	if err != nil {
		s := mapTripleError(err)
		setLastErr(s)
		return 0, s
	}
	if len(wire) > len(wireDst) {
		setLastErr(StatusBufferTooSmall)
		return len(wire), StatusBufferTooSmall
	}
	copy(wireDst, wire)
	return len(wire), StatusOK
}

// TripleDecryptMessage is the receive-side counterpart of
// [TripleEncryptMessage].
func TripleDecryptMessage(id TripleHandleID, wire, plainDst []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	plain, err := h.pipe.DecryptMessage(wire)
	if err != nil {
		s := mapTripleError(err)
		setLastErr(s)
		return 0, s
	}
	if len(plain) > len(plainDst) {
		setLastErr(StatusBufferTooSmall)
		return len(plain), StatusBufferTooSmall
	}
	copy(plainDst, plain)
	return len(plain), StatusOK
}

// mapTripleError translates a triple-package sentinel or wrapped
// error onto the matching FFI Status code. Falls through to
// StatusInternal for unclassified errors — the raw diagnostic is
// still captured verbatim in lastErr for binding-side inspection via
// [LastError].
func mapTripleError(err error) Status {
	if err == nil {
		return StatusOK
	}
	msg := err.Error()
	// Sentinels via string match — the triple package's error values
	// are unwrapped strings (see triple/pipeline.go / stream.go /
	// message.go); a substring check is enough here and stays stable
	// across future error-wrapping refactors.
	switch {
	case err == triple.ErrClosed:
		return StatusTripleClosed
	case err == triple.ErrIdenticalMasters,
		err == triple.ErrMissingMasters,
		err == triple.ErrMastersArity,
		err == triple.ErrUnknownProfile,
		err == triple.ErrBlobMismatch,
		err == triple.ErrBlobVersion,
		err == triple.ErrBlobMalformed:
		setLastErrMessageTriple(msg)
		return StatusBadInput
	case err == triple.ErrProfileNotStreaming,
		err == triple.ErrProfileNoCipher:
		setLastErrMessageTriple(msg)
		return StatusBadInput
	case errors.Is(err, itb.ErrMACFailure):
		setLastErrMessageTriple(msg)
		return StatusMACFailure
	}
	setLastErrMessageTriple(msg)
	return StatusInternal
}

// setLastErrMessageTriple stores the triple-side error message under
// the shared lastErr slot so [LastError] surfaces the raw diagnostic
// alongside the mapped Status code.
func setLastErrMessageTriple(msg string) {
	v := "triple: " + msg
	lastErr.Store(&v)
}
