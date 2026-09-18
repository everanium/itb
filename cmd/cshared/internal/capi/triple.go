package capi

import (
	"errors"
	"io/fs"
	"runtime/cgo"
	"strings"

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
// Pipeline via [TripleLoad]. Same caller-allocated-buffer convention
// as the Encrypt / Decrypt families: the returned n reports bytes
// written on success or the required capacity on
// StatusBufferTooSmall.
func TripleInit(profile string, opts string, blobOut []byte) (id TripleHandleID, n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	parsed, err := parseTripleOpts(opts)
	if err != nil {
		return 0, 0, tripleErr(StatusBadInput, err.Error())
	}
	pipe, blob, err := triple.Init(profile, parsed)
	if err != nil {
		s := mapTripleError(err)
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

// TripleLoad reconstructs a [triple.Pipeline] from a blob produced by
// [TripleInit], [TripleSave], or [TripleRekey] and returns a stable
// handle. The blob is self-describing — no profile name, no opts.
//
// The masters argument carries either zero or two byte slices in the
// (PermMaster, WrapMaster) order — zero to use the blob-embedded
// masters as-is, two to override them (the rekey-on-import path).
// Any other arity is rejected via StatusBadInput.
func TripleLoad(blob []byte, masters ...[]byte) (id TripleHandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)

	if len(masters) != 0 && len(masters) != 2 {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	pipe, err := triple.Load(blob, masters...)
	if err != nil {
		s := mapTripleError(err)
		return 0, s
	}
	h := &TripleHandle{pipe: pipe}
	return TripleHandleID(cgo.NewHandle(h)), StatusOK
}

// TripleLoadF is [TripleLoad] for a blob stored in a file: the read
// happens inside the library ([triple.LoadF]). File-system failures
// (missing file, permission denied) map to StatusBadInput with the
// raw os diagnostic in [LastError].
func TripleLoadF(path string, masters ...[]byte) (id TripleHandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)

	if len(masters) != 0 && len(masters) != 2 {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	pipe, err := triple.LoadF(path, masters...)
	if err != nil {
		s := mapTripleError(err)
		return 0, s
	}
	h := &TripleHandle{pipe: pipe}
	return TripleHandleID(cgo.NewHandle(h)), StatusOK
}

// TripleSave writes the handle's current blob — the bytes
// [TripleInit] returned, the bytes [TripleLoad] re-marshalled, or the
// bytes of the latest [TripleRekey] — into blobOut under the
// caller-allocated-buffer convention of [TripleRekey]: n reports the
// bytes written on success or the required capacity on
// StatusBufferTooSmall. A closed handle returns StatusTripleClosed.
func TripleSave(id TripleHandleID, blobOut []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	blob := h.pipe.Save()
	if blob == nil {
		setLastErr(StatusTripleClosed)
		return 0, StatusTripleClosed
	}
	defer clear(blob)
	if len(blob) > len(blobOut) {
		setLastErr(StatusBufferTooSmall)
		return len(blob), StatusBufferTooSmall
	}
	copy(blobOut, blob)
	return len(blob), StatusOK
}

// TripleSaveF writes the handle's current blob to path inside the
// library ([triple.Pipeline.SaveF], mode 0600). A closed handle
// returns StatusTripleClosed; file-system failures map to
// StatusBadInput with the raw os diagnostic in [LastError].
func TripleSaveF(id TripleHandleID, path string) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return st
	}
	if err := h.pipe.SaveF(path); err != nil {
		s := mapTripleError(err)
		return s
	}
	return StatusOK
}

// TripleInspect decodes the blob's wrap-layer without opening a
// Pipeline and writes the embedded [triple.Profile] record as its
// JSON encoding (see [triple.Profile.MarshalJSON] for the key set,
// name included) into jsonOut under the caller-allocated-buffer
// convention: n reports the bytes written on success or the required
// capacity on StatusBufferTooSmall. No registry read, no primitive
// probe — a name the local build lacks is returned unchanged.
func TripleInspect(blob []byte, jsonOut []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	prof, err := triple.Inspect(blob)
	if err != nil {
		s := mapTripleError(err)
		return 0, s
	}
	return writeJSONOut(prof, jsonOut)
}

// TripleMaxWorkers sets the handle's worker cap for every subsequent
// cipher call ([triple.Pipeline.MaxWorkers]). n is clamped exactly as
// in Go (n ≤ 0 → auto, n > 256 → 256), never rejected; the status
// exists for the handle: StatusBadHandle for an unknown handle,
// StatusTripleClosed for a closed one. Works identically on a handle
// from [TripleInit], [TripleLoad], or [TripleLoadF].
func TripleMaxWorkers(id TripleHandleID, n int) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return st
	}
	// A closed Pipeline ignores MaxWorkers by design; the FFI caller
	// needs the signal, so probe the closed state through Save (nil
	// after Close) and wipe the probe copy.
	blob := h.pipe.Save()
	if blob == nil {
		setLastErr(StatusTripleClosed)
		return StatusTripleClosed
	}
	clear(blob)
	h.pipe.MaxWorkers(n)
	return StatusOK
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
// Buffer convention is the standard caller-allocated one used across
// every cipher entry: the caller supplies a plaintext src slice + a
// wire destination buffer with capacity; the returned n reports bytes
// written on success or the required capacity on
// StatusBufferTooSmall.
//
// The whole plaintext is available up front on this surface, so the
// call routes through [triple.Pipeline.EncryptStreamBytes] — the
// whole-buffer Streaming entry whose direct path composes a
// single-chunk emission via the itb-root Cfg-aware entries when the
// parallax layer is disengaged and the plaintext fits the itb-root
// single-message cap, bypassing the per-chunk io.Reader / io.Writer
// machinery. Bindings sizing their buffer via
// max(plain_len * 2, 65536) hit the fast path in practice.
func TripleEncryptStream(id TripleHandleID, plainSrc, wireDst []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	wire, err := h.pipe.EncryptStreamBytes(plainSrc)
	if err != nil {
		s := mapTripleError(err)
		return 0, s
	}
	if len(wire) > len(wireDst) {
		setLastErr(StatusBufferTooSmall)
		return len(wire), StatusBufferTooSmall
	}
	copy(wireDst, wire)
	return len(wire), StatusOK
}

// TripleDecryptStream is the receive-side counterpart of
// [TripleEncryptStream]. Routes through
// [triple.Pipeline.DecryptStreamBytes], whose direct path decodes
// single-chunk wires via the itb-root Cfg-aware entries and whose
// wrapper posture unwraps the wire in one in-place keystream pass;
// multi-chunk and parallax-on wires take the full reverse chain. Same
// caller-allocated-buffer convention; the caller's wireSrc bytes are
// never mutated.
func TripleDecryptStream(id TripleHandleID, wireSrc, plainDst []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	plain, err := h.pipe.DecryptStreamBytes(wireSrc)
	if err != nil {
		s := mapTripleError(err)
		return 0, s
	}
	if len(plain) > len(plainDst) {
		setLastErr(StatusBufferTooSmall)
		return len(plain), StatusBufferTooSmall
	}
	copy(plainDst, plain)
	return len(plain), StatusOK
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
	// The two record sentinels are %w-wrapped by the Load validator
	// and are matched via errors.Is ahead of every identity branch;
	// the remaining triple sentinels are unwrapped values (see
	// triple/pipeline.go / stream.go / message.go) and identity
	// comparison is enough.
	switch {
	case errors.Is(err, triple.ErrBlobMalformedRecipe):
		return tripleErr(StatusBlobMalformedRecipe, msg)
	case errors.Is(err, triple.ErrRecipePrimitiveUnknown):
		return tripleErr(StatusRecipePrimitiveUnknown, msg)
	case err == triple.ErrClosed:
		return tripleErr(StatusTripleClosed, msg)
	case err == triple.ErrUnknownProfile:
		return tripleErr(StatusUnknownProfile, msg)
	case err == triple.ErrIdenticalMasters,
		err == triple.ErrMissingMasters,
		err == triple.ErrMastersArity,
		err == triple.ErrBlobVersion,
		err == triple.ErrBlobMalformed:
		return tripleErr(StatusBadInput, msg)
	case err == triple.ErrProfileNotStreaming,
		err == triple.ErrProfileNoCipher,
		err == triple.ErrEmptyInput:
		return tripleErr(StatusBadInput, msg)
	// The inner Blob{N}.Import3Cfg / Export3Cfg sentinels. triple.Load
	// wraps them with %w (see triple/open.go), so errors.Is reaches
	// them through the wrap. Without these branches a rejected blob
	// falls through to StatusInternal and surfaces to a binding as a
	// bare "internal error", indistinguishable from a library fault.
	//
	// These are itb-package sentinels and are distinct values from the
	// triple-package ErrBlobMalformed / ErrBlobVersion matched above,
	// which describe the outer wrap layer rather than the inner blob.
	case errors.Is(err, itb.ErrBlobModeMismatch):
		return tripleErr(StatusBlobModeMismatch, msg)
	case errors.Is(err, itb.ErrBlobMalformed):
		return tripleErr(StatusBlobMalformed, msg)
	case errors.Is(err, itb.ErrBlobVersionTooNew):
		return tripleErr(StatusBlobVersionTooNew, msg)
	case errors.Is(err, itb.ErrBlobTooManyOpts):
		// Defensive: no triple-side caller reaches this today, since
		// every Export3Cfg call site in triple/init.go passes exactly
		// one options struct. Mapped so the family is complete if a
		// variadic path is ever added.
		return tripleErr(StatusBlobTooManyOpts, msg)
	case errors.Is(err, triple.ErrBadKeyBits):
		return tripleErr(StatusBadKeyBits, msg)
	case errors.Is(err, itb.ErrMACFailure):
		return tripleErr(StatusMACFailure, msg)
	}
	// File-system failures from TripleLoadF / TripleSaveF (missing
	// file, permission denied, no space) are caller-side input errors
	// at the FFI boundary; the raw os diagnostic rides in lastErr.
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return tripleErr(StatusBadInput, msg)
	}
	// Mixed-primitive validation surface: allocEightSeedsMixed +
	// importInnerBlobMixed emit fmt.Errorf messages naming the
	// offending mixedHashes slot when a per-call Opts.MixedHashes
	// override (or a resolved profile default) fails the
	// non-empty / hashes.Find / width-match rules. These are
	// user-input errors regardless of whether they arrived via
	// Register (already routed to StatusBadInput at the
	// TripleRegister boundary) or via per-call TripleInit; route them
	// uniformly here.
	if strings.Contains(msg, "mixedHashes") {
		return tripleErr(StatusBadInput, msg)
	}
	// An unresolvable MAC name is the caller's input, not a library
	// fault, and StatusBadMAC exists to say so. The name is checked
	// against the registry with a plain comparison rather than a
	// sentinel, in triple and in macs alike, so there is nothing for
	// errors.Is to reach and the branch matches on the text the same
	// way the mixedHashes one above does. Without it the caller is
	// told the library broke, which sends them looking in the wrong
	// place for a typo they made.
	if strings.Contains(msg, "unknown MAC ") {
		return tripleErr(StatusBadMAC, msg)
	}
	return tripleErr(StatusInternal, msg)
}

// setLastErrMessageTriple stores the triple-side error message under
// the shared lastErr slot so [LastError] surfaces the raw diagnostic
// alongside the mapped Status code.
func setLastErrMessageTriple(msg string) {
	// Errors raised inside the triple package already carry the
	// package prefix; adding a second one reads as a stutter in the
	// text every binding surfaces to its caller.
	v := msg
	if !strings.HasPrefix(v, "triple: ") {
		v = "triple: " + v
	}
	lastErr.Store(&v)
}

// tripleErr stores the complete sentence for a failure and returns its
// status. The sentence is assembled here, once, rather than by each
// binding: the status names the class of failure and the message names
// the instance, and a caller that has to join the two is a caller that
// can forget to. A binding then prints what it received instead of
// composing anything.
func tripleErr(s Status, msg string) Status {
	if !strings.HasPrefix(msg, "triple: ") {
		msg = "triple: " + msg
	}
	v := s.String() + ": " + msg
	lastErr.Store(&v)
	return s
}
