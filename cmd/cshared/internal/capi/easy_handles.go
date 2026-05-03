package capi

import (
	"errors"
	"fmt"
	"runtime/cgo"
	"strings"
	"sync/atomic"

	"github.com/everanium/itb/easy"
)

// EasyHandle wraps a single *easy.Encryptor behind an opaque uintptr
// crossing the cgo boundary. The Encryptor owns its own seed slots,
// MAC closure, and per-instance Config snapshot — the FFI layer just
// pins it via runtime/cgo.Handle so the value survives across the
// C boundary without leaking the internal type.
//
// Mirrors the SeedHandle / MACHandle pattern in handles.go and macs.go;
// the only structural difference is that one EasyHandle replaces what
// used to be three (or seven) separate seed handles plus one MAC
// handle.
type EasyHandle struct {
	enc *easy.Encryptor
}

// EasyHandleID is the opaque uintptr passed across the C ABI as an
// Encryptor reference. Internally a runtime/cgo.Handle that maps back
// to an *EasyHandle on the Go heap.
type EasyHandleID uintptr

// lastMismatchField stores the canonical JSON field name reported by
// the most recent Import / PeekConfig call that returned
// StatusEasyMismatch. Bindings read it via LastMismatchField (and
// the matching ITB_Easy_LastMismatchField FFI export) immediately
// after a non-OK return on the same thread, the same errno-style
// pattern lastErr already follows.
//
// Held in a parallel atomic.Pointer rather than encoded into lastErr
// itself because the field is structured payload (a JSON identifier)
// and binding code wants to map it onto a typed exception attribute,
// not parse it back out of a free-form error message.
var lastMismatchField atomic.Pointer[string]

// setMismatchField records the offending JSON field on the most
// recent Import / PeekConfig failure path so the FFI getter can
// surface it to the binding. Called only from mapImportError when
// the underlying error is *easy.ErrMismatch.
func setMismatchField(field string) {
	v := field
	lastMismatchField.Store(&v)
}

// LastMismatchField returns the JSON field name from the most recent
// non-OK Import / PeekConfig call that returned StatusEasyMismatch.
// Returns "" when the most recent failure was something other than a
// mismatch (or when no Import call has run yet on this thread).
func LastMismatchField() string {
	if p := lastMismatchField.Load(); p != nil {
		return *p
	}
	return ""
}

// recoverEasyPanic translates panics raised inside the easy package
// into the matching FFI Status codes rather than letting them unwind
// across the cgo boundary.
//
// Three layers of mapping run in order:
//
//   - Typed sentinels via errors.Is — easy.ErrClosed,
//     easy.ErrLockSeedAfterEncrypt, and easy.ErrEasyMixedWidth map
//     directly to their FFI codes (StatusEasyClosed,
//     StatusEasyLockSeedAfterEncrypt, StatusBadInput respectively).
//
//   - Panic message prefix matching — easy.New / easy.NewMixed
//     panic with formatted strings like "itb/easy: unknown
//     primitive %q" / "itb/easy: unknown MAC %q" / "itb/easy:
//     key_bits=%d ...". These paths predate the typed-error
//     refactor; the substring match preserves the dedicated
//     StatusEasyUnknownPrimitive / StatusEasyUnknownMAC /
//     StatusEasyBadKeyBits codes that already existed for the
//     Import path so binding callers see the precise reason
//     rather than a generic "internal error".
//
//   - Fallback to the caller-supplied Status for everything else,
//     with the panic message preserved verbatim in lastErr so the
//     binding can read the diagnostic via ITB_LastError even when
//     the structural Status is generic.
//
// The caller pattern is `defer recoverEasyPanic(&st, fallback)`.
func recoverEasyPanic(st *Status, fallback Status) {
	r := recover()
	if r == nil {
		return
	}
	// 1. Typed sentinel error values.
	if err, ok := r.(error); ok {
		switch {
		case errors.Is(err, easy.ErrClosed):
			setLastErr(StatusEasyClosed)
			*st = StatusEasyClosed
			return
		case errors.Is(err, easy.ErrLockSeedAfterEncrypt):
			setLastErr(StatusEasyLockSeedAfterEncrypt)
			*st = StatusEasyLockSeedAfterEncrypt
			return
		case errors.Is(err, easy.ErrEasyMixedWidth):
			setLastErrMessage(StatusBadInput, err.Error())
			*st = StatusBadInput
			return
		}
		// Untyped error — fall through to message-prefix mapping.
		s := classifyPanicMessage(err.Error(), fallback)
		setLastErrMessage(s, err.Error())
		*st = s
		return
	}
	// 2. Panic with a string value (the formatted Sprintf path
	//    used by easy.New / easy.NewMixed).
	if msg, ok := r.(string); ok {
		s := classifyPanicMessage(msg, fallback)
		setLastErrMessage(s, msg)
		*st = s
		return
	}
	// 3. Anything else: fall back without context.
	setLastErr(fallback)
	*st = fallback
}

// classifyPanicMessage maps a panic message string to the most
// specific Status code by substring match against the well-known
// easy.New / easy.NewMixed / state-blob diagnostic prefixes. Falls
// through to the supplied fallback when no prefix matches.
//
// The mapping mirrors mapImportError's typed-sentinel path so the
// constructor (panic-driven) and Import (error-driven) entry points
// surface the same Status code for the same root cause.
func classifyPanicMessage(msg string, fallback Status) Status {
	switch {
	case strings.Contains(msg, "unknown primitive"):
		return StatusEasyUnknownPrimitive
	case strings.Contains(msg, "unknown MAC"):
		return StatusEasyUnknownMAC
	case strings.Contains(msg, "unknown name"):
		// easy.parseConstructorArgs cannot distinguish primitive
		// vs MAC at the call site (both registries are tried for
		// every string arg); the panic message is shared.
		// Resolving to StatusEasyUnknownPrimitive favours the
		// most-common cause — a typo in the primitive name —
		// while still surfacing a typed Status code rather than
		// the generic StatusInternal fallback.
		return StatusEasyUnknownPrimitive
	case strings.Contains(msg, "duplicate key_bits"):
		// Must precede the broad "key_bits" check below — otherwise
		// "duplicate key_bits" matches "key_bits" and surfaces as
		// StatusEasyBadKeyBits instead of StatusBadInput.
		return StatusBadInput
	case strings.Contains(msg, "key_bits"):
		return StatusEasyBadKeyBits
	case strings.Contains(msg, "mixed-mode primitives"),
		strings.Contains(msg, "lockSeed primitive"):
		return StatusBadInput
	case strings.Contains(msg, "empty slot primitive list"),
		strings.Contains(msg, "expects "),
		strings.Contains(msg, "duplicate primitive"),
		strings.Contains(msg, "duplicate MAC"),
		strings.Contains(msg, "unsupported argument type"),
		strings.Contains(msg, "unsupported primitive width"):
		// Constructor-side caller errors that predate the typed-
		// sentinel refactor — easy.parseConstructorArgs and
		// easy.NewMixed shape validators panic with these strings
		// for invalid argument shapes / counts / types. Resolving
		// to StatusBadInput preserves the typed-status promise to
		// bindings even though the underlying easy package still
		// uses panic strings rather than typed errors.
		return StatusBadInput
	case strings.Contains(msg, "Make128Pair"),
		strings.Contains(msg, "Make256Pair"),
		strings.Contains(msg, "Make512Pair"):
		// The hashes.Make{N}Pair factory panic'd inside the
		// constructor — typically a primitive lookup that
		// resolved at the registry level but failed inside the
		// factory's own validation (e.g. a malformed fixed-key
		// parameter on the restore path). Caller-input shape
		// failure → StatusBadInput.
		return StatusBadInput
	case strings.Contains(msg, "NewSeed128"),
		strings.Contains(msg, "NewSeed256"),
		strings.Contains(msg, "NewSeed512"):
		// Underlying itb.NewSeed{N} panic'd — almost always an
		// invalid keyBits in disguise (the constructor pre-
		// validates keyBits but the seed factory has its own
		// independent multiple-of-width check). StatusEasyBadKeyBits
		// captures the most likely cause; verbatim message is in
		// lastErr for the binding to inspect.
		return StatusEasyBadKeyBits
	}
	return fallback
}

// setLastErrMessage records a Status code's textual diagnostic
// alongside the underlying panic / error message, so binding
// callers can read both the structural Status (which they map to a
// typed exception class) and the verbatim diagnostic text (which
// they surface to the end user).
//
// Format: "<status string>: <panic message>". The standard
// Status.String() leads, then a colon-separated suffix carrying the
// runtime detail.
func setLastErrMessage(s Status, msg string) {
	v := fmt.Sprintf("%s: %s", s.String(), msg)
	lastErr.Store(&v)
}

// NewEasy builds a fresh easy.Encryptor handle for the given primitive
// / key_bits / MAC / mode combination. Empty primitive ("") and
// keyBits == 0 select the package defaults ("areion512" / 1024) on
// the easy side; empty macName ("") selects "kmac256". Mode must be
// 1 (Single Ouroboros) or 3 (Triple Ouroboros).
//
// The deferred recoverEasyPanic translates any easy-side panic
// (unknown primitive, invalid key_bits, crypto/rand failure during
// PRF / seed / MAC key generation) into a clean FFI Status code
// rather than tearing down the host process.
func NewEasy(primitive string, keyBits int, macName string, mode int) (id EasyHandleID, st Status) {
	defer recoverEasyPanic(&st, StatusInternal)

	if mode != 1 && mode != 3 {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}

	// Build the variadic args slice from non-zero / non-empty fields
	// so the easy package's own defaults apply for any unspecified
	// dimension. The variadic dispatcher resolves names via
	// hashes.Find / macs.Find and rejects unknown strings as a panic;
	// the recover above translates that into StatusBadHash or
	// StatusBadMAC depending on the call site (the panic message
	// itself is captured in lastErr).
	var args []any
	if primitive != "" {
		args = append(args, primitive)
	}
	if keyBits != 0 {
		args = append(args, keyBits)
	}
	if macName != "" {
		args = append(args, macName)
	}

	var enc *easy.Encryptor
	if mode == 1 {
		enc = easy.New(args...)
	} else {
		enc = easy.New3(args...)
	}

	h := &EasyHandle{enc: enc}
	return EasyHandleID(cgo.NewHandle(h)), StatusOK
}

// NewEasyMixed builds a Single-Ouroboros [easy.Encryptor] with
// per-slot PRF primitive selection across the noise / data / start
// trio plus an optional dedicated lockSeed. Surfaces [easy.NewMixed]
// across the FFI boundary; mirrors [NewEasy]'s panic-to-Status
// recovery for unknown primitive / invalid key_bits / mixed-width /
// crypto/rand failure.
//
// Empty primL signals "no dedicated lockSeed" (3-slot encryptor).
// Non-empty primL allocates a 4th slot under that primitive and
// auto-couples BitSoup + LockSoup on the on-direction, matching
// [easy.NewMixed]'s constructor contract.
func NewEasyMixed(primN, primD, primS, primL string, keyBits int, macName string) (id EasyHandleID, st Status) {
	defer recoverEasyPanic(&st, StatusInternal)

	spec := easy.MixedSpec{
		PrimitiveN: primN,
		PrimitiveD: primD,
		PrimitiveS: primS,
		PrimitiveL: primL,
		KeyBits:    keyBits,
		MACName:    macName,
	}
	enc := easy.NewMixed(spec)
	h := &EasyHandle{enc: enc}
	return EasyHandleID(cgo.NewHandle(h)), StatusOK
}

// NewEasyMixed3 is the Triple-Ouroboros counterpart of [NewEasyMixed]
// — accepts 7 per-slot primitive names (noise + 3 data + 3 start)
// plus the optional dedicated lockSeed primitive. See [NewEasyMixed]
// for the construction contract.
func NewEasyMixed3(primN, primD1, primD2, primD3, primS1, primS2, primS3, primL string, keyBits int, macName string) (id EasyHandleID, st Status) {
	defer recoverEasyPanic(&st, StatusInternal)

	spec := easy.MixedSpec3{
		PrimitiveN:  primN,
		PrimitiveD1: primD1,
		PrimitiveD2: primD2,
		PrimitiveD3: primD3,
		PrimitiveS1: primS1,
		PrimitiveS2: primS2,
		PrimitiveS3: primS3,
		PrimitiveL:  primL,
		KeyBits:     keyBits,
		MACName:     macName,
	}
	enc := easy.NewMixed3(spec)
	h := &EasyHandle{enc: enc}
	return EasyHandleID(cgo.NewHandle(h)), StatusOK
}

// FreeEasy releases the cgo.Handle backing an EasyHandleID after
// calling Close on the underlying encryptor (which zeroes PRF keys,
// MAC key, and seed components before releasing them to GC). The
// double-zero — Close from FreeEasy AND the explicit ITB_Easy_Close
// FFI entry point — is intentional: bindings that forget the
// explicit Close still get key material zeroed when they release the
// handle, while bindings that DO call Close hit Close's idempotent
// fast path here.
//
// The deferred recover translates any panic from cgo.Handle.Delete
// (stale / zero handle) into StatusBadHandle.
func FreeEasy(id EasyHandleID) (st Status) {
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
	if h, ok := cgo.Handle(id).Value().(*EasyHandle); ok && h != nil && h.enc != nil {
		_ = h.enc.Close()
	}
	cgo.Handle(id).Delete()
	return StatusOK
}

// resolveEasy returns the *EasyHandle behind an opaque EasyHandleID,
// or (nil, StatusBadHandle) on a stale or zero handle.
// cgo.Handle.Value() panics on a stale handle; the deferred recover
// translates that into a clean StatusBadHandle return so FFI callers
// get an error code instead of a process-wide panic.
func resolveEasy(id EasyHandleID) (h *EasyHandle, st Status) {
	if id == 0 {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadHandle)
			h, st = nil, StatusBadHandle
		}
	}()
	v := cgo.Handle(id).Value()
	hh, ok := v.(*EasyHandle)
	if !ok || hh == nil {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	return hh, StatusOK
}
