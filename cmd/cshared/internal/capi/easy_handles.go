package capi

import (
	"errors"
	"runtime/cgo"
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
// (e.g. ErrClosed from a method called after Close, ErrLockSeedAfterEncrypt
// from a mid-session SetLockSeed switch) into the matching FFI Status
// codes rather than letting them unwind across the cgo boundary.
//
// The fallback Status is returned for any panic value that does not
// match a recognised easy sentinel — typically ErrEncryptFailed or
// ErrDecryptFailed at cipher entry points and StatusInternal at
// constructor / state entry points.
//
// The caller pattern is `defer recoverEasyPanic(&st, fallback)`,
// mirroring the recoverPanic helper used elsewhere in this package.
func recoverEasyPanic(st *Status, fallback Status) {
	if r := recover(); r != nil {
		// The easy package panics with sentinel error values; type
		// assert and compare with errors.Is to catch wrapped variants.
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
			}
		}
		setLastErr(fallback)
		*st = fallback
	}
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
