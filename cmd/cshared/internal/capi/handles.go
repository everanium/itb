package capi

import "sync/atomic"

// lastErr stores the last status emitted by any capi call, so the
// FFI ITB_LastError entry point can report a textual reason. The
// last-error pattern is process-wide and intentionally racy under
// concurrent failure paths — callers are expected to inspect
// LastError immediately after a non-OK return on the same thread,
// the standard errno idiom.
var lastErr atomic.Pointer[string]

func setLastErr(s Status) {
	v := s.String()
	lastErr.Store(&v)
}

// recoverPanic translates any Go panic crossing this point into the
// supplied fallback Status, preventing the panic from unwinding
// across the cgo boundary and tearing down the host process. Used
// at every FFI entry point to firewall transitive panic sources
// (crypto/rand failures inside hash factories, internal slice-
// bounds panics in the cipher core, primitive constructor errors).
//
// The caller pattern is `defer recoverPanic(&st, fallback)`. If
// recover() returns a non-nil value, *st is overwritten with the
// fallback Status and the last-error message is set to a generic
// "internal error" string.
func recoverPanic(st *Status, fallback Status) {
	if r := recover(); r != nil {
		setLastErr(fallback)
		*st = fallback
	}
}

// LastError returns the textual reason for the most recent non-OK
// status produced by any capi call.
func LastError() string {
	if p := lastErr.Load(); p != nil {
		return *p
	}
	return ""
}
