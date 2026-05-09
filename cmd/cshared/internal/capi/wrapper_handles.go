package capi

import (
	"crypto/rand"
	"runtime/cgo"

	"github.com/everanium/itb/wrapper"
)

// wrapper_handles.go — handle pattern for the streaming
// format-deniability surface. The encrypt-side handle holds one
// outer-cipher Keystream whose internal counter advances across
// successive Update calls; the decrypt-side handle is the
// counterpart that consumes the leading nonce on Init and then
// inverts the keystream XOR on each Update.
//
// The same handle struct serves both directions — the only
// difference between the encrypt and decrypt initializers is who
// supplies the nonce (the encryptor draws a fresh one from
// crypto/rand and emits it via outNonce; the decryptor reads
// the first NonceSize(name) bytes from the wire's nonce prefix).
// Once the keystream is keyed, Update is the same XOR-in-place
// operation on either side.

// WrapStreamHandle wraps a single outer-cipher Keystream behind
// an opaque uintptr crossing the cgo boundary. The keystream
// counter advances monotonically across Update calls until the
// handle is freed; no per-Update reinit cost.
//
// Mirrors the SeedHandle / MACHandle pattern in handles.go and
// macs.go — the cgo.Handle pins the value so the *Keystream stays
// rooted on the Go heap until FreeWrapStream is called.
type WrapStreamHandle struct {
	name string
	ks   wrapper.Keystream
}

// WrapStreamHandleID is the opaque uintptr passed across the C
// ABI as a wrap-stream reference. Internally a runtime/cgo.Handle
// that maps back to a *WrapStreamHandle on the Go heap.
type WrapStreamHandleID uintptr

// NewWrapStreamWriter draws a fresh nonce, builds the outer
// keystream under (name, key, nonce), and returns a handle whose
// Update calls XOR caller bytes against the keystream. The nonce
// is written into outNonce so the caller can emit it once at
// stream start (the typical wire layout is `nonce || updates...`).
//
// outNonce capacity must be at least NonceSize(name). On success
// the handle is rooted behind a cgo.Handle and exposed as an
// opaque uintptr. On StatusBufferTooSmall the required nonce
// capacity is reported via the same outNonce length convention
// as WrapInPlace — the caller resizes outNonce and retries.
//
// The deferred recoverPanic translates any keystream-construction
// panic (crypto/rand failure, cipher.NewCTR initialisation
// failure) into StatusInternal rather than crossing the cgo
// boundary.
func NewWrapStreamWriter(name string, key, outNonce []byte) (id WrapStreamHandleID, n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	nonceSz, err := wrapper.NonceSize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, 0, StatusBadInput
	}
	keySz, err := wrapper.KeySize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, 0, StatusBadInput
	}
	if len(key) != keySz {
		setLastErr(StatusBadInput)
		return 0, 0, StatusBadInput
	}
	if len(outNonce) < nonceSz {
		setLastErr(StatusBufferTooSmall)
		return 0, nonceSz, StatusBufferTooSmall
	}

	nonce := outNonce[:nonceSz]
	if _, err := rand.Read(nonce); err != nil {
		setLastErr(StatusInternal)
		return 0, 0, StatusInternal
	}
	ks, err := wrapper.MakeKeystream(name, key, nonce)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, 0, StatusBadInput
	}

	h := &WrapStreamHandle{name: name, ks: ks}
	return WrapStreamHandleID(cgo.NewHandle(h)), nonceSz, StatusOK
}

// NewUnwrapStreamReader builds a handle whose Update calls reverse
// the outer keystream emitted by a matching NewWrapStreamWriter.
// The caller passes the leading nonce bytes from the wire as
// wireNonce; subsequent Update calls XOR caller-supplied
// ciphertext back to plaintext under the keystream advancing from
// counter zero.
//
// wireNonce length must equal NonceSize(name); a shorter or
// longer slice returns StatusBadInput.
func NewUnwrapStreamReader(name string, key, wireNonce []byte) (id WrapStreamHandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)

	nonceSz, err := wrapper.NonceSize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	keySz, err := wrapper.KeySize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(key) != keySz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(wireNonce) != nonceSz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}

	ks, err := wrapper.MakeKeystream(name, key, wireNonce)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}

	h := &WrapStreamHandle{name: name, ks: ks}
	return WrapStreamHandleID(cgo.NewHandle(h)), StatusOK
}

// resolveWrapStream returns the *WrapStreamHandle behind an
// opaque WrapStreamHandleID, or (nil, StatusBadHandle) on a stale
// or zero handle. cgo.Handle.Value() panics on a stale handle;
// the deferred recover translates that into a clean StatusBadHandle.
func resolveWrapStream(id WrapStreamHandleID) (h *WrapStreamHandle, st Status) {
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
	hh, ok := v.(*WrapStreamHandle)
	if !ok || hh == nil {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	return hh, StatusOK
}

// WrapStreamUpdate XORs src into dst under the handle's keystream,
// advancing the cipher counter by len(src) bytes. dst MAY equal
// src (in-place mutation); dst capacity must be >= len(src).
//
// On StatusBufferTooSmall the n return reports the required dst
// capacity (i.e. len(src)).
func WrapStreamUpdate(id WrapStreamHandleID, src, dst []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveWrapStream(id)
	if st != StatusOK {
		return 0, st
	}
	if len(dst) < len(src) {
		setLastErr(StatusBufferTooSmall)
		return len(src), StatusBufferTooSmall
	}
	if len(src) == 0 {
		return 0, StatusOK
	}
	h.ks.XORKeyStream(dst[:len(src)], src)
	return len(src), StatusOK
}

// FreeWrapStream releases the cgo.Handle backing a
// WrapStreamHandleID, allowing the underlying *WrapStreamHandle
// (and the keystream cipher state it captured) to be reclaimed
// by the GC. The deferred recover translates a stale / zero
// handle panic into StatusBadHandle.
//
// The keystream's internal state (cipher.Stream / chacha20.Cipher
// / sipCTR) is captured opaquely inside the wrapper.Keystream
// closure — capi has no public API to wipe the captured bytes
// before release, so the best-effort here is to nil out the
// closure reference so the GC can reclaim the captured state at
// the next collection cycle. Callers that need stricter wiping
// must avoid holding sibling references and arrange for an
// immediate GC.
func FreeWrapStream(id WrapStreamHandleID) (st Status) {
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
	if h, ok := cgo.Handle(id).Value().(*WrapStreamHandle); ok && h != nil {
		h.ks = nil
		h.name = ""
	}
	cgo.Handle(id).Delete()
	return StatusOK
}
