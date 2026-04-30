package capi

import (
	"runtime/cgo"

	"github.com/everanium/itb"
	"github.com/everanium/itb/macs"
)

// MACHandle wraps a pre-keyed itb.MACFunc behind an opaque uintptr
// crossing the cgo boundary, mirroring the SeedHandle design. The
// closure carries pre-keyed primitive state (cSHAKE256 absorb-state,
// pooled hmac.Hash, blake3.Hasher template) so per-call invocation
// has no key-derivation cost.
type MACHandle struct {
	name    string
	tagSize int
	fn      itb.MACFunc
}

// MACHandleID is the opaque uintptr passed across the C ABI as a
// MAC reference. Internally a runtime/cgo.Handle that maps back to
// a *MACHandle on the Go heap.
type MACHandleID uintptr

// NewMAC builds a fresh MAC handle keyed by key for the named
// primitive (one of "kmac256", "hmac-sha256", "hmac-blake3"). The
// resulting closure is rooted behind a cgo.Handle and exposed to
// the C side as an opaque MACHandleID.
//
// The deferred recoverPanic translates any panic raised inside
// the primitive constructor (e.g. an internal blake3 / sha3
// invariant violation) into StatusInternal rather than letting it
// cross the cgo boundary.
func NewMAC(name string, key []byte) (id MACHandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)

	spec, ok := macs.Find(name)
	if !ok {
		setLastErr(StatusBadMAC)
		return 0, StatusBadMAC
	}
	if len(key) < spec.MinKeyBytes {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	fn, err := macs.Make(name, key)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	h := &MACHandle{name: name, tagSize: spec.TagSize, fn: fn}
	return MACHandleID(cgo.NewHandle(h)), StatusOK
}

// FreeMAC releases a MAC handle. Subsequent uses return StatusBadMAC.
func FreeMAC(id MACHandleID) (st Status) {
	if id == 0 {
		setLastErr(StatusBadMAC)
		return StatusBadMAC
	}
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadMAC)
			st = StatusBadMAC
		}
	}()
	cgo.Handle(id).Delete()
	return StatusOK
}

func resolveMAC(id MACHandleID) (h *MACHandle, st Status) {
	if id == 0 {
		setLastErr(StatusBadMAC)
		return nil, StatusBadMAC
	}
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadMAC)
			h, st = nil, StatusBadMAC
		}
	}()
	v := cgo.Handle(id).Value()
	hh, ok := v.(*MACHandle)
	if !ok || hh == nil {
		setLastErr(StatusBadMAC)
		return nil, StatusBadMAC
	}
	return hh, StatusOK
}

// MACName returns the canonical name a MAC handle was built with.
func MACName(id MACHandleID) (string, Status) {
	h, st := resolveMAC(id)
	if st != StatusOK {
		return "", st
	}
	return h.name, StatusOK
}

// MACTagSize returns the tag size in bytes of an existing MAC handle.
func MACTagSize(id MACHandleID) (int, Status) {
	h, st := resolveMAC(id)
	if st != StatusOK {
		return 0, st
	}
	return h.tagSize, StatusOK
}

// ─── Registry introspection (no handle required) ───────────────────

// MACCount returns the number of shipped MAC primitives (currently 3).
func MACCount() int { return len(macs.Registry) }

// MACRegistryName returns the canonical name of the i-th shipped MAC
// primitive in iteration order, or "" when i is out of range.
func MACRegistryName(i int) string {
	if i < 0 || i >= len(macs.Registry) {
		return ""
	}
	return macs.Registry[i].Name
}

// MACRegistryKeySize returns the recommended key size in bytes for
// the i-th shipped MAC primitive, or 0 when i is out of range.
func MACRegistryKeySize(i int) int {
	if i < 0 || i >= len(macs.Registry) {
		return 0
	}
	return macs.Registry[i].KeySize
}

// MACRegistryTagSize returns the tag size in bytes for the i-th
// shipped MAC primitive, or 0 when i is out of range.
func MACRegistryTagSize(i int) int {
	if i < 0 || i >= len(macs.Registry) {
		return 0
	}
	return macs.Registry[i].TagSize
}

// MACRegistryMinKeyBytes returns the minimum acceptable key length
// (bytes) for the i-th shipped MAC primitive, or 0 when i is out of
// range.
func MACRegistryMinKeyBytes(i int) int {
	if i < 0 || i >= len(macs.Registry) {
		return 0
	}
	return macs.Registry[i].MinKeyBytes
}
