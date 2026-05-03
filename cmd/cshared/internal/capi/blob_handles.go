package capi

import (
	"errors"
	"runtime/cgo"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// BlobHandle wraps a single *itb.Blob{128,256,512} behind an opaque
// uintptr crossing the cgo boundary. The width discriminator pins
// the struct to one of the three width-specific containers; only the
// matching pointer is non-nil for any given handle. The FFI layer
// pins the value via runtime/cgo.Handle so it survives across the
// C boundary without leaking the internal type.
//
// Mirrors the SeedHandle pattern in handles.go — same width tag,
// same three-pointer layout — but holds blob containers rather than
// seeds. Mode (1 = Single, 3 = Triple) is meta state on the underlying
// itb.Blob{N}.Mode field; Import / Import3 update it from the parsed
// blob and Export / Export3 read the explicitly-targeted slots
// without consulting it.
type BlobHandle struct {
	width hashes.Width

	blob128 *itb.Blob128
	blob256 *itb.Blob256
	blob512 *itb.Blob512
}

// BlobHandleID is the opaque uintptr passed across the C ABI as a
// blob reference. Internally a runtime/cgo.Handle that maps back to
// a *BlobHandle on the Go heap.
type BlobHandleID uintptr

// Blob slot identifiers — name the per-component slot in a blob's
// Single (N / D / S) or Triple (N / D1..D3 / S1..S3) layout, with
// L (lockSeed) shared across both modes. Slot ordering is stable
// across releases; bindings rely on the numeric values.
const (
	BlobSlotN  = 0 // shared (Single + Triple): noiseSeed + KeyN
	BlobSlotD  = 1 // Single only: dataSeed + KeyD
	BlobSlotS  = 2 // Single only: startSeed + KeyS
	BlobSlotL  = 3 // optional (any mode): dedicated lockSeed + KeyL
	BlobSlotD1 = 4 // Triple only: dataSeed1 + KeyD1
	BlobSlotD2 = 5
	BlobSlotD3 = 6
	BlobSlotS1 = 7 // Triple only: startSeed1 + KeyS1
	BlobSlotS2 = 8
	BlobSlotS3 = 9
)

// Export option bitmask flags — passed to BlobExport / BlobExport3
// to enable optional sections of the blob. Without a flag the
// corresponding handle slots are not consulted and the resulting
// blob omits the matching JSON fields.
const (
	BlobOptLockSeed = 1 << 0 // include KeyL + LS slot in the blob
	BlobOptMAC      = 1 << 1 // include MACKey + MACName in the blob
)

// NewBlob128 / NewBlob256 / NewBlob512 construct an empty BlobHandle
// at the given width with the matching itb.Blob{N} attached. The
// caller populates the slots via BlobSetKey / BlobSetComponents /
// BlobSetMACKey / BlobSetMACName before calling BlobExport /
// BlobExport3, or feeds a JSON blob through BlobImport / BlobImport3
// to populate the slots from a prior Export.
func NewBlob128() (id BlobHandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)
	h := &BlobHandle{width: hashes.W128, blob128: &itb.Blob128{}}
	return BlobHandleID(cgo.NewHandle(h)), StatusOK
}

func NewBlob256() (id BlobHandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)
	h := &BlobHandle{width: hashes.W256, blob256: &itb.Blob256{}}
	return BlobHandleID(cgo.NewHandle(h)), StatusOK
}

func NewBlob512() (id BlobHandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)
	h := &BlobHandle{width: hashes.W512, blob512: &itb.Blob512{}}
	return BlobHandleID(cgo.NewHandle(h)), StatusOK
}

// FreeBlob releases the cgo.Handle backing a BlobHandleID. Wipes
// every key-material slot (per-slot hash keys, the seed Components
// arrays for every populated slot, the optional MAC key) before
// the cgo.Handle.Delete call so the discarded state does not
// linger in memory until the GC reclaims it. The wipe is
// best-effort — fixed-size [32]byte / [64]byte arrays embedded in
// the Blob{N} struct can be cleared in place; the [Seed{N}]
// pointers are nil-ed out after their Components slices are
// cleared so the underlying seed structs become eligible for GC.
//
// The deferred recover translates a stale / zero handle panic
// from cgo.Handle.Delete into StatusBadHandle.
//
// The blob structs do not own any resource that requires a Close
// step (no goroutines, no OS handles), so unlike FreeEasy this is
// a pure wipe + Delete with no separate close.
//
// Threading constraint mirrors FreeSeed: the wipe runs in-place
// on the live Blob{N} struct, so calling FreeBlob concurrently
// with an in-flight Export / Import / Get / Set on the same
// handle is a caller error and produces wrong output (cleared key
// bytes, zero components) rather than a late panic. Bindings must
// serialise FreeBlob against every concurrent use of the handle.
func FreeBlob(id BlobHandleID) (st Status) {
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
	if h, ok := cgo.Handle(id).Value().(*BlobHandle); ok && h != nil {
		switch h.width {
		case hashes.W128:
			wipeBlob128(h.blob128)
		case hashes.W256:
			wipeBlob256(h.blob256)
		case hashes.W512:
			wipeBlob512(h.blob512)
		}
	}
	cgo.Handle(id).Delete()
	return StatusOK
}

// wipeBlob128 / wipeBlob256 / wipeBlob512 zero every populated
// key-material slot on a Blob{N} struct: per-slot hash keys, every
// non-nil Seed{N}.Components slice, and the optional MAC key. The
// width-typed Hash key fields on Blob{128} are []byte slices —
// cleared via clear; on Blob{256} / Blob{512} they are fixed-size
// [32]byte / [64]byte arrays — overwritten in place.
func wipeBlob128(b *itb.Blob128) {
	if b == nil {
		return
	}
	clear(b.KeyN)
	clear(b.KeyD)
	clear(b.KeyS)
	clear(b.KeyL)
	clear(b.KeyD1)
	clear(b.KeyD2)
	clear(b.KeyD3)
	clear(b.KeyS1)
	clear(b.KeyS2)
	clear(b.KeyS3)
	for _, s := range []*itb.Seed128{b.NS, b.DS, b.SS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3} {
		if s != nil {
			clear(s.Components)
		}
	}
	clear(b.MACKey)
	b.MACName = ""
}

func wipeBlob256(b *itb.Blob256) {
	if b == nil {
		return
	}
	for _, k := range []*[32]byte{&b.KeyN, &b.KeyD, &b.KeyS, &b.KeyL, &b.KeyD1, &b.KeyD2, &b.KeyD3, &b.KeyS1, &b.KeyS2, &b.KeyS3} {
		*k = [32]byte{}
	}
	for _, s := range []*itb.Seed256{b.NS, b.DS, b.SS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3} {
		if s != nil {
			clear(s.Components)
		}
	}
	clear(b.MACKey)
	b.MACName = ""
}

func wipeBlob512(b *itb.Blob512) {
	if b == nil {
		return
	}
	for _, k := range []*[64]byte{&b.KeyN, &b.KeyD, &b.KeyS, &b.KeyL, &b.KeyD1, &b.KeyD2, &b.KeyD3, &b.KeyS1, &b.KeyS2, &b.KeyS3} {
		*k = [64]byte{}
	}
	for _, s := range []*itb.Seed512{b.NS, b.DS, b.SS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3} {
		if s != nil {
			clear(s.Components)
		}
	}
	clear(b.MACKey)
	b.MACName = ""
}

// resolveBlob returns the *BlobHandle behind an opaque BlobHandleID,
// or (nil, StatusBadHandle) on a stale or zero handle.
// cgo.Handle.Value() panics on a stale handle; the deferred recover
// translates that into a clean StatusBadHandle return so FFI callers
// get an error code instead of a process-wide panic.
func resolveBlob(id BlobHandleID) (h *BlobHandle, st Status) {
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
	hh, ok := v.(*BlobHandle)
	if !ok || hh == nil {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	return hh, StatusOK
}

// BlobWidth returns the native hash width of an existing blob handle
// (128, 256, or 512). Bindings call this to size their downstream
// buffers — e.g. a 32-byte vs 64-byte hash key buffer for BlobGetKey.
func BlobWidth(id BlobHandleID) (hashes.Width, Status) {
	h, st := resolveBlob(id)
	if st != StatusOK {
		return 0, st
	}
	return h.width, StatusOK
}

// BlobMode returns the blob's mode field (0 = unset, 1 = Single,
// 3 = Triple). Set to 1 / 3 by the most recent Import / Import3
// call, or by any successful Export / Export3 call. A freshly
// constructed handle has Mode == 0 until the caller drives one of
// these state transitions.
func BlobMode(id BlobHandleID) (int, Status) {
	h, st := resolveBlob(id)
	if st != StatusOK {
		return 0, st
	}
	switch h.width {
	case hashes.W128:
		return h.blob128.Mode, StatusOK
	case hashes.W256:
		return h.blob256.Mode, StatusOK
	case hashes.W512:
		return h.blob512.Mode, StatusOK
	}
	setLastErr(StatusInternal)
	return 0, StatusInternal
}

// mapBlobError translates an itb.Blob{N}.Export / Import error onto
// the matching FFI Status code. The four sentinel errors map 1:1;
// any other error (nil seed, mismatched component count) is treated
// as caller-side bad input rather than a malformed blob — those
// preconditions are observable on the handle's slot state before
// the call.
//
// The errors.Is path covers wrapped sentinels (the itb package does
// not currently wrap them, but a future revision might — better to
// be defensive than rely on identity comparison).
func mapBlobError(err error) Status {
	if err == nil {
		return StatusOK
	}
	switch {
	case errors.Is(err, itb.ErrBlobModeMismatch):
		return StatusBlobModeMismatch
	case errors.Is(err, itb.ErrBlobMalformed):
		return StatusBlobMalformed
	case errors.Is(err, itb.ErrBlobVersionTooNew):
		return StatusBlobVersionTooNew
	case errors.Is(err, itb.ErrBlobTooManyOpts):
		return StatusBlobTooManyOpts
	}
	return StatusBadInput
}
