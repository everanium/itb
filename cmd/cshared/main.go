// libitb — C ABI shared-library entry points for ITB.
//
// Build:
//
//	go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared
//
// The output is a shared library (.so / .dll / .dylib depending on
// GOOS) plus an auto-generated libitb.h header consumed by every
// language binding under bindings/<lang>/. Every entry point here
// is a thin //export wrapper around capi (see
// cmd/cshared/internal/capi/) — the real logic and tests live there.
//
// Surface. The FFI shim exposes two families, both frozen under
// RULE #2:
//
//   - Triple family (ITB_Triple_*) — the whole-object cipher /
//     lifecycle surface. Bindings construct one Pipeline handle
//     against a named profile and use it for every encrypt / decrypt /
//     save / rekey call. Streaming, message, register, and lookup
//     surfaces all live here.
//   - Runtime family — build-time constants (ITB_Version,
//     ITB_MaxKeyBits, ITB_Channels, ITB_DefaultNonceBits,
//     ITB_HeaderSize), runtime tunables (ITB_SetMemoryLimit,
//     ITB_SetGCPercent), and the last-error accessor (ITB_LastError).
//
// Buffer convention. All input/output buffers are caller-allocated.
// For functions that produce variable-size output (every string-
// returning entry point, every cipher entry point, ITB_Triple_Save,
// ITB_Triple_Inspect, ITB_Triple_HashNames, ITB_Triple_ProfileJSON,
// ITB_Triple_Lookup, ITB_Triple_Profiles) the caller passes (out,
// out_cap, &out_len). On success out_len is set to the number of
// bytes written; on ITB_ERR_BUFFER_TOO_SMALL out_len is set to the
// required capacity so the caller can resize and retry.
//
// Handles. Triple Pipelines are exposed as opaque uintptr_t handles
// (ITB_Triple_Init / ITB_Triple_Load / ITB_Triple_LoadF); every
// handle must be paired with exactly one ITB_Triple_Free. Streaming
// session handles (ITB_Triple_EncryptStreamBegin /
// ITB_Triple_DecryptStreamBegin) are separately allocated and
// released via ITB_Triple_StreamFree.
//
// Threading. The library is safe for concurrent use across OS
// threads after handles are constructed; concurrent
// ITB_Triple_Init / ITB_Triple_Free calls are also safe (cgo.Handle
// is internally synchronised). Per-instance configuration is passed
// explicitly on each ITB_Triple_Init call (via the opts string)
// rather than through process-wide setters.
package main

// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
import "C"

import (
	"runtime/debug"
	"unsafe"

	"github.com/everanium/itb/cmd/cshared/internal/capi"
	_ "github.com/everanium/itb/internal/runtimecfg"
	"github.com/everanium/itb/triple"
)

// Library version exposed via ITB_Version. Bumped per ABI-relevant
// release. The value is informational; binding code may key feature
// detection off it.
const libitbVersion = "0.5.0"

func main() {} // required for buildmode=c-shared

// maxSliceLen is the largest C buffer length we accept across the
// FFI boundary, capped at the largest value Go's int type can
// represent on the host. On 64-bit hosts this is ~9.2 EiB; on
// 32-bit hosts it is 2 GiB minus 1. Larger values from the C side
// are rejected (goBytesView / goBytesViewMut return nil) rather
// than truncated, defending against length-truncation attacks
// from a hostile or buggy caller. The dispatch wrappers translate
// that nil into StatusBadInput.
const maxSliceLen = C.size_t(int(^uint(0) >> 1))

// goBytesView wraps a (ptr, len) C buffer as a Go []byte without
// copying. The returned slice aliases C memory and must not outlive
// the C call. Safe because Encrypt / Decrypt consume the slice
// synchronously and never retain it. Returns nil for ptr==nil,
// length==0, or length > maxSliceLen.
func goBytesView(ptr unsafe.Pointer, length C.size_t) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	if length > maxSliceLen {
		return nil
	}
	return unsafe.Slice((*byte)(ptr), int(length))
}

// goBytesViewMut returns a mutable []byte over a C-side caller-
// allocated output buffer. Same length guard as goBytesView.
func goBytesViewMut(ptr unsafe.Pointer, capBytes C.size_t) []byte {
	if ptr == nil || capBytes == 0 {
		return nil
	}
	if capBytes > maxSliceLen {
		return nil
	}
	return unsafe.Slice((*byte)(ptr), int(capBytes))
}

// validateLen rejects any C-side length argument that exceeds
// [maxSliceLen]. Used at the top of every cgo //export wrapper
// before [goBytesView] / [goBytesViewMut] runs: without this guard
// a hostile or buggy caller passing length > maxSliceLen would get
// nil from the helpers and the wrapper would silently proceed as if
// the input were empty (returning StatusOK with an empty
// ciphertext, etc.) instead of StatusBadInput.
//
// The helpers themselves still return nil for the legitimate
// probe forms (ptr==nil OR length==0), which is indistinguishable
// from the truncation case at the helper level — so the bounds
// check has to live at the wrapper.
func validateLen(lengths ...C.size_t) bool {
	for _, l := range lengths {
		if l > maxSliceLen {
			return false
		}
	}
	return true
}

// writeCString copies s into a caller-allocated C buffer following
// the size-out-param idiom. On success outLen reports the number of
// bytes that have been written (including the trailing NUL).
//
// Probe form: passing out==NULL with capBytes==0 reports the
// required capacity through *outLen and returns StatusBufferTooSmall
// without writing anywhere. Bindings use this to size their output
// buffer in two phases (see e.g. bindings/python/itb/_ffi.py).
//
// When out!=NULL but capBytes < required, returns
// StatusBufferTooSmall and outLen reports required capacity
// including the trailing NUL so the caller can resize and retry.
func writeCString(s string, out unsafe.Pointer, capBytes C.size_t, outLen *C.size_t) capi.Status {
	need := C.size_t(len(s) + 1)
	if outLen != nil {
		*outLen = need
	}
	if capBytes < need {
		return capi.StatusBufferTooSmall
	}
	if out == nil {
		// Caller passed cap > 0 but a nil buffer — that's a real bug.
		return capi.StatusBadInput
	}
	dst := unsafe.Slice((*byte)(out), int(capBytes))
	copy(dst, s)
	dst[len(s)] = 0
	return capi.StatusOK
}

// ─── Library introspection ─────────────────────────────────────────

// Writes the library version (NUL-terminated ASCII) into out, sets
// *out_len to the number of bytes written including the NUL.
// Returns ITB_OK on success, ITB_ERR_BUFFER_TOO_SMALL if cap is too
// small (out_len then carries the required size).
//
//export ITB_Version
func ITB_Version(out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	return C.int(writeCString(libitbVersion, unsafe.Pointer(out), capBytes, outLen))
}

// Writes the last error message produced on this thread's most
// recent capi call. Standard errno-style: read it immediately after
// a non-OK return on the same thread.
//
//export ITB_LastError
func ITB_LastError(out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	return C.int(writeCString(capi.LastError(), unsafe.Pointer(out), capBytes, outLen))
}

// Configures the Go runtime's heap-size soft limit (bytes). Pass -1
// (or any negative value) to query the current limit without changing
// it; the previous limit is returned. Setter calls override any
// ITB_GOMEMLIMIT env var set at libitb load time.
//
//export ITB_SetMemoryLimit
func ITB_SetMemoryLimit(limit C.int64_t) C.int64_t {
	return C.int64_t(debug.SetMemoryLimit(int64(limit)))
}

// Configures the Go runtime's GC trigger percentage. The default is
// 100 (GC fires at +100% heap growth); lower values trigger GC more
// aggressively. Pass -1 (or any negative value) to query the current
// value without changing it; the previous value is returned. Setter
// calls override any ITB_GOGC env var set at libitb load time.
//
//export ITB_SetGCPercent
func ITB_SetGCPercent(pct C.int) C.int {
	if pct < 0 {
		// Query mode — round-trip set-then-restore to retrieve current
		// without long-term change. debug.SetGCPercent has no native
		// query path; every call sets. Use 100 as the sentinel pass
		// since it is the documented default and a benign target.
		curr := debug.SetGCPercent(100)
		debug.SetGCPercent(curr)
		return C.int(curr)
	}
	return C.int(debug.SetGCPercent(int(pct)))
}

// ─── Read-only build constants ─────────────────────────────────────

//export ITB_MaxKeyBits
func ITB_MaxKeyBits() C.int { return C.int(capi.MaxKeyBits()) }

//export ITB_Channels
func ITB_Channels() C.int { return C.int(capi.Channels()) }

// Returns the ciphertext-chunk header size in bytes for the given
// nonce_bytes (main_nonce + interlock_nonce + width(2) + height(2),
// i.e. 2*nonce_bytes + 4). Header size = 36 for 16-byte nonce, 68
// for 32-byte, 132 for 64-byte. Streaming consumers use this to size
// the per-chunk header they read before decoding.
//
// The parameter is explicit rather than implied by a process-global
// setter. Bindings pass the value their Pipeline / Config selected.
// Returns ITB_ERR_BAD_INPUT when nonce_bytes is not one of {16, 32,
// 64}.
//
// ITB_DefaultNonceBits exposes the compile-in default in bits (512);
// divide by 8 to get the byte count.
//
//export ITB_HeaderSize
func ITB_HeaderSize(nonceBytes C.uint32_t) C.int {
	n, st := capi.HeaderSize(int(nonceBytes))
	if st != capi.StatusOK {
		return -1
	}
	return C.int(n)
}

// Returns the compile-in default nonce width in bits used when a
// Config leaves NonceBits at zero.
//
//export ITB_DefaultNonceBits
func ITB_DefaultNonceBits() C.int { return C.int(capi.DefaultNonceBits()) }

// Returns the upper sanity bound on a Triple Pipeline profile name
// (matching triple.ProfileNameMaxLen). Bindings that expose a Register
// entry use this to reject over-long user-supplied names client-side
// without a round trip through ITB_Triple_Register.
//
//export ITB_TripleProfileNameMaxLen
func ITB_TripleProfileNameMaxLen() C.int { return C.int(triple.ProfileNameMaxLen) }

// ─── Triple Pipeline (itb/triple facade) ───────────────────────────
//
// The ITB_Triple_* surface wraps the github.com/everanium/itb/triple
// sub-package — one Pipeline handle collects the 8-seed constellation,
// parallax layer, wrapper (Outer cipher) layer, and MAC behind a
// single lifecycle object. A fresh Pipeline is constructed against a
// registered profile name (the shipped catalogue — see
// triple/profile.go — or a name installed via ITB_Triple_Register);
// a URL-query-encoded opts string carries any per-Pipeline overrides
// (see capi.parseTripleOpts for the accepted keys).
//
// All cipher entry points share the same caller-allocated
// out / out_cap / *out_len buffer convention as the string-returning
// entries; the two-phase probe (NULL / 0 → resize → retry) works
// identically.
//
// State persistence rides on the self-describing blob bytes
// ITB_Triple_Init returns (also available at any time through
// ITB_Triple_Save / ITB_Triple_SaveF). The receiver calls
// ITB_Triple_Load (bytes) or ITB_Triple_LoadF (file path) with the
// blob and optional master overrides — no profile name, no opts —
// then encrypts / decrypts against the reconstructed Pipeline.
// ITB_Triple_Inspect reads the blob's embedded profile record without
// opening it. ITB_Triple_Rekey rotates the parallax + wrapper masters
// without disturbing the underlying seed material; ITB_Triple_MaxWorkers
// sets the per-machine worker cap on a live handle.

// Constructs a fresh Pipeline handle against the named profile and
// writes the exported blob bytes into blob_out.
//
// opts is a URL-query-encoded overrides string (see
// capi.parseTripleOpts); pass NULL / empty for pure profile defaults.
// blob_out follows the standard caller-allocated buffer convention —
// on ITB_ERR_BUFFER_TOO_SMALL *blob_len receives the required size
// and the Pipeline is closed before return so the caller does not
// chase a handle it never received.
//
//export ITB_Triple_Init
func ITB_Triple_Init(
	profile *C.char, opts *C.char,
	blobOut unsafe.Pointer, blobCap C.size_t, blobLen *C.size_t,
	outHandle *C.uintptr_t,
) C.int {
	if profile == nil || blobLen == nil || outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(blobCap) {
		return C.int(capi.StatusBadInput)
	}
	var optsStr string
	if opts != nil {
		optsStr = C.GoString(opts)
	}
	dst := goBytesViewMut(blobOut, blobCap)
	id, n, st := capi.TripleInit(C.GoString(profile), optsStr, dst)
	*blobLen = C.size_t(n)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Reconstructs a Pipeline handle from a self-describing blob produced
// by ITB_Triple_Init, ITB_Triple_Save, or ITB_Triple_Rekey. The
// blob's embedded profile record is the sole structural source — no
// profile name and no opts are taken; the profile registry is not
// consulted. masters_count == 0 uses the blob-embedded masters;
// masters_count == 2 overrides them (with perm_master at index 0,
// wrap_master at index 1). Any other arity returns ITB_ERR_BAD_INPUT.
//
// A blob whose record names a primitive absent from the local
// registries returns ITB_STATUS_RECIPE_PRIMITIVE_UNKNOWN; a record
// that fails the profile field rules or disagrees with the inner blob
// returns ITB_STATUS_BLOB_MALFORMED_RECIPE; a blob from an earlier
// release (wrap-layer version 1) returns ITB_ERR_BAD_INPUT
// (triple.ErrBlobVersion in ITB_LastError).
//
//export ITB_Triple_Load
func ITB_Triple_Load(
	blob unsafe.Pointer, blobLen C.size_t,
	permMaster unsafe.Pointer, permMasterLen C.size_t,
	wrapMaster unsafe.Pointer, wrapMasterLen C.size_t,
	mastersCount C.size_t,
	outHandle *C.uintptr_t,
) C.int {
	if outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(blobLen, permMasterLen, wrapMasterLen) {
		return C.int(capi.StatusBadInput)
	}
	masters, ok := tripleMastersView(permMaster, permMasterLen, wrapMaster, wrapMasterLen, mastersCount)
	if !ok {
		return C.int(capi.StatusBadInput)
	}
	blobBytes := goBytesView(blob, blobLen)
	id, st := capi.TripleLoad(blobBytes, masters...)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// ITB_Triple_Load for a blob stored in a file. The file is read
// inside the library (size-capped at itb.MaxBlobJSONSize); a missing
// or unreadable file returns ITB_ERR_BAD_INPUT with the os diagnostic
// in ITB_LastError. Masters semantics are identical to
// ITB_Triple_Load.
//
//export ITB_Triple_LoadF
func ITB_Triple_LoadF(
	path *C.char,
	permMaster unsafe.Pointer, permMasterLen C.size_t,
	wrapMaster unsafe.Pointer, wrapMasterLen C.size_t,
	mastersCount C.size_t,
	outHandle *C.uintptr_t,
) C.int {
	if path == nil || outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(permMasterLen, wrapMasterLen) {
		return C.int(capi.StatusBadInput)
	}
	masters, ok := tripleMastersView(permMaster, permMasterLen, wrapMaster, wrapMasterLen, mastersCount)
	if !ok {
		return C.int(capi.StatusBadInput)
	}
	id, st := capi.TripleLoadF(C.GoString(path), masters...)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// tripleMastersView folds the (perm_master, wrap_master,
// masters_count) triple shared by ITB_Triple_Load / ITB_Triple_LoadF
// into the variadic masters slice. masters_count must be 0 or 2; under
// 2 both slots must be non-NULL (a zero-length master is inadmissible
// when the caller signals both are supplied).
func tripleMastersView(
	permMaster unsafe.Pointer, permMasterLen C.size_t,
	wrapMaster unsafe.Pointer, wrapMasterLen C.size_t,
	mastersCount C.size_t,
) ([][]byte, bool) {
	switch mastersCount {
	case 0:
		return nil, true
	case 2:
		pm := goBytesView(permMaster, permMasterLen)
		wm := goBytesView(wrapMaster, wrapMasterLen)
		if pm == nil || wm == nil {
			return nil, false
		}
		return [][]byte{pm, wm}, true
	}
	return nil, false
}

// Writes the handle's current blob — the bytes ITB_Triple_Init
// returned, the bytes ITB_Triple_Load re-marshalled (a master
// override folded in), or the bytes of the latest ITB_Triple_Rekey —
// into blob_out under the caller-allocated buffer convention: on
// ITB_ERR_BUFFER_TOO_SMALL *blob_len receives the required size. A
// closed handle returns ITB_ERR_TRIPLE_CLOSED.
//
//export ITB_Triple_Save
func ITB_Triple_Save(
	handle C.uintptr_t,
	blobOut unsafe.Pointer, blobCap C.size_t, blobLen *C.size_t,
) C.int {
	if blobLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(blobCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(blobOut, blobCap)
	n, st := capi.TripleSave(capi.TripleHandleID(handle), dst)
	*blobLen = C.size_t(n)
	return C.int(st)
}

// Writes the handle's current blob to path inside the library with
// mode 0600 (the blob is key material). The containing directory
// must exist. A closed handle returns ITB_ERR_TRIPLE_CLOSED; a
// file-system failure returns ITB_ERR_BAD_INPUT with the os
// diagnostic in ITB_LastError.
//
//export ITB_Triple_SaveF
func ITB_Triple_SaveF(handle C.uintptr_t, path *C.char) C.int {
	if path == nil {
		return C.int(capi.StatusBadInput)
	}
	return C.int(capi.TripleSaveF(capi.TripleHandleID(handle), C.GoString(path)))
}

// Decodes the blob's wrap-layer without opening a Pipeline and writes
// the embedded profile record as its JSON encoding (the same key set
// ITB_Triple_Register accepts and the blob carries; name included)
// into json_out under the caller-allocated buffer convention: on
// ITB_ERR_BUFFER_TOO_SMALL *json_len receives the required size. No
// registry read, no primitive probe — a primitive name the local
// build lacks is returned unchanged.
//
//export ITB_Triple_Inspect
func ITB_Triple_Inspect(
	blob unsafe.Pointer, blobLen C.size_t,
	jsonOut unsafe.Pointer, jsonCap C.size_t, jsonLen *C.size_t,
) C.int {
	if jsonLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(blobLen, jsonCap) {
		return C.int(capi.StatusBadInput)
	}
	blobBytes := goBytesView(blob, blobLen)
	dst := goBytesViewMut(jsonOut, jsonCap)
	n, st := capi.TripleInspect(blobBytes, dst)
	*jsonLen = C.size_t(n)
	return C.int(st)
}

// Sets the handle's worker cap for every subsequent cipher call. n is
// clamped, never rejected: n <= 0 selects auto (runtime.NumCPU),
// 1..256 pins the cap, n > 256 is treated as 256. The status reports
// the handle only — ITB_ERR_BAD_HANDLE for an unknown handle,
// ITB_ERR_TRIPLE_CLOSED for a closed one. Works identically on a
// handle from ITB_Triple_Init, ITB_Triple_Load, or ITB_Triple_LoadF;
// the worker cap is per-machine tuning and is never written to the
// blob.
//
//export ITB_Triple_MaxWorkers
func ITB_Triple_MaxWorkers(handle C.uintptr_t, n C.int) C.int {
	return C.int(capi.TripleMaxWorkers(capi.TripleHandleID(handle), int(n)))
}

// Rotates the Pipeline's parallax + wrapper masters and writes the
// fresh blob bytes into blob_out. The receiver applies the new blob
// via ITB_Triple_Load to stay in sync. Rekey mutates Pipeline state;
// the caller is responsible for serialising this against every
// concurrent cipher-path call on the same handle.
//
//export ITB_Triple_Rekey
func ITB_Triple_Rekey(
	handle C.uintptr_t,
	permMaster unsafe.Pointer, permMasterLen C.size_t,
	wrapMaster unsafe.Pointer, wrapMasterLen C.size_t,
	blobOut unsafe.Pointer, blobCap C.size_t, blobLen *C.size_t,
) C.int {
	if blobLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(permMasterLen, wrapMasterLen, blobCap) {
		return C.int(capi.StatusBadInput)
	}
	pm := goBytesView(permMaster, permMasterLen)
	wm := goBytesView(wrapMaster, wrapMasterLen)
	dst := goBytesViewMut(blobOut, blobCap)
	n, st := capi.TripleRekey(capi.TripleHandleID(handle), pm, wm, dst)
	*blobLen = C.size_t(n)
	return C.int(st)
}

// Zeroes the Pipeline's secret material and marks the handle closed.
// Subsequent cipher-path calls return ITB_ERR_TRIPLE_CLOSED (see
// capi/errors.go: StatusTripleClosed). Idempotent — multiple calls
// return ITB_OK without panic. The handle itself remains valid until
// ITB_Triple_Free is called.
//
//export ITB_Triple_Close
func ITB_Triple_Close(handle C.uintptr_t) C.int {
	return C.int(capi.TripleClose(capi.TripleHandleID(handle)))
}

// Releases the Pipeline handle. Internally calls the Pipeline's
// Close (zeroing seed components, PRF keys, wrapper key, MAC key,
// parallax subkeys) before deleting the cgo.Handle so key material
// does not linger after the binding drops the handle.
//
//export ITB_Triple_Free
func ITB_Triple_Free(handle C.uintptr_t) C.int {
	return C.int(capi.FreeTriple(capi.TripleHandleID(handle)))
}

// Encrypts a plaintext through the Pipeline's Streaming AEAD chain
// (or Non-AEAD when the profile is No MAC) — parallax
// encrypt-Reader → itb Triple 8-seed Streaming AEAD (or Non-AEAD) →
// wrapper wrap-Writer. Buffer-in / buffer-out on the FFI side; the
// Pipeline handles the streaming wiring internally via bytes.Reader /
// bytes.Buffer.
//
// Same caller-allocated-buffer convention as every other cipher
// entry: on ITB_ERR_BUFFER_TOO_SMALL *out_len receives the required
// capacity.
//
//export ITB_Triple_EncryptStream
func ITB_Triple_EncryptStream(
	handle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ptlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	pt := goBytesView(plaintext, ptlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.TripleEncryptStream(capi.TripleHandleID(handle), pt, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Receive-side counterpart of ITB_Triple_EncryptStream. Reverses the
// Pipeline chain: wrapper unwrap-Reader → itb Triple 8-seed Streaming
// AEAD (or Non-AEAD) decrypt → parallax decrypt-Writer.
//
//export ITB_Triple_DecryptStream
func ITB_Triple_DecryptStream(
	handle C.uintptr_t,
	wire unsafe.Pointer, wireLen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(wireLen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	wireBytes := goBytesView(wire, wireLen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.TripleDecryptStream(capi.TripleHandleID(handle), wireBytes, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Encrypts a single message through the Pipeline. Convenience surface
// for callers without an io.Reader / io.Writer at hand — the byte
// shape produced is a stream that happens to fit in one chunk.
//
// Accepted profile modes: Streaming AEAD, Streaming Non-AEAD, Single
// Message MAC, Single Message No MAC. The blob-only profile has no
// cipher surface and returns ITB_ERR_BAD_INPUT (the underlying
// [triple.ErrProfileNoCipher] maps to bad-input).
//
//export ITB_Triple_EncryptMessage
func ITB_Triple_EncryptMessage(
	handle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ptlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	pt := goBytesView(plaintext, ptlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.TripleEncryptMessage(capi.TripleHandleID(handle), pt, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Receive-side counterpart of ITB_Triple_EncryptMessage.
//
//export ITB_Triple_DecryptMessage
func ITB_Triple_DecryptMessage(
	handle C.uintptr_t,
	wire unsafe.Pointer, wireLen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(wireLen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	wireBytes := goBytesView(wire, wireLen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.TripleDecryptMessage(capi.TripleHandleID(handle), wireBytes, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Installs a user-defined Triple Pipeline profile under name so
// subsequent ITB_Triple_Init / ITB_Triple_Lookup calls resolve name
// to the newly-registered record. profile_json is the profile JSON
// record — the same encoding ITB_Triple_Inspect emits and the blob's
// wrap-layer carries (see triple.Profile.MarshalJSON for the key
// set); a name key inside it, if present, must be empty or equal to
// the name argument. Returns ITB_ERR_PROFILE_EXISTS when the name is
// already in the catalogue, ITB_ERR_BAD_INPUT on any validation
// failure (unknown JSON key, name pattern, reserved prefix, field
// rules), and ITB_OK on success.
//
// Name rules mirror triple.Register: must match
// `^[a-z][a-z0-9-]{2,}$` (length capped at triple.ProfileNameMaxLen,
// also exposed via ITB_TripleProfileNameMaxLen) and must not start
// with one of the reserved shipped-catalogue prefixes (streaming- /
// singlemsg- / blob-).
//
//export ITB_Triple_Register
func ITB_Triple_Register(name *C.char, profileJSON *C.char) C.int {
	if name == nil || profileJSON == nil {
		return C.int(capi.StatusBadInput)
	}
	return C.int(capi.TripleRegister(C.GoString(name), C.GoString(profileJSON)))
}

// Writes the profile registered under name — a shipped catalogue
// entry or a prior ITB_Triple_Register registration — as its JSON
// record into json_out under the caller-allocated buffer convention
// (same encoding as ITB_Triple_Inspect). An unknown name returns
// ITB_STATUS_UNKNOWN_PROFILE (the same code ITB_Triple_Init returns
// for an unregistered name).
//
//export ITB_Triple_Lookup
func ITB_Triple_Lookup(
	name *C.char,
	jsonOut unsafe.Pointer, jsonCap C.size_t, jsonLen *C.size_t,
) C.int {
	if name == nil || jsonLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(jsonCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(jsonOut, jsonCap)
	n, st := capi.TripleLookup(C.GoString(name), dst)
	*jsonLen = C.size_t(n)
	return C.int(st)
}

// Writes the sorted list of every registered profile name — the
// shipped catalogue plus prior ITB_Triple_Register calls — as a JSON
// array of strings into json_out under the caller-allocated buffer
// convention.
//
//export ITB_Triple_Profiles
func ITB_Triple_Profiles(
	jsonOut unsafe.Pointer, jsonCap C.size_t, jsonLen *C.size_t,
) C.int {
	if jsonLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(jsonCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(jsonOut, jsonCap)
	n, st := capi.TripleProfiles(dst)
	*jsonLen = C.size_t(n)
	return C.int(st)
}

// Writes the shipped hashes.Registry primitive names in canonical
// order as a JSON array of strings into json_out under the caller-
// allocated buffer convention. Bindings that want to expose the
// registry set (for a UI dropdown or a compatibility probe) call this
// instead of iterating the retired ITB_HashName index surface.
//
// The returned list observes only the shipped hashes.Registry —
// runtime-registered custom primitives via hashes.Register live in a
// separate slice not part of this enumeration (matching bindings'
// triple-only surface where custom primitive plug is not exposed).
//
//export ITB_Triple_HashNames
func ITB_Triple_HashNames(
	jsonOut unsafe.Pointer, jsonCap C.size_t, jsonLen *C.size_t,
) C.int {
	if jsonLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(jsonCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(jsonOut, jsonCap)
	n, st := capi.TripleHashNames(dst)
	*jsonLen = C.size_t(n)
	return C.int(st)
}

// Writes the profile registered under name as its JSON encoding into
// json_out. Behaviourally identical to ITB_Triple_Lookup — the
// separate name signals intent (a caller who wants the profile JSON
// for their own storage or introspection use, distinct from a caller
// who is querying the catalogue). Same caller-allocated buffer
// convention.
//
//export ITB_Triple_ProfileJSON
func ITB_Triple_ProfileJSON(
	name *C.char,
	jsonOut unsafe.Pointer, jsonCap C.size_t, jsonLen *C.size_t,
) C.int {
	if name == nil || jsonLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(jsonCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(jsonOut, jsonCap)
	n, st := capi.TripleLookup(C.GoString(name), dst)
	*jsonLen = C.size_t(n)
	return C.int(st)
}

// Installs a user-defined Triple Pipeline profile from its JSON
// record alone. The profile's Name field carries the registered name;
// callers who prefer to supply the name explicitly use
// ITB_Triple_Register instead. An empty Name in the JSON returns
// ITB_ERR_BAD_INPUT. Duplicate name returns ITB_ERR_PROFILE_EXISTS;
// every other validation failure (name pattern, reserved prefix,
// field rules) returns ITB_ERR_BAD_INPUT with the diagnostic in
// ITB_LastError.
//
//export ITB_Triple_ProfileFromJSON
func ITB_Triple_ProfileFromJSON(profileJSON *C.char) C.int {
	if profileJSON == nil {
		return C.int(capi.StatusBadInput)
	}
	return C.int(capi.TripleProfileFromJSON(C.GoString(profileJSON)))
}

// Opens an incremental encrypt session over an already-open Pipeline
// handle. The returned session handle is distinct from the Pipeline
// handle and lives until ITB_Triple_StreamFree releases it. Multiple
// concurrent sessions per Pipeline are permitted; the Pipeline's
// cipher path is concurrent-safe by construction. Only Streaming
// profiles are accepted — a Single Message profile makes the session
// error out on the first write with ITB_ERR_BAD_INPUT.
//
//export ITB_Triple_EncryptStreamBegin
func ITB_Triple_EncryptStreamBegin(pipe C.uintptr_t, outStream *C.uintptr_t) C.int {
	if outStream == nil {
		return C.int(capi.StatusBadInput)
	}
	id, st := capi.TripleEncryptStreamBegin(capi.TripleHandleID(pipe))
	if st == capi.StatusOK {
		*outStream = C.uintptr_t(id)
	} else {
		*outStream = 0
	}
	return C.int(st)
}

// Receive-side counterpart of ITB_Triple_EncryptStreamBegin.
//
//export ITB_Triple_DecryptStreamBegin
func ITB_Triple_DecryptStreamBegin(pipe C.uintptr_t, outStream *C.uintptr_t) C.int {
	if outStream == nil {
		return C.int(capi.StatusBadInput)
	}
	id, st := capi.TripleDecryptStreamBegin(capi.TripleHandleID(pipe))
	if st == capi.StatusOK {
		*outStream = C.uintptr_t(id)
	} else {
		*outStream = 0
	}
	return C.int(st)
}

// Feeds src[0..src_len) into an open session. Blocks until the
// cipher chain accepts the bytes (bounded by chunk granularity — the
// session's output spool never blocks the producer, so forward
// progress is guaranteed while the session is live). src_len == 0
// is a no-op returning ITB_OK. Returns the mapped cipher-chain error
// if the session has already failed; the error is sticky.
//
//export ITB_Triple_StreamWrite
func ITB_Triple_StreamWrite(stream C.uintptr_t, src unsafe.Pointer, srcLen C.size_t) C.int {
	if !validateLen(srcLen) {
		return C.int(capi.StatusBadInput)
	}
	buf := goBytesView(src, srcLen)
	return C.int(capi.TripleStreamWrite(capi.TripleStreamID(stream), buf))
}

// Signals end-of-input to the cipher chain. The terminal chunk and
// any MAC / envelope finalisation flow into the session spool and
// become visible to subsequent ITB_Triple_StreamRead calls.
// Idempotent — a second End on the same session returns ITB_OK
// without re-closing the input pipe. After End, ITB_Triple_StreamWrite
// on the same session returns ITB_ERR_BAD_INPUT.
//
//export ITB_Triple_StreamEnd
func ITB_Triple_StreamEnd(stream C.uintptr_t) C.int {
	return C.int(capi.TripleStreamEnd(capi.TripleStreamID(stream)))
}

// Drains up to out_cap produced bytes into out. *out_len receives the
// byte count (0 when nothing is currently available). *finished
// receives 1 once the session has ended AND the spool is fully
// drained; 0 otherwise. Never returns ITB_ERR_BUFFER_TOO_SMALL —
// partial drains are the normal mode, remaining bytes stay spooled.
// After End, a Read with an empty spool blocks until the terminal
// bytes arrive or the session errors, so the final drain loop never
// busy-spins. The mapped cipher-chain error becomes sticky once the
// failure point is reached.
//
//export ITB_Triple_StreamRead
func ITB_Triple_StreamRead(
	stream C.uintptr_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t, finished *C.int,
) C.int {
	if outLen == nil || finished == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(outCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, fin, st := capi.TripleStreamRead(capi.TripleStreamID(stream), dst)
	*outLen = C.size_t(n)
	if fin {
		*finished = 1
	} else {
		*finished = 0
	}
	return C.int(st)
}

// Cancels (if still running) and releases the session. Safe to call
// from any state — mid-flight, mid-error, or after a clean drain.
// Wipes the session's output spool so key-adjacent plaintext or
// wire fragments do not linger on the heap. A second Free on the
// same id returns ITB_ERR_BAD_HANDLE, matching the other _Free
// entries on this ABI.
//
//export ITB_Triple_StreamFree
func ITB_Triple_StreamFree(stream C.uintptr_t) C.int {
	return C.int(capi.TripleStreamFree(capi.TripleStreamID(stream)))
}
