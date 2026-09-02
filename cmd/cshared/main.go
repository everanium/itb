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
// Buffer convention. All input/output buffers are caller-allocated.
// For functions that produce variable-size output (Encrypt, Decrypt,
// HashName, Version, LastError) the caller passes (out, out_cap,
// &out_len). On success out_len is set to the number of bytes
// written; on ITB_ERR_BUFFER_TOO_SMALL out_len is set to the
// required capacity so the caller can resize and retry.
//
// Handles. Seeds are exposed as opaque uintptr_t handles. Every
// ITB_NewSeed must be paired with exactly one ITB_FreeSeed. A handle
// from one seed cannot be mixed with seeds of a different native
// hash width inside one Encrypt / Decrypt call (returns
// ITB_ERR_SEED_WIDTH_MIX).
//
// Threading. The library is safe for concurrent use across OS
// threads after seed handles are constructed; concurrent
// ITB_NewSeed / ITB_FreeSeed calls are also safe (cgo.Handle is
// internally synchronised). Per-instance configuration is passed
// explicitly on each Encrypt / Decrypt call rather than through
// process-wide setters.
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
)

// Library version exposed via ITB_Version. Bumped per ABI-relevant
// release. The value is informational; binding code may key feature
// detection off it.
const libitbVersion = "0.3.4"

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

// Returns the number of PRF-grade hash primitives shipped.
//
//export ITB_HashCount
func ITB_HashCount() C.int { return C.int(capi.HashCount()) }

// Writes the canonical name of the i-th hash primitive (NUL-
// terminated) into out. Returns ITB_OK / ITB_ERR_BUFFER_TOO_SMALL /
// ITB_ERR_BAD_INPUT (i out of range).
//
//export ITB_HashName
func ITB_HashName(i C.int, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name := capi.HashName(int(i))
	if name == "" {
		return C.int(capi.StatusBadInput)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

// Returns the native intermediate-state width (128 / 256 / 512) of
// the i-th hash primitive, or 0 when i is out of range.
//
//export ITB_HashWidth
func ITB_HashWidth(i C.int) C.int { return C.int(capi.HashWidth(int(i))) }

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

// ─── Seed lifecycle ────────────────────────────────────────────────

// Builds a fresh seed with the named hash primitive and ITB key
// width in bits (512..2048, multiple of 64). The native hash width
// is determined by hashName via the registry; *outHandle receives
// an opaque uintptr_t paired with exactly one ITB_FreeSeed call.
//
//export ITB_NewSeed
func ITB_NewSeed(hashName *C.char, keyBits C.int, outHandle *C.uintptr_t) C.int {
	if hashName == nil || outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	id, st := capi.NewSeed(C.GoString(hashName), int(keyBits))
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Releases the seed handle. Calling this on a stale or zero handle
// returns ITB_ERR_BAD_HANDLE; the underlying *Seed becomes eligible
// for GC after a successful call.
//
//export ITB_FreeSeed
func ITB_FreeSeed(handle C.uintptr_t) C.int {
	return C.int(capi.FreeSeed(capi.HandleID(handle)))
}

// Reports the native hash width (128 / 256 / 512) of an existing
// seed handle, or 0 on a bad handle (status returned via *outStatus
// for the BAD_HANDLE distinction).
//
//export ITB_SeedWidth
func ITB_SeedWidth(handle C.uintptr_t, outStatus *C.int) C.int {
	w, st := capi.SeedWidth(capi.HandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(w)
}

// Writes the canonical hash name an existing seed handle was built
// with (NUL-terminated) into out.
//
//export ITB_SeedHashName
func ITB_SeedHashName(handle C.uintptr_t, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name, st := capi.SeedHashName(capi.HandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

// Builds a seed from caller-supplied uint64 components (deterministic
// counterpart of ITB_NewSeed which generates components from
// crypto/rand). hashKey is optional — pass NULL / 0 length for
// CSPRNG-generated key (random-key path) or a buffer of the
// primitive's native fixed-key size for the persistence-restore path.
//
// componentsLen must be in [8, MaxKeyBits/64] and a multiple of 8.
// hashKeyLen, if non-zero, must match the primitive's fixed-key size,
// hashKey is ignored for "siphash24".
//
//export ITB_NewSeedFromComponents
func ITB_NewSeedFromComponents(
	hashName *C.char,
	components *C.uint64_t,
	componentsLen C.int,
	hashKey *C.uint8_t,
	hashKeyLen C.int,
	outHandle *C.uintptr_t,
) C.int {
	if hashName == nil || outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	if componentsLen <= 0 || components == nil {
		return C.int(capi.StatusBadInput)
	}
	if hashKeyLen < 0 {
		return C.int(capi.StatusBadInput)
	}
	if hashKeyLen > 0 && hashKey == nil {
		return C.int(capi.StatusBadInput)
	}
	componentsSlice := unsafe.Slice((*uint64)(unsafe.Pointer(components)), int(componentsLen))
	var hashKeySlice []byte
	if hashKeyLen > 0 {
		hashKeySlice = C.GoBytes(unsafe.Pointer(hashKey), hashKeyLen)
	}
	id, st := capi.NewSeedFromComponents(C.GoString(hashName), componentsSlice, hashKeySlice)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Writes the seed's underlying hash fixed key into out. *outLen
// receives the actual key length on success (16 / 32 / 64 depending
// on the primitive; 0 for "siphash24" which has no internal fixed
// key — the seed components alone are sufficient for SipHash
// persistence). capBytes must be at least the primitive's fixed-key
// size or StatusBadInput is returned. Save the bytes alongside the
// seed components for cross-process restore via
// ITB_NewSeedFromComponents.
//
//export ITB_GetSeedHashKey
func ITB_GetSeedHashKey(
	handle C.uintptr_t,
	out *C.uint8_t,
	capBytes C.size_t,
	outLen *C.size_t,
) C.int {
	if !validateLen(capBytes) {
		return C.int(capi.StatusBadInput)
	}
	key, st := capi.SeedHashKey(capi.HandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	if outLen != nil {
		*outLen = C.size_t(len(key))
	}
	if len(key) == 0 {
		return C.int(capi.StatusOK)
	}
	if out == nil || capBytes < C.size_t(len(key)) {
		return C.int(capi.StatusBufferTooSmall)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capBytes))
	copy(dst, key)
	return C.int(capi.StatusOK)
}

// Writes the seed's uint64 components into out. *outLen receives the
// component count on success (8..32). capCount (counted in uint64
// elements, not bytes) must be at least the seed's component count
// or StatusBadInput is returned. Save the components alongside
// ITB_GetSeedHashKey for cross-process restore via
// ITB_NewSeedFromComponents.
//
//export ITB_GetSeedComponents
func ITB_GetSeedComponents(
	handle C.uintptr_t,
	out *C.uint64_t,
	capCount C.int,
	outLen *C.int,
) C.int {
	comps, st := capi.SeedComponents(capi.HandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	if outLen != nil {
		*outLen = C.int(len(comps))
	}
	if out == nil || capCount < C.int(len(comps)) {
		return C.int(capi.StatusBufferTooSmall)
	}
	dst := unsafe.Slice((*uint64)(unsafe.Pointer(out)), int(capCount))
	copy(dst, comps)
	return C.int(capi.StatusOK)
}

// ─── Encrypt / Decrypt ─────────────────────────────────────────────

// Triple Ouroboros encrypt: takes 8 seed handles (one shared
// noise + one lockSeed + three data + three start) and produces one
// ciphertext that interleaves three snake payloads. Wire format:
// [nonce || width(2) || height(2) || pixels]. All 8 handles
// must share the same native hash width (mixing 128/256/512 returns
// ITB_ERR_SEED_WIDTH_MIX). Caller-allocated output buffer; on
// success *outLen receives the bytes written, on
// ITB_ERR_BUFFER_TOO_SMALL *outLen receives the required size.
//
//export ITB_Encrypt3
func ITB_Encrypt3(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
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
	n, st := capi.Encrypt3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		pt, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Inverse of ITB_Encrypt3.
//
//export ITB_Decrypt3
func ITB_Decrypt3(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ctlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	ct := goBytesView(ciphertext, ctlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.Decrypt3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		ct, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// ─── MAC lifecycle and introspection ───────────────────────────────

// Returns the number of shipped MAC primitives (currently 3).
//
//export ITB_MACCount
func ITB_MACCount() C.int { return C.int(capi.MACCount()) }

// Writes the canonical name of the i-th MAC primitive (NUL-
// terminated) into out. Returns ITB_OK / ITB_ERR_BUFFER_TOO_SMALL /
// ITB_ERR_BAD_INPUT (i out of range).
//
//export ITB_MACName
func ITB_MACName(i C.int, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name := capi.MACRegistryName(int(i))
	if name == "" {
		return C.int(capi.StatusBadInput)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

// Returns the recommended key size in bytes for the i-th MAC
// primitive, or 0 when i is out of range.
//
//export ITB_MACKeySize
func ITB_MACKeySize(i C.int) C.int {
	return C.int(capi.MACRegistryKeySize(int(i)))
}

// Returns the tag size in bytes for the i-th MAC primitive, or 0
// when i is out of range.
//
//export ITB_MACTagSize
func ITB_MACTagSize(i C.int) C.int {
	return C.int(capi.MACRegistryTagSize(int(i)))
}

// Returns the minimum acceptable key length (bytes) for the i-th
// MAC primitive, or 0 when i is out of range.
//
//export ITB_MACMinKeyBytes
func ITB_MACMinKeyBytes(i C.int) C.int {
	return C.int(capi.MACRegistryMinKeyBytes(int(i)))
}

// Builds a fresh MAC handle keyed by key[0..keyLen) for the named
// primitive. *outHandle receives an opaque uintptr_t that must be
// paired with exactly one ITB_FreeMAC call.
//
//export ITB_NewMAC
func ITB_NewMAC(macName *C.char, key unsafe.Pointer, keyLen C.size_t, outHandle *C.uintptr_t) C.int {
	if macName == nil || outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(keyLen) {
		return C.int(capi.StatusBadInput)
	}
	keyBytes := goBytesView(key, keyLen)
	id, st := capi.NewMAC(C.GoString(macName), keyBytes)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Releases the MAC handle. Subsequent uses return ITB_ERR_BAD_MAC.
//
//export ITB_FreeMAC
func ITB_FreeMAC(handle C.uintptr_t) C.int {
	return C.int(capi.FreeMAC(capi.MACHandleID(handle)))
}

// ─── Authenticated Encrypt / Decrypt ───────────────────────────────

// Authenticated Triple Ouroboros encrypt: 8 seed handles plus a
// MAC handle.
//
//export ITB_EncryptAuth3
func ITB_EncryptAuth3(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	macHandle C.uintptr_t,
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
	n, st := capi.EncryptAuth3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), pt, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Authenticated Triple Ouroboros decrypt.
//
//export ITB_DecryptAuth3
func ITB_DecryptAuth3(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	macHandle C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ctlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	ct := goBytesView(ciphertext, ctlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.DecryptAuth3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), ct, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// ─── Streaming helpers ─────────────────────────────────────────────

// Reads a chunk header (the fixed-size
// [main_nonce(N) || interlock_nonce(N) || width(2) || height(2)]
// prefix where N is nonce_bytes — one of 16 / 32 / 64; the main and
// interlock nonces are symmetric in width) at the start of the
// supplied buffer and writes the total chunk length on the wire to
// *outChunkLen. Used by streaming consumers to walk a concatenated
// chunk stream one chunk at a time without buffering the whole
// stream in memory: read (2*nonce_bytes+4) bytes → call
// ITB_ParseChunkLen → read the remaining bytes → hand the full chunk
// to ITB_Decrypt3 / ITB_DecryptAuth3 / etc., repeat.
//
// Breaking ABI change: this function now takes a nonce_bytes
// parameter. Previously the value came from the process-global
// SetNonceBits state, but the setters have been retired in favour of
// per-instance Config; the FFI surface exposes the parameter
// explicitly so bindings can pass the value their Pipeline / Config
// selected.
//
// Returns ITB_OK on success, ITB_ERR_BAD_INPUT when nonce_bytes is
// not one of {16, 32, 64}, the buffer is shorter than the header,
// the dimensions are zero, the width × height multiplication
// overflows, or the announced pixel count exceeds the container
// pixel cap. The function does no decryption work — it only parses
// the wire-format header.
//
//export ITB_ParseChunkLen
func ITB_ParseChunkLen(header unsafe.Pointer, headerLen C.size_t, nonceBytes C.uint32_t, outChunkLen *C.size_t) C.int {
	if outChunkLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(headerLen) {
		return C.int(capi.StatusBadInput)
	}
	hdr := goBytesView(header, headerLen)
	n, st := capi.ParseChunkLen(hdr, int(nonceBytes))
	if st == capi.StatusOK {
		*outChunkLen = C.size_t(n)
	} else {
		*outChunkLen = 0
	}
	return C.int(st)
}

// ─── Read-only build constants ─────────────────────────────────────

//export ITB_MaxKeyBits
func ITB_MaxKeyBits() C.int { return C.int(capi.MaxKeyBits()) }

//export ITB_Channels
func ITB_Channels() C.int { return C.int(capi.Channels()) }

// Returns the ciphertext-chunk header size in bytes for the given
// nonce_bytes (main_nonce + interlock_nonce + width(2) + height(2),
// i.e. 2*nonce_bytes + 4). Header size = 36 for 16-byte nonce, 68
// for 32-byte, 132 for 64-byte. Streaming consumers must read this
// many bytes from the wire before calling ITB_ParseChunkLen on each
// fresh chunk.
//
// Breaking ABI change: the parameter is now explicit rather than
// implied by a process-global setter (the setters have been retired
// in favour of per-instance Config). Bindings pass the value their
// Pipeline / Config selected. Returns ITB_ERR_BAD_INPUT when
// nonce_bytes is not one of {16, 32, 64}.
//
// ITB_DefaultNonceBits exposes the compile-in default in bits (128);
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

// ─── Native Blob — low-level state persistence ────────────────────
//
// itb.Blob{128,256,512} pack the low-level encryptor material —
// per-seed hash key + Components + optional dedicated lockSeed +
// optional MAC material — plus the captured process-wide
// configuration into one self-describing JSON blob. Native (mix-
// and-match-primitives) surface: no primitive name is recorded
// because each seed slot can carry a different primitive on the
// low-level path. Callers wire the matching factory onto each
// restored seed after Import.
//
// The C ABI exposes the blob as an opaque BlobHandleID built via
// ITB_Blob{128,256,512}_New, populated through slot-keyed setters
// (ITB_Blob_SetKey / ITB_Blob_SetComponents) and optional MAC
// setters, then serialised with ITB_Blob_Export / ITB_Blob_Export3.
// The receiving side constructs a same-width handle, drives
// ITB_Blob_Import / ITB_Blob_Import3, then reads each slot back via
// the matching getter to feed its hash factory.
//
// Slot identifiers (ITB_BLOB_SLOT_*):
//   N=0 (shared), D=1 / S=2 (Single only), L=3 (optional lockSeed,
//   any mode), D1..D3=4..6 + S1..S3=7..9 (Triple only).
//
// Export option bitmask (ITB_BLOB_OPT_*):
//   LOCKSEED=0x1 emits the L slot; MAC=0x2 emits MAC key + name.

// Constructs a fresh empty Blob128 handle. Zero / unset slots are
// emitted as zero-length / zero-array fields by Export — the caller
// populates the slots that apply to the active mode (Single or
// Triple) before serialising.
//
//export ITB_Blob128_New
func ITB_Blob128_New(outHandle *C.uintptr_t) C.int {
	if outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	id, st := capi.NewBlob128()
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Constructs a fresh empty Blob256 handle. See ITB_Blob128_New.
//
//export ITB_Blob256_New
func ITB_Blob256_New(outHandle *C.uintptr_t) C.int {
	if outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	id, st := capi.NewBlob256()
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Constructs a fresh empty Blob512 handle. See ITB_Blob128_New.
//
//export ITB_Blob512_New
func ITB_Blob512_New(outHandle *C.uintptr_t) C.int {
	if outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	id, st := capi.NewBlob512()
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Releases a blob handle. Safe to call on a zero handle (returns
// ITB_ERR_BAD_HANDLE); idempotent across all three widths since
// the underlying type is discriminated on the Go side.
//
//export ITB_Blob_Free
func ITB_Blob_Free(handle C.uintptr_t) C.int {
	return C.int(capi.FreeBlob(capi.BlobHandleID(handle)))
}

// Returns the native hash width of an existing blob handle (128 /
// 256 / 512). Status returned via *outStatus.
//
//export ITB_Blob_Width
func ITB_Blob_Width(handle C.uintptr_t, outStatus *C.int) C.int {
	w, st := capi.BlobWidth(capi.BlobHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(w)
}

// Returns the blob's mode field (0 = unset, 1 = Single, 3 = Triple).
// Updated by Import / Import3; freshly constructed handles report 0
// until Export / Export3 / Import / Import3 has run.
//
//export ITB_Blob_Mode
func ITB_Blob_Mode(handle C.uintptr_t, outStatus *C.int) C.int {
	m, st := capi.BlobMode(capi.BlobHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(m)
}

// Stores the hash key bytes for the requested slot on the handle.
// 256-bit width requires exactly 32 bytes; 512-bit width requires
// exactly 64 bytes. 128-bit width accepts variable lengths (empty
// for siphash24, 16 bytes for aescmac); the downstream factory
// validates the per-primitive length on Import-side wiring.
//
//export ITB_Blob_SetKey
func ITB_Blob_SetKey(
	handle C.uintptr_t, slot C.int,
	key unsafe.Pointer, keyLen C.size_t,
) C.int {
	if !validateLen(keyLen) {
		return C.int(capi.StatusBadInput)
	}
	k := goBytesView(key, keyLen)
	return C.int(capi.BlobSetKey(capi.BlobHandleID(handle), int(slot), k))
}

// Copies the hash key bytes from the requested slot into the
// caller-allocated out buffer. Probe-then-retry: pass out=NULL /
// outCap=0 to discover the required size in *outLen.
//
//export ITB_Blob_GetKey
func ITB_Blob_GetKey(
	handle C.uintptr_t, slot C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(outCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.BlobGetKey(capi.BlobHandleID(handle), int(slot), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Stores the seed components (uint64 array) for the requested slot
// on the handle. Component count is validated lazily at Export /
// Import time — same 8..MaxKeyBits/64 multiple-of-8 invariants as
// ITB_NewSeedFromComponents.
//
//export ITB_Blob_SetComponents
func ITB_Blob_SetComponents(
	handle C.uintptr_t, slot C.int,
	comps *C.uint64_t, count C.size_t,
) C.int {
	if count > maxSliceLen {
		return C.int(capi.StatusBadInput)
	}
	// Reject the inconsistent (comps==NULL && count>0) shape — a
	// hostile or buggy caller passing a non-zero count without a
	// matching pointer would otherwise be silently treated as the
	// (NULL, 0) probe / clear form, dropping the components for
	// the slot without diagnostic.
	if comps == nil && count > 0 {
		return C.int(capi.StatusBadInput)
	}
	var compsView []uint64
	if comps != nil && count > 0 {
		compsView = unsafe.Slice((*uint64)(unsafe.Pointer(comps)), int(count))
	}
	return C.int(capi.BlobSetComponents(
		capi.BlobHandleID(handle), int(slot), compsView,
	))
}

// Copies the seed components from the requested slot into the
// caller-allocated uint64 array. Probe-then-retry: pass out=NULL /
// outCap=0 to discover the required count (in uint64 elements,
// not bytes) in *outCount.
//
//export ITB_Blob_GetComponents
func ITB_Blob_GetComponents(
	handle C.uintptr_t, slot C.int,
	out *C.uint64_t, outCap C.size_t, outCount *C.size_t,
) C.int {
	if outCount == nil {
		return C.int(capi.StatusBadInput)
	}
	if outCap > maxSliceLen {
		return C.int(capi.StatusBadInput)
	}
	var dst []uint64
	if out != nil && outCap > 0 {
		dst = unsafe.Slice((*uint64)(unsafe.Pointer(out)), int(outCap))
	}
	n, st := capi.BlobGetComponents(capi.BlobHandleID(handle), int(slot), dst)
	*outCount = C.size_t(n)
	return C.int(st)
}

// Stores the optional MAC key bytes on the handle. Pass NULL / 0 to
// clear a previously-set key. Export / Export3 only emits the MAC
// section when both ITB_BLOB_OPT_MAC is set in the bitmask AND the
// MAC key on the handle is non-empty.
//
//export ITB_Blob_SetMACKey
func ITB_Blob_SetMACKey(
	handle C.uintptr_t,
	key unsafe.Pointer, keyLen C.size_t,
) C.int {
	if !validateLen(keyLen) {
		return C.int(capi.StatusBadInput)
	}
	k := goBytesView(key, keyLen)
	return C.int(capi.BlobSetMACKey(capi.BlobHandleID(handle), k))
}

// Copies the MAC key from the handle into the caller-allocated out
// buffer. Probe-then-retry standard convention.
//
//export ITB_Blob_GetMACKey
func ITB_Blob_GetMACKey(
	handle C.uintptr_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(outCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.BlobGetMACKey(capi.BlobHandleID(handle), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Stores the optional MAC name on the handle (e.g. "kmac256",
// "hmac-blake3"). Pass NULL / 0 to clear a previously-set name.
//
//export ITB_Blob_SetMACName
func ITB_Blob_SetMACName(
	handle C.uintptr_t,
	name *C.char, nameLen C.size_t,
) C.int {
	if !validateLen(nameLen) {
		return C.int(capi.StatusBadInput)
	}
	var s string
	if name != nil && nameLen > 0 {
		s = C.GoStringN(name, C.int(nameLen))
	}
	return C.int(capi.BlobSetMACName(capi.BlobHandleID(handle), s))
}

// Writes the MAC name from the handle into the caller-allocated
// out buffer (NUL-terminated). Probe-then-retry standard convention.
//
//export ITB_Blob_GetMACName
func ITB_Blob_GetMACName(
	handle C.uintptr_t,
	out *C.char, outCap C.size_t, outLen *C.size_t,
) C.int {
	name, st := capi.BlobGetMACName(capi.BlobHandleID(handle))
	if st != capi.StatusOK {
		if outLen != nil {
			*outLen = 0
		}
		return C.int(st)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), outCap, outLen))
}

// ─── Streaming AEAD Encrypt / Decrypt ──────────────────────────────

// streamIDFromC copies a 32-byte Streaming AEAD anchor out of a C
// pointer into a fixed-size Go array. Returns false if the pointer
// is NULL.
func streamIDFromC(p *C.uint8_t) (sid [32]byte, ok bool) {
	if p == nil {
		return sid, false
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(p)), 32)
	copy(sid[:], src)
	return sid, true
}

// Streaming AEAD Triple Ouroboros encrypt for one chunk: 7 seed
// handles plus a MAC handle plus the streaming-binding components.
// All 7 seeds must share native width 128.
//
//export ITB_EncryptStreamAuthenticated3x128
func ITB_EncryptStreamAuthenticated3x128(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	macHandle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	streamID *C.uint8_t,
	cumulativePixelOffset C.uint64_t,
	finalFlag C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ptlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	sid, ok := streamIDFromC(streamID)
	if !ok {
		return C.int(capi.StatusBadInput)
	}
	pt := goBytesView(plaintext, ptlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.EncryptStreamAuth3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD Triple Ouroboros encrypt for one chunk (width-256
// seeds). See ITB_EncryptStreamAuthenticated3x128 for the parameter
// contract.
//
//export ITB_EncryptStreamAuthenticated3x256
func ITB_EncryptStreamAuthenticated3x256(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	macHandle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	streamID *C.uint8_t,
	cumulativePixelOffset C.uint64_t,
	finalFlag C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ptlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	sid, ok := streamIDFromC(streamID)
	if !ok {
		return C.int(capi.StatusBadInput)
	}
	pt := goBytesView(plaintext, ptlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.EncryptStreamAuth3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD Triple Ouroboros encrypt for one chunk (width-512
// seeds). See ITB_EncryptStreamAuthenticated3x128 for the parameter
// contract.
//
//export ITB_EncryptStreamAuthenticated3x512
func ITB_EncryptStreamAuthenticated3x512(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	macHandle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	streamID *C.uint8_t,
	cumulativePixelOffset C.uint64_t,
	finalFlag C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ptlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	sid, ok := streamIDFromC(streamID)
	if !ok {
		return C.int(capi.StatusBadInput)
	}
	pt := goBytesView(plaintext, ptlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.EncryptStreamAuth3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD Triple Ouroboros decrypt for one chunk. finalFlagOut,
// when non-NULL, receives the recovered flag byte interpreted as
// {0 = non-terminal, 1 = terminating}.
//
//export ITB_DecryptStreamAuthenticated3x128
func ITB_DecryptStreamAuthenticated3x128(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	macHandle C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	streamID *C.uint8_t,
	cumulativePixelOffset C.uint64_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
	finalFlagOut *C.int,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ctlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	sid, ok := streamIDFromC(streamID)
	if !ok {
		return C.int(capi.StatusBadInput)
	}
	ct := goBytesView(ciphertext, ctlen)
	dst := goBytesViewMut(out, outCap)
	n, ff, st := capi.DecryptStreamAuth3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), ct, dst,
		sid, uint64(cumulativePixelOffset),
	)
	*outLen = C.size_t(n)
	if finalFlagOut != nil {
		if ff {
			*finalFlagOut = 1
		} else {
			*finalFlagOut = 0
		}
	}
	return C.int(st)
}

// Streaming AEAD Triple Ouroboros decrypt for one chunk (width-256
// seeds). See ITB_DecryptStreamAuthenticated3x128 for the parameter
// contract.
//
//export ITB_DecryptStreamAuthenticated3x256
func ITB_DecryptStreamAuthenticated3x256(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	macHandle C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	streamID *C.uint8_t,
	cumulativePixelOffset C.uint64_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
	finalFlagOut *C.int,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ctlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	sid, ok := streamIDFromC(streamID)
	if !ok {
		return C.int(capi.StatusBadInput)
	}
	ct := goBytesView(ciphertext, ctlen)
	dst := goBytesViewMut(out, outCap)
	n, ff, st := capi.DecryptStreamAuth3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), ct, dst,
		sid, uint64(cumulativePixelOffset),
	)
	*outLen = C.size_t(n)
	if finalFlagOut != nil {
		if ff {
			*finalFlagOut = 1
		} else {
			*finalFlagOut = 0
		}
	}
	return C.int(st)
}

// Streaming AEAD Triple Ouroboros decrypt for one chunk (width-512
// seeds). See ITB_DecryptStreamAuthenticated3x128 for the parameter
// contract.
//
//export ITB_DecryptStreamAuthenticated3x512
func ITB_DecryptStreamAuthenticated3x512(
	noiseHandle, lockHandle C.uintptr_t,
	dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	macHandle C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	streamID *C.uint8_t,
	cumulativePixelOffset C.uint64_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
	finalFlagOut *C.int,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(ctlen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	sid, ok := streamIDFromC(streamID)
	if !ok {
		return C.int(capi.StatusBadInput)
	}
	ct := goBytesView(ciphertext, ctlen)
	dst := goBytesViewMut(out, outCap)
	n, ff, st := capi.DecryptStreamAuth3(
		capi.HandleID(noiseHandle), capi.HandleID(lockHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), ct, dst,
		sid, uint64(cumulativePixelOffset),
	)
	*outLen = C.size_t(n)
	if finalFlagOut != nil {
		if ff {
			*finalFlagOut = 1
		} else {
			*finalFlagOut = 0
		}
	}
	return C.int(st)
}

// ─── Format-deniability wrapper (outer CTR cipher) ─────────────────
//
// The wrapper surface seals an ITB ciphertext inside one of
// PRF-grade outer keystream ciphers so the wire bytes carry no header /
// magic the receiver could match against. Every entry point dispatches off
// a `cipher_name` string naming any PRF-grade ITB registry primitive,
// mirroring the MAC-factory pattern: one unified ABI per operation rather
// than one per cipher. The Go-side implementation lives in
// github.com/everanium/itb/wrapper; the helpers in capi/wrapper.go
// and capi/wrapper_handles.go bridge the C ABI to that package
// without copying the body bytes.
//
// Memcpy avoidance. Every body buffer crosses as a (ptr, len)
// pair turned into a Go []byte alias via goBytesView /
// goBytesViewMut — the keystream XOR mutates the C-side buffer in
// place. Single Message Wrap allocates the per-stream nonce inside
// the caller-supplied output buffer's prefix; WrapInPlace lets
// the caller own both the plaintext buffer (mutated in place)
// and the nonce buffer.

// Reports the byte length of the keystream-cipher key for the named
// outer cipher (16 / 32 / 64). Returns ITB_ERR_BAD_INPUT for an
// unknown cipher name.
//
//export ITB_WrapperKeySize
func ITB_WrapperKeySize(cipherName *C.char, outSize *C.size_t) C.int {
	if cipherName == nil || outSize == nil {
		return C.int(capi.StatusBadInput)
	}
	n, st := capi.WrapperKeySize(C.GoString(cipherName))
	if st == capi.StatusOK {
		*outSize = C.size_t(n)
	} else {
		*outSize = 0
	}
	return C.int(st)
}

// Reports the on-wire nonce length the named outer cipher emits
// per stream (12 for chacha20, 16 for every other cipher).
// Returns ITB_ERR_BAD_INPUT for an unknown cipher name.
//
//export ITB_WrapperNonceSize
func ITB_WrapperNonceSize(cipherName *C.char, outSize *C.size_t) C.int {
	if cipherName == nil || outSize == nil {
		return C.int(capi.StatusBadInput)
	}
	n, st := capi.WrapperNonceSize(C.GoString(cipherName))
	if st == capi.StatusOK {
		*outSize = C.size_t(n)
	} else {
		*outSize = 0
	}
	return C.int(st)
}

// Deterministically derives the outer cipher key for the named cipher
// from a caller-supplied master secret (e.g. an ML-KEM shared secret),
// writing it into out[0..KeySize(name)). The result is a deterministic
// function of (name, master), so both endpoints derive the same key
// from a shared master. Same caller-allocated-buffer convention as
// ITB_Wrap: on ITB_ERR_BUFFER_TOO_SMALL *out_len receives the required
// size (KeySize(name)). master_len must be at least 32 (the wrapper's
// uniform security floor); a shorter master returns ITB_ERR_BAD_INPUT.
//
//export ITB_WrapperDeriveKey
func ITB_WrapperDeriveKey(
	cipherName *C.char,
	master unsafe.Pointer, masterLen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if cipherName == nil || outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(masterLen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	masterBytes := goBytesView(master, masterLen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.WrapperDeriveKey(C.GoString(cipherName), masterBytes, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Seals one ITB ciphertext blob under the named outer cipher.
// Wire form is `nonce || keystream-XOR(blob)` where the nonce
// is freshly drawn from crypto/rand per call. The required out
// capacity is NonceSize(name) + blob_len. Same caller-allocated-
// buffer convention as ITB_Encrypt: on ITB_ERR_BUFFER_TOO_SMALL
// *out_len receives the required size.
//
//export ITB_Wrap
func ITB_Wrap(
	cipherName *C.char,
	key unsafe.Pointer, keyLen C.size_t,
	blob unsafe.Pointer, blobLen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if cipherName == nil || outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(keyLen, blobLen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	keyBytes := goBytesView(key, keyLen)
	blobBytes := goBytesView(blob, blobLen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.Wrap(C.GoString(cipherName), keyBytes, blobBytes, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Reverses ITB_Wrap. Reads the leading NonceSize(name) bytes of
// wire as the nonce, XOR-decrypts the remainder under (key,
// nonce) into out. The recovered payload size is wire_len -
// NonceSize(name); on ITB_ERR_BUFFER_TOO_SMALL *out_len receives
// the required size.
//
//export ITB_Unwrap
func ITB_Unwrap(
	cipherName *C.char,
	key unsafe.Pointer, keyLen C.size_t,
	wire unsafe.Pointer, wireLen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if cipherName == nil || outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(keyLen, wireLen, outCap) {
		return C.int(capi.StatusBadInput)
	}
	keyBytes := goBytesView(key, keyLen)
	wireBytes := goBytesView(wire, wireLen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.Unwrap(C.GoString(cipherName), keyBytes, wireBytes, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// XORs blob in place under a freshly-drawn outer keystream and
// writes the per-stream nonce into out_nonce[0..NonceSize(name)).
// blob is MUTATED. The caller is expected to emit nonce ||
// blob to the wire. nonce_cap must be at least NonceSize(name);
// on ITB_ERR_BUFFER_TOO_SMALL ITB_WrapperNonceSize reports the
// required nonce length.
//
//export ITB_WrapInPlace
func ITB_WrapInPlace(
	cipherName *C.char,
	key unsafe.Pointer, keyLen C.size_t,
	blob unsafe.Pointer, blobLen C.size_t,
	outNonce unsafe.Pointer, nonceCap C.size_t,
) C.int {
	if cipherName == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(keyLen, blobLen, nonceCap) {
		return C.int(capi.StatusBadInput)
	}
	keyBytes := goBytesView(key, keyLen)
	// Allow zero-length blob (degenerate case): blobBytes nil is
	// fine — the keystream XOR over an empty slice is a no-op.
	blobBytes := goBytesView(blob, blobLen)
	if blobBytes == nil && blobLen != 0 {
		return C.int(capi.StatusBadInput)
	}
	nonceBuf := goBytesViewMut(outNonce, nonceCap)
	_, st := capi.WrapInPlace(C.GoString(cipherName), keyBytes, blobBytes, nonceBuf)
	return C.int(st)
}

// Strips the leading NonceSize(name) bytes from wire and XORs
// the remainder in place. wire is MUTATED. The decrypted body
// occupies wire[NonceSize(name):]; the nonce prefix is left
// unchanged. wire_len must be >= NonceSize(name) or
// ITB_ERR_BAD_INPUT is returned.
//
//export ITB_UnwrapInPlace
func ITB_UnwrapInPlace(
	cipherName *C.char,
	key unsafe.Pointer, keyLen C.size_t,
	wire unsafe.Pointer, wireLen C.size_t,
) C.int {
	if cipherName == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(keyLen, wireLen) {
		return C.int(capi.StatusBadInput)
	}
	keyBytes := goBytesView(key, keyLen)
	wireBytes := goBytesViewMut(wire, wireLen)
	if wireBytes == nil {
		return C.int(capi.StatusBadInput)
	}
	_, st := capi.UnwrapInPlace(C.GoString(cipherName), keyBytes, wireBytes)
	return C.int(st)
}

// Allocates a streaming wrap-encrypt handle, draws a fresh nonce
// from crypto/rand, and writes that nonce into out_nonce. The
// caller must emit nonce_cap = NonceSize(name) bytes once at
// stream start (typically as the wire prefix), then drive
// subsequent body bytes through ITB_WrapStreamWriter_Update on
// the returned handle. Pair with exactly one
// ITB_WrapStreamWriter_Free call.
//
//export ITB_WrapStreamWriter_Init
func ITB_WrapStreamWriter_Init(
	cipherName *C.char,
	key unsafe.Pointer, keyLen C.size_t,
	outNonce unsafe.Pointer, nonceCap C.size_t,
	outHandle *C.uintptr_t,
) C.int {
	if cipherName == nil || outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(keyLen, nonceCap) {
		return C.int(capi.StatusBadInput)
	}
	keyBytes := goBytesView(key, keyLen)
	nonceBuf := goBytesViewMut(outNonce, nonceCap)
	id, _, st := capi.NewWrapStreamWriter(C.GoString(cipherName), keyBytes, nonceBuf)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// XORs src[0..src_len) into dst[0..src_len) under the handle's
// keystream, advancing the cipher counter. dst MAY equal src
// (in-place mutation); dst_cap must be >= src_len.
//
//export ITB_WrapStreamWriter_Update
func ITB_WrapStreamWriter_Update(
	handle C.uintptr_t,
	src unsafe.Pointer, srcLen C.size_t,
	dst unsafe.Pointer, dstCap C.size_t,
) C.int {
	if !validateLen(srcLen, dstCap) {
		return C.int(capi.StatusBadInput)
	}
	srcBytes := goBytesView(src, srcLen)
	dstBytes := goBytesViewMut(dst, dstCap)
	if srcLen != 0 && (srcBytes == nil || dstBytes == nil) {
		return C.int(capi.StatusBadInput)
	}
	_, st := capi.WrapStreamUpdate(capi.WrapStreamHandleID(handle), srcBytes, dstBytes)
	return C.int(st)
}

// Releases the wrap-encrypt streaming handle. Subsequent uses
// return ITB_ERR_BAD_HANDLE.
//
//export ITB_WrapStreamWriter_Free
func ITB_WrapStreamWriter_Free(handle C.uintptr_t) C.int {
	return C.int(capi.FreeWrapStream(capi.WrapStreamHandleID(handle)))
}

// Allocates a streaming wrap-decrypt handle keyed by the leading
// NonceSize(name) bytes of the wire (passed as wire_nonce). The
// returned handle XORs subsequent body bytes back to plaintext
// under the keystream advancing from counter zero. Pair with
// exactly one ITB_UnwrapStreamReader_Free call.
//
//export ITB_UnwrapStreamReader_Init
func ITB_UnwrapStreamReader_Init(
	cipherName *C.char,
	key unsafe.Pointer, keyLen C.size_t,
	wireNonce unsafe.Pointer, nonceLen C.size_t,
	outHandle *C.uintptr_t,
) C.int {
	if cipherName == nil || outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(keyLen, nonceLen) {
		return C.int(capi.StatusBadInput)
	}
	keyBytes := goBytesView(key, keyLen)
	nonceBytes := goBytesView(wireNonce, nonceLen)
	id, st := capi.NewUnwrapStreamReader(C.GoString(cipherName), keyBytes, nonceBytes)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// XORs src[0..src_len) into dst[0..src_len) under the handle's
// keystream. Mirror of ITB_WrapStreamWriter_Update with the same
// in-place semantics.
//
//export ITB_UnwrapStreamReader_Update
func ITB_UnwrapStreamReader_Update(
	handle C.uintptr_t,
	src unsafe.Pointer, srcLen C.size_t,
	dst unsafe.Pointer, dstCap C.size_t,
) C.int {
	if !validateLen(srcLen, dstCap) {
		return C.int(capi.StatusBadInput)
	}
	srcBytes := goBytesView(src, srcLen)
	dstBytes := goBytesViewMut(dst, dstCap)
	if srcLen != 0 && (srcBytes == nil || dstBytes == nil) {
		return C.int(capi.StatusBadInput)
	}
	_, st := capi.WrapStreamUpdate(capi.WrapStreamHandleID(handle), srcBytes, dstBytes)
	return C.int(st)
}

// Releases the wrap-decrypt streaming handle.
//
//export ITB_UnwrapStreamReader_Free
func ITB_UnwrapStreamReader_Free(handle C.uintptr_t) C.int {
	return C.int(capi.FreeWrapStream(capi.WrapStreamHandleID(handle)))
}

// ─── Triple Pipeline (itb/triple facade) ───────────────────────────
//
// The ITB_Triple_* surface wraps the github.com/everanium/itb/triple
// sub-package — one Pipeline handle replaces the 8-seed +
// parallax + wrapper + MAC ceremony of the low-level path. The
// Pipeline is opened against one of the shipped profile names (see
// triple/profile.go: ProfileStreamingAEADTripleMACV1 /
// ProfileStreamingNoAEADTripleV1 / ProfileSingleMsgTripleMACV1 /
// ProfileSingleMsgTripleNoMACV1 / ProfileBlobTripleMACV1); a
// URL-query-encoded opts string carries any per-Pipeline overrides
// (see capi.parseTripleOpts for the accepted keys).
//
// All cipher entry points share the same caller-allocated
// out / out_cap / *out_len buffer convention as the low-level
// ITB_Encrypt / ITB_Decrypt path; the two-phase probe (NULL / 0 →
// resize → retry) works identically.
//
// State persistence rides on the blob bytes ITB_Triple_Init returns.
// The receiver calls ITB_Triple_Open on the same profile with the
// blob and optional master overrides, then encrypts / decrypts
// against the reconstructed Pipeline. ITB_Triple_Rekey rotates the
// parallax + wrapper masters without disturbing the underlying seed
// material.

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

// Reconstructs a Pipeline handle from a blob produced by
// ITB_Triple_Init or ITB_Triple_Rekey. masters_count == 0 uses the
// blob-embedded masters; masters_count == 2 overrides them (with
// perm_master at index 0, wrap_master at index 1). Any other arity
// returns ITB_ERR_BAD_INPUT.
//
//export ITB_Triple_Open
func ITB_Triple_Open(
	profile *C.char,
	blob unsafe.Pointer, blobLen C.size_t,
	opts *C.char,
	permMaster unsafe.Pointer, permMasterLen C.size_t,
	wrapMaster unsafe.Pointer, wrapMasterLen C.size_t,
	mastersCount C.size_t,
	outHandle *C.uintptr_t,
) C.int {
	if profile == nil || outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(blobLen, permMasterLen, wrapMasterLen) {
		return C.int(capi.StatusBadInput)
	}
	if mastersCount != 0 && mastersCount != 2 {
		return C.int(capi.StatusBadInput)
	}
	var optsStr string
	if opts != nil {
		optsStr = C.GoString(opts)
	}
	blobBytes := goBytesView(blob, blobLen)
	var masters [][]byte
	if mastersCount == 2 {
		pm := goBytesView(permMaster, permMasterLen)
		wm := goBytesView(wrapMaster, wrapMasterLen)
		// A zero-length master under mastersCount==2 is inadmissible
		// here — the caller's mastersCount signals both slots are
		// supplied.
		if pm == nil || wm == nil {
			return C.int(capi.StatusBadInput)
		}
		masters = [][]byte{pm, wm}
	}
	id, st := capi.TripleOpen(C.GoString(profile), blobBytes, optsStr, masters...)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Rotates the Pipeline's parallax + wrapper masters and writes the
// fresh blob bytes into blob_out. The receiver applies the new blob
// via ITB_Triple_Open to stay in sync. Rekey mutates Pipeline state;
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
// Same caller-allocated-buffer convention as the low-level
// ITB_EncryptStream* family: on ITB_ERR_BUFFER_TOO_SMALL *out_len
// receives the required capacity.
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
// subsequent ITB_Triple_Init / ITB_Triple_Open calls resolve name to
// the newly-registered record. opts is a URL-query-encoded profile-
// shape string (see capi.parseTripleRegisterOpts for the accepted
// keys). Returns ITB_ERR_PROFILE_EXISTS when the name is already in
// the catalogue, ITB_ERR_BAD_INPUT on any validation failure, and
// ITB_OK on success.
//
// Name rules mirror triple.RegisterProfile: must match
// `^[a-z][a-z0-9-]{2,63}$` and must not start with one of the
// reserved shipped-catalogue prefixes (streaming- / singlemsg- /
// blob-).
//
//export ITB_Triple_RegisterProfile
func ITB_Triple_RegisterProfile(name *C.char, opts *C.char) C.int {
	if name == nil {
		return C.int(capi.StatusBadInput)
	}
	var optsStr string
	if opts != nil {
		optsStr = C.GoString(opts)
	}
	return C.int(capi.TripleRegisterProfile(C.GoString(name), optsStr))
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
