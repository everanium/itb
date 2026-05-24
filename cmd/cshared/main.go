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
// internally synchronised). Process-wide config setters
// (ITB_SetBitSoup etc.) take effect for all subsequent
// Encrypt / Decrypt calls and are atomic.
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
const libitbVersion = "0.1.2"

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

// Returns the number of PRF-grade hash primitives shipped (currently 9).
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
// hashKeyLen, if non-zero, must match the primitive's fixed-key size:
// 16 (aescmac), 32 (areion256/blake2{s,b256}/blake3/chacha20),
// 64 (areion512/blake2b512). hashKey is ignored for "siphash24".
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

// Encrypts plaintext[0..ptlen) under (noiseHandle, dataHandle,
// startHandle) into the caller-allocated buffer out[0..*outLen).
// On success *outLen receives the bytes written. On
// ITB_ERR_BUFFER_TOO_SMALL *outLen receives the required size.
//
//export ITB_Encrypt
func ITB_Encrypt(
	noiseHandle, dataHandle, startHandle C.uintptr_t,
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
	n, st := capi.Encrypt(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
		pt, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Decrypts ciphertext[0..ctlen) under (noiseHandle, dataHandle,
// startHandle) into the caller-allocated buffer out[0..*outLen).
// Same buffer convention as ITB_Encrypt.
//
//export ITB_Decrypt
func ITB_Decrypt(
	noiseHandle, dataHandle, startHandle C.uintptr_t,
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
	n, st := capi.Decrypt(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
		ct, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Triple Ouroboros encrypt: takes seven seed handles (one shared
// noise + three data + three start) and produces one ciphertext
// that interleaves three snake payloads. Wire format identical to
// ITB_Encrypt — the difference is internal split / interleave under
// the same nonce + dimensions header.
//
// All seven handles must share the same native hash width
// (mixing 128/256/512 returns ITB_ERR_SEED_WIDTH_MIX). Same caller-
// allocated-buffer convention as ITB_Encrypt.
//
//export ITB_Encrypt3
func ITB_Encrypt3(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
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
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
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

// Authenticated single-Ouroboros encrypt: takes the (noise, data,
// start) seed trio plus a MAC handle, computes a tag over the
// encrypted payload, and embeds it inside the container under the
// barrier. Same caller-allocated-buffer convention as ITB_Encrypt.
//
//export ITB_EncryptAuth
func ITB_EncryptAuth(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
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
	n, st := capi.EncryptAuth(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
		capi.MACHandleID(macHandle), pt, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Authenticated single-Ouroboros decrypt. Returns ITB_ERR_MAC_FAILURE
// on tampered ciphertext / wrong MAC key (distinct from generic
// decrypt failure).
//
//export ITB_DecryptAuth
func ITB_DecryptAuth(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
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
	n, st := capi.DecryptAuth(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
		capi.MACHandleID(macHandle), ct, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Authenticated Triple Ouroboros encrypt: 7 seed handles plus a
// MAC handle.
//
//export ITB_EncryptAuth3
func ITB_EncryptAuth3(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
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
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), ct, dst,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// ─── Process-wide configuration ────────────────────────────────────

//export ITB_SetBitSoup
func ITB_SetBitSoup(mode C.int) C.int { return C.int(capi.SetBitSoup(int(mode))) }

//export ITB_GetBitSoup
func ITB_GetBitSoup() C.int { return C.int(capi.GetBitSoup()) }

//export ITB_SetLockSoup
func ITB_SetLockSoup(mode C.int) C.int { return C.int(capi.SetLockSoup(int(mode))) }

//export ITB_GetLockSoup
func ITB_GetLockSoup() C.int { return C.int(capi.GetLockSoup()) }

//export ITB_SetMaxWorkers
func ITB_SetMaxWorkers(n C.int) C.int { return C.int(capi.SetMaxWorkers(int(n))) }

//export ITB_GetMaxWorkers
func ITB_GetMaxWorkers() C.int { return C.int(capi.GetMaxWorkers()) }

// Accepts 128, 256, or 512. Other values return ITB_ERR_BAD_INPUT.
//
//export ITB_SetNonceBits
func ITB_SetNonceBits(n C.int) C.int { return C.int(capi.SetNonceBits(int(n))) }

//export ITB_GetNonceBits
func ITB_GetNonceBits() C.int { return C.int(capi.GetNonceBits()) }

// Accepts 1, 2, 4, 8, 16, 32. Other values return ITB_ERR_BAD_INPUT.
//
//export ITB_SetBarrierFill
func ITB_SetBarrierFill(n C.int) C.int { return C.int(capi.SetBarrierFill(int(n))) }

//export ITB_GetBarrierFill
func ITB_GetBarrierFill() C.int { return C.int(capi.GetBarrierFill()) }

// ─── Streaming helpers ─────────────────────────────────────────────

// Reads a chunk header (the fixed-size
// [nonce(N) || width(2) || height(2)] prefix where N comes from the
// active ITB_GetNonceBits configuration; query ITB_HeaderSize for
// the exact byte count) at the start of the supplied buffer and
// writes the total chunk length on the wire to *outChunkLen. Used
// by streaming consumers to walk a concatenated chunk stream one
// chunk at a time without buffering the whole stream in memory:
// read ITB_HeaderSize() bytes → call ITB_ParseChunkLen → read the
// remaining (chunk_len - header_size) bytes → hand the full chunk
// to ITB_Decrypt / ITB_Decrypt3 / ITB_DecryptAuth / etc., repeat.
//
// Returns ITB_OK on success, ITB_ERR_BAD_INPUT when the buffer is
// shorter than the header, the dimensions are zero, the
// width × height multiplication overflows, or the announced pixel
// count exceeds the container pixel cap. The function does no
// decryption work — it only parses the wire-format header.
//
//export ITB_ParseChunkLen
func ITB_ParseChunkLen(header unsafe.Pointer, headerLen C.size_t, outChunkLen *C.size_t) C.int {
	if outChunkLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(headerLen) {
		return C.int(capi.StatusBadInput)
	}
	hdr := goBytesView(header, headerLen)
	n, st := capi.ParseChunkLen(hdr)
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

// Returns the current ciphertext-chunk header size in bytes
// (nonce + width(2) + height(2)). Tracks the active nonce-size
// configuration: 20 by default (128-bit nonce), 36 under
// ITB_SetNonceBits(256), 68 under ITB_SetNonceBits(512). Streaming
// consumers must read this many bytes from the wire before calling
// ITB_ParseChunkLen on each fresh chunk.
//
//export ITB_HeaderSize
func ITB_HeaderSize() C.int { return C.int(capi.HeaderSize()) }

// ─── Easy encryptor ────────────────────────────────────────────────
//
// The ITB_Easy_* surface wraps the github.com/everanium/itb/easy
// sub-package — one Encryptor handle replaces the (3 / 7 seeds + MAC)
// constructor ceremony of the low-level path. The constructor takes
// up to four parameters (primitive, keyBits, macName, mode); empty
// strings and 0 select the package defaults ("areion512", 1024,
// "kmac256"). All cipher entry points share the same caller-allocated
// out / out_cap / *out_len buffer convention as the low-level
// ITB_Encrypt / ITB_Decrypt path; the two-phase probe (NULL / 0 →
// resize → retry) works identically.
//
// State persistence rides on the JSON-encoded blob produced by
// ITB_Easy_Export; ITB_Easy_PeekConfig inspects a saved blob's
// metadata before constructing a matching encryptor; ITB_Easy_Import
// rebuilds the receiver's PRF / seed / MAC material from a prior
// blob. Mismatch errors during Import surface the offending field
// through ITB_Easy_LastMismatchField.

// Constructs a fresh Encryptor handle. The first three arguments
// each accept a "default" sentinel:
//
//   - primitive: NULL for the package default ("areion512")
//   - keyBits: 0 for the package default (1024)
//   - macName: NULL for the package default ("kmac256")
//
// The fourth argument (mode) does NOT accept a default sentinel —
// it must be 1 (Single Ouroboros) or 3 (Triple Ouroboros); any
// other value (including 0) yields ITB_ERR_BAD_INPUT.
//
//export ITB_Easy_New
func ITB_Easy_New(
	primitive *C.char, keyBits C.int, macName *C.char, mode C.int,
	outHandle *C.uintptr_t,
) C.int {
	if outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	var primStr, macStr string
	if primitive != nil {
		primStr = C.GoString(primitive)
	}
	if macName != nil {
		macStr = C.GoString(macName)
	}
	id, st := capi.NewEasy(primStr, int(keyBits), macStr, int(mode))
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Releases the Encryptor handle. Internally calls the encryptor's
// Close (zeroing PRF keys, MAC key, seed components) before deleting
// the cgo.Handle so key material does not linger after the binding
// drops the handle.
//
//export ITB_Easy_Free
func ITB_Easy_Free(handle C.uintptr_t) C.int {
	return C.int(capi.FreeEasy(capi.EasyHandleID(handle)))
}

// Encrypts plaintext through the Encryptor. Plain mode — does not
// attach a MAC tag; for authenticated encryption use
// ITB_Easy_EncryptAuth.
//
//export ITB_Easy_Encrypt
func ITB_Easy_Encrypt(
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
	n, st := capi.EasyEncrypt(capi.EasyHandleID(handle), pt, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Decrypts ciphertext produced by ITB_Easy_Encrypt under the same
// Encryptor handle.
//
//export ITB_Easy_Decrypt
func ITB_Easy_Decrypt(
	handle C.uintptr_t,
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
	n, st := capi.EasyDecrypt(capi.EasyHandleID(handle), ct, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Authenticated encrypt: attaches a MAC tag computed under the
// Encryptor's bound MAC closure.
//
//export ITB_Easy_EncryptAuth
func ITB_Easy_EncryptAuth(
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
	n, st := capi.EasyEncryptAuth(capi.EasyHandleID(handle), pt, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Authenticated decrypt. Returns ITB_ERR_MAC_FAILURE on tampered
// ciphertext / wrong MAC key (distinct from generic decrypt failure).
//
//export ITB_Easy_DecryptAuth
func ITB_Easy_DecryptAuth(
	handle C.uintptr_t,
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
	n, st := capi.EasyDecryptAuth(capi.EasyHandleID(handle), ct, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// ─── Per-instance configuration setters ───────────────────────────

// Accepts 128, 256, or 512. Other values yield ITB_ERR_BAD_INPUT.
// Mutates only the encryptor's own Config copy; process-wide
// ITB_SetNonceBits is unaffected.
//
//export ITB_Easy_SetNonceBits
func ITB_Easy_SetNonceBits(handle C.uintptr_t, n C.int) C.int {
	return C.int(capi.EasySetNonceBits(capi.EasyHandleID(handle), int(n)))
}

// Accepts 1, 2, 4, 8, 16, 32. Other values yield ITB_ERR_BAD_INPUT.
//
//export ITB_Easy_SetBarrierFill
func ITB_Easy_SetBarrierFill(handle C.uintptr_t, n C.int) C.int {
	return C.int(capi.EasySetBarrierFill(capi.EasyHandleID(handle), int(n)))
}

// 0 = byte-level split (default); non-zero = bit-level Bit Soup
// split.
//
//export ITB_Easy_SetBitSoup
func ITB_Easy_SetBitSoup(handle C.uintptr_t, mode C.int) C.int {
	return C.int(capi.EasySetBitSoup(capi.EasyHandleID(handle), int(mode)))
}

// 0 = off (default); non-zero = on. Auto-couples BitSoup=1 on this
// encryptor.
//
//export ITB_Easy_SetLockSoup
func ITB_Easy_SetLockSoup(handle C.uintptr_t, mode C.int) C.int {
	return C.int(capi.EasySetLockSoup(capi.EasyHandleID(handle), int(mode)))
}

// 0 = off; 1 = on (allocates a dedicated lockSeed and routes the
// bit-permutation overlay through it; auto-couples LockSoup=1 +
// BitSoup=1 on this encryptor). Calling after the first Encrypt
// yields ITB_ERR_EASY_LOCKSEED_AFTER_ENCRYPT (status code 18).
//
//export ITB_Easy_SetLockSeed
func ITB_Easy_SetLockSeed(handle C.uintptr_t, mode C.int) C.int {
	return C.int(capi.EasySetLockSeed(capi.EasyHandleID(handle), int(mode)))
}

// Per-instance streaming chunk-size override (0 = auto-detect).
//
//export ITB_Easy_SetChunkSize
func ITB_Easy_SetChunkSize(handle C.uintptr_t, n C.int) C.int {
	return C.int(capi.EasySetChunkSize(capi.EasyHandleID(handle), int(n)))
}

// ─── Read-only field getters ──────────────────────────────────────

// Writes the encryptor's hash primitive name (NUL-terminated) into
// out.
//
//export ITB_Easy_Primitive
func ITB_Easy_Primitive(handle C.uintptr_t, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name, st := capi.EasyPrimitive(capi.EasyHandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

// Returns the per-seed key width in bits, or 0 on a bad handle
// (status returned via *outStatus).
//
//export ITB_Easy_KeyBits
func ITB_Easy_KeyBits(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyKeyBits(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

// Returns 1 (Single Ouroboros) or 3 (Triple Ouroboros), or 0 on a bad
// handle (status returned via *outStatus).
//
//export ITB_Easy_Mode
func ITB_Easy_Mode(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyMode(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

// Writes the encryptor's MAC primitive name (NUL-terminated) into
// out.
//
//export ITB_Easy_MACName
func ITB_Easy_MACName(handle C.uintptr_t, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name, st := capi.EasyMACName(capi.EasyHandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

// ─── Material getters (defensive copies) ──────────────────────────

// Returns the number of seed slots: 3 (Single without LockSeed),
// 4 (Single with LockSeed), 7 (Triple without LockSeed), 8 (Triple
// with LockSeed). Status returned via *outStatus.
//
//export ITB_Easy_SeedCount
func ITB_Easy_SeedCount(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasySeedCount(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

// Writes the uint64 components of one seed slot into out (defensive
// copy). *outLen receives the component count on success. capCount
// (counted in uint64 elements) must be at least the slot's component
// count or ITB_ERR_BAD_INPUT is returned. Pass capCount=0 / out=NULL
// to probe the required size.
//
//export ITB_Easy_SeedComponents
func ITB_Easy_SeedComponents(
	handle C.uintptr_t, slot C.int,
	out *C.uint64_t, capCount C.int, outLen *C.int,
) C.int {
	comps, st := capi.EasySeedComponents(capi.EasyHandleID(handle), int(slot))
	if st != capi.StatusOK {
		return C.int(st)
	}
	if outLen != nil {
		*outLen = C.int(len(comps))
	}
	// Probe / undersized buffer surfaces as StatusBufferTooSmall —
	// distinct from StatusBadInput (which is reserved for genuine
	// caller errors like an out-of-range slot index, raised by
	// capi.EasySeedComponents above before reaching this branch).
	if out == nil || capCount < C.int(len(comps)) {
		return C.int(capi.StatusBufferTooSmall)
	}
	dst := unsafe.Slice((*uint64)(unsafe.Pointer(out)), int(capCount))
	copy(dst, comps)
	return C.int(capi.StatusOK)
}

// Returns 1 when the encryptor's primitive uses fixed PRF keys per
// seed slot (every shipped primitive except siphash24), 0 otherwise.
// Status returned via *outStatus.
//
//export ITB_Easy_HasPRFKeys
func ITB_Easy_HasPRFKeys(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyHasPRFKeys(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

// Writes the fixed PRF key bytes for one seed slot into out (defensive
// copy). Returns ITB_ERR_BAD_INPUT when the primitive has no fixed
// PRF keys (siphash24 — caller should consult ITB_Easy_HasPRFKeys
// first) or when slot is out of range.
//
//export ITB_Easy_PRFKey
func ITB_Easy_PRFKey(
	handle C.uintptr_t, slot C.int,
	out *C.uint8_t, capBytes C.size_t, outLen *C.size_t,
) C.int {
	if !validateLen(capBytes) {
		return C.int(capi.StatusBadInput)
	}
	key, st := capi.EasyPRFKey(capi.EasyHandleID(handle), int(slot))
	if st != capi.StatusOK {
		return C.int(st)
	}
	if outLen != nil {
		*outLen = C.size_t(len(key))
	}
	if len(key) == 0 {
		return C.int(capi.StatusOK)
	}
	// Probe / undersized buffer → StatusBufferTooSmall, distinct
	// from StatusBadInput (which is reserved for out-of-range slot
	// or no-fixed-key primitive — both raised by capi.EasyPRFKey
	// before this branch is reached).
	if out == nil || capBytes < C.size_t(len(key)) {
		return C.int(capi.StatusBufferTooSmall)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capBytes))
	copy(dst, key)
	return C.int(capi.StatusOK)
}

// Writes a defensive copy of the encryptor's bound MAC fixed key into
// out.
//
//export ITB_Easy_MACKey
func ITB_Easy_MACKey(
	handle C.uintptr_t,
	out *C.uint8_t, capBytes C.size_t, outLen *C.size_t,
) C.int {
	if !validateLen(capBytes) {
		return C.int(capi.StatusBadInput)
	}
	key, st := capi.EasyMACKey(capi.EasyHandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	if outLen != nil {
		*outLen = C.size_t(len(key))
	}
	// Probe / undersized buffer → StatusBufferTooSmall.
	if out == nil || capBytes < C.size_t(len(key)) {
		return C.int(capi.StatusBufferTooSmall)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capBytes))
	copy(dst, key)
	return C.int(capi.StatusOK)
}

// ─── Lifecycle ─────────────────────────────────────────────────────

// Zeroes the encryptor's PRF keys, MAC key, and seed components and
// marks it closed. Subsequent method calls on the same handle return
// ITB_ERR_EASY_CLOSED. Idempotent — multiple Close calls return
// ITB_OK without panic. Releases the handle slot via ITB_Easy_Free
// (Close alone does not delete the cgo.Handle).
//
//export ITB_Easy_Close
func ITB_Easy_Close(handle C.uintptr_t) C.int {
	return C.int(capi.EasyClose(capi.EasyHandleID(handle)))
}

// ─── State serialization ──────────────────────────────────────────

// Serialises the encryptor's full state (PRF keys, seed components,
// MAC key, dedicated lockSeed material when active) as a JSON blob
// into the caller-allocated buffer. Same probe-then-retry buffer
// convention as ITB_Encrypt: pass out=NULL / outCap=0 to discover
// the required size, then resize and call again.
//
//export ITB_Easy_Export
func ITB_Easy_Export(
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
	n, st := capi.EasyExport(capi.EasyHandleID(handle), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Replaces the encryptor's PRF keys, seed components, MAC key, and
// (optionally) dedicated lockSeed material with the values carried
// in a JSON blob produced by a prior ITB_Easy_Export call. On any
// non-OK return the encryptor's pre-Import state is unchanged.
//
// On ITB_ERR_EASY_MISMATCH the offending JSON field is recorded; the
// caller reads it through ITB_Easy_LastMismatchField immediately
// after the failure on the same thread.
//
//export ITB_Easy_Import
func ITB_Easy_Import(
	handle C.uintptr_t,
	blob unsafe.Pointer, blobLen C.size_t,
) C.int {
	if !validateLen(blobLen) {
		return C.int(capi.StatusBadInput)
	}
	in := goBytesView(blob, blobLen)
	return C.int(capi.EasyImport(capi.EasyHandleID(handle), in))
}

// Parses a state blob's metadata (primitive, key_bits, mode, mac)
// without performing full validation, allowing a caller to inspect a
// saved blob before constructing a matching encryptor.
//
// Both string out-buffers follow the standard probe-then-retry
// convention (pass NULL / 0 to discover the required size). The
// integer outputs are populated on every successful call.
//
//export ITB_Easy_PeekConfig
func ITB_Easy_PeekConfig(
	blob unsafe.Pointer, blobLen C.size_t,
	primOut *C.char, primCap C.size_t, primLen *C.size_t,
	keyBitsOut *C.int, modeOut *C.int,
	macOut *C.char, macCap C.size_t, macLen *C.size_t,
) C.int {
	if !validateLen(blobLen, primCap, macCap) {
		return C.int(capi.StatusBadInput)
	}
	in := goBytesView(blob, blobLen)
	prim, kb, mode, mac, st := capi.EasyPeekConfig(in)
	if st != capi.StatusOK {
		return C.int(st)
	}
	if keyBitsOut != nil {
		*keyBitsOut = C.int(kb)
	}
	if modeOut != nil {
		*modeOut = C.int(mode)
	}
	// Both writeCString calls must run so primLen AND macLen are both
	// populated on the probe pass (cap=0 / out=NULL). Returning early
	// after the first BufferTooSmall would leave macLen unset and
	// force the caller into a guess-and-check sizing loop.
	primSt := writeCString(prim, unsafe.Pointer(primOut), primCap, primLen)
	macSt := writeCString(mac, unsafe.Pointer(macOut), macCap, macLen)
	if primSt != capi.StatusOK {
		return C.int(primSt)
	}
	return C.int(macSt)
}

// Writes the offending JSON field name from the most recent
// ITB_Easy_Import call that returned ITB_ERR_EASY_MISMATCH. The
// caller reads this immediately after the failure on the same
// thread; the field text is empty when the most recent failure was
// not a mismatch.
//
//export ITB_Easy_LastMismatchField
func ITB_Easy_LastMismatchField(out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	return C.int(writeCString(capi.LastMismatchField(), unsafe.Pointer(out), capBytes, outLen))
}

// ─── Per-instance nonce / chunk introspection ──────────────────────

// Returns the per-instance nonce size in bits (128 / 256 / 512).
// Falls back to the global ITB_GetNonceBits reading when no
// per-instance override has been issued via ITB_Easy_SetNonceBits.
// Status returned via *outStatus.
//
//export ITB_Easy_NonceBits
func ITB_Easy_NonceBits(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyNonceBits(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

// Returns the per-instance ciphertext-chunk header size in bytes
// (nonce + 2-byte width + 2-byte height). Tracks this encryptor's
// own NonceBits, NOT the process-wide ITB_HeaderSize reading —
// important when the encryptor has called ITB_Easy_SetNonceBits to
// override the default. Status returned via *outStatus.
//
//export ITB_Easy_HeaderSize
func ITB_Easy_HeaderSize(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyHeaderSize(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

// Per-instance chunk-length parser: inspects a chunk header at the
// front of the supplied buffer and writes the total wire length of
// the chunk to *outChunkLen. Counterpart of ITB_ParseChunkLen but
// keyed on this encryptor's own NonceBits, so a stream produced by
// the encryptor under a non-default nonce size is parsed correctly
// regardless of the process-wide nonce setting.
//
// Returns ITB_OK on success, ITB_ERR_BAD_INPUT when the buffer is
// shorter than the header, the dimensions are zero, or the
// width × height multiplication overflows the container pixel cap.
//
//export ITB_Easy_ParseChunkLen
func ITB_Easy_ParseChunkLen(
	handle C.uintptr_t,
	header unsafe.Pointer, headerLen C.size_t,
	outChunkLen *C.size_t,
) C.int {
	if outChunkLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(headerLen) {
		return C.int(capi.StatusBadInput)
	}
	hdr := goBytesView(header, headerLen)
	n, st := capi.EasyParseChunkLen(capi.EasyHandleID(handle), hdr)
	if st == capi.StatusOK {
		*outChunkLen = C.size_t(n)
	} else {
		*outChunkLen = 0
	}
	return C.int(st)
}

// ─── Seed lifecycle — additional mutators ──────────────────────────

// Wires a dedicated lockSeed handle onto an existing noise seed
// handle. The per-chunk PRF closure for the bit-permutation overlay
// captures BOTH the lockSeed's Components AND its Hash function, so
// the lockSeed primitive may legitimately differ from the noise seed
// primitive within the same native width — keying-material isolation
// plus algorithm diversity for defence-in-depth on the overlay path.
// Both handles must share the same native hash width — mixing widths
// returns ITB_ERR_SEED_WIDTH_MIX. The dedicated lockSeed has no
// observable effect on the wire output unless the bit-permutation
// overlay is engaged via ITB_SetBitSoup(1) or ITB_SetLockSoup(1)
// before the first encrypt; the overlay-off guard inside the build-PRF
// closure raises a panic on encrypt-time when an attach is present
// without either flag.
//
// Misuse paths surface as ITB_ERR_BAD_INPUT: self-attach (passing
// the same handle for noise and lock), component-array aliasing
// (two distinct handles whose components slices share the same
// backing array), and post-Encrypt switching (calling AttachLockSeed
// on a noise seed that has already produced ciphertext).
//
// The lockSeed handle remains owned by the caller — AttachLockSeed
// only records the pointer on the noise seed; releasing the lockSeed
// via ITB_FreeSeed before the noise seed is used invalidates the
// dedicated derivation path. Standard pairing: keep the lockSeed
// alive for the lifetime of the noise seed.
//
//export ITB_AttachLockSeed
func ITB_AttachLockSeed(noiseHandle, lockHandle C.uintptr_t) C.int {
	return C.int(capi.AttachLockSeed(
		capi.HandleID(noiseHandle),
		capi.HandleID(lockHandle),
	))
}

// ─── Native Blob — low-level state persistence ────────────────────
//
// itb.Blob{128,256,512} pack the low-level encryptor material —
// per-seed hash key + Components + optional dedicated lockSeed +
// optional MAC material — plus the captured process-wide
// configuration into one self-describing JSON blob. Mirrors the
// easy.Encryptor state-blob surface but at the native (mix-and-
// match-primitives) level: no primitive name is recorded because
// each seed slot can carry a different primitive on the low-level
// path. Callers wire the matching factory onto each restored seed
// after Import.
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

// Serialises the handle's Single-Ouroboros state into a JSON blob.
// The optsBitmask is a bitwise-OR of ITB_BLOB_OPT_* flags
// (LOCKSEED=0x1, MAC=0x2). Probe-then-retry buffer convention.
//
//export ITB_Blob_Export
func ITB_Blob_Export(
	handle C.uintptr_t, optsBitmask C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(outCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.BlobExport(capi.BlobHandleID(handle), int(optsBitmask), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Serialises the handle's Triple-Ouroboros state into a JSON blob.
// See ITB_Blob_Export for the bitmask + buffer convention.
//
//export ITB_Blob_Export3
func ITB_Blob_Export3(
	handle C.uintptr_t, optsBitmask C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	if !validateLen(outCap) {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.BlobExport3(capi.BlobHandleID(handle), int(optsBitmask), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Parses a Single-Ouroboros JSON blob, populates the handle's slots,
// and applies the captured globals via the process-wide setters.
// Returns ITB_ERR_BLOB_MODE_MISMATCH on mode=3 input (call
// ITB_Blob_Import3 instead), ITB_ERR_BLOB_MALFORMED on parse / shape
// failure, ITB_ERR_BLOB_VERSION_TOO_NEW on unsupported version.
//
//export ITB_Blob_Import
func ITB_Blob_Import(
	handle C.uintptr_t,
	blob unsafe.Pointer, blobLen C.size_t,
) C.int {
	if !validateLen(blobLen) {
		return C.int(capi.StatusBadInput)
	}
	in := goBytesView(blob, blobLen)
	return C.int(capi.BlobImport(capi.BlobHandleID(handle), in))
}

// Triple-Ouroboros counterpart of ITB_Blob_Import. Same error
// contract.
//
//export ITB_Blob_Import3
func ITB_Blob_Import3(
	handle C.uintptr_t,
	blob unsafe.Pointer, blobLen C.size_t,
) C.int {
	if !validateLen(blobLen) {
		return C.int(capi.StatusBadInput)
	}
	in := goBytesView(blob, blobLen)
	return C.int(capi.BlobImport3(capi.BlobHandleID(handle), in))
}

// ─── Easy Mode — per-slot PRF mixing ───────────────────────────────
//
// [easy.NewMixed] / [easy.NewMixed3] surface allows the noise / data
// / start (and optional dedicated lockSeed) seed slots to use
// different PRF primitives within the same native hash width — the
// mix-and-match-PRF freedom the lower-level itb.Encrypt256 path
// already supports, exposed through the high-level Easy Mode without
// forcing the caller to plumb seven-line low-level setup per
// encryptor.
//
// All per-slot primitive names must resolve to the same native hash
// width via the local hashes.Registry; mixing widths returns
// ITB_ERR_INTERNAL with the panic message captured in
// ITB_LastError. Empty primL signals "no dedicated lockSeed" (3-slot
// or 7-slot encryptor). A non-empty primL allocates the trailing
// slot under that primitive and auto-couples BitSoup + LockSoup on
// the on-direction, mirroring ITB_Easy_SetLockSeed(handle, 1) but
// routing the bit-permutation derivation through the
// caller-specified primitive instead of the noiseSeed primitive.
//
// Per-slot enumeration: ITB_Easy_PrimitiveAt(handle, slot) reads
// the per-slot canonical name; ITB_Easy_IsMixed(handle) reports
// whether the encryptor uses per-slot mixing.

// Constructs a Single-Ouroboros Encryptor with per-slot PRF
// primitive selection. primN / primD / primS cover the noise /
// data / start slots; primL is the optional dedicated lockSeed
// primitive (NULL or empty = no lockSeed allocation). All four
// names must share the same native hash width via the hashes
// registry.
//
//export ITB_Easy_NewMixed
func ITB_Easy_NewMixed(
	primN, primD, primS, primL *C.char,
	keyBits C.int, macName *C.char,
	outHandle *C.uintptr_t,
) C.int {
	if outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	var pN, pD, pS, pL, mac string
	if primN != nil {
		pN = C.GoString(primN)
	}
	if primD != nil {
		pD = C.GoString(primD)
	}
	if primS != nil {
		pS = C.GoString(primS)
	}
	if primL != nil {
		pL = C.GoString(primL)
	}
	if macName != nil {
		mac = C.GoString(macName)
	}
	id, st := capi.NewEasyMixed(pN, pD, pS, pL, int(keyBits), mac)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Triple-Ouroboros counterpart of ITB_Easy_NewMixed. Accepts seven
// per-slot primitive names (noise + 3 data + 3 start) plus the
// optional lockSeed primitive (primL; NULL or empty = no lockSeed
// allocation). All eight names must share the same native hash
// width.
//
//export ITB_Easy_NewMixed3
func ITB_Easy_NewMixed3(
	primN *C.char,
	primD1, primD2, primD3 *C.char,
	primS1, primS2, primS3 *C.char,
	primL *C.char,
	keyBits C.int, macName *C.char,
	outHandle *C.uintptr_t,
) C.int {
	if outHandle == nil {
		return C.int(capi.StatusBadInput)
	}
	cstr := func(p *C.char) string {
		if p == nil {
			return ""
		}
		return C.GoString(p)
	}
	id, st := capi.NewEasyMixed3(
		cstr(primN),
		cstr(primD1), cstr(primD2), cstr(primD3),
		cstr(primS1), cstr(primS2), cstr(primS3),
		cstr(primL),
		int(keyBits), cstr(macName),
	)
	if st == capi.StatusOK {
		*outHandle = C.uintptr_t(id)
	} else {
		*outHandle = 0
	}
	return C.int(st)
}

// Returns the canonical hash primitive name bound to the given
// seed slot index. For single-primitive encryptors every slot
// returns the same name as ITB_Easy_Primitive; for mixed-mode
// encryptors each slot can carry a different name. Slot ordering:
// 0 = noiseSeed, 1..len-1 = data / start in canonical order, with
// the optional dedicated lockSeed at the trailing slot.
//
// Out-of-range slots return the empty string. Same probe-then-retry
// buffer convention as ITB_Easy_Primitive.
//
//export ITB_Easy_PrimitiveAt
func ITB_Easy_PrimitiveAt(
	handle C.uintptr_t, slot C.int,
	out *C.char, capBytes C.size_t, outLen *C.size_t,
) C.int {
	name, st := capi.EasyPrimitiveAt(capi.EasyHandleID(handle), int(slot))
	if st != capi.StatusOK {
		if outLen != nil {
			*outLen = 0
		}
		return C.int(st)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

// Returns 1 if the encryptor was constructed via ITB_Easy_NewMixed
// / ITB_Easy_NewMixed3 (per-slot primitive selection), 0 if via
// ITB_Easy_New (single primitive across all slots). Status returned
// via *outStatus.
//
//export ITB_Easy_IsMixed
func ITB_Easy_IsMixed(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyIsMixed(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
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

// Streaming AEAD single-Ouroboros encrypt for one chunk: takes the
// (noise, data, start) seed trio (all width-128), a MAC handle, and
// the streaming-binding components (32-byte streamID, running
// cumulativePixelOffset, finalFlag). The MAC tag and the flag byte
// are folded inside the cipher container under the barrier; same
// caller-allocated-buffer convention as ITB_EncryptAuth. The exported
// 128 / 256 / 512 entry points are kept distinct purely for ABI
// symmetry with the existing ITB_EncryptAuth* family — the underlying
// capi handler dispatches by the seeds' native hash width.
//
//export ITB_EncryptStreamAuthenticated128
func ITB_EncryptStreamAuthenticated128(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
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
	n, st := capi.EncryptStreamAuth(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD single-Ouroboros encrypt for one chunk (width-256
// seeds). See ITB_EncryptStreamAuthenticated128 for the parameter
// contract.
//
//export ITB_EncryptStreamAuthenticated256
func ITB_EncryptStreamAuthenticated256(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
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
	n, st := capi.EncryptStreamAuth(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD single-Ouroboros encrypt for one chunk (width-512
// seeds). See ITB_EncryptStreamAuthenticated128 for the parameter
// contract.
//
//export ITB_EncryptStreamAuthenticated512
func ITB_EncryptStreamAuthenticated512(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
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
	n, st := capi.EncryptStreamAuth(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD single-Ouroboros decrypt for one chunk. finalFlagOut,
// when non-NULL, receives the recovered flag byte interpreted as
// {0 = non-terminal, 1 = terminating}. Returns ITB_ERR_MAC_FAILURE on
// tampered ciphertext / wrong MAC key / mismatched streamID /
// mismatched cumulativePixelOffset. The 128 / 256 / 512 entry points
// are kept distinct for ABI symmetry; the capi handler dispatches by
// the seeds' native hash width.
//
//export ITB_DecryptStreamAuthenticated128
func ITB_DecryptStreamAuthenticated128(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
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
	n, ff, st := capi.DecryptStreamAuth(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
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

// Streaming AEAD single-Ouroboros decrypt for one chunk (width-256
// seeds). See ITB_DecryptStreamAuthenticated128 for the parameter
// contract.
//
//export ITB_DecryptStreamAuthenticated256
func ITB_DecryptStreamAuthenticated256(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
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
	n, ff, st := capi.DecryptStreamAuth(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
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

// Streaming AEAD single-Ouroboros decrypt for one chunk (width-512
// seeds). See ITB_DecryptStreamAuthenticated128 for the parameter
// contract.
//
//export ITB_DecryptStreamAuthenticated512
func ITB_DecryptStreamAuthenticated512(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
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
	n, ff, st := capi.DecryptStreamAuth(
		capi.HandleID(noiseHandle), capi.HandleID(dataHandle), capi.HandleID(startHandle),
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

// Streaming AEAD Triple-Ouroboros encrypt for one chunk: 7 seed
// handles plus a MAC handle plus the streaming-binding components.
// All 7 seeds must share native width 128.
//
//export ITB_EncryptStreamAuthenticated3x128
func ITB_EncryptStreamAuthenticated3x128(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD Triple-Ouroboros encrypt for one chunk (width-256
// seeds). See ITB_EncryptStreamAuthenticated3x128 for the parameter
// contract.
//
//export ITB_EncryptStreamAuthenticated3x256
func ITB_EncryptStreamAuthenticated3x256(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD Triple-Ouroboros encrypt for one chunk (width-512
// seeds). See ITB_EncryptStreamAuthenticated3x128 for the parameter
// contract.
//
//export ITB_EncryptStreamAuthenticated3x512
func ITB_EncryptStreamAuthenticated3x512(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
		capi.HandleID(dataHandle1), capi.HandleID(dataHandle2), capi.HandleID(dataHandle3),
		capi.HandleID(startHandle1), capi.HandleID(startHandle2), capi.HandleID(startHandle3),
		capi.MACHandleID(macHandle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD Triple-Ouroboros decrypt for one chunk. finalFlagOut,
// when non-NULL, receives the recovered flag byte interpreted as
// {0 = non-terminal, 1 = terminating}.
//
//export ITB_DecryptStreamAuthenticated3x128
func ITB_DecryptStreamAuthenticated3x128(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
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

// Streaming AEAD Triple-Ouroboros decrypt for one chunk (width-256
// seeds). See ITB_DecryptStreamAuthenticated3x128 for the parameter
// contract.
//
//export ITB_DecryptStreamAuthenticated3x256
func ITB_DecryptStreamAuthenticated3x256(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
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

// Streaming AEAD Triple-Ouroboros decrypt for one chunk (width-512
// seeds). See ITB_DecryptStreamAuthenticated3x128 for the parameter
// contract.
//
//export ITB_DecryptStreamAuthenticated3x512
func ITB_DecryptStreamAuthenticated3x512(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
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
		capi.HandleID(noiseHandle),
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

// Streaming AEAD encrypt through an Encryptor handle. The encryptor's
// bound MAC closure is reused for every chunk; the caller drives the
// loop, supplying a CSPRNG-fresh streamID once at stream start, the
// running cumulativePixelOffset per chunk, and finalFlag != 0 on the
// terminating chunk only. Same caller-allocated-buffer convention as
// ITB_Easy_EncryptAuth.
//
//export ITB_Easy_EncryptStreamAuth
func ITB_Easy_EncryptStreamAuth(
	handle C.uintptr_t,
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
	n, st := capi.EasyEncryptStreamAuth(
		capi.EasyHandleID(handle), pt, dst,
		sid, uint64(cumulativePixelOffset), finalFlag != 0,
	)
	*outLen = C.size_t(n)
	return C.int(st)
}

// Streaming AEAD decrypt through an Encryptor handle. finalFlagOut,
// when non-NULL, receives the recovered flag byte interpreted as
// {0 = non-terminal, 1 = terminating}. Returns ITB_ERR_MAC_FAILURE
// on tampered ciphertext / wrong MAC key / mismatched streamID /
// mismatched cumulativePixelOffset.
//
//export ITB_Easy_DecryptStreamAuth
func ITB_Easy_DecryptStreamAuth(
	handle C.uintptr_t,
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
	n, ff, st := capi.EasyDecryptStreamAuth(
		capi.EasyHandleID(handle), ct, dst,
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
// The wrapper surface seals an ITB ciphertext inside one of the nine
// PRF-grade outer keystream ciphers so the wire bytes carry no header /
// magic the receiver could match against. Every entry point dispatches off
// a `cipher_name` string naming any PRF-grade ITB registry primitive
// (areion256 / areion512 / siphash24 / aescmac / blake2b256 / blake2b512 /
// blake2s / blake3 / chacha20), mirroring the MAC-factory
// pattern: one unified ABI per operation rather than one per
// cipher. The Go-side implementation lives in
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
// outer cipher (16 for aescmac / siphash24, 32 for areion256 / chacha20 /
// blake2b256 / blake2b512 / blake2s / blake3, 64 for areion512).
// Returns ITB_ERR_BAD_INPUT for an unknown cipher name.
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
