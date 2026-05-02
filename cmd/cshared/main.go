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
	"unsafe"

	"github.com/everanium/itb/cmd/cshared/internal/capi"
)

// Library version exposed via ITB_Version. Bumped per ABI-relevant
// release. The value is informational; binding code may key feature
// detection off it.
const libitbVersion = "0.1.0"

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

//export ITB_Version
//
// Writes the library version (NUL-terminated ASCII) into out, sets
// *out_len to the number of bytes written including the NUL.
// Returns ITB_OK on success, ITB_ERR_BUFFER_TOO_SMALL if cap is too
// small (out_len then carries the required size).
func ITB_Version(out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	return C.int(writeCString(libitbVersion, unsafe.Pointer(out), capBytes, outLen))
}

//export ITB_HashCount
//
// Returns the number of PRF-grade hash primitives shipped (currently 9).
func ITB_HashCount() C.int { return C.int(capi.HashCount()) }

//export ITB_HashName
//
// Writes the canonical name of the i-th hash primitive (NUL-
// terminated) into out. Returns ITB_OK / ITB_ERR_BUFFER_TOO_SMALL /
// ITB_ERR_BAD_INPUT (i out of range).
func ITB_HashName(i C.int, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name := capi.HashName(int(i))
	if name == "" {
		return C.int(capi.StatusBadInput)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

//export ITB_HashWidth
//
// Returns the native intermediate-state width (128 / 256 / 512) of
// the i-th hash primitive, or 0 when i is out of range.
func ITB_HashWidth(i C.int) C.int { return C.int(capi.HashWidth(int(i))) }

//export ITB_LastError
//
// Writes the last error message produced on this thread's most
// recent capi call. Standard errno-style: read it immediately after
// a non-OK return on the same thread.
func ITB_LastError(out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	return C.int(writeCString(capi.LastError(), unsafe.Pointer(out), capBytes, outLen))
}

// ─── Seed lifecycle ────────────────────────────────────────────────

//export ITB_NewSeed
//
// Builds a fresh seed with the named hash primitive and ITB key
// width in bits (512..2048, multiple of 64). The native hash width
// is determined by hashName via the registry; *outHandle receives
// an opaque uintptr_t paired with exactly one ITB_FreeSeed call.
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

//export ITB_FreeSeed
//
// Releases the seed handle. Calling this on a stale or zero handle
// returns ITB_ERR_BAD_HANDLE; the underlying *Seed becomes eligible
// for GC after a successful call.
func ITB_FreeSeed(handle C.uintptr_t) C.int {
	return C.int(capi.FreeSeed(capi.HandleID(handle)))
}

//export ITB_SeedWidth
//
// Reports the native hash width (128 / 256 / 512) of an existing
// seed handle, or 0 on a bad handle (status returned via *outStatus
// for the BAD_HANDLE distinction).
func ITB_SeedWidth(handle C.uintptr_t, outStatus *C.int) C.int {
	w, st := capi.SeedWidth(capi.HandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(w)
}

//export ITB_SeedHashName
//
// Writes the canonical hash name an existing seed handle was built
// with (NUL-terminated) into out.
func ITB_SeedHashName(handle C.uintptr_t, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name, st := capi.SeedHashName(capi.HandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

//export ITB_NewSeedFromComponents
//
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

//export ITB_GetSeedHashKey
//
// Writes the seed's underlying hash fixed key into out. *outLen
// receives the actual key length on success (16 / 32 / 64 depending
// on the primitive; 0 for "siphash24" which has no internal fixed
// key — the seed components alone are sufficient for SipHash
// persistence). capBytes must be at least the primitive's fixed-key
// size or StatusBadInput is returned. Save the bytes alongside the
// seed components for cross-process restore via
// ITB_NewSeedFromComponents.
func ITB_GetSeedHashKey(
	handle C.uintptr_t,
	out *C.uint8_t,
	capBytes C.size_t,
	outLen *C.size_t,
) C.int {
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
		return C.int(capi.StatusBadInput)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capBytes))
	copy(dst, key)
	return C.int(capi.StatusOK)
}

//export ITB_GetSeedComponents
//
// Writes the seed's uint64 components into out. *outLen receives the
// component count on success (8..32). capCount (counted in uint64
// elements, not bytes) must be at least the seed's component count
// or StatusBadInput is returned. Save the components alongside
// ITB_GetSeedHashKey for cross-process restore via
// ITB_NewSeedFromComponents.
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
		return C.int(capi.StatusBadInput)
	}
	dst := unsafe.Slice((*uint64)(unsafe.Pointer(out)), int(capCount))
	copy(dst, comps)
	return C.int(capi.StatusOK)
}

// ─── Encrypt / Decrypt ─────────────────────────────────────────────

//export ITB_Encrypt
//
// Encrypts plaintext[0..ptlen) under (noiseHandle, dataHandle,
// startHandle) into the caller-allocated buffer out[0..*outLen).
// On success *outLen receives the bytes written. On
// ITB_ERR_BUFFER_TOO_SMALL *outLen receives the required size.
func ITB_Encrypt(
	noiseHandle, dataHandle, startHandle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
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

//export ITB_Decrypt
//
// Decrypts ciphertext[0..ctlen) under (noiseHandle, dataHandle,
// startHandle) into the caller-allocated buffer out[0..*outLen).
// Same buffer convention as ITB_Encrypt.
func ITB_Decrypt(
	noiseHandle, dataHandle, startHandle C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
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

//export ITB_Encrypt3
//
// Triple Ouroboros encrypt: takes seven seed handles (one shared
// noise + three data + three start) and produces one ciphertext
// that interleaves three snake payloads. Wire format identical to
// ITB_Encrypt — the difference is internal split / interleave under
// the same nonce + dimensions header.
//
// All seven handles must share the same native hash width
// (mixing 128/256/512 returns ITB_ERR_SEED_WIDTH_MIX). Same caller-
// allocated-buffer convention as ITB_Encrypt.
func ITB_Encrypt3(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
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

//export ITB_Decrypt3
//
// Inverse of ITB_Encrypt3.
func ITB_Decrypt3(
	noiseHandle, dataHandle1, dataHandle2, dataHandle3 C.uintptr_t,
	startHandle1, startHandle2, startHandle3 C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
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

//export ITB_MACCount
//
// Returns the number of shipped MAC primitives (currently 3).
func ITB_MACCount() C.int { return C.int(capi.MACCount()) }

//export ITB_MACName
//
// Writes the canonical name of the i-th MAC primitive (NUL-
// terminated) into out. Returns ITB_OK / ITB_ERR_BUFFER_TOO_SMALL /
// ITB_ERR_BAD_INPUT (i out of range).
func ITB_MACName(i C.int, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name := capi.MACRegistryName(int(i))
	if name == "" {
		return C.int(capi.StatusBadInput)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

//export ITB_MACKeySize
//
// Returns the recommended key size in bytes for the i-th MAC
// primitive, or 0 when i is out of range.
func ITB_MACKeySize(i C.int) C.int {
	return C.int(capi.MACRegistryKeySize(int(i)))
}

//export ITB_MACTagSize
//
// Returns the tag size in bytes for the i-th MAC primitive, or 0
// when i is out of range.
func ITB_MACTagSize(i C.int) C.int {
	return C.int(capi.MACRegistryTagSize(int(i)))
}

//export ITB_MACMinKeyBytes
//
// Returns the minimum acceptable key length (bytes) for the i-th
// MAC primitive, or 0 when i is out of range.
func ITB_MACMinKeyBytes(i C.int) C.int {
	return C.int(capi.MACRegistryMinKeyBytes(int(i)))
}

//export ITB_NewMAC
//
// Builds a fresh MAC handle keyed by key[0..keyLen) for the named
// primitive. *outHandle receives an opaque uintptr_t that must be
// paired with exactly one ITB_FreeMAC call.
func ITB_NewMAC(macName *C.char, key unsafe.Pointer, keyLen C.size_t, outHandle *C.uintptr_t) C.int {
	if macName == nil || outHandle == nil {
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

//export ITB_FreeMAC
//
// Releases the MAC handle. Subsequent uses return ITB_ERR_BAD_MAC.
func ITB_FreeMAC(handle C.uintptr_t) C.int {
	return C.int(capi.FreeMAC(capi.MACHandleID(handle)))
}

// ─── Authenticated Encrypt / Decrypt ───────────────────────────────

//export ITB_EncryptAuth
//
// Authenticated single-Ouroboros encrypt: takes the (noise, data,
// start) seed trio plus a MAC handle, computes a tag over the
// encrypted payload, and embeds it inside the container under the
// barrier. Same caller-allocated-buffer convention as ITB_Encrypt.
func ITB_EncryptAuth(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
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

//export ITB_DecryptAuth
//
// Authenticated single-Ouroboros decrypt. Returns ITB_ERR_MAC_FAILURE
// on tampered ciphertext / wrong MAC key (distinct from generic
// decrypt failure).
func ITB_DecryptAuth(
	noiseHandle, dataHandle, startHandle C.uintptr_t, macHandle C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
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

//export ITB_EncryptAuth3
//
// Authenticated Triple Ouroboros encrypt: 7 seed handles plus a
// MAC handle.
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

//export ITB_DecryptAuth3
//
// Authenticated Triple Ouroboros decrypt.
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

//export ITB_SetNonceBits
//
// Accepts 128, 256, or 512. Other values return ITB_ERR_BAD_INPUT.
func ITB_SetNonceBits(n C.int) C.int { return C.int(capi.SetNonceBits(int(n))) }

//export ITB_GetNonceBits
func ITB_GetNonceBits() C.int { return C.int(capi.GetNonceBits()) }

//export ITB_SetBarrierFill
//
// Accepts 1, 2, 4, 8, 16, 32. Other values return ITB_ERR_BAD_INPUT.
func ITB_SetBarrierFill(n C.int) C.int { return C.int(capi.SetBarrierFill(int(n))) }

//export ITB_GetBarrierFill
func ITB_GetBarrierFill() C.int { return C.int(capi.GetBarrierFill()) }

// ─── Streaming helpers ─────────────────────────────────────────────

//export ITB_ParseChunkLen
//
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
func ITB_ParseChunkLen(header unsafe.Pointer, headerLen C.size_t, outChunkLen *C.size_t) C.int {
	if outChunkLen == nil {
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

//export ITB_HeaderSize
//
// Returns the current ciphertext-chunk header size in bytes
// (nonce + width(2) + height(2)). Tracks the active nonce-size
// configuration: 20 by default (128-bit nonce), 36 under
// ITB_SetNonceBits(256), 68 under ITB_SetNonceBits(512). Streaming
// consumers must read this many bytes from the wire before calling
// ITB_ParseChunkLen on each fresh chunk.
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

//export ITB_Easy_New
//
// Constructs a fresh Encryptor handle. Pass NULL / 0 / NULL for
// defaults ("areion512", 1024, "kmac256"). Mode must be 1 (Single
// Ouroboros) or 3 (Triple Ouroboros); other values yield
// ITB_ERR_BAD_INPUT.
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

//export ITB_Easy_Free
//
// Releases the Encryptor handle. Internally calls the encryptor's
// Close (zeroing PRF keys, MAC key, seed components) before deleting
// the cgo.Handle so key material does not linger after the binding
// drops the handle.
func ITB_Easy_Free(handle C.uintptr_t) C.int {
	return C.int(capi.FreeEasy(capi.EasyHandleID(handle)))
}

//export ITB_Easy_Encrypt
//
// Encrypts plaintext through the Encryptor. Plain mode — does not
// attach a MAC tag; for authenticated encryption use
// ITB_Easy_EncryptAuth.
func ITB_Easy_Encrypt(
	handle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	pt := goBytesView(plaintext, ptlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.EasyEncrypt(capi.EasyHandleID(handle), pt, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

//export ITB_Easy_Decrypt
//
// Decrypts ciphertext produced by ITB_Easy_Encrypt under the same
// Encryptor handle.
func ITB_Easy_Decrypt(
	handle C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	ct := goBytesView(ciphertext, ctlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.EasyDecrypt(capi.EasyHandleID(handle), ct, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

//export ITB_Easy_EncryptAuth
//
// Authenticated encrypt: attaches a MAC tag computed under the
// Encryptor's bound MAC closure.
func ITB_Easy_EncryptAuth(
	handle C.uintptr_t,
	plaintext unsafe.Pointer, ptlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	pt := goBytesView(plaintext, ptlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.EasyEncryptAuth(capi.EasyHandleID(handle), pt, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

//export ITB_Easy_DecryptAuth
//
// Authenticated decrypt. Returns ITB_ERR_MAC_FAILURE on tampered
// ciphertext / wrong MAC key (distinct from generic decrypt failure).
func ITB_Easy_DecryptAuth(
	handle C.uintptr_t,
	ciphertext unsafe.Pointer, ctlen C.size_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	ct := goBytesView(ciphertext, ctlen)
	dst := goBytesViewMut(out, outCap)
	n, st := capi.EasyDecryptAuth(capi.EasyHandleID(handle), ct, dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

// ─── Per-instance configuration setters ───────────────────────────

//export ITB_Easy_SetNonceBits
//
// Accepts 128, 256, or 512. Other values yield ITB_ERR_BAD_INPUT.
// Mutates only the encryptor's own Config copy; process-wide
// ITB_SetNonceBits is unaffected.
func ITB_Easy_SetNonceBits(handle C.uintptr_t, n C.int) C.int {
	return C.int(capi.EasySetNonceBits(capi.EasyHandleID(handle), int(n)))
}

//export ITB_Easy_SetBarrierFill
//
// Accepts 1, 2, 4, 8, 16, 32. Other values yield ITB_ERR_BAD_INPUT.
func ITB_Easy_SetBarrierFill(handle C.uintptr_t, n C.int) C.int {
	return C.int(capi.EasySetBarrierFill(capi.EasyHandleID(handle), int(n)))
}

//export ITB_Easy_SetBitSoup
//
// 0 = byte-level split (default); non-zero = bit-level Bit Soup
// split.
func ITB_Easy_SetBitSoup(handle C.uintptr_t, mode C.int) C.int {
	return C.int(capi.EasySetBitSoup(capi.EasyHandleID(handle), int(mode)))
}

//export ITB_Easy_SetLockSoup
//
// 0 = off (default); non-zero = on. Auto-couples BitSoup=1 on this
// encryptor.
func ITB_Easy_SetLockSoup(handle C.uintptr_t, mode C.int) C.int {
	return C.int(capi.EasySetLockSoup(capi.EasyHandleID(handle), int(mode)))
}

//export ITB_Easy_SetLockSeed
//
// 0 = off; 1 = on (allocates a dedicated lockSeed and routes the
// bit-permutation overlay through it; auto-couples LockSoup=1 +
// BitSoup=1 on this encryptor). Calling after the first Encrypt
// yields ITB_ERR_EASY_LOCKSEED_AFTER_ENCRYPT (status code 18).
func ITB_Easy_SetLockSeed(handle C.uintptr_t, mode C.int) C.int {
	return C.int(capi.EasySetLockSeed(capi.EasyHandleID(handle), int(mode)))
}

//export ITB_Easy_SetChunkSize
//
// Per-instance streaming chunk-size override (0 = auto-detect).
func ITB_Easy_SetChunkSize(handle C.uintptr_t, n C.int) C.int {
	return C.int(capi.EasySetChunkSize(capi.EasyHandleID(handle), int(n)))
}

// ─── Read-only field getters ──────────────────────────────────────

//export ITB_Easy_Primitive
//
// Writes the encryptor's hash primitive name (NUL-terminated) into
// out.
func ITB_Easy_Primitive(handle C.uintptr_t, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name, st := capi.EasyPrimitive(capi.EasyHandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

//export ITB_Easy_KeyBits
//
// Returns the per-seed key width in bits, or 0 on a bad handle
// (status returned via *outStatus).
func ITB_Easy_KeyBits(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyKeyBits(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

//export ITB_Easy_Mode
//
// Returns 1 (Single Ouroboros) or 3 (Triple Ouroboros), or 0 on a bad
// handle (status returned via *outStatus).
func ITB_Easy_Mode(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyMode(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

//export ITB_Easy_MACName
//
// Writes the encryptor's MAC primitive name (NUL-terminated) into
// out.
func ITB_Easy_MACName(handle C.uintptr_t, out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	name, st := capi.EasyMACName(capi.EasyHandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	return C.int(writeCString(name, unsafe.Pointer(out), capBytes, outLen))
}

// ─── Material getters (defensive copies) ──────────────────────────

//export ITB_Easy_SeedCount
//
// Returns the number of seed slots: 3 (Single without LockSeed),
// 4 (Single with LockSeed), 7 (Triple without LockSeed), 8 (Triple
// with LockSeed). Status returned via *outStatus.
func ITB_Easy_SeedCount(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasySeedCount(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

//export ITB_Easy_SeedComponents
//
// Writes the uint64 components of one seed slot into out (defensive
// copy). *outLen receives the component count on success. capCount
// (counted in uint64 elements) must be at least the slot's component
// count or ITB_ERR_BAD_INPUT is returned. Pass capCount=0 / out=NULL
// to probe the required size.
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
	if out == nil || capCount < C.int(len(comps)) {
		return C.int(capi.StatusBadInput)
	}
	dst := unsafe.Slice((*uint64)(unsafe.Pointer(out)), int(capCount))
	copy(dst, comps)
	return C.int(capi.StatusOK)
}

//export ITB_Easy_HasPRFKeys
//
// Returns 1 when the encryptor's primitive uses fixed PRF keys per
// seed slot (every shipped primitive except siphash24), 0 otherwise.
// Status returned via *outStatus.
func ITB_Easy_HasPRFKeys(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyHasPRFKeys(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

//export ITB_Easy_PRFKey
//
// Writes the fixed PRF key bytes for one seed slot into out (defensive
// copy). Returns ITB_ERR_BAD_INPUT when the primitive has no fixed
// PRF keys (siphash24 — caller should consult ITB_Easy_HasPRFKeys
// first) or when slot is out of range.
func ITB_Easy_PRFKey(
	handle C.uintptr_t, slot C.int,
	out *C.uint8_t, capBytes C.size_t, outLen *C.size_t,
) C.int {
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
	if out == nil || capBytes < C.size_t(len(key)) {
		return C.int(capi.StatusBadInput)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capBytes))
	copy(dst, key)
	return C.int(capi.StatusOK)
}

//export ITB_Easy_MACKey
//
// Writes a defensive copy of the encryptor's bound MAC fixed key into
// out.
func ITB_Easy_MACKey(
	handle C.uintptr_t,
	out *C.uint8_t, capBytes C.size_t, outLen *C.size_t,
) C.int {
	key, st := capi.EasyMACKey(capi.EasyHandleID(handle))
	if st != capi.StatusOK {
		return C.int(st)
	}
	if outLen != nil {
		*outLen = C.size_t(len(key))
	}
	if out == nil || capBytes < C.size_t(len(key)) {
		return C.int(capi.StatusBadInput)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(capBytes))
	copy(dst, key)
	return C.int(capi.StatusOK)
}

// ─── Lifecycle ─────────────────────────────────────────────────────

//export ITB_Easy_Close
//
// Zeroes the encryptor's PRF keys, MAC key, and seed components and
// marks it closed. Subsequent method calls on the same handle return
// ITB_ERR_EASY_CLOSED. Idempotent — multiple Close calls return
// ITB_OK without panic. Releases the handle slot via ITB_Easy_Free
// (Close alone does not delete the cgo.Handle).
func ITB_Easy_Close(handle C.uintptr_t) C.int {
	return C.int(capi.EasyClose(capi.EasyHandleID(handle)))
}

// ─── State serialization ──────────────────────────────────────────

//export ITB_Easy_Export
//
// Serialises the encryptor's full state (PRF keys, seed components,
// MAC key, dedicated lockSeed material when active) as a JSON blob
// into the caller-allocated buffer. Same probe-then-retry buffer
// convention as ITB_Encrypt: pass out=NULL / outCap=0 to discover
// the required size, then resize and call again.
func ITB_Easy_Export(
	handle C.uintptr_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.EasyExport(capi.EasyHandleID(handle), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

//export ITB_Easy_Import
//
// Replaces the encryptor's PRF keys, seed components, MAC key, and
// (optionally) dedicated lockSeed material with the values carried
// in a JSON blob produced by a prior ITB_Easy_Export call. On any
// non-OK return the encryptor's pre-Import state is unchanged.
//
// On ITB_ERR_EASY_MISMATCH the offending JSON field is recorded; the
// caller reads it through ITB_Easy_LastMismatchField immediately
// after the failure on the same thread.
func ITB_Easy_Import(
	handle C.uintptr_t,
	blob unsafe.Pointer, blobLen C.size_t,
) C.int {
	in := goBytesView(blob, blobLen)
	return C.int(capi.EasyImport(capi.EasyHandleID(handle), in))
}

//export ITB_Easy_PeekConfig
//
// Parses a state blob's metadata (primitive, key_bits, mode, mac)
// without performing full validation, allowing a caller to inspect a
// saved blob before constructing a matching encryptor.
//
// Both string out-buffers follow the standard probe-then-retry
// convention (pass NULL / 0 to discover the required size). The
// integer outputs are populated on every successful call.
func ITB_Easy_PeekConfig(
	blob unsafe.Pointer, blobLen C.size_t,
	primOut *C.char, primCap C.size_t, primLen *C.size_t,
	keyBitsOut *C.int, modeOut *C.int,
	macOut *C.char, macCap C.size_t, macLen *C.size_t,
) C.int {
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

//export ITB_Easy_LastMismatchField
//
// Writes the offending JSON field name from the most recent
// ITB_Easy_Import call that returned ITB_ERR_EASY_MISMATCH. The
// caller reads this immediately after the failure on the same
// thread; the field text is empty when the most recent failure was
// not a mismatch.
func ITB_Easy_LastMismatchField(out *C.char, capBytes C.size_t, outLen *C.size_t) C.int {
	return C.int(writeCString(capi.LastMismatchField(), unsafe.Pointer(out), capBytes, outLen))
}

// ─── Per-instance nonce / chunk introspection ──────────────────────

//export ITB_Easy_NonceBits
//
// Returns the per-instance nonce size in bits (128 / 256 / 512).
// Falls back to the global ITB_GetNonceBits reading when no
// per-instance override has been issued via ITB_Easy_SetNonceBits.
// Status returned via *outStatus.
func ITB_Easy_NonceBits(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyNonceBits(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

//export ITB_Easy_HeaderSize
//
// Returns the per-instance ciphertext-chunk header size in bytes
// (nonce + 2-byte width + 2-byte height). Tracks this encryptor's
// own NonceBits, NOT the process-wide ITB_HeaderSize reading —
// important when the encryptor has called ITB_Easy_SetNonceBits to
// override the default. Status returned via *outStatus.
func ITB_Easy_HeaderSize(handle C.uintptr_t, outStatus *C.int) C.int {
	v, st := capi.EasyHeaderSize(capi.EasyHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(v)
}

//export ITB_Easy_ParseChunkLen
//
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
func ITB_Easy_ParseChunkLen(
	handle C.uintptr_t,
	header unsafe.Pointer, headerLen C.size_t,
	outChunkLen *C.size_t,
) C.int {
	if outChunkLen == nil {
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

//export ITB_AttachLockSeed
//
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

//export ITB_Blob128_New
//
// Constructs a fresh empty Blob128 handle. Zero / unset slots are
// emitted as zero-length / zero-array fields by Export — the caller
// populates the slots that apply to the active mode (Single or
// Triple) before serialising.
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

//export ITB_Blob256_New
//
// Constructs a fresh empty Blob256 handle. See ITB_Blob128_New.
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

//export ITB_Blob512_New
//
// Constructs a fresh empty Blob512 handle. See ITB_Blob128_New.
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

//export ITB_Blob_Free
//
// Releases a blob handle. Safe to call on a zero handle (returns
// ITB_ERR_BAD_HANDLE); idempotent across all three widths since
// the underlying type is discriminated on the Go side.
func ITB_Blob_Free(handle C.uintptr_t) C.int {
	return C.int(capi.FreeBlob(capi.BlobHandleID(handle)))
}

//export ITB_Blob_Width
//
// Returns the native hash width of an existing blob handle (128 /
// 256 / 512). Status returned via *outStatus.
func ITB_Blob_Width(handle C.uintptr_t, outStatus *C.int) C.int {
	w, st := capi.BlobWidth(capi.BlobHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(w)
}

//export ITB_Blob_Mode
//
// Returns the blob's mode field (0 = unset, 1 = Single, 3 = Triple).
// Updated by Import / Import3; freshly constructed handles report 0
// until Export / Export3 / Import / Import3 has run.
func ITB_Blob_Mode(handle C.uintptr_t, outStatus *C.int) C.int {
	m, st := capi.BlobMode(capi.BlobHandleID(handle))
	if outStatus != nil {
		*outStatus = C.int(st)
	}
	return C.int(m)
}

//export ITB_Blob_SetKey
//
// Stores the hash key bytes for the requested slot on the handle.
// 256-bit width requires exactly 32 bytes; 512-bit width requires
// exactly 64 bytes. 128-bit width accepts variable lengths (empty
// for siphash24, 16 bytes for aescmac); the downstream factory
// validates the per-primitive length on Import-side wiring.
func ITB_Blob_SetKey(
	handle C.uintptr_t, slot C.int,
	key unsafe.Pointer, keyLen C.size_t,
) C.int {
	k := goBytesView(key, keyLen)
	return C.int(capi.BlobSetKey(capi.BlobHandleID(handle), int(slot), k))
}

//export ITB_Blob_GetKey
//
// Copies the hash key bytes from the requested slot into the
// caller-allocated out buffer. Probe-then-retry: pass out=NULL /
// outCap=0 to discover the required size in *outLen.
func ITB_Blob_GetKey(
	handle C.uintptr_t, slot C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.BlobGetKey(capi.BlobHandleID(handle), int(slot), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

//export ITB_Blob_SetComponents
//
// Stores the seed components (uint64 array) for the requested slot
// on the handle. Component count is validated lazily at Export /
// Import time — same 8..MaxKeyBits/64 multiple-of-8 invariants as
// ITB_NewSeedFromComponents.
func ITB_Blob_SetComponents(
	handle C.uintptr_t, slot C.int,
	comps *C.uint64_t, count C.size_t,
) C.int {
	if count > maxSliceLen {
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

//export ITB_Blob_GetComponents
//
// Copies the seed components from the requested slot into the
// caller-allocated uint64 array. Probe-then-retry: pass out=NULL /
// outCap=0 to discover the required count (in uint64 elements,
// not bytes) in *outCount.
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

//export ITB_Blob_SetMACKey
//
// Stores the optional MAC key bytes on the handle. Pass NULL / 0 to
// clear a previously-set key. Export / Export3 only emits the MAC
// section when both ITB_BLOB_OPT_MAC is set in the bitmask AND the
// MAC key on the handle is non-empty.
func ITB_Blob_SetMACKey(
	handle C.uintptr_t,
	key unsafe.Pointer, keyLen C.size_t,
) C.int {
	k := goBytesView(key, keyLen)
	return C.int(capi.BlobSetMACKey(capi.BlobHandleID(handle), k))
}

//export ITB_Blob_GetMACKey
//
// Copies the MAC key from the handle into the caller-allocated out
// buffer. Probe-then-retry standard convention.
func ITB_Blob_GetMACKey(
	handle C.uintptr_t,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.BlobGetMACKey(capi.BlobHandleID(handle), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

//export ITB_Blob_SetMACName
//
// Stores the optional MAC name on the handle (e.g. "kmac256",
// "hmac-blake3"). Pass NULL / 0 to clear a previously-set name.
func ITB_Blob_SetMACName(
	handle C.uintptr_t,
	name *C.char, nameLen C.size_t,
) C.int {
	var s string
	if name != nil && nameLen > 0 {
		s = C.GoStringN(name, C.int(nameLen))
	}
	return C.int(capi.BlobSetMACName(capi.BlobHandleID(handle), s))
}

//export ITB_Blob_GetMACName
//
// Writes the MAC name from the handle into the caller-allocated
// out buffer (NUL-terminated). Probe-then-retry standard convention.
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

//export ITB_Blob_Export
//
// Serialises the handle's Single-Ouroboros state into a JSON blob.
// The optsBitmask is a bitwise-OR of ITB_BLOB_OPT_* flags
// (LOCKSEED=0x1, MAC=0x2). Probe-then-retry buffer convention.
func ITB_Blob_Export(
	handle C.uintptr_t, optsBitmask C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.BlobExport(capi.BlobHandleID(handle), int(optsBitmask), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

//export ITB_Blob_Export3
//
// Serialises the handle's Triple-Ouroboros state into a JSON blob.
// See ITB_Blob_Export for the bitmask + buffer convention.
func ITB_Blob_Export3(
	handle C.uintptr_t, optsBitmask C.int,
	out unsafe.Pointer, outCap C.size_t, outLen *C.size_t,
) C.int {
	if outLen == nil {
		return C.int(capi.StatusBadInput)
	}
	dst := goBytesViewMut(out, outCap)
	n, st := capi.BlobExport3(capi.BlobHandleID(handle), int(optsBitmask), dst)
	*outLen = C.size_t(n)
	return C.int(st)
}

//export ITB_Blob_Import
//
// Parses a Single-Ouroboros JSON blob, populates the handle's slots,
// and applies the captured globals via the process-wide setters.
// Returns ITB_ERR_BLOB_MODE_MISMATCH on mode=3 input (call
// ITB_Blob_Import3 instead), ITB_ERR_BLOB_MALFORMED on parse / shape
// failure, ITB_ERR_BLOB_VERSION_TOO_NEW on unsupported version.
func ITB_Blob_Import(
	handle C.uintptr_t,
	blob unsafe.Pointer, blobLen C.size_t,
) C.int {
	in := goBytesView(blob, blobLen)
	return C.int(capi.BlobImport(capi.BlobHandleID(handle), in))
}

//export ITB_Blob_Import3
//
// Triple-Ouroboros counterpart of ITB_Blob_Import. Same error
// contract.
func ITB_Blob_Import3(
	handle C.uintptr_t,
	blob unsafe.Pointer, blobLen C.size_t,
) C.int {
	in := goBytesView(blob, blobLen)
	return C.int(capi.BlobImport3(capi.BlobHandleID(handle), in))
}
