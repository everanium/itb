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
