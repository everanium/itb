package hashes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"unsafe"

	"github.com/everanium/itb"
)

// AESCMAC returns a cached itb.HashFunc128 backed by AES, with a
// freshly-generated 16-byte fixed key.
//
// Construction (same as the bench-validated reference wrapper from
// itb_test.go):
//
//   - key (16 random bytes) is loaded once into a cipher.Block
//     (AES-NI hardware path on amd64 / arm64 hosts that expose the
//     AES round instructions; software AES fallback otherwise);
//   - per call: seed0||seed1 is XOR'd into the first 16 data bytes,
//     then encrypted in-place; remaining 16-byte data chunks are
//     XOR'd into state and encrypted; the final 16-byte block is
//     returned as (lo64, hi64).
//
// The cipher.Block is shared across all invocations of the closure
// (it carries no per-call state), so concurrent goroutines may call
// the returned function in parallel — Go's stdlib AES Encrypt path
// is reentrant.
func AESCMAC() itb.HashFunc128 {
	var aesKey [16]byte
	if _, err := rand.Read(aesKey[:]); err != nil {
		panic(err)
	}
	return AESCMACWithKey(aesKey)
}

// AESCMACWithKey returns the AESCMAC closure built around a caller-
// supplied 16-byte key, intended for serialization paths where the
// fixed key must persist across processes (Encrypt today / Decrypt
// tomorrow).
func AESCMACWithKey(aesKey [16]byte) itb.HashFunc128 {
	block, _ := aes.NewCipher(aesKey[:])
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		// First block: load seed components into b1 unconditionally
		// so seeds always contribute regardless of len(data), then
		// XOR the available data bytes (up to 16) on top.
		//
		// A 64-bit length tag is XOR'd into both halves of the
		// seed prefix to disambiguate inputs of different lengths.
		// Without it, empty input, [0x00], [0x00, 0x00], ... all
		// hash to the same AES_K(seed0||seed1) because zero data
		// bytes XOR'd into the state are no-ops. The length tag
		// breaks that collision class. AES-CMAC's 16-byte state
		// has no dedicated metadata region (unlike Areion /
		// ChaCha20 which keep state[0..8) for the length tag and
		// state[8..N) for data), so the tag is folded symmetric-
		// ally into both halves rather than stealing a fixed
		// region from the seed input.
		lenTag := uint64(len(data))
		var b1 [16]byte
		binary.LittleEndian.PutUint64(b1[0:], seed0^lenTag)
		binary.LittleEndian.PutUint64(b1[8:], seed1^lenTag)
		firstBlockLen := len(data)
		if firstBlockLen > 16 {
			firstBlockLen = 16
		}
		absorbXOR(b1[:firstBlockLen], data[:firstBlockLen])
		aesEncryptNoescape(block, &b1)

		for off := 16; off < len(data); off += 16 {
			end := off + 16
			if end > len(data) {
				end = len(data)
			}
			absorbXOR(b1[:end-off], data[off:end])
			aesEncryptNoescape(block, &b1)
		}
		return binary.LittleEndian.Uint64(b1[:8]), binary.LittleEndian.Uint64(b1[8:])
	}
}

// absorbXOR XORs src into dst in 8-byte uint64 chunks where
// possible, with a byte-tail for the trailing < 8 bytes.
//
// Caller invariant: len(dst) == len(src). The helper does not
// double-check; the resulting smaller body cost lets the Go
// compiler inline this at all call sites (CBC-MAC slow path in
// the ChaCha20 closure here, AES-CMAC's per-block absorb).
//
// Lives in this file (alongside the AES-CMAC factory) because
// AES-CMAC was the first user; the ChaCha20 closure shares it.
// The Areion-SoEM closures in itb/areion.go carry an internal
// copy with the same shape since they cannot import this
// subpackage without a dependency cycle.
func absorbXOR(dst, src []byte) {
	n := len(dst)
	i := 0
	for ; i+8 <= n; i += 8 {
		d := binary.LittleEndian.Uint64(dst[i:])
		s := binary.LittleEndian.Uint64(src[i:])
		binary.LittleEndian.PutUint64(dst[i:], d^s)
	}
	for ; i < n; i++ {
		dst[i] ^= src[i]
	}
}

// noescape hides a pointer from escape analysis. Standard Go runtime
// trick — safe when the callee does not retain the pointer.
//
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

// aesEncryptNoescape calls block.Encrypt without escaping the buffer
// to the heap. cipher.Block.Encrypt is documented to not retain slice
// references, so this is safe.
func aesEncryptNoescape(block cipher.Block, buf *[16]byte) {
	dst := (*[16]byte)(noescape(unsafe.Pointer(buf)))
	block.Encrypt(dst[:], dst[:])
}
