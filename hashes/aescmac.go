package hashes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"unsafe"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/aescmacasm"
)

// AESCMAC returns a cached itb.HashFunc128 backed by AES along with
// the 16-byte fixed key the closure is bound to. With no argument the
// key is freshly generated via crypto/rand; passing a single
// caller-supplied [16]byte uses that key instead.
//
// The returned key is always the actual key in use — callers on the
// persistence path must save it (encrypt today, decrypt tomorrow);
// test fixtures and other throw-away usages can discard via `_`.
//
// Construction:
//
//   - key (16 bytes) is loaded once into a cipher.Block (AES-NI
//     hardware path on amd64 / arm64 hosts that expose the AES round
//     instructions; software AES fallback otherwise);
//   - per call: seed0||seed1 is XOR'd into the first 16 data bytes,
//     then encrypted in-place; remaining 16-byte data chunks are
//     XOR'd into state and encrypted; the final 16-byte block is
//     returned as (lo64, hi64).
//
// The cipher.Block is shared across all invocations of the closure
// (it carries no per-call state), so concurrent goroutines may call
// the returned function in parallel — Go's stdlib AES Encrypt path
// is reentrant.
func AESCMAC(key ...[16]byte) (itb.HashFunc128, [16]byte) {
	var aesKey [16]byte
	if len(key) > 0 {
		aesKey = key[0]
	} else if _, err := rand.Read(aesKey[:]); err != nil {
		panic(err)
	}
	return AESCMACWithKey(aesKey), aesKey
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

// AESCMACPair returns a fresh (single, batched) AES-CMAC-128 hash
// pair for itb.Seed128 integration. The two arms share the same
// internally-generated random 16-byte AES key so per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc128).
//
// On amd64 with VAES + AVX-512 the batched arm dispatches to a fused
// ZMM-batched chain-absorb kernel for ITB's three SetNonceBits buf
// shapes (20 / 36 / 68 byte inputs) — VAESENC on ZMM operates on
// four independent AES blocks per instruction, so the per-pixel
// AES-CMAC chain advances four lanes through one VAESENC instead of
// four serial cipher.Block.Encrypt calls. On hosts without VAES +
// AVX-512, and for non-{20,36,68} input lengths, the batched arm
// falls back to four single-call invocations and remains bit-exact.
//
// With no argument a fresh 16-byte AES key is generated via
// crypto/rand; passing a single caller-supplied [16]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
//
// Realistic uplift target: substantial over the upstream
// crypto/aes-driven scalar dispatch on Rocket Lake; higher on AMD
// Zen 5 / Sapphire Rapids+ where full-width 512-bit ALUs and VAESENC
// per-cycle throughput (4 AES rounds/cycle on Zen 5 vs ~2-3 on
// Rocket Lake) widen the envelope. The gain is a mix of 4-lane
// parallelism (four independent AES-CMAC chains advancing through
// one VAESENC) and per-call cipher.Block.Encrypt interface-dispatch
// amortisation across the lanes.
func AESCMACPair(key ...[16]byte) (itb.HashFunc128, itb.BatchHashFunc128, [16]byte) {
	var k [16]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	single, batched := AESCMACPairWithKey(k)
	return single, batched, k
}

// AESCMACPairWithKey returns the (single, batched) AES-CMAC-128
// pair built around a caller-supplied 16-byte AES key, for the
// persistence-restore path where the original key has been saved
// across processes (encrypt today, decrypt tomorrow).
//
// The single arm is identical to AESCMACWithKey(aesKey). The
// batched arm hot-dispatches to the fused ZMM-batched chain-absorb
// kernel when all four lanes share an input length in {20, 36, 68};
// for any other lane-length configuration it falls back to four
// single-call invocations of the single arm.
//
// The AES-128 round-key schedule (11 × 16-byte round keys = 176
// bytes) is pre-expanded once via aescmacasm.ExpandKeyAES128 and
// captured by the batched closure; the kernels broadcast each round
// key to all 4 lanes via VBROADCASTI32X4 at function entry.
func AESCMACPairWithKey(aesKey [16]byte) (itb.HashFunc128, itb.BatchHashFunc128) {
	single := AESCMACWithKey(aesKey)
	roundKeys := aescmacasm.ExpandKeyAES128(aesKey)
	batched := func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
		commonLen := len(data[0])
		if (commonLen == 20 || commonLen == 36 || commonLen == 68) &&
			len(data[1]) == commonLen &&
			len(data[2]) == commonLen &&
			len(data[3]) == commonLen {
			var dataPtrs [4]*byte
			dataPtrs[0] = &data[0][0]
			dataPtrs[1] = &data[1][0]
			dataPtrs[2] = &data[2][0]
			dataPtrs[3] = &data[3][0]
			var out [4][2]uint64
			seedsCopy := seeds
			switch commonLen {
			case 20:
				aescmacasm.AESCMAC128ChainAbsorb20x4(
					&roundKeys,
					&aesKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			case 36:
				aescmacasm.AESCMAC128ChainAbsorb36x4(
					&roundKeys,
					&aesKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			case 68:
				aescmacasm.AESCMAC128ChainAbsorb68x4(
					&roundKeys,
					&aesKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			}
			return out
		}
		var out [4][2]uint64
		for lane := 0; lane < 4; lane++ {
			lo, hi := single(data[lane], seeds[lane][0], seeds[lane][1])
			out[lane][0] = lo
			out[lane][1] = hi
		}
		return out
	}
	return single, batched
}
