package hashes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/aescmacasm"
	"github.com/everanium/itb/internal/forcetier"
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
// The batched arm evaluates the four lanes through the single arm
// under their per-lane seeds. The assembly kernels of the primitive
// (hashes/internal/aescmacasm) evaluate the whole ChainHash128 cascade
// — every lane over one shared component slice — and are reached
// through the fused hooks the name-keyed constructors install, which
// intercept before either arm is called; see
// [Spec.FusedChainHash128].
//
// With no argument a fresh 16-byte AES key is generated via
// crypto/rand; passing a single caller-supplied [16]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
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
// The single arm is identical to AESCMACWithKey(aesKey); the batched
// arm evaluates the four lanes through it under their per-lane seeds
// and is bit-exact with four single calls on every input.
func AESCMACPairWithKey(aesKey [16]byte) (itb.HashFunc128, itb.BatchHashFunc128) {
	single := AESCMACWithKey(aesKey)
	batched := func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
		var out [4][2]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane][0], out[lane][1] = single(data[lane], seeds[lane][0], seeds[lane][1])
		}
		return out
	}
	return single, batched
}

// aesCMACFusedChainHash is the [Spec.FusedChainHash128] factory of the
// aescmac entry. The returned evaluators run the ChainHash128 cascade
// inside one hashes/internal/aescmacasm kernel call for the four
// per-pixel shapes (13 / 20 / 36 / 68 bytes) and report ok = false for
// any other input length, which sends the seed back to the sequential
// loop. When ITB_FORCE_CHAINHASH_SEQ is set both evaluators are nil so
// the sequential loop runs unconditionally (benchmark / parity knob).
// The AES-128 round-key schedule is expanded once per factory call and
// shared by every evaluation.
func aesCMACFusedChainHash(key []byte) (itb.FusedChainHashFunc128, itb.BatchFusedChainHashFunc128, error) {
	if len(key) != 16 {
		return nil, nil, fmt.Errorf("hashes: %q fused cascade needs a 16-byte key, got %d", CipherAES128CTR, len(key))
	}
	if forcetier.ChainHashSeq() {
		return nil, nil, nil
	}
	var k [16]byte
	copy(k[:], key)
	s := aescmacasm.NewSchedule(k)
	single := func(components []uint64, data []byte) (uint64, uint64, bool) {
		var out [2]uint64
		switch len(data) {
		case 13:
			aescmacasm.FusedChain13x1(s, components, &data[0], &out)
		case 20:
			aescmacasm.FusedChain20x1(s, components, &data[0], &out)
		case 36:
			aescmacasm.FusedChain36x1(s, components, &data[0], &out)
		case 68:
			aescmacasm.FusedChain68x1(s, components, &data[0], &out)
		default:
			return 0, 0, false
		}
		return out[0], out[1], true
	}
	batched := func(components []uint64, data *[4][]byte) ([4][2]uint64, bool) {
		var out [4][2]uint64
		n := len(data[0])
		if len(data[1]) != n || len(data[2]) != n || len(data[3]) != n {
			return out, false
		}
		switch n {
		case 13, 20, 36, 68:
		default:
			return out, false
		}
		dataPtrs := [4]*byte{&data[0][0], &data[1][0], &data[2][0], &data[3][0]}
		switch n {
		case 13:
			aescmacasm.FusedChain13x4(s, components, &dataPtrs, &out)
		case 20:
			aescmacasm.FusedChain20x4(s, components, &dataPtrs, &out)
		case 36:
			aescmacasm.FusedChain36x4(s, components, &dataPtrs, &out)
		case 68:
			aescmacasm.FusedChain68x4(s, components, &dataPtrs, &out)
		}
		return out, true
	}
	return single, batched, nil
}

// aesCMACFusedChainHash8 builds the eight-lane fused cascade hook of
// the aescmac entry (see [itb.BatchFusedChainHashFunc128x8]): the whole
// ChainHash128 cascade on eight lanes inside one
// hashes/internal/aescmacasm eight-lane dispatcher call for the three
// nonce-buf shapes (20 / 36 / 68 bytes, all lanes equal); any other
// lane-length configuration reports ok = false and the seed runs the
// four-lane path twice.
func aesCMACFusedChainHash8(s *aescmacasm.Schedule) itb.BatchFusedChainHashFunc128x8 {
	return func(components []uint64, data *[8][]byte) ([8][2]uint64, bool) {
		var out [8][2]uint64
		n := len(data[0])
		switch n {
		case 20, 36, 68:
		default:
			return out, false
		}
		var dataPtrs [8]*byte
		for l := range data {
			if len(data[l]) != n {
				return out, false
			}
			dataPtrs[l] = &data[l][0]
		}
		switch n {
		case 20:
			aescmacasm.FusedChain20x8(s, components, &dataPtrs, &out)
		case 36:
			aescmacasm.FusedChain36x8(s, components, &dataPtrs, &out)
		case 68:
			aescmacasm.FusedChain68x8(s, components, &dataPtrs, &out)
		}
		return out, true
	}
}

// aesCMACFusedChainHash128x8 is the [Spec.FusedChainHash128x8] factory
// of the aescmac entry: [aesCMACFusedChainHash8] over the key schedule
// of the 16-byte fixed key, returned only where the eight-lane ZMM arm
// is the selected tier (aescmacasm.FusedX8Active), so a seed built on
// any other host or tier keeps the four-lane stride; under
// ITB_FORCE_CHAINHASH_SEQ it is nil as the four-lane evaluators are.
func aesCMACFusedChainHash128x8(key []byte) (itb.BatchFusedChainHashFunc128x8, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("hashes: %q fused cascade needs a 16-byte key, got %d", CipherAES128CTR, len(key))
	}
	if forcetier.ChainHashSeq() || !aescmacasm.FusedX8Active() {
		return nil, nil
	}
	var k [16]byte
	copy(k[:], key)
	return aesCMACFusedChainHash8(aescmacasm.NewSchedule(k)), nil
}

// aesCMACInterlockFillBatch16 is the [Spec.InterlockFillBatch16] factory
// of the aescmac entry. Returns the batch-16 Interlocked Barrier fill
// kernel that synthesizes 16 consecutive 13-byte fill buffers (domain
// tag 0x03, group index at bytes [1:9], zero padding) and runs the whole
// AES-CMAC ChainHash cascade over the supplied components on every lane
// inside one hashes/internal/aescmacasm kernel call (tier avx512,
// vaesavx2, vex, aesni, neon, or the scalar reference) — the batch-16
// arm of the cascade fill every lockSeed runs, see
// [itb.InterlockFillFunc16].
func aesCMACInterlockFillBatch16(key []byte) (itb.InterlockFillFunc16, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 needs a 16-byte key, got %d", CipherAES128CTR, len(key))
	}
	var k [16]byte
	copy(k[:], key)
	s := aescmacasm.NewSchedule(k)
	return func(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
		aescmacasm.FusedChain13x16(s, components, groupIdxBase, out)
	}, nil
}
