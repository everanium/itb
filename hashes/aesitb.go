package hashes

import (
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/internal/forcetier"
)

// AESITB128Pair returns a fresh (single, batched) AES-ITB hash pair
// for itb.Seed128 integration. The two arms share the same
// internally-generated random fixed key so that per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc128).
//
// AES-ITB is an ITB-native primitive: reduced-round AES structure
// (2 AES rounds per call over a Merkle–Damgård absorption) intentionally
// weak standalone (matches the aes2r control in HARNESS.md § 3.7).
// Safe only under ITB's compound defence stack (ChainHash cascade +
// Interlocked Barrier + Part 2 absorption); do not use as a general-
// purpose hash outside ITB.
//
// The returned (HashFunc128, BatchHashFunc128) pair is the standard
// shipped factory shape used by every AES-ITB-128 seed-plumbing path:
// the single arm is [itb.MakeAESITB128Hash]'s aesITB128GenericHash
// (nonce-free 16-byte-block sponge with per-block RC rotation) and
// the batched arm routes the four ITB per-pixel shapes
// (13 / 20 / 36 / 68 bytes, all lanes equal) through the
// internal/aesitbasm 4-lane chain-absorb kernel (auto-selected AES
// tier or the package's scalar reference), falling back to four
// single-arm calls for any other lane-length configuration.
// Whole-cascade evaluation via [Spec.FusedChainHash128] is wired
// separately through the [itb.Seed128] fused hooks — see
// [AttachFused128].
//
// This is a thin wrapper over the in-package itb.MakeAESITB128Hash
// helper; it exists so that AES-ITB fits the same name-keyed
// factory shape as the rest of the hashes/ package.
//
// With no argument a fresh 16-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [16]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func AESITB128Pair(key ...[16]byte) (itb.HashFunc128, itb.BatchHashFunc128, [16]byte) {
	return itb.MakeAESITB128Hash(key...)
}

// AESITB128PairWithKey returns the (single, batched) AES-ITB pair
// built around a caller-supplied 16-byte fixed key. Same role as the
// WithKey variants on the other hashes/ primitives — meant for the
// persistence-restore path where the original fixed key has been
// saved across processes (encrypt today, decrypt tomorrow).
//
// Thin wrapper over itb.MakeAESITB128Hash for symmetry with the rest
// of the hashes/ package's WithKey factories.
func AESITB128PairWithKey(fixedKey [16]byte) (itb.HashFunc128, itb.BatchHashFunc128) {
	h, b, _ := itb.MakeAESITB128Hash(fixedKey)
	return h, b
}

// aesITB128FusedChainHash is the [Spec.FusedChainHash128] factory of the
// aesitb128 entry. The returned evaluators run the ChainHash128 cascade
// inside one internal/aesitbasm kernel call for the four per-pixel
// shapes (13 / 20 / 36 / 68 bytes) and report ok = false for any other
// input length, which sends the seed back to the sequential loop. When
// ITB_FORCE_CHAINHASH_SEQ is set both evaluators are nil so the
// sequential loop runs unconditionally (benchmark / parity knob).
func aesITB128FusedChainHash(key []byte) (itb.FusedChainHashFunc128, itb.BatchFusedChainHashFunc128, error) {
	if len(key) != 16 {
		return nil, nil, fmt.Errorf("hashes: %q fused cascade needs a 16-byte key, got %d", CipherAESITB128, len(key))
	}
	if forcetier.ChainHashSeq() {
		return nil, nil, nil
	}
	var k [16]byte
	copy(k[:], key)
	single := func(components []uint64, data []byte) (uint64, uint64, bool) {
		var out [2]uint64
		switch len(data) {
		case 13:
			aesitbasm.FusedChain13x1(&k, components, &data[0], &out)
		case 20:
			aesitbasm.FusedChain20x1(&k, components, &data[0], &out)
		case 36:
			aesitbasm.FusedChain36x1(&k, components, &data[0], &out)
		case 68:
			aesitbasm.FusedChain68x1(&k, components, &data[0], &out)
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
			aesitbasm.FusedChain13x4(&k, components, &dataPtrs, &out)
		case 20:
			aesitbasm.FusedChain20x4(&k, components, &dataPtrs, &out)
		case 36:
			aesitbasm.FusedChain36x4(&k, components, &dataPtrs, &out)
		case 68:
			aesitbasm.FusedChain68x4(&k, components, &dataPtrs, &out)
		}
		return out, true
	}
	return single, batched, nil
}

// AttachFused128 populates s.FusedChain / s.BatchFusedChain from the
// named primitive's [Spec.FusedChainHash128] factory, using the fixed
// key the seed's Hash / BatchHash arms were built with. Primitives
// without a fused cascade, unknown names, and factories that decline
// (nil evaluators) leave the seed unchanged — the sequential loop keeps
// running. A factory error is returned; the seed is left unchanged.
func AttachFused128(s *itb.Seed128, name string, key []byte) error {
	spec, ok := Find(name)
	if !ok || spec.FusedChainHash128 == nil {
		return nil
	}
	single, batched, err := spec.FusedChainHash128(key)
	if err != nil {
		return err
	}
	s.FusedChain, s.BatchFusedChain = single, batched
	return nil
}

// aesITB128InterlockFillBatch16 is the [Spec.InterlockFillBatch16] factory.
// Returns a batch-16 interlock PRF fill kernel that synthesizes 16 consecutive
// 13-byte buffers (domain tag 0x03, group index at bytes [1:9], PKCS#7 pad)
// and runs the AES-ITB hash under the shared seed pair. Dispatches to tier
// (avx512, vaesavx2, vex, aesni) or scalar fallback.
func aesITB128InterlockFillBatch16(key []byte) (itb.InterlockFillFunc16, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 needs a 16-byte key, got %d", CipherAESITB128, len(key))
	}
	var k [16]byte
	copy(k[:], key)
	return func(groupIdxBase uint64, seed0, seed1 uint64, out *[16][2]uint64) {
		aesitbasm.AESITB128ChainAbsorb13x16(&k, seed0, seed1, groupIdxBase, out)
	}, nil
}

// AttachInterlockBatch16 populates s.interlockFillX16 from the named
// primitive's [Spec.InterlockFillBatch16] factory, using the fixed key
// the seed's Hash arm was built with. Primitives without batch-16 support,
// unknown names, and factories that decline (nil) leave the seed unchanged
// — the per-round fillRanks path keeps running. A factory error is
// returned; the seed is left unchanged.
func AttachInterlockBatch16(s *itb.Seed128, name string, key []byte) error {
	spec, ok := Find(name)
	if !ok || spec.InterlockFillBatch16 == nil {
		return nil
	}
	fn, err := spec.InterlockFillBatch16(key)
	if err != nil {
		return err
	}
	s.SetInterlockBatch16(fn)
	return nil
}
