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
// (one AES round per absorbed block plus two finalising rounds over a
// Merkle–Damgård absorption) intentionally weak standalone — HARNESS.md
// § 3.10 records its standalone breaks and their dissolution through
// the cascade, alongside the aes2r control of § 3.7. Safe only under
// ITB's compound defence stack (ChainHash cascade + Interlocked Barrier
// + Part 2 absorption); do not use as a general-purpose hash outside ITB.
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
// Returns the batch-16 Interlocked Barrier fill kernel that synthesizes 16
// consecutive 13-byte fill buffers (domain tag 0x03, group index at bytes
// [1:9], PKCS#7 pad) and runs the whole AES-ITB ChainHash cascade over the
// supplied components on every lane inside one internal/aesitbasm kernel
// call (tier avx512, vaesavx2, vex, aesni, neon, or the scalar reference).
// Its presence on a lockSeed selects the cascade fill — see
// [itb.InterlockFillFunc16].
func aesITB128InterlockFillBatch16(key []byte) (itb.InterlockFillFunc16, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 needs a 16-byte key, got %d", CipherAESITB128, len(key))
	}
	var k [16]byte
	copy(k[:], key)
	return func(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
		aesitbasm.FusedChain13x16(&k, components, groupIdxBase, out)
	}, nil
}

// AttachInterlockBatch16 populates s.interlockFillX16 from the named
// primitive's [Spec.InterlockFillBatch16] factory, using the fixed key
// the seed's Hash arm was built with. Primitives without batch-16 support,
// unknown names, and factories that decline (nil) leave the seed unchanged
// — the seed fills the Interlocked Barrier through the single derived-pair
// call. For aesitb128 the attached hook selects the cascade fill, so a
// seed with the hook and the same seed without it produce different wire
// (see [itb.InterlockFillFunc16]); every shipped constructor attaches. A
// factory error is returned; the seed is left unchanged.
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

// NewSeed128x16 constructs a [itb.Seed128] with every fast-path hook
// attached in one call — the Low-Level Mode symmetric of the triple
// package's automatic attach in [github.com/everanium/itb/triple.Init]
// and [github.com/everanium/itb/triple.Load]. Equivalent to:
//
//	single, batched, key, _ := hashes.Make128Pair(primitiveName, key...)
//	seed, _ := itb.NewSeed128(bits, single)
//	seed.BatchHash = batched
//	hashes.AttachFused128(seed, primitiveName, key)
//	hashes.AttachInterlockBatch16(seed, primitiveName, key)
//
// The variadic key argument follows [Make128Pair]: pass nothing to
// generate a fresh random fixed key, or a single caller-supplied slice
// of the primitive's native key length for the persistence-restore
// path. The key the seed's arms are bound to (random or supplied) is
// returned alongside the seed; it is nil for keyless primitives
// (siphash24, which rejects an explicit key).
//
// Primitives without fused / batch-16 factories get the base Hash /
// BatchHash arms; the optional hooks remain nil and the hot paths keep
// the sequential fallback. Seeds constructed directly through
// [itb.NewSeed128] never receive the hooks — this helper closes that gap
// for the Low-Level entry points (Encrypt3x128Cfg and siblings).
func NewSeed128x16(bits int, primitiveName string, key ...[]byte) (*itb.Seed128, []byte, error) {
	single, batched, fixedKey, err := Make128Pair(primitiveName, key...)
	if err != nil {
		return nil, nil, fmt.Errorf("hashes: NewSeed128x16(%q): %w", primitiveName, err)
	}
	s, err := itb.NewSeed128(bits, single)
	if err != nil {
		return nil, nil, fmt.Errorf("hashes: NewSeed128x16(%q): %w", primitiveName, err)
	}
	s.BatchHash = batched
	if err := AttachFused128(s, primitiveName, fixedKey); err != nil {
		return nil, nil, fmt.Errorf("hashes: NewSeed128x16(%q): %w", primitiveName, err)
	}
	if err := AttachInterlockBatch16(s, primitiveName, fixedKey); err != nil {
		return nil, nil, fmt.Errorf("hashes: NewSeed128x16(%q): %w", primitiveName, err)
	}
	return s, fixedKey, nil
}

// SeedFromComponents128x16 constructs a [itb.Seed128] from existing
// components with every fast-path hook attached in one call — the
// existing-components counterpart of [NewSeed128x16] and the Low-Level
// bridge for seeds that come back from [itb.Blob128.Import3Cfg] with
// Components populated and Hash / BatchHash nil. Equivalent to:
//
//	single, batched, _, _ := hashes.Make128Pair(primitiveName, key) // key omitted when empty
//	seed, _ := itb.SeedFromComponents128(single, components...)
//	seed.BatchHash = batched
//	hashes.AttachFused128(seed, primitiveName, key)
//	hashes.AttachInterlockBatch16(seed, primitiveName, key)
//
// key is the primitive's fixed key the seed's arms were originally
// built with (the Key* bytes of the blob). Pass nil or an empty slice
// for a keyless primitive (siphash24, whose blob key field is empty and
// which rejects an explicit key); an empty key for a keyed primitive is
// an error, since arms built on a fresh random key would not reproduce
// the exported seed's wire.
//
// The attach step is wire-affecting for aesitb128: its batch-16 hook
// selects the Interlocked Barrier cascade fill (see
// [itb.InterlockFillFunc16]), so an aesitb128 lockSeed rebuilt from
// imported components without this helper — or without
// [AttachInterlockBatch16] — fills through the single derived-pair call
// and decrypts nothing the exporting side encrypted, with no error
// oracle. Primitives without fused / batch-16 factories get the base
// Hash / BatchHash arms; their optional hooks remain nil.
func SeedFromComponents128x16(primitiveName string, key []byte, components ...uint64) (*itb.Seed128, error) {
	var keyArg [][]byte
	if len(key) > 0 {
		keyArg = [][]byte{key}
	}
	single, batched, fixedKey, err := Make128Pair(primitiveName, keyArg...)
	if err != nil {
		return nil, fmt.Errorf("hashes: SeedFromComponents128x16(%q): %w", primitiveName, err)
	}
	if len(key) == 0 && len(fixedKey) > 0 {
		return nil, fmt.Errorf("hashes: SeedFromComponents128x16(%q): the primitive is keyed; pass the fixed key the components were exported with", primitiveName)
	}
	s, err := itb.SeedFromComponents128(single, components...)
	if err != nil {
		return nil, fmt.Errorf("hashes: SeedFromComponents128x16(%q): %w", primitiveName, err)
	}
	s.BatchHash = batched
	if err := AttachFused128(s, primitiveName, fixedKey); err != nil {
		return nil, fmt.Errorf("hashes: SeedFromComponents128x16(%q): %w", primitiveName, err)
	}
	if err := AttachInterlockBatch16(s, primitiveName, fixedKey); err != nil {
		return nil, fmt.Errorf("hashes: SeedFromComponents128x16(%q): %w", primitiveName, err)
	}
	return s, nil
}
