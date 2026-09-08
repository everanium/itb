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
// the batched arm applies the pure-Go 4-lane scalar cascade
// reference from internal/aesitbasm at the four ITB per-pixel
// shapes (13 / 20 / 36 / 68 bytes, all lanes equal), falling back
// to four single-arm calls for any other lane-length configuration.
// The shipping-runtime dispatch attaches the fused-cascade hooks
// via [AttachFused128], which intercept before this batched arm
// is reached — see [Spec.FusedChainHash128].
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
// key the seed's Hash / BatchHash arms were built with, and the
// eight-lane hook ([itb.Seed128.SetBatchFusedChain8]) from the
// [Spec.FusedChainHash128x8] factory when the entry populates it and
// the factory returns a kernel for the selected tier; either factory
// may be present without the other. Primitives without a fused cascade,
// unknown names, and factories that decline (nil evaluators) leave the
// seed unchanged — the sequential loop keeps running. A factory error
// is returned; the seed is left unchanged. The hooks are a performance
// path only: the seed produces the same wire with and without them.
// Every shipping constructor path — the triple package's Init / Load
// seed builders and the C ABI seed constructors — calls AttachFused128
// and [AttachInterlockBatch16] together.
func AttachFused128(s *itb.Seed128, name string, key []byte) error {
	spec, ok := Find(name)
	if !ok {
		return nil
	}
	if spec.FusedChainHash128 != nil {
		single, batched, err := spec.FusedChainHash128(key)
		if err != nil {
			return err
		}
		s.FusedChain, s.BatchFusedChain = single, batched
	}
	if spec.FusedChainHash128x8 != nil {
		x8, err := spec.FusedChainHash128x8(key)
		if err != nil {
			return err
		}
		if x8 != nil {
			s.SetBatchFusedChain8(x8)
		}
	}
	return nil
}

// aesITB128FusedChainHash128x8 is the [Spec.FusedChainHash128x8] factory
// of the aesitb128 entry: [aesITB128FusedChainHash8] under the 16-byte
// fixed key, returned only where the eight-lane ZMM arm is the selected
// tier (aesitbasm.FusedX8Active), so a seed built on any other host or
// tier keeps the four-lane stride; under ITB_FORCE_CHAINHASH_SEQ it is
// nil as the four-lane evaluators are.
func aesITB128FusedChainHash128x8(key []byte) (itb.BatchFusedChainHashFunc128x8, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("hashes: %q fused cascade needs a 16-byte key, got %d", CipherAESITB128, len(key))
	}
	if forcetier.ChainHashSeq() || !aesitbasm.FusedX8Active() {
		return nil, nil
	}
	var k [16]byte
	copy(k[:], key)
	return aesITB128FusedChainHash8(k), nil
}

// aesITB128FusedChainHash8 builds the eight-lane fused cascade hook of
// the aesitb128 entry (see [itb.BatchFusedChainHashFunc128x8]): the
// whole ChainHash128 cascade on eight lanes inside one internal/aesitbasm
// eight-lane dispatcher call for the three nonce-buf shapes (20 / 36 /
// 68 bytes, all lanes equal); any other lane-length configuration
// reports ok = false and the seed runs the four-lane path twice.
func aesITB128FusedChainHash8(k [16]byte) itb.BatchFusedChainHashFunc128x8 {
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
			aesitbasm.FusedChain20x8(&k, components, &dataPtrs, &out)
		case 36:
			aesitbasm.FusedChain36x8(&k, components, &dataPtrs, &out)
		case 68:
			aesitbasm.FusedChain68x8(&k, components, &dataPtrs, &out)
		}
		return out, true
	}
}

// aesITB128InterlockFillBatch16 is the [Spec.InterlockFillBatch16] factory.
// Returns the batch-16 Interlocked Barrier fill kernel that synthesizes 16
// consecutive 13-byte fill buffers (domain tag 0x03, group index at bytes
// [1:9], PKCS#7 pad) and runs the whole AES-ITB ChainHash cascade over the
// supplied components on every lane inside one internal/aesitbasm kernel
// call (tier avx512, vaesavx2, vex, aesni, neon, or the scalar reference)
// — the batch-16 arm of the cascade fill every lockSeed runs, see
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
// the seed's Hash arm was built with. Primitives without batch-16
// support, unknown names, and factories that decline (nil) leave the
// seed unchanged — the seed fills the Interlocked Barrier cascade
// through its four-lane and single-lane arms. The hook is a performance
// path only: a seed with the hook and the same seed without it produce
// the same wire (see [itb.InterlockFillFunc16]); every shipped
// constructor attaches. A factory error is returned; the seed is left
// unchanged.
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

// smokeWideHooks128 is the Register-time check of the optional
// [Spec.FusedChainHash128x8] factory of a user-registered W128 Spec — the
// width-128 counterpart of smokeWideHooks256: a populated factory must
// return without error, and a non-nil evaluator must be bit-exact with
// the sequential HashFunc128 loop on every lane it accepts. A nil
// evaluator is a valid opt-out.
func smokeWideHooks128(spec Spec, single itb.HashFunc128, key []byte) error {
	if spec.FusedChainHash128x8 == nil {
		return nil
	}
	x8, err := spec.FusedChainHash128x8(key)
	if err != nil {
		return fmt.Errorf("hashes: Register: %q FusedChainHash128x8(key): %w", spec.Name, err)
	}
	if x8 == nil {
		return nil
	}
	var comps [8]uint64
	for i := range comps {
		comps[i] = 0x0123456789abcdef ^ uint64(i)*0x9e3779b97f4a7c15
	}
	seqChain := func(data []byte) [2]uint64 {
		lo, hi := single(data, comps[0], comps[1])
		for i := 2; i < len(comps); i += 2 {
			lo, hi = single(data, comps[i]^lo, comps[i+1]^hi)
		}
		return [2]uint64{lo, hi}
	}
	for _, n := range [...]int{13, 20, 36, 68} {
		var lanes [8][]byte
		for l := range lanes {
			lanes[l] = make([]byte, n)
			for i := range lanes[l] {
				lanes[l][i] = byte(i + l*7)
			}
		}
		if out, ok := x8(comps[:], &lanes); ok {
			for l := 0; l < 8; l++ {
				if out[l] != seqChain(lanes[l]) {
					return fmt.Errorf("hashes: Register: %q FusedChainHash128x8 lane %d diverges from the sequential HashFunc128 loop at len=%d", spec.Name, l, n)
				}
			}
		}
	}
	return nil
}
