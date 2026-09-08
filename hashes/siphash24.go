package hashes

import (
	"fmt"
	"hash"

	"github.com/dchest/siphash"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/siphashasm"
	"github.com/everanium/itb/internal/forcetier"
)

// SipHash24 returns a SipHash-2-4 itb.HashFunc128 closure.
//
// SipHash-2-4 is a designed PRF whose 128-bit key is supplied per call
// as the (seed0, seed1) pair — exactly the shape ITB's Seed128
// ChainHash128 produces from the seed components. There is no
// pre-keyed state to cache (no fixed key, no internal hasher object,
// no scratch buffer) so the closure is a direct call into siphash.
//
// Returns: (low64, high64) of SipHash128(key=(seed0, seed1), data).
//
// No WithKey variant — the seed components are the entire SipHash key.
// Long-lived seed serialization is a matter of saving Components only.
func SipHash24() itb.HashFunc128 {
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		return siphash.Hash128(seed0, seed1, data)
	}
}

// SipHash24Pair returns a (single, batched) SipHash-2-4-128 hash
// pair for itb.Seed128 integration. SipHash has no fixed key — the
// per-call (seed0, seed1) pair is the entire SipHash key — so the
// factory takes no arguments and returns no key, distinguishing it
// from the AESCMACPair / AESCMACPairWithKey shape used by the other
// W128 primitive in the registry.
//
// The batched arm evaluates the four lanes through the single arm
// under their per-lane seeds and is bit-exact with four single calls
// on every input. The assembly kernels of the primitive
// (hashes/internal/siphashasm) evaluate the whole ChainHash128 cascade
// — every lane over one shared component slice — and are reached
// through the fused hooks [AttachFused128] and [AttachInterlockBatch16]
// install, which intercept before either arm is called; see
// [Spec.FusedChainHash128].
func SipHash24Pair() (itb.HashFunc128, itb.BatchHashFunc128) {
	single := SipHash24()
	batched := func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
		var out [4][2]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane][0], out[lane][1] = single(data[lane], seeds[lane][0], seeds[lane][1])
		}
		return out
	}
	return single, batched
}

// sipHash24FusedChainHash is the [Spec.FusedChainHash128] factory of the
// siphash24 entry. SipHash is keyed by the seed components alone, so the
// factory accepts only an empty key. The returned evaluators run the
// ChainHash128 cascade inside one hashes/internal/siphashasm kernel call
// for the four per-pixel shapes (13 / 20 / 36 / 68 bytes) and report
// ok = false for any other input length, which sends the seed back to
// the sequential loop. When ITB_FORCE_CHAINHASH_SEQ is set both
// evaluators are nil so the sequential loop runs unconditionally
// (benchmark / parity knob).
func sipHash24FusedChainHash(key []byte) (itb.FusedChainHashFunc128, itb.BatchFusedChainHashFunc128, error) {
	if len(key) != 0 {
		return nil, nil, fmt.Errorf("hashes: %q fused cascade takes no key (keyed by seed components), got %d bytes", CipherSipHash24, len(key))
	}
	if forcetier.ChainHashSeq() {
		return nil, nil, nil
	}
	single := func(components []uint64, data []byte) (uint64, uint64, bool) {
		var out [2]uint64
		switch len(data) {
		case 13:
			siphashasm.FusedChain13x1(components, &data[0], &out)
		case 20:
			siphashasm.FusedChain20x1(components, &data[0], &out)
		case 36:
			siphashasm.FusedChain36x1(components, &data[0], &out)
		case 68:
			siphashasm.FusedChain68x1(components, &data[0], &out)
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
			siphashasm.FusedChain13x4(components, &dataPtrs, &out)
		case 20:
			siphashasm.FusedChain20x4(components, &dataPtrs, &out)
		case 36:
			siphashasm.FusedChain36x4(components, &dataPtrs, &out)
		case 68:
			siphashasm.FusedChain68x4(components, &dataPtrs, &out)
		}
		return out, true
	}
	return single, batched, nil
}

// sipHash24FusedChainHash8 builds the eight-lane fused cascade hook of
// the siphash24 entry (see [itb.BatchFusedChainHashFunc128x8]): the whole
// ChainHash128 cascade on eight lanes inside one
// hashes/internal/siphashasm eight-lane dispatcher call for the three
// nonce-buf shapes (20 / 36 / 68 bytes, all lanes equal); any other
// lane-length configuration reports ok = false and the seed runs the
// four-lane path twice.
func sipHash24FusedChainHash8() itb.BatchFusedChainHashFunc128x8 {
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
			siphashasm.FusedChain20x8(components, &dataPtrs, &out)
		case 36:
			siphashasm.FusedChain36x8(components, &dataPtrs, &out)
		case 68:
			siphashasm.FusedChain68x8(components, &dataPtrs, &out)
		}
		return out, true
	}
}

// sipHash24FusedChainHash128x8 is the [Spec.FusedChainHash128x8] factory
// of the siphash24 entry: [sipHash24FusedChainHash8], returned only
// where the eight-lane ZMM arm is the selected tier
// (siphashasm.FusedX8Active), so a seed built on any other host or tier
// keeps the four-lane stride; under ITB_FORCE_CHAINHASH_SEQ it is nil as
// the four-lane evaluators are. The primitive is keyed by its seed
// components alone, so key must be empty.
func sipHash24FusedChainHash128x8(key []byte) (itb.BatchFusedChainHashFunc128x8, error) {
	if len(key) != 0 {
		return nil, fmt.Errorf("hashes: %q takes no fixed key, got %d bytes", CipherSipHash24, len(key))
	}
	if forcetier.ChainHashSeq() || !siphashasm.FusedX8Active() {
		return nil, nil
	}
	return sipHash24FusedChainHash8(), nil
}

// sipHash24InterlockFillBatch16 is the [Spec.InterlockFillBatch16]
// factory of the siphash24 entry. Returns the batch-16 Interlocked
// Barrier fill kernel that synthesizes 16 consecutive 13-byte fill
// buffers (domain tag 0x03, group index at bytes [1:9], zero padding)
// and runs the whole SipHash-2-4 ChainHash cascade over the supplied
// components on every lane through hashes/internal/siphashasm (the
// sixteen-lane ZMM kernel on the avx512 tier, two eight-lane kernel calls
// on avx2 / neon, or the scalar reference) — the batch-16 arm of the cascade fill every
// lockSeed runs, see [itb.InterlockFillFunc16]. The factory accepts only
// an empty key.
func sipHash24InterlockFillBatch16(key []byte) (itb.InterlockFillFunc16, error) {
	if len(key) != 0 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 takes no key (keyed by seed components), got %d bytes", CipherSipHash24, len(key))
	}
	return func(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
		siphashasm.FusedChain13x16(components, groupIdxBase, out)
	}, nil
}

// siphash24KeyedHash backs the shipped registry entry's
// [Spec.KeyedHash] field: SipHash-2-4 in its native 128-bit-output
// keyed mode. SipHash keys are exactly 16 bytes; any other length is
// rejected with an error. The shipped entry leaves [Spec.HashHash]
// nil — SipHash has no unkeyed general-purpose hash.Hash form.
func siphash24KeyedHash(key []byte) (hash.Hash, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("siphash24 key must be exactly 16 bytes, got %d", len(key))
	}
	return siphash.New128(key), nil
}
