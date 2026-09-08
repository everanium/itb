package hashes

import (
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/areionasm"
	"github.com/everanium/itb/internal/forcetier"
)

// Areion256Pair returns a fresh (single, batched) Areion-SoEM-256 hash
// pair for itb.Seed256 integration. The two arms share the same
// internally-generated random fixed key so that per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc256).
//
// On amd64 with VAES + AVX-512 the batched arm routes per-pixel
// hashing four pixels per call through AreionSoEM256x4, yielding ~2×
// throughput over the single-call path. On hosts without those
// extensions the batched arm falls back to four single-call
// invocations and remains bit-exact.
//
// This is a thin wrapper over the in-package itb.MakeAreionSoEM256Hash
// helper; it exists so that Areion-SoEM-256 fits the same name-keyed
// factory shape as the rest of the hashes/ package.
//
// With no argument a fresh 32-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [32]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func Areion256Pair(key ...[32]byte) (itb.HashFunc256, itb.BatchHashFunc256, [32]byte) {
	return itb.MakeAreionSoEM256Hash(key...)
}

// Areion256PairWithKey returns the (single, batched) Areion-SoEM-256
// pair built around a caller-supplied 32-byte fixed key. Same role as
// the WithKey variants on the other hashes/ primitives — meant for the
// persistence-restore path where the original fixed key has been saved
// across processes (encrypt today, decrypt tomorrow).
//
// Thin wrapper over itb.MakeAreionSoEM256HashWithKey for symmetry with
// the rest of the hashes/ package's WithKey factories.
func Areion256PairWithKey(fixedKey [32]byte) (itb.HashFunc256, itb.BatchHashFunc256) {
	return itb.MakeAreionSoEM256HashWithKey(fixedKey)
}

// areion256FusedChainHash is the [Spec.FusedChainHash256] factory of the
// areion256 entry. The returned evaluators run the ChainHash256 cascade
// inside one internal/areionasm kernel call for the four per-pixel
// shapes (13 / 20 / 36 / 68 bytes) and report ok = false for any other
// input length or unequal lane lengths, which sends the seed back to the
// sequential loop. The key is the 32-byte fixed key the arms were built
// with. When ITB_FORCE_CHAINHASH_SEQ is set both evaluators are nil so
// the sequential loop runs end to end.
func areion256FusedChainHash(key []byte) (itb.FusedChainHashFunc256, itb.BatchFusedChainHashFunc256, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("hashes: %q fused cascade needs a 32-byte key, got %d", CipherAreion256, len(key))
	}
	if forcetier.ChainHashSeq() {
		return nil, nil, nil
	}
	var k [32]byte
	copy(k[:], key)
	single := func(components []uint64, data []byte) ([4]uint64, bool) {
		var out [4]uint64
		switch len(data) {
		case 13:
			areionasm.Fused256Chain13x1(&k, components, &data[0], &out)
		case 20:
			areionasm.Fused256Chain20x1(&k, components, &data[0], &out)
		case 36:
			areionasm.Fused256Chain36x1(&k, components, &data[0], &out)
		case 68:
			areionasm.Fused256Chain68x1(&k, components, &data[0], &out)
		default:
			return out, false
		}
		return out, true
	}
	batched := func(components []uint64, data *[4][]byte) ([4][4]uint64, bool) {
		var out [4][4]uint64
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
			areionasm.Fused256Chain13x4(&k, components, &dataPtrs, &out)
		case 20:
			areionasm.Fused256Chain20x4(&k, components, &dataPtrs, &out)
		case 36:
			areionasm.Fused256Chain36x4(&k, components, &dataPtrs, &out)
		case 68:
			areionasm.Fused256Chain68x4(&k, components, &dataPtrs, &out)
		}
		return out, true
	}
	return single, batched, nil
}

// areion256InterlockFillBatch16 is the [Spec.InterlockFillBatch16x256]
// factory: the batch-16 Interlocked Barrier fill hook that runs the
// whole cascade over eight consecutive 13-byte fill blocks per call
// (see [itb.InterlockFillFunc16x256]).
func areion256InterlockFillBatch16(key []byte) (itb.InterlockFillFunc16x256, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 needs a 32-byte key, got %d", CipherAreion256, len(key))
	}
	var k [32]byte
	copy(k[:], key)
	return func(components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
		areionasm.Fused256Fill13x8(&k, components, groupIdxBase, out)
	}, nil
}
