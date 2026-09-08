package hashes

import (
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/areionasm"
	"github.com/everanium/itb/internal/forcetier"
)

// Areion512Pair returns a fresh (single, batched) Areion-SoEM-512 hash
// pair for itb.Seed512 integration. Same construction principle as
// Areion256Pair: a fresh random 64-byte fixed key shared between the
// single-call and batched arms, ensuring bit-exact agreement between
// the two dispatch paths.
//
// On amd64 with VAES + AVX-512 the batched arm uses the
// AreionSoEM512x4 ASM kernel; on other hosts both arms degrade to the
// portable Go fallback while remaining bit-identical.
// With no argument a fresh 64-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [64]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func Areion512Pair(key ...[64]byte) (itb.HashFunc512, itb.BatchHashFunc512, [64]byte) {
	return itb.MakeAreionSoEM512Hash(key...)
}

// Areion512PairWithKey returns the (single, batched) Areion-SoEM-512
// pair built around a caller-supplied 64-byte fixed key. Same role as
// the WithKey variants on the other hashes/ primitives — meant for the
// persistence-restore path where the original fixed key has been saved
// across processes (encrypt today, decrypt tomorrow).
//
// Thin wrapper over itb.MakeAreionSoEM512HashWithKey.
func Areion512PairWithKey(fixedKey [64]byte) (itb.HashFunc512, itb.BatchHashFunc512) {
	return itb.MakeAreionSoEM512HashWithKey(fixedKey)
}

// areion512FusedChainHash is the [Spec.FusedChainHash512] factory of the
// areion512 entry — the width-512 form of areion256FusedChainHash with
// the 64-byte fixed key of the arms.
func areion512FusedChainHash(key []byte) (itb.FusedChainHashFunc512, itb.BatchFusedChainHashFunc512, error) {
	if len(key) != 64 {
		return nil, nil, fmt.Errorf("hashes: %q fused cascade needs a 64-byte key, got %d", CipherAreion512, len(key))
	}
	if forcetier.ChainHashSeq() {
		return nil, nil, nil
	}
	var k [64]byte
	copy(k[:], key)
	single := func(components []uint64, data []byte) ([8]uint64, bool) {
		var out [8]uint64
		switch len(data) {
		case 13:
			areionasm.Fused512Chain13x1(&k, components, &data[0], &out)
		case 20:
			areionasm.Fused512Chain20x1(&k, components, &data[0], &out)
		case 36:
			areionasm.Fused512Chain36x1(&k, components, &data[0], &out)
		case 68:
			areionasm.Fused512Chain68x1(&k, components, &data[0], &out)
		default:
			return out, false
		}
		return out, true
	}
	batched := func(components []uint64, data *[4][]byte) ([4][8]uint64, bool) {
		var out [4][8]uint64
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
			areionasm.Fused512Chain13x4(&k, components, &dataPtrs, &out)
		case 20:
			areionasm.Fused512Chain20x4(&k, components, &dataPtrs, &out)
		case 36:
			areionasm.Fused512Chain36x4(&k, components, &dataPtrs, &out)
		case 68:
			areionasm.Fused512Chain68x4(&k, components, &dataPtrs, &out)
		}
		return out, true
	}
	return single, batched, nil
}

// areion512InterlockFillBatch16 is the [Spec.InterlockFillBatch16x512]
// factory: the batch-16 Interlocked Barrier fill hook that runs the
// whole cascade over four consecutive 13-byte fill blocks per call (see
// [itb.InterlockFillFunc16x512]).
func areion512InterlockFillBatch16(key []byte) (itb.InterlockFillFunc16x512, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 needs a 64-byte key, got %d", CipherAreion512, len(key))
	}
	var k [64]byte
	copy(k[:], key)
	return func(components []uint64, groupIdxBase uint64, out *[4][8]uint64) {
		areionasm.Fused512Fill13x4(&k, components, groupIdxBase, out)
	}, nil
}
