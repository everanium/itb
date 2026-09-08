package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/blake2s"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake2sasm"
	"github.com/everanium/itb/internal/forcetier"
)

// BLAKE2s returns a cached BLAKE2s-256 itb.HashFunc256 with a
// freshly-generated 32-byte fixed key.
//
// Same construction as BLAKE2b256: H(key || data ^ seed) using
// blake2s.Sum256 (no allocation, no keyed-mode handle). The payload
// region is zero-padded to 32 bytes for short inputs so all four
// seed uint64's contribute to the digest.
// BLAKE2s returns a cached BLAKE2s-256 itb.HashFunc256 along with the
// 32-byte fixed key the closure is bound to. With no argument a
// fresh key is generated via crypto/rand; passing a single
// caller-supplied [32]byte uses that key instead. Save the returned
// key for cross-process persistence.
func BLAKE2s(key ...[32]byte) (itb.HashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return BLAKE2sWithKey(k), k
}

// BLAKE2sWithKey returns the BLAKE2s-256 closure built around a
// caller-supplied 32-byte fixed key, for serialization paths.
func BLAKE2sWithKey(b2key [32]byte) itb.HashFunc256 {
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		const keyLen = 32
		const seedInjectBytes = 32
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		need := keyLen + payloadLen
		bufPtr := pool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < need {
			buf = make([]byte, need)
		} else {
			buf = buf[:need]
		}
		for i := keyLen + len(data); i < need; i++ {
			buf[i] = 0
		}
		copy(buf[:keyLen], b2key[:])
		copy(buf[keyLen:keyLen+len(data)], data)
		for i := 0; i < 4; i++ {
			off := keyLen + i*8
			binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
		}
		digest := blake2s.Sum256(buf)
		*bufPtr = buf
		pool.Put(bufPtr)
		return [4]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
		}
	}
}

// BLAKE2s256Pair returns a fresh (single, batched) BLAKE2s-256 hash
// pair for itb.Seed256 integration. The two arms share the same
// internally-generated random 32-byte fixed key so per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc256).
//
// The batched arm evaluates the four lanes through the single arm;
// the per-pixel and Interlocked Barrier fill work of a seed built
// through the registry runs in the fused cascade kernels of
// hashes/internal/blake2sasm, installed by the blake2s entry's
// FusedChainHash256 / InterlockFillBatch16x256 factories.
//
// With no argument a fresh 32-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [32]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func BLAKE2s256Pair(key ...[32]byte) (itb.HashFunc256, itb.BatchHashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	single, batched := BLAKE2s256PairWithKey(k)
	return single, batched, k
}

// BLAKE2s256PairWithKey returns the (single, batched) BLAKE2s-256 pair
// built around a caller-supplied 32-byte fixed key. Same role as the
// WithKey variants on the other hashes/ primitives — meant for the
// persistence-restore path where the original fixed key has been
// saved across processes (encrypt today, decrypt tomorrow).
//
// The single arm is identical to BLAKE2sWithKey(fixedKey); the
// batched arm evaluates the four lanes through it under their per-lane
// seeds and is bit-exact with four single calls on every input. Every
// shipped constructor path attaches the fused cascade hooks of the
// blake2s registry entry, which the batched ChainHash256 entry points
// consult first, so the batched arm is the fallback for seeds built
// without those hooks.
func BLAKE2s256PairWithKey(fixedKey [32]byte) (itb.HashFunc256, itb.BatchHashFunc256) {
	single := BLAKE2sWithKey(fixedKey)
	batched := func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
		var out [4][4]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane] = single(data[lane], seeds[lane])
		}
		return out
	}
	return single, batched
}

// blake2sHashHash backs the shipped registry entry's [Spec.HashHash]
// field: the unkeyed BLAKE2s-256 hash.Hash form the HMAC
// construction wraps. A nil key is always accepted by the upstream
// constructor, so the error arm is unreachable.
func blake2sHashHash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// blake2sKeyedHash backs the shipped registry entry's
// [Spec.KeyedHash] field: BLAKE2s-256 in its native keyed mode. The
// upstream constructor accepts key lengths up to 32 bytes and
// returns an error for longer keys.
func blake2sKeyedHash(key []byte) (hash.Hash, error) {
	return blake2s.New256(key)
}

// blake2sFusedChainHash is the [Spec.FusedChainHash256] factory of the
// blake2s entry. The returned evaluators run the ChainHash256 cascade
// inside one hashes/internal/blake2sasm kernel call for the four
// per-pixel shapes (13 / 20 / 36 / 68 bytes) and report ok = false for
// any other input length or unequal lane lengths, which sends the seed
// back to the sequential loop. The key is the 32-byte fixed key the
// arms were built with. When ITB_FORCE_CHAINHASH_SEQ is set both
// evaluators are nil so the sequential loop runs end to end.
func blake2sFusedChainHash(key []byte) (itb.FusedChainHashFunc256, itb.BatchFusedChainHashFunc256, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("hashes: %q fused cascade needs a 32-byte key, got %d", CipherBLAKE2s, len(key))
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
			blake2sasm.Fused256Chain13x1(&k, components, &data[0], &out)
		case 20:
			blake2sasm.Fused256Chain20x1(&k, components, &data[0], &out)
		case 36:
			blake2sasm.Fused256Chain36x1(&k, components, &data[0], &out)
		case 68:
			blake2sasm.Fused256Chain68x1(&k, components, &data[0], &out)
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
			blake2sasm.Fused256Chain13x4(&k, components, &dataPtrs, &out)
		case 20:
			blake2sasm.Fused256Chain20x4(&k, components, &dataPtrs, &out)
		case 36:
			blake2sasm.Fused256Chain36x4(&k, components, &dataPtrs, &out)
		case 68:
			blake2sasm.Fused256Chain68x4(&k, components, &dataPtrs, &out)
		}
		return out, true
	}
	return single, batched, nil
}

// blake2sInterlockFillBatch16 is the [Spec.InterlockFillBatch16x256]
// factory: the batch-16 Interlocked Barrier fill hook that runs the
// whole cascade over eight consecutive 13-byte fill blocks per call
// (see [itb.InterlockFillFunc16x256]).
func blake2sInterlockFillBatch16(key []byte) (itb.InterlockFillFunc16x256, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 needs a 32-byte key, got %d", CipherBLAKE2s, len(key))
	}
	var k [32]byte
	copy(k[:], key)
	return func(components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
		blake2sasm.Fused256Fill13x8(&k, components, groupIdxBase, out)
	}, nil
}

// blake2sFusedChainHash8 is the [Spec.FusedChainHash256x8] factory of
// the blake2s entry: the whole ChainHash256 cascade on eight lanes
// inside one hashes/internal/blake2sasm eight-lane dispatcher call for
// the three nonce-buf shapes (20 / 36 / 68 bytes, all lanes equal); any
// other lane-length configuration reports ok = false and the seed runs
// the four-lane path twice. The hook is returned only where the
// eight-lane YMM arm is the selected tier (blake2sasm.FusedX8Active), so
// a seed built on any other host or tier keeps the four-lane stride;
// under ITB_FORCE_CHAINHASH_SEQ it is nil as the four-lane evaluators
// are.
func blake2sFusedChainHash8(key []byte) (itb.BatchFusedChainHashFunc256x8, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("hashes: %q fused cascade needs a 32-byte key, got %d", CipherBLAKE2s, len(key))
	}
	if forcetier.ChainHashSeq() || !blake2sasm.FusedX8Active() {
		return nil, nil
	}
	var k [32]byte
	copy(k[:], key)
	return func(components []uint64, data *[8][]byte) ([8][4]uint64, bool) {
		var out [8][4]uint64
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
			blake2sasm.Fused256Chain20x8(&k, components, &dataPtrs, &out)
		case 36:
			blake2sasm.Fused256Chain36x8(&k, components, &dataPtrs, &out)
		case 68:
			blake2sasm.Fused256Chain68x8(&k, components, &dataPtrs, &out)
		}
		return out, true
	}, nil
}
