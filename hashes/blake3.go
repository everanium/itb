package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake3asm"
	"github.com/everanium/itb/internal/forcetier"
)

// BLAKE3 returns a cached BLAKE3-256 itb.HashFunc256 with a freshly-
// generated 32-byte BLAKE3 key.
//
// The pre-keyed BLAKE3 hasher template is created once via
// blake3.NewKeyed; each call clones the template instead of
// re-keying, sidestepping the data race that Reset() on a shared
// hasher would cause when ITB's process256 dispatches multiple
// goroutines on the same seed. A sync.Pool of scratch buffers keeps
// per-call allocation at zero.
//
// Seed components are mixed into the hashed payload as XOR over the
// first 32 bytes; the input is zero-padded out to 32 bytes when the
// caller's data is shorter, so all four seed uint64's contribute
// regardless of how short the caller's data is.
// BLAKE3 returns a cached BLAKE3-256 itb.HashFunc256 along with the
// 32-byte BLAKE3 key the closure is bound to. With no argument a
// fresh key is generated via crypto/rand; passing a single
// caller-supplied [32]byte uses that key instead. Save the returned
// key for cross-process persistence.
func BLAKE3(key ...[32]byte) (itb.HashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return BLAKE3WithKey(k), k
}

// BLAKE3WithKey returns the BLAKE3 closure built around a caller-
// supplied 32-byte BLAKE3 key, for serialization across processes.
func BLAKE3WithKey(key [32]byte) itb.HashFunc256 {
	template, _ := blake3.NewKeyed(key[:])
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		h := template.Clone()

		const seedInjectBytes = 32
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		mixedPtr := pool.Get().(*[]byte)
		mixed := *mixedPtr
		if cap(mixed) < payloadLen {
			mixed = make([]byte, payloadLen)
		} else {
			mixed = mixed[:payloadLen]
		}
		for i := len(data); i < payloadLen; i++ {
			mixed[i] = 0
		}
		copy(mixed[:len(data)], data)
		for i := 0; i < 4; i++ {
			off := i * 8
			binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
		}
		h.Write(mixed)
		*mixedPtr = mixed
		pool.Put(mixedPtr)

		var buf [32]byte
		h.Sum(buf[:0])
		return [4]uint64{
			binary.LittleEndian.Uint64(buf[0:]),
			binary.LittleEndian.Uint64(buf[8:]),
			binary.LittleEndian.Uint64(buf[16:]),
			binary.LittleEndian.Uint64(buf[24:]),
		}
	}
}

// BLAKE3256Pair returns a fresh (single, batched) BLAKE3-256 hash
// pair for itb.Seed256 integration. The two arms share the same
// internally-generated random 32-byte BLAKE3 key so per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc256).
//
// On amd64 with AVX-512+VL the batched arm dispatches to a fused
// ZMM-batched chain-absorb kernel for ITB's three per-pixel buf
// shapes (20 / 36 / 68 byte inputs). On hosts without AVX-512+VL,
// and for non-{20,36,68} input lengths, the batched arm falls back
// to four single-call invocations and remains bit-exact.
//
// With no argument a fresh 32-byte BLAKE3 key is generated via
// crypto/rand; passing a single caller-supplied [32]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
//
// Realistic uplift target: 1.3-2.0× over the upstream zeebo/blake3
// per-call dispatch. github.com/zeebo/blake3 already carries
// hand-written AVX-512 assembly for the BLAKE3 compression, so the
// batched arm's gain over upstream is mostly from amortising the
// per-call Hasher.Clone / Write / Sum overhead across 4 lanes
// rather than from kernel-internal speedup.
func BLAKE3256Pair(key ...[32]byte) (itb.HashFunc256, itb.BatchHashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	single, batched := BLAKE3256PairWithKey(k)
	return single, batched, k
}

// BLAKE3256PairWithKey returns the (single, batched) BLAKE3-256 pair
// built around a caller-supplied 32-byte BLAKE3 key, for the
// persistence-restore path where the original key has been saved
// across processes (encrypt today, decrypt tomorrow).
//
// The single arm is identical to BLAKE3WithKey(key). The batched
// arm hot-dispatches to the fused ZMM-batched chain-absorb kernel
// when all four lanes share an input length in {20, 36, 68}; for
// any other lane-length configuration it falls back to four
// single-call invocations of the single arm.
//
// The ASM kernel returns 8 × uint32 per lane (32 bytes of digest);
// the closure repacks each lane's 8 uint32 into 4 uint64 for the
// itb.BatchHashFunc256 contract (LE byte ordering).
func BLAKE3256PairWithKey(fixedKey [32]byte) (itb.HashFunc256, itb.BatchHashFunc256) {
	single := BLAKE3WithKey(fixedKey)
	// Without a fused chain-absorb path (neither AVX-512 nor AVX2), the
	// 4-lane batched closure pays the cost of marshalling [4][]byte /
	// *byte / seeds arrays only to dispatch into the scalar Go fallback
	// in blake3asm_chain_scalar.go, which loops 4 lanes through fresh
	// blake3.NewKeyed → Write → Sum calls with no kernel-internal
	// batching benefit. Returning nil here lets process_cgo.go's
	// non-batch path drive the per-pixel hash through the upstream
	// zeebo/blake3 single-call asm directly — same end-state speed
	// as the single-Func path.
	if !blake3asm.HasAVX512Fused && !blake3asm.HasAVX2Fused {
		return single, nil
	}
	batched := func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
		commonLen := len(data[0])
		if (commonLen == 13 || commonLen == 20 || commonLen == 36 || commonLen == 68) &&
			len(data[1]) == commonLen &&
			len(data[2]) == commonLen &&
			len(data[3]) == commonLen {
			var dataPtrs [4]*byte
			dataPtrs[0] = &data[0][0]
			dataPtrs[1] = &data[1][0]
			dataPtrs[2] = &data[2][0]
			dataPtrs[3] = &data[3][0]
			var out8 [4][8]uint32
			seedsCopy := seeds
			switch commonLen {
			case 13:
				// Interlocked Barrier PRF fill shape (Lift 2).
				blake3asm.Blake3256ChainAbsorb13x4(
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out8,
				)
			case 20:
				blake3asm.Blake3256ChainAbsorb20x4(
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out8,
				)
			case 36:
				blake3asm.Blake3256ChainAbsorb36x4(
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out8,
				)
			case 68:
				blake3asm.Blake3256ChainAbsorb68x4(
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out8,
				)
			}
			var out [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				out[lane][0] = uint64(out8[lane][0]) | uint64(out8[lane][1])<<32
				out[lane][1] = uint64(out8[lane][2]) | uint64(out8[lane][3])<<32
				out[lane][2] = uint64(out8[lane][4]) | uint64(out8[lane][5])<<32
				out[lane][3] = uint64(out8[lane][6]) | uint64(out8[lane][7])<<32
			}
			return out
		}
		var out [4][4]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane] = single(data[lane], seeds[lane])
		}
		return out
	}
	return single, batched
}

// blake3HashHash backs the shipped registry entry's [Spec.HashHash]
// field: the unkeyed BLAKE3 hash.Hash form the HMAC construction
// wraps.
func blake3HashHash() hash.Hash {
	return blake3.New()
}

// blake3KeyedHash backs the shipped registry entry's [Spec.KeyedHash]
// field: BLAKE3's native keyed mode. The upstream constructor
// requires an exactly-32-byte key and returns an error for any other
// length. The explicit nil-on-error arm keeps a failed construction
// from leaking a typed-nil *blake3.Hasher through the hash.Hash
// interface.
func blake3KeyedHash(key []byte) (hash.Hash, error) {
	h, err := blake3.NewKeyed(key)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// blake3FusedChainHash is the [Spec.FusedChainHash256] factory of the
// blake3 entry. The returned evaluators run the ChainHash256 cascade
// inside one hashes/internal/blake3asm kernel call for the four
// per-pixel shapes (13 / 20 / 36 / 68 bytes) and report ok = false for
// any other input length or unequal lane lengths, which sends the seed
// back to the sequential loop. The key is the 32-byte fixed key the
// arms were built with. When ITB_FORCE_CHAINHASH_SEQ is set both
// evaluators are nil so the sequential loop runs end to end.
func blake3FusedChainHash(key []byte) (itb.FusedChainHashFunc256, itb.BatchFusedChainHashFunc256, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("hashes: %q fused cascade needs a 32-byte key, got %d", CipherBLAKE3, len(key))
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
			blake3asm.Fused256Chain13x1(&k, components, &data[0], &out)
		case 20:
			blake3asm.Fused256Chain20x1(&k, components, &data[0], &out)
		case 36:
			blake3asm.Fused256Chain36x1(&k, components, &data[0], &out)
		case 68:
			blake3asm.Fused256Chain68x1(&k, components, &data[0], &out)
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
			blake3asm.Fused256Chain13x4(&k, components, &dataPtrs, &out)
		case 20:
			blake3asm.Fused256Chain20x4(&k, components, &dataPtrs, &out)
		case 36:
			blake3asm.Fused256Chain36x4(&k, components, &dataPtrs, &out)
		case 68:
			blake3asm.Fused256Chain68x4(&k, components, &dataPtrs, &out)
		}
		return out, true
	}
	return single, batched, nil
}

// blake3InterlockFillBatch16 is the [Spec.InterlockFillBatch16x256]
// factory: the batch-16 Interlocked Barrier fill hook that runs the
// whole cascade over eight consecutive 13-byte fill blocks per call
// (see [itb.InterlockFillFunc16x256]).
func blake3InterlockFillBatch16(key []byte) (itb.InterlockFillFunc16x256, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 needs a 32-byte key, got %d", CipherBLAKE3, len(key))
	}
	var k [32]byte
	copy(k[:], key)
	return func(components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
		blake3asm.Fused256Fill13x8(&k, components, groupIdxBase, out)
	}, nil
}

// blake3FusedChainHash8 is the [Spec.FusedChainHash256x8] factory of
// the blake3 entry: the whole ChainHash256 cascade on eight lanes
// inside one hashes/internal/blake3asm eight-lane dispatcher call for
// the three nonce-buf shapes (20 / 36 / 68 bytes, all lanes equal); any
// other lane-length configuration reports ok = false and the seed runs
// the four-lane path twice. The hook is returned only where the
// eight-lane YMM arm is the selected tier (blake3asm.FusedX8Active), so
// a seed built on any other host or tier keeps the four-lane stride;
// under ITB_FORCE_CHAINHASH_SEQ it is nil as the four-lane evaluators
// are.
func blake3FusedChainHash8(key []byte) (itb.BatchFusedChainHashFunc256x8, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("hashes: %q fused cascade needs a 32-byte key, got %d", CipherBLAKE3, len(key))
	}
	if forcetier.ChainHashSeq() || !blake3asm.FusedX8Active() {
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
			blake3asm.Fused256Chain20x8(&k, components, &dataPtrs, &out)
		case 36:
			blake3asm.Fused256Chain36x8(&k, components, &dataPtrs, &out)
		case 68:
			blake3asm.Fused256Chain68x8(&k, components, &dataPtrs, &out)
		}
		return out, true
	}, nil
}
