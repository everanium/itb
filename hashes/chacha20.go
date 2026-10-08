package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/chacha20asm"
	"github.com/everanium/itb/internal/forcetier"
)

// ChaCha20 returns a cached ChaCha20 itb.HashFunc256 along with the
// 32-byte fixed key the closure is bound to. With no argument the
// key is freshly generated via crypto/rand; passing a single
// caller-supplied [32]byte uses that key instead. Save the returned
// key for cross-process persistence.
//
// Construction (ARX-only PRF, no S-box / no table lookups): the
// fixed key is XOR'd with the seed components to derive a per-call
// 256-bit key, and the data is absorbed through an HChaCha20 chain —
// the data is encoded as 16-byte slot blocks of 15 data bytes and one
// tag byte, each block enters the counter / nonce words of a ChaCha20
// block state [σ | key | block], and the permuted words 0..3 and
// 12..15 (the HChaCha20 output, no feed-forward) are the key of the
// next block. The last key is the digest. The tag byte marks the final
// block and carries its data byte count, so the encoding is injective
// and prefix-free; every data byte enters a permutation input and the
// chaining state is 256 bits at every step, so the 128-, 256-, and
// 512-bit nonce configurations all reach the digest with full
// strength. See hashes/internal/chacha20asm.HChaCha20Chain for the
// step and the encoding.
//
// The closure allocates nothing: the per-call key, the block words
// and the chaining state live on the closure's stack frame.
// Concurrent goroutines may invoke the returned closure in parallel —
// there is no shared mutable state.
func ChaCha20(key ...[32]byte) (itb.HashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return ChaCha20WithKey(k), k
}

// ChaCha20WithKey returns the ChaCha20 closure built around a
// caller-supplied 32-byte fixed key, for serialization paths.
func ChaCha20WithKey(fixedKey [32]byte) itb.HashFunc256 {
	return func(data []byte, seed [4]uint64) [4]uint64 {
		// Per-call key derivation: fixedKey XOR seed components. The
		// seed never touches the block input words, and the data
		// never touches the key words: the data reaches the digest
		// only through the permutation inputs of the chain, keyed by
		// the per-call key and then by the pseudorandom key each
		// block produces for the next.
		var key [32]byte
		copy(key[:], fixedKey[:])
		for i := 0; i < 4; i++ {
			off := i * 8
			v := binary.LittleEndian.Uint64(key[off:])
			binary.LittleEndian.PutUint64(key[off:], v^seed[i])
		}
		return chacha20asm.HChaCha20Chain(&key, data)
	}
}

// ChaCha20256Pair returns a fresh (single, batched) ChaCha20-256 hash
// pair for itb.Seed256 integration. The two arms share the same
// internally-generated random 32-byte fixed key so per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc256).
//
// The batched arm evaluates the four lanes through the single arm;
// the per-pixel and Interlocked Barrier fill work of a seed built
// through the registry runs in the fused cascade kernels of
// hashes/internal/chacha20asm, installed by the chacha20 entry's
// FusedChainHash256 / InterlockFillBatch16x256 factories.
//
// With no argument a fresh 32-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [32]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func ChaCha20256Pair(key ...[32]byte) (itb.HashFunc256, itb.BatchHashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	single, batched := ChaCha20256PairWithKey(k)
	return single, batched, k
}

// ChaCha20256PairWithKey returns the (single, batched) ChaCha20-256
// pair built around a caller-supplied 32-byte fixed key, for the
// persistence-restore path where the original key has been saved
// across processes (encrypt today, decrypt tomorrow).
//
// The single arm is identical to ChaCha20WithKey(fixedKey); the
// batched arm evaluates the four lanes through it under their per-lane
// seeds and is bit-exact with four single calls on every input. Every
// shipped constructor path attaches the fused cascade hooks of the
// chacha20 registry entry, which the batched ChainHash256 entry points
// consult first, so the batched arm is the fallback for seeds built
// without those hooks.
func ChaCha20256PairWithKey(fixedKey [32]byte) (itb.HashFunc256, itb.BatchHashFunc256) {
	single := ChaCha20WithKey(fixedKey)
	batched := func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
		var out [4][4]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane] = single(data[lane], seeds[lane])
		}
		return out
	}
	return single, batched
}

// chacha20FusedChainHash is the [Spec.FusedChainHash256] factory of the
// chacha20 entry. The returned evaluators run the ChainHash256 cascade
// inside one hashes/internal/chacha20asm kernel call for the four
// per-pixel shapes (13 / 20 / 36 / 68 bytes) and report ok = false for
// any other input length or unequal lane lengths, which sends the seed
// back to the sequential loop. The key is the 32-byte fixed key the
// arms were built with. When ITB_FORCE_CHAINHASH_SEQ is set both
// evaluators are nil so the sequential loop runs end to end.
func chacha20FusedChainHash(key []byte) (itb.FusedChainHashFunc256, itb.BatchFusedChainHashFunc256, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("hashes: %q fused cascade needs a 32-byte key, got %d", CipherChaCha20, len(key))
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
			chacha20asm.Fused256Chain13x1(&k, components, &data[0], &out)
		case 20:
			chacha20asm.Fused256Chain20x1(&k, components, &data[0], &out)
		case 36:
			chacha20asm.Fused256Chain36x1(&k, components, &data[0], &out)
		case 68:
			chacha20asm.Fused256Chain68x1(&k, components, &data[0], &out)
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
			chacha20asm.Fused256Chain13x4(&k, components, &dataPtrs, &out)
		case 20:
			chacha20asm.Fused256Chain20x4(&k, components, &dataPtrs, &out)
		case 36:
			chacha20asm.Fused256Chain36x4(&k, components, &dataPtrs, &out)
		case 68:
			chacha20asm.Fused256Chain68x4(&k, components, &dataPtrs, &out)
		}
		return out, true
	}
	return single, batched, nil
}

// chacha20InterlockFillBatch16 is the [Spec.InterlockFillBatch16x256]
// factory: the batch-16 Interlocked Barrier fill hook that runs the
// whole cascade over eight consecutive 13-byte fill blocks per call
// (see [itb.InterlockFillFunc16x256]).
func chacha20InterlockFillBatch16(key []byte) (itb.InterlockFillFunc16x256, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("hashes: %q interlock fill batch-16 needs a 32-byte key, got %d", CipherChaCha20, len(key))
	}
	var k [32]byte
	copy(k[:], key)
	return func(components []uint64, groupIdxBase uint64, out *[8][4]uint64) {
		chacha20asm.Fused256Fill13x8(&k, components, groupIdxBase, out)
	}, nil
}

// chacha20FusedChainHash8 is the [Spec.FusedChainHash256x8] factory of
// the chacha20 entry: the whole ChainHash256 cascade on eight lanes
// inside one hashes/internal/chacha20asm eight-lane dispatcher call for
// the three nonce-buf shapes (20 / 36 / 68 bytes, all lanes equal); any
// other lane-length configuration reports ok = false and the seed runs
// the four-lane path twice. The hook is returned only where the
// eight-lane YMM arm is the selected tier (chacha20asm.FusedX8Active), so
// a seed built on any other host or tier keeps the four-lane stride;
// under ITB_FORCE_CHAINHASH_SEQ it is nil as the four-lane evaluators
// are.
func chacha20FusedChainHash8(key []byte) (itb.BatchFusedChainHashFunc256x8, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("hashes: %q fused cascade needs a 32-byte key, got %d", CipherChaCha20, len(key))
	}
	if forcetier.ChainHashSeq() || !chacha20asm.FusedX8Active() {
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
			chacha20asm.Fused256Chain20x8(&k, components, &dataPtrs, &out)
		case 36:
			chacha20asm.Fused256Chain36x8(&k, components, &dataPtrs, &out)
		case 68:
			chacha20asm.Fused256Chain68x8(&k, components, &dataPtrs, &out)
		}
		return out, true
	}, nil
}
