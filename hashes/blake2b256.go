package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/blake2b"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake2basm"
)

// BLAKE2b256 returns a cached BLAKE2b-256 itb.HashFunc256 with a
// freshly-generated 32-byte fixed key.
//
// Construction prepends the fixed key as a 32-byte prefix to the
// hash input and mixes seed components by XOR over the next 32
// bytes: H(key || data ^ seed). blake2b.Sum256 is the entry point
// (no allocation, no keyed-mode handle), so the closure has zero
// per-call allocations modulo the pooled scratch buffer.
//
// The payload region is zero-padded out to 32 bytes when len(data)
// is shorter, ensuring all four seed uint64's contribute regardless
// of how short the caller's data is — important for ITB which
// hashes 20-byte (pixel_le + nonce) inputs in the inner loop.
// BLAKE2b256 returns a cached BLAKE2b-256 itb.HashFunc256 along with
// the 32-byte fixed key the closure is bound to. With no argument a
// fresh key is generated via crypto/rand; passing a single
// caller-supplied [32]byte uses that key instead. Save the returned
// key for cross-process persistence.
func BLAKE2b256(key ...[32]byte) (itb.HashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return BLAKE2b256WithKey(k), k
}

// BLAKE2b256WithKey returns the BLAKE2b-256 closure built around a
// caller-supplied 32-byte fixed key, for serialization paths.
//
// The closure runs on the upstream golang.org/x/crypto/blake2b path
// (which itself uses the BLAKE2b AVX2 kernel on amd64). For ITB
// throughput-critical use, prefer BLAKE2b256Pair: the batched arm of
// the pair dispatches to a 4-pixel-parallel AVX-512 ZMM kernel that
// amortises the per-call overhead the upstream single-pixel path
// cannot.
func BLAKE2b256WithKey(b2key [32]byte) itb.HashFunc256 {
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
		digest := blake2b.Sum256(buf)
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

// BLAKE2b256Pair returns a fresh (single, batched) BLAKE2b-256 hash
// pair for itb.Seed256 integration. The two arms share the same
// internally-generated random 32-byte fixed key so per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc256).
//
// On amd64 with AVX-512+VL the batched arm dispatches to a fused
// ZMM-batched chain-absorb kernel for ITB's three SetNonceBits buf
// shapes (20 / 36 / 68 byte inputs). On hosts without AVX-512+VL, and
// for non-{20,36,68} input lengths, the batched arm falls back to
// four single-call invocations and remains bit-exact.
//
// With no argument a fresh 32-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [32]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func BLAKE2b256Pair(key ...[32]byte) (itb.HashFunc256, itb.BatchHashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	single, batched := BLAKE2b256PairWithKey(k)
	return single, batched, k
}

// BLAKE2b256PairWithKey returns the (single, batched) BLAKE2b-256 pair
// built around a caller-supplied 32-byte fixed key. Same role as the
// WithKey variants on the other hashes/ primitives — meant for the
// persistence-restore path where the original fixed key has been
// saved across processes (encrypt today, decrypt tomorrow).
//
// The single arm is identical to BLAKE2b256WithKey(fixedKey). The
// batched arm hot-dispatches to the fused ZMM-batched chain-absorb
// kernel when all four lanes share an input length in {20, 36, 68};
// for any other lane-length configuration it falls back to four
// single-call invocations of the single arm.
func BLAKE2b256PairWithKey(fixedKey [32]byte) (itb.HashFunc256, itb.BatchHashFunc256) {
	single := BLAKE2b256WithKey(fixedKey)
	// On hosts without the AVX-512 fused chain-absorb path the batched
	// closure dispatches through the scalar Go reference, which costs
	// the 4-lane data-marshalling wrapper on top of work that the
	// single arm already performs via the upstream golang.org/x/crypto
	// BLAKE2b asm. Returning nil here lets process_cgo.go's nil-
	// fallback drive per-pixel hashing through the single arm
	// directly — same OLDBENCH-style speed without the wrapper tax.
	if !blake2basm.HasAVX512Fused {
		return single, nil
	}
	batched := func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
		commonLen := len(data[0])
		if (commonLen == 20 || commonLen == 36 || commonLen == 68) &&
			len(data[1]) == commonLen &&
			len(data[2]) == commonLen &&
			len(data[3]) == commonLen {
			var dataPtrs [4]*byte
			dataPtrs[0] = &data[0][0]
			dataPtrs[1] = &data[1][0]
			dataPtrs[2] = &data[2][0]
			dataPtrs[3] = &data[3][0]
			var out8 [4][8]uint64
			seedsCopy := seeds
			switch commonLen {
			case 20:
				blake2basm.Blake2b256ChainAbsorb20x4(
					&blake2basm.Blake2bIV256Param,
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out8,
				)
			case 36:
				blake2basm.Blake2b256ChainAbsorb36x4(
					&blake2basm.Blake2bIV256Param,
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out8,
				)
			case 68:
				blake2basm.Blake2b256ChainAbsorb68x4(
					&blake2basm.Blake2bIV256Param,
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out8,
				)
			}
			var out [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				out[lane][0] = out8[lane][0]
				out[lane][1] = out8[lane][1]
				out[lane][2] = out8[lane][2]
				out[lane][3] = out8[lane][3]
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
