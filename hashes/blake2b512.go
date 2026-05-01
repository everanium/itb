package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/blake2b"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake2basm"
)

// BLAKE2b512 returns a cached BLAKE2b-512 itb.HashFunc512 with a
// freshly-generated 64-byte fixed key.
//
// BLAKE2b natively supports 512-bit output and up to a 64-byte key.
// The construction is identical to BLAKE2b256 modulo widths:
// H(key || data ^ seed) where the payload is zero-padded out to 64
// bytes when shorter, ensuring all eight seed uint64's contribute
// regardless of how short the caller's data is.
// BLAKE2b512 returns a cached BLAKE2b-512 itb.HashFunc512 along with
// the 64-byte fixed key the closure is bound to. With no argument a
// fresh key is generated via crypto/rand; passing a single
// caller-supplied [64]byte uses that key instead. Save the returned
// key for cross-process persistence.
func BLAKE2b512(key ...[64]byte) (itb.HashFunc512, [64]byte) {
	var k [64]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return BLAKE2b512WithKey(k), k
}

// BLAKE2b512WithKey returns the BLAKE2b-512 closure built around a
// caller-supplied 64-byte fixed key, for serialization paths.
//
// The closure runs on the upstream golang.org/x/crypto/blake2b path
// (which itself uses the BLAKE2b AVX2 kernel on amd64). For ITB
// throughput-critical use, prefer BLAKE2b512Pair: the batched arm of
// the pair dispatches to a 4-pixel-parallel AVX-512 ZMM kernel that
// amortises the per-call overhead the upstream single-pixel path
// cannot.
func BLAKE2b512WithKey(b2key [64]byte) itb.HashFunc512 {
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [8]uint64) [8]uint64 {
		const keyLen = 64
		const seedInjectBytes = 64
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
		for i := 0; i < 8; i++ {
			off := keyLen + i*8
			binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
		}
		digest := blake2b.Sum512(buf)
		*bufPtr = buf
		pool.Put(bufPtr)
		return [8]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
			binary.LittleEndian.Uint64(digest[32:]),
			binary.LittleEndian.Uint64(digest[40:]),
			binary.LittleEndian.Uint64(digest[48:]),
			binary.LittleEndian.Uint64(digest[56:]),
		}
	}
}

// BLAKE2b512Pair returns a fresh (single, batched) BLAKE2b-512 hash
// pair for itb.Seed512 integration. The two arms share the same
// internally-generated random 64-byte fixed key so per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc512).
//
// On amd64 with AVX-512+VL the batched arm dispatches to a fused
// ZMM-batched chain-absorb kernel for ITB's three SetNonceBits buf
// shapes (20 / 36 / 68 byte inputs), holding four lane-isolated
// BLAKE2b states in 16 ZMM registers across all 12 mixing rounds.
// On hosts without AVX-512+VL, and for non-{20,36,68} input lengths,
// the batched arm falls back to four single-call invocations and
// remains bit-exact.
//
// With no argument a fresh 64-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [64]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func BLAKE2b512Pair(key ...[64]byte) (itb.HashFunc512, itb.BatchHashFunc512, [64]byte) {
	var k [64]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	single, batched := BLAKE2b512PairWithKey(k)
	return single, batched, k
}

// BLAKE2b512PairWithKey returns the (single, batched) BLAKE2b-512 pair
// built around a caller-supplied 64-byte fixed key. Same role as the
// WithKey variants on the other hashes/ primitives — meant for the
// persistence-restore path where the original fixed key has been
// saved across processes (encrypt today, decrypt tomorrow).
//
// The single arm is identical to BLAKE2b512WithKey(fixedKey). The
// batched arm hot-dispatches to the fused ZMM-batched chain-absorb
// kernel when all four lanes share an input length in {20, 36, 68};
// for any other lane-length configuration it falls back to four
// single-call invocations of the single arm.
func BLAKE2b512PairWithKey(fixedKey [64]byte) (itb.HashFunc512, itb.BatchHashFunc512) {
	single := BLAKE2b512WithKey(fixedKey)
	batched := func(data *[4][]byte, seeds [4][8]uint64) [4][8]uint64 {
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
			var out [4][8]uint64
			seedsCopy := seeds
			switch commonLen {
			case 20:
				blake2basm.Blake2b512ChainAbsorb20x4(
					&blake2basm.Blake2bIV512Param,
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			case 36:
				blake2basm.Blake2b512ChainAbsorb36x4(
					&blake2basm.Blake2bIV512Param,
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			case 68:
				blake2basm.Blake2b512ChainAbsorb68x4(
					&blake2basm.Blake2bIV512Param,
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			}
			return out
		}
		var out [4][8]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane] = single(data[lane], seeds[lane])
		}
		return out
	}
	return single, batched
}
