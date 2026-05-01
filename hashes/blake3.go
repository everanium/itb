package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/blake3asm"
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
// ZMM-batched chain-absorb kernel for ITB's three SetNonceBits buf
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
			var out8 [4][8]uint32
			seedsCopy := seeds
			switch commonLen {
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
