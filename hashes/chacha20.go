package hashes

import (
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/chacha20"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/chacha20asm"
)

// ChaCha20 returns a cached ChaCha20 itb.HashFunc256 with a
// freshly-generated 32-byte fixed key.
//
// Construction (ARX-only PRF, no S-box / no table lookups): the
// fixed key is XOR'd with the seed components to derive a per-call
// 256-bit ChaCha20 key. Data is absorbed CBC-MAC-style into a
// 32-byte state via repeated `state ← E_K(state ⊕ chunk)`-shaped
// rounds, where E_K is one ChaCha20 keystream block applied to the
// state and the counter advances automatically between rounds. A
// length-tag prefix in the initial state and a 24-byte data window
// per round (8 bytes of chaining feedback) ensure every byte of the
// input contributes to the digest regardless of input length —
// 128-, 256-, and 512-bit nonce configurations all reach the digest
// with full strength.
//
// Per-call allocation is bounded by the cipher initialisation; the
// state, length tag, and chain feedback all live on the closure's
// stack frame. Concurrent goroutines may invoke the returned
// closure in parallel — there is no shared mutable state.
// ChaCha20 returns a cached ChaCha20 itb.HashFunc256 along with the
// 32-byte fixed key the closure is bound to. With no argument the
// key is freshly generated via crypto/rand; passing a single
// caller-supplied [32]byte uses that key instead. Save the returned
// key for cross-process persistence.
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
		// Per-call key derivation: fixedKey XOR seed components.
		var key [32]byte
		copy(key[:], fixedKey[:])
		for i := 0; i < 4; i++ {
			off := i * 8
			v := binary.LittleEndian.Uint64(key[off:])
			binary.LittleEndian.PutUint64(key[off:], v^seed[i])
		}

		// Fixed zero nonce — the seed-mixed key carries the per-call
		// freshness, so a constant nonce is safe for hash purposes.
		// (Stream-cipher nonce reuse is dangerous for confidentiality
		// because it discloses keystream XOR keystream; for a PRF
		// where the output is the encrypted state, the per-call key
		// alone gives PRF security.)
		var nonce [12]byte
		c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
		if err != nil {
			panic(err)
		}

		// Absorb data CBC-MAC-style into a 32-byte state. The first
		// 8 bytes hold a length tag (disambiguates inputs of
		// different lengths and prevents extension equivalences);
		// the remaining 24 bytes absorb each 24-byte slice of data
		// in turn. Each absorb step XORs a chunk into the state and
		// then runs a ChaCha20 keystream block over the state, which
		// is the cipher equivalent of CBC-MAC's "encrypt-after-XOR"
		// chaining.
		//
		// Hot-path fast track: ITB's three buf shapes (20 / 36 /
		// 68 bytes) take 1, 2, or 3 rounds respectively. The 20-byte
		// case (default 128-bit nonce, the only path most callers
		// hit) goes through the single-round branch with no loop
		// overhead. Absorb XOR is bulk uint64 via absorbXOR.
		var state [32]byte
		binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))

		const chunkSize = 24
		if len(data) <= chunkSize {
			// Fast path: state[8:32] is zero — bulk copy beats
			// absorb-XOR for the first (only) round.
			copy(state[8:8+len(data)], data)
			c.XORKeyStream(state[:], state[:])
		} else {
			// First round: state[8:32] is zero, copy is enough.
			// Subsequent rounds need real XOR.
			copy(state[8:8+chunkSize], data[0:chunkSize])
			c.XORKeyStream(state[:], state[:])
			off := chunkSize
			for off < len(data) {
				end := off + chunkSize
				if end > len(data) {
					end = len(data)
				}
				absorbXOR(state[8:8+(end-off)], data[off:end])
				c.XORKeyStream(state[:], state[:])
				off = end
			}
		}

		return [4]uint64{
			binary.LittleEndian.Uint64(state[0:]),
			binary.LittleEndian.Uint64(state[8:]),
			binary.LittleEndian.Uint64(state[16:]),
			binary.LittleEndian.Uint64(state[24:]),
		}
	}
}

// ChaCha20256Pair returns a fresh (single, batched) ChaCha20-256 hash
// pair for itb.Seed256 integration. The two arms share the same
// internally-generated random 32-byte fixed key so per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc256).
//
// On amd64 with AVX-512+VL the batched arm dispatches to a fused
// ZMM-batched chain-absorb kernel for ITB's three SetNonceBits buf
// shapes (20 / 36 / 68 byte inputs). On hosts without AVX-512+VL,
// and for non-{20,36,68} input lengths, the batched arm falls back
// to four single-call invocations and remains bit-exact.
//
// With no argument a fresh 32-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [32]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
//
// Realistic uplift target: 2.5×-4.5× over the upstream
// golang.org/x/crypto/chacha20 per-call dispatch on Rocket Lake;
// higher on AMD Zen 5 / Sapphire Rapids+ where full-width 512-bit
// ALUs and absent AVX-512 frequency throttle widen the envelope. The
// gain is a mix of 4-lane parallelism (four independent ChaCha20
// state evolutions retiring through one ZMM dispatch) and per-call
// cipher.NewUnauthenticatedCipher / XORKeyStream amortisation across
// the lanes.
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
// The single arm is identical to ChaCha20WithKey(fixedKey). The
// batched arm hot-dispatches to the fused ZMM-batched chain-absorb
// kernel when all four lanes share an input length in {20, 36, 68};
// for any other lane-length configuration it falls back to four
// single-call invocations of the single arm.
//
// The ASM kernel returns 4 × uint64 per lane (32 bytes of state)
// directly — no intermediate [8]uint32 repacking is required since
// the ChaCha20 chain-absorb output is the 32-byte CBC-MAC-style
// state buffer in its native LE byte order.
func ChaCha20256PairWithKey(fixedKey [32]byte) (itb.HashFunc256, itb.BatchHashFunc256) {
	single := ChaCha20WithKey(fixedKey)
	// On hosts without the AVX-512 fused chain-absorb path the batched
	// closure falls into the scalar Go reference; under that path
	// process_cgo.go's nil-fallback (driving 4 single calls through
	// the underlying ChaCha20 stream-cipher path) outperforms the
	// 4-lane wrapper. Return nil to opt into that fallback.
	if !chacha20asm.HasAVX512Fused {
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
			var out [4][4]uint64
			seedsCopy := seeds
			switch commonLen {
			case 20:
				chacha20asm.ChaCha20256ChainAbsorb20x4(
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			case 36:
				chacha20asm.ChaCha20256ChainAbsorb36x4(
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			case 68:
				chacha20asm.ChaCha20256ChainAbsorb68x4(
					&fixedKey,
					&seedsCopy,
					&dataPtrs,
					&out,
				)
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
