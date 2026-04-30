package hashes

import (
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/chacha20"

	"github.com/everanium/itb"
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
func ChaCha20() itb.HashFunc256 {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		panic(err)
	}
	return ChaCha20WithKey(key)
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
