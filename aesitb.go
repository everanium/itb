package itb

// AES-ITB primitive — 128-bit-state keyed hash primitive tuned to ITB's
// per-pixel PRF workload. Exposes a nonce-free (HashFunc128,
// BatchHashFunc128) factory that plugs into the shipped ChainHash128
// dispatch and the hashes/ package registry passthrough.
//
// This is an ITB-native primitive: reduced-round AES structure that is
// intentionally weak standalone (2 AES rounds per call, breakable by
// integral / differential / meet-in-the-middle attacks in the standard
// standalone model, matching the aes2r control in HARNESS.md § 3.7).
// The construction is safe only under ITB's compound defence stack —
// ChainHash cascade over 4–16 rounds × 8 seed components extends the
// effective key beyond primitive brute range, and the Interlocked
// Barrier / Part 2 absorption layers close the observation gap the
// primitive's own weakness would otherwise expose. HARNESS.md § 3.7
// records the empirical validation of the reduced-AES + ChainHash pattern:
// integral break at rounds = 1 (raw primitive) dissolves at rounds ≥ 2
// via the cascade feedforward mechanism.
//
// Design principles:
//
//   1. Combinadic-friendly. Round-based bijection over 128-bit state gives
//      near-uniform output distribution, ideal input for the 48-bit
//      Interlocked Barrier's combinadic unrank (Exact-B reduction into
//      C(48,16)·C(32,16) mask space).
//   2. NUMS round constants. The eight 128-bit round keys are big-endian
//      packings of FIPS 180-4 IV words (BLAKE3 IV == SHA-256 IV, SHA-512
//      IV, SHA-384 IV) — fractional bits of square roots of small primes —
//      so no designer-chosen value enters the constants.

import (
	"crypto/rand"
	"encoding/binary"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/aesitbasm"
)

// aesITBRoundConstants are eight pairwise-distinct Nothing-Up-My-Sleeve
// round keys, each a big-endian packing of FIPS 180-4 initial-hash-value
// words (fractional bits of square roots of small primes):
//
//   - RC[0..1]: BLAKE3 IV == SHA-256 IV (FIPS 180-4 § 5.3.3), eight 32-bit
//     words for p ∈ {2, 3, 5, 7, 11, 13, 17, 19}.
//   - RC[2..5]: SHA-512 IV (FIPS 180-4 § 5.3.5), eight 64-bit words for the
//     same primes.
//   - RC[6..7]: SHA-384 IV (FIPS 180-4 § 5.3.4), first four 64-bit words for
//     p ∈ {23, 29, 31, 37}.
//
// The generic (nonce-free) hash cycles RC[0..7] over its input blocks and
// finalises with RC[0] then RC[1].
var aesITBRoundConstants = [8][16]byte{
	// SHA-256 IV[0..3], [4..7]
	{0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85, 0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A},
	{0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C, 0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19},
	// SHA-512 IV[0..1], [2..3], [4..5], [6..7]
	{0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08, 0xBB, 0x67, 0xAE, 0x85, 0x84, 0xCA, 0xA7, 0x3B},
	{0x3C, 0x6E, 0xF3, 0x72, 0xFE, 0x94, 0xF8, 0x2B, 0xA5, 0x4F, 0xF5, 0x3A, 0x5F, 0x1D, 0x36, 0xF1},
	{0x51, 0x0E, 0x52, 0x7F, 0xAD, 0xE6, 0x82, 0xD1, 0x9B, 0x05, 0x68, 0x8C, 0x2B, 0x3E, 0x6C, 0x1F},
	{0x1F, 0x83, 0xD9, 0xAB, 0xFB, 0x41, 0xBD, 0x6B, 0x5B, 0xE0, 0xCD, 0x19, 0x13, 0x7E, 0x21, 0x79},
	// SHA-384 IV[0..1], [2..3]
	{0xCB, 0xBB, 0x9D, 0x5D, 0xC1, 0x05, 0x9E, 0xD8, 0x62, 0x9A, 0x29, 0x2A, 0x36, 0x7C, 0xD5, 0x07},
	{0x91, 0x59, 0x01, 0x5A, 0x30, 0x70, 0xDD, 0x17, 0x15, 0x2F, 0xEC, 0xD8, 0xF7, 0x0E, 0x59, 0x39},
}

// aesITB128GenericHash is the standard HashFunc128 for use through the
// shipped ChainHash128 dispatch. It is a nonce-free Merkle–Damgård
// construction over 16-byte blocks:
//
//	state  = fixedKey XOR (LE64(seed0) || LE64(seed1))
//	padded = data || PKCS#7 padding to a 16-byte multiple (always ≥ 1 byte)
//	state  = AESRound(state XOR block_i, RC[i mod 8])   for each block i
//	out    = AESRound(AESRound(state, RC[0]), RC[1])
//
// The padding is injective across input lengths, so inputs of different
// lengths never absorb the same block sequence. The result is bit-exact
// for any given (data, seed0, seed1) tuple.
func aesITB128GenericHash(fixedKey [16]byte) HashFunc128 {
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		var state [16]byte
		binary.LittleEndian.PutUint64(state[:8], binary.LittleEndian.Uint64(fixedKey[:8])^seed0)
		binary.LittleEndian.PutUint64(state[8:], binary.LittleEndian.Uint64(fixedKey[8:])^seed1)

		n := len(data)
		full := n &^ 15
		blk := 0
		for off := 0; off < full; off += 16 {
			for i := 0; i < 16; i++ {
				state[i] ^= data[off+i]
			}
			aes.RoundHW((*aes.Block)(&state), (*aes.Block)(&aesITBRoundConstants[blk&7]))
			blk++
		}
		rem := n - full
		pad := byte(16 - rem)
		for i := 0; i < rem; i++ {
			state[i] ^= data[full+i]
		}
		for i := rem; i < 16; i++ {
			state[i] ^= pad
		}
		aes.RoundHW((*aes.Block)(&state), (*aes.Block)(&aesITBRoundConstants[blk&7]))

		aes.RoundHW((*aes.Block)(&state), (*aes.Block)(&aesITBRoundConstants[0]))
		aes.RoundHW((*aes.Block)(&state), (*aes.Block)(&aesITBRoundConstants[1]))
		return binary.LittleEndian.Uint64(state[:8]), binary.LittleEndian.Uint64(state[8:])
	}
}

// MakeAESITB128Hash returns a (HashFunc128, BatchHashFunc128, [16]byte)
// triple wired around the AES-ITB primitive under an optional caller-
// supplied fixed key. The returned functions match the shipped
// MakeAreionSoEM256Hash / MakeAreionSoEM512Hash factory shape so the
// primitive can be plugged into the existing hashes-registry passthrough
// (see hashes/aesitb.go) without any pipeline surgery.
func MakeAESITB128Hash(key ...[16]byte) (HashFunc128, BatchHashFunc128, [16]byte) {
	var fixedKey [16]byte
	if len(key) > 0 {
		fixedKey = key[0]
	} else {
		if _, err := rand.Read(fixedKey[:]); err != nil {
			panic("itb: crypto/rand failed: " + err.Error())
		}
	}
	h, bh := makeAESITB128HashWithKey(fixedKey)
	return h, bh, fixedKey
}

// makeAESITB128HashWithKey builds the (HashFunc128, BatchHashFunc128) pair
// for a caller-provided key. Split out so tests / registry entries can
// bind a specific key without the CSPRNG draw MakeAESITB128Hash performs.
func makeAESITB128HashWithKey(fixedKey [16]byte) (HashFunc128, BatchHashFunc128) {
	h := aesITB128GenericHash(fixedKey)
	// The batched arm routes the four ITB per-pixel shapes (13 / 20 / 36 /
	// 68 bytes, all lanes equal) through the internal/aesitbasm 4-lane
	// chain-absorb dispatcher — the auto-selected AES tier, or the
	// package's scalar reference where no tier applies — and any other
	// lane-length configuration through four single-arm calls. Both
	// paths are bit-exact with h.
	key := fixedKey
	bh := func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
		var out [4][2]uint64
		n := len(data[0])
		if (n == 13 || n == 20 || n == 36 || n == 68) &&
			len(data[1]) == n && len(data[2]) == n && len(data[3]) == n {
			dataPtrs := [4]*byte{&data[0][0], &data[1][0], &data[2][0], &data[3][0]}
			switch n {
			case 13:
				aesitbasm.AESITB128ChainAbsorb13x4(&key, &seeds, &dataPtrs, &out)
			case 20:
				aesitbasm.AESITB128ChainAbsorb20x4(&key, &seeds, &dataPtrs, &out)
			case 36:
				aesitbasm.AESITB128ChainAbsorb36x4(&key, &seeds, &dataPtrs, &out)
			case 68:
				aesitbasm.AESITB128ChainAbsorb68x4(&key, &seeds, &dataPtrs, &out)
			}
			return out
		}
		for i := 0; i < 4; i++ {
			lo, hi := h(data[i], seeds[i][0], seeds[i][1])
			out[i] = [2]uint64{lo, hi}
		}
		return out
	}
	return h, bh
}
