package itb

// AES-ITB primitive — 128-bit-state keyed hash primitive tuned to ITB's
// per-pixel PRF workload. Exposes a nonce-free (HashFunc128,
// BatchHashFunc128) factory that plugs into the shipped ChainHash128
// dispatch and the hashes/ package registry passthrough.
//
// This is an ITB-native primitive: reduced-round AES structure that is
// intentionally weak standalone (one AES round per absorbed block plus
// two finalising rounds — three rounds at the one-block shapes — with
// the seed entering once by XOR ahead of a public permutation, so the
// raw primitive is one-pair invertible with the full state visible and
// carries a probability-1 Square integral; HARNESS.md § 3.10 records
// these standalone breaks alongside the aes2r control of § 3.7). The
// construction is safe only under ITB's compound defence stack — the
// ChainHash cascade over 4–16 rounds (8–32 seed components) extends the
// effective key beyond primitive brute range, and the Rank Barrier /
// Pixel Barrier absorption layers close the observation gap the
// primitive's own weakness would otherwise expose. HARNESS.md § 3.10
// records the empirical validation: the integral and the structured
// recoveries measured at rounds = 1 (raw primitive) sit at the floor on
// the shipped observable from rounds ≥ 2 via the cascade feedforward.
//
// Design principles:
//
//   1. Combinadic-friendly. Round-based bijection over 128-bit state gives
//      near-uniform output distribution, ideal input for the 48-bit
//      Interlocked Barrier's combinadic unrank (Exact-B reduction into
//      C(48,16)·C(32,16) mask space).
//   2. NUMS round constants. The eight 128-bit round keys are the first
//      eight 128-bit words of the hexadecimal fractional expansion of π,
//      so no designer-chosen value enters the constants.

import (
	"crypto/rand"
	"encoding/binary"
	"runtime"

	"github.com/everanium/areion"
)

// aesITBRoundConstants are eight pairwise-distinct Nothing-Up-My-Sleeve
// round keys: RC[i] is fractional hexadecimal digits 32·i + 1 … 32·i + 32
// of π (π = 3.243F6A88…), i.e. the first eight 128-bit words of its
// hexadecimal fractional expansion. Byte order: the 128-bit word is
// loaded big-endian — its most significant byte (the first two hex
// digits) is AES state byte 0 and its least significant byte is state
// byte 15, in the column-major state order s[4·col + row] that AESENC
// uses. RC[0] = 243F6A88 85A308D3 13198A2E 03707344 thus loads as
// state bytes 0x24, 0x3F, 0x6A, 0x88, …, 0x44.
//
// The generic (nonce-free) hash runs RC[i mod 8] over its absorbed
// blocks i = 0 … b−1 and finalises with RC[b mod 8] then
// RC[(b+1) mod 8], continuing the cycle, so one call uses no constant
// twice up to six absorbed blocks.
var aesITBRoundConstants = [8][16]byte{
	{0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44},
	{0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0, 0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89},
	{0x45, 0x28, 0x21, 0xE6, 0x38, 0xD0, 0x13, 0x77, 0xBE, 0x54, 0x66, 0xCF, 0x34, 0xE9, 0x0C, 0x6C},
	{0xC0, 0xAC, 0x29, 0xB7, 0xC9, 0x7C, 0x50, 0xDD, 0x3F, 0x84, 0xD5, 0xB5, 0xB5, 0x47, 0x09, 0x17},
	{0x92, 0x16, 0xD5, 0xD9, 0x89, 0x79, 0xFB, 0x1B, 0xD1, 0x31, 0x0B, 0xA6, 0x98, 0xDF, 0xB5, 0xAC},
	{0x2F, 0xFD, 0x72, 0xDB, 0xD0, 0x1A, 0xDF, 0xB7, 0xB8, 0xE1, 0xAF, 0xED, 0x6A, 0x26, 0x7E, 0x96},
	{0xBA, 0x7C, 0x90, 0x45, 0xF1, 0x2C, 0x7F, 0x99, 0x24, 0xA1, 0x99, 0x47, 0xB3, 0x91, 0x6C, 0xF7},
	{0x08, 0x01, 0xF2, 0xE2, 0x85, 0x8E, 0xFC, 0x16, 0x63, 0x69, 0x20, 0xD8, 0x71, 0x57, 0x4E, 0x69},
}

// aesITB128GenericHash is the standard HashFunc128 for use through the
// shipped ChainHash128 dispatch. It is a nonce-free CBC-MAC-style chain
// absorption over public AES rounds, keyed through the initial state, on
// 16-byte blocks:
//
//	state  = fixedKey XOR (LE64(seed0) || LE64(seed1))
//	padded = data || PKCS#7 padding to a 16-byte multiple (always ≥ 1 byte)
//	state  = AESRound(state XOR block_i, RC[i mod 8])   for each block i < b
//	out    = AESRound(AESRound(state, RC[b mod 8]), RC[(b+1) mod 8])
//
// where b is the number of padded blocks. The padding is injective
// across input lengths, so inputs of different lengths never absorb the
// same block sequence. The result is bit-exact
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
			areion.AES128Round((*areion.Block)(&state), (*areion.Block)(&aesITBRoundConstants[blk&7]))
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
		areion.AES128Round((*areion.Block)(&state), (*areion.Block)(&aesITBRoundConstants[blk&7]))
		blk++

		areion.AES128Round((*areion.Block)(&state), (*areion.Block)(&aesITBRoundConstants[blk&7]))
		areion.AES128Round((*areion.Block)(&state), (*areion.Block)(&aesITBRoundConstants[(blk+1)&7]))
		lo := binary.LittleEndian.Uint64(state[:8])
		hi := binary.LittleEndian.Uint64(state[8:])
		clear(state[:])
		runtime.KeepAlive(&state)
		return lo, hi
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
	// The batched arm evaluates the four lanes through four single-arm
	// calls of h. Every shipped constructor path attaches the fused
	// cascade hook (Seed128.BatchFusedChain), which the batched
	// ChainHash128 entry points consult first, so this closure is the
	// fallback for seeds built without that hook.
	bh := func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
		var out [4][2]uint64
		for i := 0; i < 4; i++ {
			lo, hi := h(data[i], seeds[i][0], seeds[i][1])
			out[i] = [2]uint64{lo, hi}
		}
		return out
	}
	return h, bh
}
