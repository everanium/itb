// Package itb — 4-way batched Areion-SoEM primitives.
//
// AreionSoEM256x4 and AreionSoEM512x4 process four independent
// (key, input) tuples simultaneously using the upstream
// `github.com/jedisct1/go-aes` parallel AES-round primitives. On x86_64
// CPUs with VAES (AVX-512) the inner loop dispatches to a single
// `vaesenc` instruction processing four AES blocks in one ZMM register;
// without VAES the same Block4 path falls back to four sequential
// AES-NI instructions. ARM64 with Crypto Extensions uses the analogous
// parallel hardware instruction.
//
// Bit-exact parity invariant. For every i in {0,1,2,3}:
//
//	AreionSoEM256x4(keys, inputs)[i] == aes.AreionSoEM256(&keys[i], &inputs[i])
//	AreionSoEM512x4(keys, inputs)[i] == aes.AreionSoEM512(&keys[i], &inputs[i])
//
// This is enforced empirically by `TestAreionSoEM{256,512}x4Parity` in
// areion_test.go on every test run and is mandatory for ITB security
// claims under the batched dispatch path (any divergence breaks the
// PRF assumption invocation in SECURITY.md).
//
// Algorithm reference. The SoEM construction is from Iwata-Mennink
// (Sum of Even-Mansour, beyond-birthday-bound PRF):
//
//	F(k1, k2, m) = P(m ⊕ k1) ⊕ P(m ⊕ k2 ⊕ d)
//
// where P is the Areion permutation (10 rounds for Areion256, 15 for
// Areion512), d is a fixed domain separation constant (`[N]byte{0x01}`),
// k1 is the first half of the SoEM key, k2 the second half. The
// upstream serial reference is in
// `github.com/jedisct1/go-aes/areion.go` (`AreionSoEM256` /
// `AreionSoEM512`). The 4-way batched composition here applies the
// permutation to four independent states in parallel using the
// `Block4`/`RoundNoKey4HW`/`FinalRoundNoKey4HW`/`XorBlock4` primitives
// from the same upstream package.
//
// Layout. Each batched permutation reshapes the four Areion states from
// the natural array-of-structures layout (one contiguous 32- or 64-byte
// state per lane) into structure-of-arrays layout where every Block4
// holds the same logical AES-block index across all four lanes. The
// reshape is a one-shot 64–256 byte copy at entry and exit; all round
// operations run entirely in the SoA layout so VAES instructions can
// process four lanes per issued instruction without per-round
// gather/scatter cost.
package itb

import (
	"crypto/rand"
	"encoding/binary"
	"unsafe"

	"github.com/jedisct1/go-aes"
)

// Areion round constants (digits of pi, little-endian) — must match
// `github.com/jedisct1/go-aes/areion.go:areionRoundConstants`. Areion256
// uses entries 0..9; Areion512 uses entries 0..14. The upstream constants
// are package-private so the values are duplicated here verbatim. Any
// drift from upstream breaks the parity invariant; the parity test
// catches divergence on every run.
var areionRC = [15][16]byte{
	{0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24},
	{0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4},
	{0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45},
	{0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0},
	{0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92},
	{0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f},
	{0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba},
	{0x90, 0xe6, 0x74, 0x15, 0x87, 0x0d, 0x92, 0x36, 0x66, 0xc1, 0xef, 0x58, 0x28, 0x2e, 0x1f, 0x80},
	{0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4},
	{0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71},
	{0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c},
	{0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca},
	{0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c},
	{0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78},
	{0xb6, 0x10, 0xab, 0x2a, 0x6a, 0x39, 0xca, 0x55, 0x40, 0x14, 0xe8, 0x63, 0x62, 0x98, 0x48, 0x57},
}

// areionSoEM256DomainSepX4 is the SoEM-256 domain separator broadcast to
// four lanes. The serial value is `[32]byte{0x01}` (one byte 0x01 at
// position 0, the rest zero).
var areionSoEM256DomainSepX4 = [32]byte{0x01}

// areionSoEM512DomainSepX4 is the SoEM-512 domain separator broadcast.
// Serial value is `[64]byte{0x01}`.
var areionSoEM512DomainSepX4 = [64]byte{0x01}

// The pre-broadcast round constant table (`AreionRC4x`) used by the
// VAES assembly path lives in `internal/areionasm` because Go does not
// allow assembly files in CGO-using packages. The amd64 ASM symbol
// references `·AreionRC4x(SB)` from that subpackage; the dispatch
// functions in `areion_amd64.go` import it.

// rcBlock4 broadcasts one 16-byte round constant into a Block4 (four
// identical 16-byte copies, one per lane). Result is suitable for
// `XorBlock4` against a four-lane state.
func rcBlock4(rc *[16]byte) aes.Block4 {
	var out aes.Block4
	copy(out[0:16], rc[:])
	copy(out[16:32], rc[:])
	copy(out[32:48], rc[:])
	copy(out[48:64], rc[:])
	return out
}

// areionZeroKey4 is a four-lane all-zero round key reused for every
// `Round4HW` / `FinalRound4HW` call inside the Areion permutations.
// Areion uses no-key AES rounds, but the upstream library only routes
// the *keyed* `Round4HW` / `FinalRound4HW` to VAES instructions on
// x86_64 (`vaes_amd64.go:vaesRound4` / `vaesFinalRound4`); the
// `RoundNoKey4HW` / `FinalRoundNoKey4HW` paths fall back to four
// sequential single-block AES-NI invocations even when VAES is
// available. Calling `Round4HW(state, &areionZeroKey4)` instead is
// mathematically identical to `RoundNoKey4HW(state)` (`AESENC` with the
// zero round key omits the AddRoundKey contribution) and routes to the
// VAES single-instruction-per-four-blocks path. Same logic applies to
// `FinalRound4HW`.
var areionZeroKey4 aes.Key4

// roundNoKey4Fast applies one 4-way AES "round-without-key" using the
// VAES-accelerated keyed path with a constant zero key. Equivalent to
// `roundNoKey4Fast(state)` byte-for-byte (verified by parity test on
// every run) but ~4× faster on hardware with VAES + AVX-512 because the
// upstream `RoundNoKey4HW` does not activate the VAES path.
func roundNoKey4Fast(state *aes.Block4) {
	aes.Round4HW(state, &areionZeroKey4)
}

// finalRoundNoKey4Fast is the VAES-routed counterpart for the final AES
// round (no MixColumns).
func finalRoundNoKey4Fast(state *aes.Block4) {
	aes.FinalRound4HW(state, &areionZeroKey4)
}

// pack256x4SoA reshapes four Areion256 states from array-of-structures
// (lane i state contiguous at &states[i]) into structure-of-arrays
// (Block4_0 holds x0 of every lane, Block4_1 holds x1 of every lane).
// Used at entry of `areion256Permutex4` so all subsequent round work
// runs in SoA layout.
func pack256x4SoA(states *[4][32]byte) (b0, b1 aes.Block4) {
	// state[i][0:16] -> b0[i*16 : (i+1)*16]
	// state[i][16:32] -> b1[i*16 : (i+1)*16]
	for i := 0; i < 4; i++ {
		copy(b0[i*16:(i+1)*16], states[i][0:16])
		copy(b1[i*16:(i+1)*16], states[i][16:32])
	}
	return
}

// unpack256x4SoA reverses `pack256x4SoA`, writing the four lanes back
// into the AOS layout.
func unpack256x4SoA(b0, b1 *aes.Block4, states *[4][32]byte) {
	for i := 0; i < 4; i++ {
		copy(states[i][0:16], b0[i*16:(i+1)*16])
		copy(states[i][16:32], b1[i*16:(i+1)*16])
	}
}

// areion256Permutex4Default is the portable Go implementation of the
// 4-way batched Areion256 permutation. Used directly on non-amd64
// platforms and as the parity reference / fallback path on amd64 when
// VAES is unavailable. The amd64 fast path (`areion_amd64.s`)
// implements the same operation with full-loop-unrolled VAES ZMM
// instructions, avoiding the per-round Go function call overhead that
// dominates this implementation's wall-clock cost.
//
// Mirrors the serial round structure in
// `github.com/jedisct1/go-aes/areion.go:areion256PermuteSoftware`
// bit-for-bit; the only difference is each operation runs on four
// lanes via `Round4HW` (with zero key, equivalent to `RoundNoKey4`) /
// `FinalRound4HW` / `XorBlock4` instead of per-block primitives.
func areion256Permutex4Default(states *[4][32]byte) {
	x0, x1 := pack256x4SoA(states)

	for r := 0; r < 10; r++ {
		rc := rcBlock4(&areionRC[r])
		var temp aes.Block4

		if r%2 == 0 {
			// temp = x0
			temp = x0
			// RoundNoKey(temp)
			roundNoKey4Fast(&temp)
			// temp ^= rc
			aes.XorBlock4(&temp, &temp, &rc)
			// RoundNoKey(temp)
			roundNoKey4Fast(&temp)
			// temp ^= x1
			aes.XorBlock4(&temp, &temp, &x1)
			// FinalRoundNoKey(x0)
			finalRoundNoKey4Fast(&x0)
			// x1 = temp
			x1 = temp
		} else {
			// temp = x1
			temp = x1
			roundNoKey4Fast(&temp)
			aes.XorBlock4(&temp, &temp, &rc)
			roundNoKey4Fast(&temp)
			aes.XorBlock4(&temp, &temp, &x0)
			finalRoundNoKey4Fast(&x1)
			// x0 = temp
			x0 = temp
		}
	}

	unpack256x4SoA(&x0, &x1, states)
}

// AreionSoEM256x4 evaluates the Areion-SoEM-256 PRF on four independent
// (key, input) tuples in parallel.
//
//	output[i] = aes.AreionSoEM256(&keys[i], &inputs[i])  for i in {0,1,2,3}
//
// Each `keys[i]` is 64 bytes (two 32-byte SoEM subkeys k1‖k2). Each
// `inputs[i]` is 32 bytes. The result is four independent 32-byte PRF
// outputs.
//
// The function is `crypto/rand`-equivalent in security to four serial
// `aes.AreionSoEM256` calls — output is bit-exact identical (verified
// in `TestAreionSoEM256x4Parity`). Throughput is faster on x86_64 with
// VAES (AVX-512) because the four lanes share VAES instruction issue;
// on hardware without VAES the function falls back to per-lane AES-NI
// at near-identical cost to four serial calls.
func AreionSoEM256x4(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	// Build state1 = input ⊕ key[0:32] and state2 = input ⊕ key[32:64] ⊕ d
	// for every lane. Two parallel Areion256 permutations of four lanes
	// each: 8 permutations total, dispatched as 2 × `areion256Permutex4`.
	//
	// XOR loops use uint64 chunks (4 ops per 32-byte half instead of 32
	// byte-level ops), cutting Go-side overhead by ~8× over the natural
	// byte-by-byte loop. The domain-separator effect collapses to a
	// single uint64 constant (`areionSoEM256DomainSepU64 = 0x01`)
	// because the serial domain separator is `[32]byte{0x01}` — only
	// the first byte is nonzero, the remaining 31 bytes XOR as zero.
	var state1, state2 [4][32]byte
	const domainSepU64 = uint64(0x01) // = areionSoEM256DomainSepX4 first u64 word
	keysU64 := (*[4][8]uint64)(unsafe.Pointer(keys))
	inputsU64 := (*[4][4]uint64)(unsafe.Pointer(inputs))
	state1U64 := (*[4][4]uint64)(unsafe.Pointer(&state1))
	state2U64 := (*[4][4]uint64)(unsafe.Pointer(&state2))
	for i := 0; i < 4; i++ {
		state1U64[i][0] = inputsU64[i][0] ^ keysU64[i][0]
		state1U64[i][1] = inputsU64[i][1] ^ keysU64[i][1]
		state1U64[i][2] = inputsU64[i][2] ^ keysU64[i][2]
		state1U64[i][3] = inputsU64[i][3] ^ keysU64[i][3]
		state2U64[i][0] = inputsU64[i][0] ^ keysU64[i][4] ^ domainSepU64
		state2U64[i][1] = inputsU64[i][1] ^ keysU64[i][5]
		state2U64[i][2] = inputsU64[i][2] ^ keysU64[i][6]
		state2U64[i][3] = inputsU64[i][3] ^ keysU64[i][7]
	}

	areion256Permutex4(&state1)
	areion256Permutex4(&state2)

	// Output[i] = state1[i] ⊕ state2[i]
	var out [4][32]byte
	outU64 := (*[4][4]uint64)(unsafe.Pointer(&out))
	for i := 0; i < 4; i++ {
		outU64[i][0] = state1U64[i][0] ^ state2U64[i][0]
		outU64[i][1] = state1U64[i][1] ^ state2U64[i][1]
		outU64[i][2] = state1U64[i][2] ^ state2U64[i][2]
		outU64[i][3] = state1U64[i][3] ^ state2U64[i][3]
	}
	return out
}

// pack512x4SoA reshapes four Areion512 states from AOS into four Block4
// SoA buffers, one per AES-block index (x0, x1, x2, x3).
func pack512x4SoA(states *[4][64]byte) (b0, b1, b2, b3 aes.Block4) {
	for i := 0; i < 4; i++ {
		copy(b0[i*16:(i+1)*16], states[i][0:16])
		copy(b1[i*16:(i+1)*16], states[i][16:32])
		copy(b2[i*16:(i+1)*16], states[i][32:48])
		copy(b3[i*16:(i+1)*16], states[i][48:64])
	}
	return
}

// unpack512x4SoA reverses `pack512x4SoA`.
func unpack512x4SoA(b0, b1, b2, b3 *aes.Block4, states *[4][64]byte) {
	for i := 0; i < 4; i++ {
		copy(states[i][0:16], b0[i*16:(i+1)*16])
		copy(states[i][16:32], b1[i*16:(i+1)*16])
		copy(states[i][32:48], b2[i*16:(i+1)*16])
		copy(states[i][48:64], b3[i*16:(i+1)*16])
	}
}

// areion512Roundx4 mirrors the serial `areion512Round` closure from
// `github.com/jedisct1/go-aes/areion.go:areion512PermuteSoftware`. The
// inner work pattern is:
//
//	temp1 = a; RoundNoKey(temp1); b = temp1 ⊕ b
//	temp2 = c; RoundNoKey(temp2); d = temp2 ⊕ d
//	FinalRoundNoKey(a); FinalRoundNoKey(c); c = c ⊕ rc; RoundNoKey(c)
//
// All operations replicated four-wide via Block4 primitives.
func areion512Roundx4(a, b, c, d *aes.Block4, rc *[16]byte) {
	rcB4 := rcBlock4(rc)

	var temp1, temp2 aes.Block4

	temp1 = *a
	roundNoKey4Fast(&temp1)
	aes.XorBlock4(b, &temp1, b)

	temp2 = *c
	roundNoKey4Fast(&temp2)
	aes.XorBlock4(d, &temp2, d)

	finalRoundNoKey4Fast(a)
	finalRoundNoKey4Fast(c)
	aes.XorBlock4(c, c, &rcB4)
	roundNoKey4Fast(c)
}

// areion512Permutex4Default is the portable Go implementation of the
// 4-way batched Areion512 permutation. Used directly on non-amd64
// platforms and as the fallback path on amd64 (until a dedicated VAES
// assembly variant is added).
//
// Mirrors the serial round + final rotation structure of
// `github.com/jedisct1/go-aes/areion.go:areion512PermuteSoftware`
// bit-for-bit; same per-round pattern as the serial reference, four
// lanes wide.
func areion512Permutex4Default(states *[4][64]byte) {
	x0, x1, x2, x3 := pack512x4SoA(states)

	// Main 12 rounds (3 outer iterations of 4 sub-rounds each).
	for i := 0; i < 12; i += 4 {
		areion512Roundx4(&x0, &x1, &x2, &x3, &areionRC[i+0])
		areion512Roundx4(&x1, &x2, &x3, &x0, &areionRC[i+1])
		areion512Roundx4(&x2, &x3, &x0, &x1, &areionRC[i+2])
		areion512Roundx4(&x3, &x0, &x1, &x2, &areionRC[i+3])
	}
	// Final 3 rounds.
	areion512Roundx4(&x0, &x1, &x2, &x3, &areionRC[12])
	areion512Roundx4(&x1, &x2, &x3, &x0, &areionRC[13])
	areion512Roundx4(&x2, &x3, &x0, &x1, &areionRC[14])

	// Final rotation: temp=x0; x0=x3; x3=x2; x2=x1; x1=temp
	temp := x0
	x0 = x3
	x3 = x2
	x2 = x1
	x1 = temp

	unpack512x4SoA(&x0, &x1, &x2, &x3, states)
}

// AreionSoEM512x4 evaluates the Areion-SoEM-512 PRF on four independent
// (key, input) tuples in parallel.
//
//	output[i] = aes.AreionSoEM512(&keys[i], &inputs[i])  for i in {0,1,2,3}
//
// Each `keys[i]` is 128 bytes (two 64-byte SoEM subkeys k1‖k2). Each
// `inputs[i]` is 64 bytes. The result is four independent 64-byte PRF
// outputs. Bit-exact parity invariant identical to the SoEM-256 case;
// see `TestAreionSoEM512x4Parity`.
func AreionSoEM512x4(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	// uint64-chunked XOR loops, same optimization as the 256-bit
	// counterpart. Domain separator `[64]byte{0x01}` collapses to a
	// single uint64 nonzero word at index 0.
	var state1, state2 [4][64]byte
	const domainSepU64 = uint64(0x01) // = areionSoEM512DomainSepX4 first u64 word
	keysU64 := (*[4][16]uint64)(unsafe.Pointer(keys))
	inputsU64 := (*[4][8]uint64)(unsafe.Pointer(inputs))
	state1U64 := (*[4][8]uint64)(unsafe.Pointer(&state1))
	state2U64 := (*[4][8]uint64)(unsafe.Pointer(&state2))
	for i := 0; i < 4; i++ {
		state1U64[i][0] = inputsU64[i][0] ^ keysU64[i][0]
		state1U64[i][1] = inputsU64[i][1] ^ keysU64[i][1]
		state1U64[i][2] = inputsU64[i][2] ^ keysU64[i][2]
		state1U64[i][3] = inputsU64[i][3] ^ keysU64[i][3]
		state1U64[i][4] = inputsU64[i][4] ^ keysU64[i][4]
		state1U64[i][5] = inputsU64[i][5] ^ keysU64[i][5]
		state1U64[i][6] = inputsU64[i][6] ^ keysU64[i][6]
		state1U64[i][7] = inputsU64[i][7] ^ keysU64[i][7]
		state2U64[i][0] = inputsU64[i][0] ^ keysU64[i][8] ^ domainSepU64
		state2U64[i][1] = inputsU64[i][1] ^ keysU64[i][9]
		state2U64[i][2] = inputsU64[i][2] ^ keysU64[i][10]
		state2U64[i][3] = inputsU64[i][3] ^ keysU64[i][11]
		state2U64[i][4] = inputsU64[i][4] ^ keysU64[i][12]
		state2U64[i][5] = inputsU64[i][5] ^ keysU64[i][13]
		state2U64[i][6] = inputsU64[i][6] ^ keysU64[i][14]
		state2U64[i][7] = inputsU64[i][7] ^ keysU64[i][15]
	}

	areion512Permutex4(&state1)
	areion512Permutex4(&state2)

	var out [4][64]byte
	outU64 := (*[4][8]uint64)(unsafe.Pointer(&out))
	for i := 0; i < 4; i++ {
		outU64[i][0] = state1U64[i][0] ^ state2U64[i][0]
		outU64[i][1] = state1U64[i][1] ^ state2U64[i][1]
		outU64[i][2] = state1U64[i][2] ^ state2U64[i][2]
		outU64[i][3] = state1U64[i][3] ^ state2U64[i][3]
		outU64[i][4] = state1U64[i][4] ^ state2U64[i][4]
		outU64[i][5] = state1U64[i][5] ^ state2U64[i][5]
		outU64[i][6] = state1U64[i][6] ^ state2U64[i][6]
		outU64[i][7] = state1U64[i][7] ^ state2U64[i][7]
	}
	return out
}

// ─── Paired (single + batched) Hash factories for ITB integration ──────

// MakeAreionSoEM256Hash returns a fresh (single, batched) hash pair
// suitable for Seed256.Hash and Seed256.BatchHash. Both share the same
// internally-generated random fixed key so per-pixel hashes computed
// via the batched dispatch match the single-call path bit-exact (the
// invariant required by BatchHashFunc256).
//
// Construction (matches the cached-wrapper README example for
// Areion-SoEM-256): the fixed key occupies bytes [0..32) of the
// 64-byte SoEM subkey arrangement; per-pixel seed components fill
// bytes [32..64) as 4 × little-endian uint64. The SoEM-256 PRF is then
// applied to the 32-byte data input.
//
// Usage:
//
//	ns, _ := itb.NewSeed256(2048, nil) // Hash set below
//	ns.Hash, ns.BatchHash = itb.MakeAreionSoEM256Hash()
//	ds, _ := itb.NewSeed256(2048, nil)
//	ds.Hash, ds.BatchHash = itb.MakeAreionSoEM256Hash()
//	ss, _ := itb.NewSeed256(2048, nil)
//	ss.Hash, ss.BatchHash = itb.MakeAreionSoEM256Hash()
//
// On x86_64 hardware with VAES + AVX-512 the BatchHash path routes
// per-pixel hashing four pixels per call through AreionSoEM256x4,
// yielding ~2× throughput over the single-call path on this primitive.
func MakeAreionSoEM256Hash() (HashFunc256, BatchHashFunc256) {
	var fixedKey [32]byte
	if _, err := rand.Read(fixedKey[:]); err != nil {
		panic("itb: crypto/rand failed: " + err.Error())
	}
	return makeAreionSoEM256HashWithKey(fixedKey)
}

func makeAreionSoEM256HashWithKey(fixedKey [32]byte) (HashFunc256, BatchHashFunc256) {
	single := func(data []byte, seed [4]uint64) [4]uint64 {
		var key [64]byte
		copy(key[:32], fixedKey[:])
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(key[32+i*8:], seed[i])
		}
		var input [32]byte
		copy(input[:], data)
		result := aes.AreionSoEM256(&key, &input)
		return [4]uint64{
			binary.LittleEndian.Uint64(result[0:]),
			binary.LittleEndian.Uint64(result[8:]),
			binary.LittleEndian.Uint64(result[16:]),
			binary.LittleEndian.Uint64(result[24:]),
		}
	}
	batched := func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
		var keys [4][64]byte
		var inputs [4][32]byte
		for lane := 0; lane < 4; lane++ {
			copy(keys[lane][:32], fixedKey[:])
			for i := 0; i < 4; i++ {
				binary.LittleEndian.PutUint64(keys[lane][32+i*8:], seeds[lane][i])
			}
			copy(inputs[lane][:], data[lane])
		}
		results := AreionSoEM256x4(&keys, &inputs)
		var out [4][4]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane][0] = binary.LittleEndian.Uint64(results[lane][0:])
			out[lane][1] = binary.LittleEndian.Uint64(results[lane][8:])
			out[lane][2] = binary.LittleEndian.Uint64(results[lane][16:])
			out[lane][3] = binary.LittleEndian.Uint64(results[lane][24:])
		}
		return out
	}
	return single, batched
}

// MakeAreionSoEM512Hash returns the 512-bit counterpart of
// MakeAreionSoEM256Hash. Same construction principle: 64-byte fixed
// key in bytes [0..64) of the 128-byte SoEM-512 subkey arrangement,
// per-pixel seed components in bytes [64..128) as 8 × little-endian
// uint64. Bit-exact parity invariant identical to the 256-bit case.
func MakeAreionSoEM512Hash() (HashFunc512, BatchHashFunc512) {
	var fixedKey [64]byte
	if _, err := rand.Read(fixedKey[:]); err != nil {
		panic("itb: crypto/rand failed: " + err.Error())
	}
	return makeAreionSoEM512HashWithKey(fixedKey)
}

func makeAreionSoEM512HashWithKey(fixedKey [64]byte) (HashFunc512, BatchHashFunc512) {
	single := func(data []byte, seed [8]uint64) [8]uint64 {
		var key [128]byte
		copy(key[:64], fixedKey[:])
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(key[64+i*8:], seed[i])
		}
		var input [64]byte
		copy(input[:], data)
		result := aes.AreionSoEM512(&key, &input)
		var out [8]uint64
		for i := range out {
			out[i] = binary.LittleEndian.Uint64(result[i*8:])
		}
		return out
	}
	batched := func(data *[4][]byte, seeds [4][8]uint64) [4][8]uint64 {
		var keys [4][128]byte
		var inputs [4][64]byte
		for lane := 0; lane < 4; lane++ {
			copy(keys[lane][:64], fixedKey[:])
			for i := 0; i < 8; i++ {
				binary.LittleEndian.PutUint64(keys[lane][64+i*8:], seeds[lane][i])
			}
			copy(inputs[lane][:], data[lane])
		}
		results := AreionSoEM512x4(&keys, &inputs)
		var out [4][8]uint64
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 8; i++ {
				out[lane][i] = binary.LittleEndian.Uint64(results[lane][i*8:])
			}
		}
		return out
	}
	return single, batched
}
