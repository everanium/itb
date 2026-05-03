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

	"github.com/everanium/itb/internal/areionasm"
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
// into the AoS layout.
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
	// for every lane, **directly in SoA Block4 layout** so the
	// downstream VAES kernel runs without a separate pack pass.
	// SoA convention (matches pack256x4SoA): lane i's first 16-byte
	// AES block lives at &b0[i*16], second at &b1[i*16].
	//
	// Cuts ~16 inline MOVUPS per call vs the previous AoS-then-pack
	// flow (was: 32 uint64 XORs → 2 × 8-MOVUPS pack → permute →
	// 2 × 8-MOVUPS unpack → 16 uint64 XORs; now: 32 uint64 XORs to
	// SoA destinations → permute → 16 uint64 XORs unpack-and-XOR
	// in one pass). Each Areion256x4 batched call drops ~5-10 ns
	// of Go-side overhead — measurable on slow-path
	// SetNonceBits(256/512) workloads where the closure dispatches
	// 2-3 batched calls per ChainHash round.
	const domainSepU64 = uint64(0x01) // = areionSoEM256DomainSepX4 first u64 word
	keysU64 := (*[4][8]uint64)(unsafe.Pointer(keys))
	inputsU64 := (*[4][4]uint64)(unsafe.Pointer(inputs))

	var s1b0, s1b1, s2b0, s2b1 aes.Block4
	for lane := 0; lane < 4; lane++ {
		s1b0U64 := (*[2]uint64)(unsafe.Pointer(&s1b0[lane*16]))
		s1b1U64 := (*[2]uint64)(unsafe.Pointer(&s1b1[lane*16]))
		s2b0U64 := (*[2]uint64)(unsafe.Pointer(&s2b0[lane*16]))
		s2b1U64 := (*[2]uint64)(unsafe.Pointer(&s2b1[lane*16]))

		s1b0U64[0] = inputsU64[lane][0] ^ keysU64[lane][0]
		s1b0U64[1] = inputsU64[lane][1] ^ keysU64[lane][1]
		s1b1U64[0] = inputsU64[lane][2] ^ keysU64[lane][2]
		s1b1U64[1] = inputsU64[lane][3] ^ keysU64[lane][3]

		s2b0U64[0] = inputsU64[lane][0] ^ keysU64[lane][4] ^ domainSepU64
		s2b0U64[1] = inputsU64[lane][1] ^ keysU64[lane][5]
		s2b1U64[0] = inputsU64[lane][2] ^ keysU64[lane][6]
		s2b1U64[1] = inputsU64[lane][3] ^ keysU64[lane][7]
	}

	// On AVX-512 + VAES, the fused kernel runs both permutes
	// interleaved (masking VAESENC latency) and computes the SoEM
	// XOR in registers, writing the result back into (s1b0, s1b1).
	// On other paths, the dispatcher falls through to two separate
	// permutex4 calls + a manual XOR loop, bit-exact identical.
	areionSoEM256Permutex4SoA(&s1b0, &s1b1, &s2b0, &s2b1)

	// Unpack the SoEM-XOR'd state from SoA (already in s1b0/s1b1) to
	// AoS output. No second XOR step — the dispatcher delivered the
	// final state1' ⊕ state2' result.
	var out [4][32]byte
	for lane := 0; lane < 4; lane++ {
		s1b0U64 := (*[2]uint64)(unsafe.Pointer(&s1b0[lane*16]))
		s1b1U64 := (*[2]uint64)(unsafe.Pointer(&s1b1[lane*16]))
		outU64 := (*[4]uint64)(unsafe.Pointer(&out[lane]))

		outU64[0] = s1b0U64[0]
		outU64[1] = s1b0U64[1]
		outU64[2] = s1b1U64[0]
		outU64[3] = s1b1U64[1]
	}
	return out
}

// pack512x4SoA reshapes four Areion512 states from AoS into four Block4
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
	// SoA-direct build of state1, state2 — same shape as the 256-bit
	// counterpart, scaled to four Block4 buffers per state (b0..b3
	// holding AES blocks 0..3 of every lane). Skips the AoS pack/
	// unpack steps the AoS dispatcher would otherwise emit.
	const domainSepU64 = uint64(0x01) // = areionSoEM512DomainSepX4 first u64 word
	keysU64 := (*[4][16]uint64)(unsafe.Pointer(keys))
	inputsU64 := (*[4][8]uint64)(unsafe.Pointer(inputs))

	var s1b0, s1b1, s1b2, s1b3, s2b0, s2b1, s2b2, s2b3 aes.Block4
	for lane := 0; lane < 4; lane++ {
		s1b0U64 := (*[2]uint64)(unsafe.Pointer(&s1b0[lane*16]))
		s1b1U64 := (*[2]uint64)(unsafe.Pointer(&s1b1[lane*16]))
		s1b2U64 := (*[2]uint64)(unsafe.Pointer(&s1b2[lane*16]))
		s1b3U64 := (*[2]uint64)(unsafe.Pointer(&s1b3[lane*16]))
		s2b0U64 := (*[2]uint64)(unsafe.Pointer(&s2b0[lane*16]))
		s2b1U64 := (*[2]uint64)(unsafe.Pointer(&s2b1[lane*16]))
		s2b2U64 := (*[2]uint64)(unsafe.Pointer(&s2b2[lane*16]))
		s2b3U64 := (*[2]uint64)(unsafe.Pointer(&s2b3[lane*16]))

		s1b0U64[0] = inputsU64[lane][0] ^ keysU64[lane][0]
		s1b0U64[1] = inputsU64[lane][1] ^ keysU64[lane][1]
		s1b1U64[0] = inputsU64[lane][2] ^ keysU64[lane][2]
		s1b1U64[1] = inputsU64[lane][3] ^ keysU64[lane][3]
		s1b2U64[0] = inputsU64[lane][4] ^ keysU64[lane][4]
		s1b2U64[1] = inputsU64[lane][5] ^ keysU64[lane][5]
		s1b3U64[0] = inputsU64[lane][6] ^ keysU64[lane][6]
		s1b3U64[1] = inputsU64[lane][7] ^ keysU64[lane][7]

		s2b0U64[0] = inputsU64[lane][0] ^ keysU64[lane][8] ^ domainSepU64
		s2b0U64[1] = inputsU64[lane][1] ^ keysU64[lane][9]
		s2b1U64[0] = inputsU64[lane][2] ^ keysU64[lane][10]
		s2b1U64[1] = inputsU64[lane][3] ^ keysU64[lane][11]
		s2b2U64[0] = inputsU64[lane][4] ^ keysU64[lane][12]
		s2b2U64[1] = inputsU64[lane][5] ^ keysU64[lane][13]
		s2b3U64[0] = inputsU64[lane][6] ^ keysU64[lane][14]
		s2b3U64[1] = inputsU64[lane][7] ^ keysU64[lane][15]
	}

	// On AVX-512 + VAES, the fused 15-round kernel runs both permutes
	// interleaved, applies the cyclic state rotation
	// `(x0,x1,x2,x3) → (x3,x0,x1,x2)` fused with the SoEM XOR, and
	// writes the result back into (s1b0..s1b3). On other paths, the
	// dispatcher falls through to two separate permutex4 calls + a
	// manual XOR loop, bit-exact identical.
	areionSoEM512Permutex4SoA(&s1b0, &s1b1, &s1b2, &s1b3, &s2b0, &s2b1, &s2b2, &s2b3)

	// Unpack the SoEM-XOR'd state from SoA (already in s1b0..s1b3) to
	// AoS output. No second XOR step — the dispatcher delivered the
	// final state1' ⊕ state2' result.
	var out [4][64]byte
	for lane := 0; lane < 4; lane++ {
		s1b0U64 := (*[2]uint64)(unsafe.Pointer(&s1b0[lane*16]))
		s1b1U64 := (*[2]uint64)(unsafe.Pointer(&s1b1[lane*16]))
		s1b2U64 := (*[2]uint64)(unsafe.Pointer(&s1b2[lane*16]))
		s1b3U64 := (*[2]uint64)(unsafe.Pointer(&s1b3[lane*16]))
		outU64 := (*[8]uint64)(unsafe.Pointer(&out[lane]))

		outU64[0] = s1b0U64[0]
		outU64[1] = s1b0U64[1]
		outU64[2] = s1b1U64[0]
		outU64[3] = s1b1U64[1]
		outU64[4] = s1b2U64[0]
		outU64[5] = s1b2U64[1]
		outU64[6] = s1b3U64[0]
		outU64[7] = s1b3U64[1]
	}
	return out
}

// ─── Paired (single + batched) Hash factories for ITB integration ──────

// MakeAreionSoEM256Hash returns a fresh (single, batched) hash pair
// suitable for Seed256.Hash and Seed256.BatchHash, plus the 32-byte
// fixed key the pair is bound to. With no argument the key is freshly
// generated via crypto/rand; passing a single caller-supplied
// [32]byte uses that key instead — meant for the persistence-restore
// path (encrypt today, decrypt tomorrow). Both arms share the same
// fixed key so per-pixel hashes computed via the batched dispatch
// match the single-call path bit-exact (the invariant required by
// BatchHashFunc256).
//
// Construction (matches the cached-wrapper README example for
// Areion-SoEM-256): the fixed key occupies bytes [0..32) of the
// 64-byte SoEM subkey arrangement; per-pixel seed components fill
// bytes [32..64) as 4 × little-endian uint64. The SoEM-256 PRF is then
// applied to the 32-byte data input.
//
// Usage (random key, save it for cross-process persistence):
//
//	ns, _ := itb.NewSeed256(2048, nil) // Hash set below
//	hashFn, batchFn, hashKey := itb.MakeAreionSoEM256Hash()
//	ns.Hash, ns.BatchHash = hashFn, batchFn
//	saveKey(hashKey)
//
// Usage (explicit key, restored from storage):
//
//	hashFn, batchFn, _ := itb.MakeAreionSoEM256Hash(savedKey)
//	ns.Hash, ns.BatchHash = hashFn, batchFn
//
// On x86_64 hardware with VAES + AVX-512 the BatchHash path routes
// per-pixel hashing four pixels per call through AreionSoEM256x4,
// yielding ~2× throughput over the single-call path on this primitive.
func MakeAreionSoEM256Hash(key ...[32]byte) (HashFunc256, BatchHashFunc256, [32]byte) {
	var fixedKey [32]byte
	if len(key) > 0 {
		fixedKey = key[0]
	} else if _, err := rand.Read(fixedKey[:]); err != nil {
		panic("itb: crypto/rand failed: " + err.Error())
	}
	h, b := MakeAreionSoEM256HashWithKey(fixedKey)
	return h, b, fixedKey
}

// MakeAreionSoEM256HashWithKey is the explicit-key counterpart of
// MakeAreionSoEM256Hash. Use this on the persistence-restore path
// when the 32-byte fixed key has been saved across processes — the
// returned (single, batched) pair will reproduce the same per-pixel
// hashes as the original encrypt-side closure.
func MakeAreionSoEM256HashWithKey(fixedKey [32]byte) (HashFunc256, BatchHashFunc256) {
	// CBC-MAC-style chained absorb. The 32-byte state holds an
	// 8-byte length tag in bytes [0..8) (disambiguates inputs of
	// different lengths) and absorbs the remainder of `data` in
	// 24-byte chunks into bytes [8..32) per round, encrypting the
	// state through AreionSoEM256 between rounds. The chain runs
	// at least once even for empty data so the length-tagged state
	// is always encrypted before being returned. Every byte of
	// `data` reaches the digest regardless of length, so the
	// effective nonce-uniqueness scales with len(data) instead of
	// being capped at the SoEM-256 block size.
	//
	// Hot-path optimisations: ITB feeds 20-, 36-, or 68-byte buf
	// shapes per pixel (one of the three SetNonceBits configs).
	// The 20-byte case takes the single-round fast path below
	// (zero loop overhead); the 36- and 68-byte cases run 2 or 3
	// chained rounds. Absorb XOR is done in 8-byte uint64 chunks
	// (with a byte-tail) so a 16- or 20-byte absorb is 2 uint64
	// XORs + few tail bytes instead of 16-20 single-byte XORs.
	const chunkSize = 24
	single := func(data []byte, seed [4]uint64) [4]uint64 {
		var key [64]byte
		copy(key[:32], fixedKey[:])
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(key[32+i*8:], seed[i])
		}
		var state [32]byte
		binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))

		if len(data) <= chunkSize {
			// Fast path: single AreionSoEM256 round. state[8:32] is
			// freshly zero from the `var state [32]byte` declaration,
			// so absorb-XOR is equivalent to a bulk copy — Go's
			// `copy` builtin lowers to memmove / SIMD MOVDQU which
			// is significantly faster than the byte/uint64 XOR
			// path for short data.
			copy(state[8:8+len(data)], data)
			state = aes.AreionSoEM256(&key, &state)
		} else {
			// Slow path: CBC-MAC chain for inputs > 24 bytes. The
			// first round still benefits from copy-instead-of-XOR
			// (state[8:32] is zero); subsequent rounds must use the
			// real XOR because state holds the previous AES output.
			copy(state[8:8+chunkSize], data[0:chunkSize])
			state = aes.AreionSoEM256(&key, &state)
			off := chunkSize
			for off < len(data) {
				end := off + chunkSize
				if end > len(data) {
					end = len(data)
				}
				absorbXOR(state[8:8+(end-off)], data[off:end])
				state = aes.AreionSoEM256(&key, &state)
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
	// On hosts without any VAES-capable asm path (purego / non-amd64
	// / no-AESNI) the batched closure's AreionSoEM256x4 dispatch falls
	// through to the package's portable Go SoEM scalar path, which
	// pays the 4-lane wrapper cost on top of work the single arm
	// already does through its own dispatcher. Returning nil here
	// lets process_cgo.go's nil-fallback drive per-pixel hashing
	// through the single arm directly. The check covers both AVX-512
	// + VAES (HasVAESAVX512) and AVX-2 + VAES (HasVAESAVX2NoAVX512);
	// either flag is enough to keep the batched path engaged because
	// the AVX-2 4-way permutation still SIMD-parallelises across
	// lanes.
	if !areionasm.HasVAESAVX512 && !areionasm.HasVAESAVX2NoAVX512 {
		return single, nil
	}
	// Batched chain: 4 lanes run their CBC-MAC chain in lock-step,
	// each round dispatching one AreionSoEM256x4 call so the AVX-512
	// 4-way SIMD parallelism is preserved. ITB feeds equal-length
	// data per batched call (one ChainHash round across 4 pixels);
	// the inner XOR loops clamp at each lane's own length boundary
	// to stay safe if a future caller violates the equal-length
	// invariant.
	batched := func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
		commonLen := len(data[0])

		// Hot-path fast track: ITB feeds 20-, 36-, or 68-byte buf shapes
		// per batched call (one of the three SetNonceBits configs).
		// Specialised AVX-512 kernels for each length keep the SoEM
		// state in ZMM registers across all CBC-MAC absorb rounds and
		// skip the keys[4][64] / states[4][32] memory roundtrips that
		// the general path emits. The dispatcher returns ok=false on
		// non-amd64 hosts and on lengths outside {20, 36, 68}, in
		// which case the general path below runs.
		if out, ok := areionSoEM256ChainAbsorbHot(&fixedKey, &seeds, data, commonLen); ok {
			return out
		}

		// General path: arbitrary equal-length data, or non-AVX-512 host.
		var keys [4][64]byte
		var states [4][32]byte
		for lane := 0; lane < 4; lane++ {
			copy(keys[lane][:32], fixedKey[:])
			for i := 0; i < 4; i++ {
				binary.LittleEndian.PutUint64(keys[lane][32+i*8:], seeds[lane][i])
			}
			binary.LittleEndian.PutUint64(states[lane][:8], uint64(len(data[lane])))
		}

		if commonLen <= chunkSize {
			// Fast path: single batched AreionSoEM256x4 round.
			// states[lane][8:32] is freshly zero from declaration,
			// so absorb-XOR is equivalent to bulk copy — same
			// optimisation as the single closure.
			for lane := 0; lane < 4; lane++ {
				copy(states[lane][8:8+len(data[lane])], data[lane])
			}
			states = AreionSoEM256x4(&keys, &states)
		} else {
			// First round uses copy (zero initial state); subsequent
			// rounds use absorb-XOR.
			for lane := 0; lane < 4; lane++ {
				laneN := chunkSize
				if laneN > len(data[lane]) {
					laneN = len(data[lane])
				}
				copy(states[lane][8:8+laneN], data[lane][0:laneN])
			}
			states = AreionSoEM256x4(&keys, &states)
			off := chunkSize
			for off < commonLen {
				end := off + chunkSize
				if end > commonLen {
					end = commonLen
				}
				for lane := 0; lane < 4; lane++ {
					laneEnd := end
					if laneEnd > len(data[lane]) {
						laneEnd = len(data[lane])
					}
					absorbXOR(states[lane][8:8+(laneEnd-off)], data[lane][off:laneEnd])
				}
				states = AreionSoEM256x4(&keys, &states)
				off = end
			}
		}

		var out [4][4]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane][0] = binary.LittleEndian.Uint64(states[lane][0:])
			out[lane][1] = binary.LittleEndian.Uint64(states[lane][8:])
			out[lane][2] = binary.LittleEndian.Uint64(states[lane][16:])
			out[lane][3] = binary.LittleEndian.Uint64(states[lane][24:])
		}
		return out
	}
	return single, batched
}

// MakeAreionSoEM512Hash returns the 512-bit counterpart of
// MakeAreionSoEM256Hash, plus the 64-byte fixed key the pair is bound
// to. Same construction principle: 64-byte fixed key in bytes [0..64)
// of the 128-byte SoEM-512 subkey arrangement, per-pixel seed
// components in bytes [64..128) as 8 × little-endian uint64. Bit-exact
// parity invariant identical to the 256-bit case. Variadic key arg
// and saved-key flow identical to MakeAreionSoEM256Hash.
func MakeAreionSoEM512Hash(key ...[64]byte) (HashFunc512, BatchHashFunc512, [64]byte) {
	var fixedKey [64]byte
	if len(key) > 0 {
		fixedKey = key[0]
	} else if _, err := rand.Read(fixedKey[:]); err != nil {
		panic("itb: crypto/rand failed: " + err.Error())
	}
	h, b := MakeAreionSoEM512HashWithKey(fixedKey)
	return h, b, fixedKey
}

// MakeAreionSoEM512HashWithKey is the explicit-key counterpart of
// MakeAreionSoEM512Hash. Same role as MakeAreionSoEM256HashWithKey
// scaled to the 64-byte fixed key of Areion-SoEM-512.
func MakeAreionSoEM512HashWithKey(fixedKey [64]byte) (HashFunc512, BatchHashFunc512) {
	// CBC-MAC-style chained absorb, same shape as the SoEM-256
	// counterpart, scaled to a 64-byte state and a 56-byte data
	// chunk per round (8 bytes reserved for the length tag in the
	// initial state). For ITB's three nonce-bit configurations:
	//   buf 20 (default 128-bit nonce):    1 round (fast path)
	//   buf 36 (256-bit nonce):            1 round (fast path)
	//   buf 68 (512-bit nonce):            2 rounds
	// Absorb XOR is bulk uint64 with a byte tail, identical
	// optimisation to the SoEM-256 path.
	const chunkSize = 56
	single := func(data []byte, seed [8]uint64) [8]uint64 {
		var key [128]byte
		copy(key[:64], fixedKey[:])
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(key[64+i*8:], seed[i])
		}
		var state [64]byte
		binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))

		if len(data) <= chunkSize {
			// Fast path: state[8:64] is zero — bulk copy beats
			// absorb-XOR for the first round.
			copy(state[8:8+len(data)], data)
			state = aes.AreionSoEM512(&key, &state)
		} else {
			copy(state[8:8+chunkSize], data[0:chunkSize])
			state = aes.AreionSoEM512(&key, &state)
			off := chunkSize
			for off < len(data) {
				end := off + chunkSize
				if end > len(data) {
					end = len(data)
				}
				absorbXOR(state[8:8+(end-off)], data[off:end])
				state = aes.AreionSoEM512(&key, &state)
				off = end
			}
		}

		var out [8]uint64
		for i := range out {
			out[i] = binary.LittleEndian.Uint64(state[i*8:])
		}
		return out
	}
	// On hosts without any VAES-capable asm path the batched
	// AreionSoEM512x4 dispatch falls through to the portable Go
	// scalar SoEM path; nil-out the batched arm so process_cgo.go's
	// nil-fallback drives per-pixel hashing through the single arm
	// directly. See the SoEM-256 counterpart above for the rationale.
	if !areionasm.HasVAESAVX512 && !areionasm.HasVAESAVX2NoAVX512 {
		return single, nil
	}
	batched := func(data *[4][]byte, seeds [4][8]uint64) [4][8]uint64 {
		commonLen := len(data[0])

		// Hot-path fast track for ITB's three SetNonceBits buf shapes.
		// Mirrors the Areion-SoEM-256 dispatch — specialised AVX-512
		// kernels per length keep the SoEM state in ZMM across all
		// CBC-MAC absorb rounds.
		if out, ok := areionSoEM512ChainAbsorbHot(&fixedKey, &seeds, data, commonLen); ok {
			return out
		}

		// General path.
		var keys [4][128]byte
		var states [4][64]byte
		for lane := 0; lane < 4; lane++ {
			copy(keys[lane][:64], fixedKey[:])
			for i := 0; i < 8; i++ {
				binary.LittleEndian.PutUint64(keys[lane][64+i*8:], seeds[lane][i])
			}
			binary.LittleEndian.PutUint64(states[lane][:8], uint64(len(data[lane])))
		}

		if commonLen <= chunkSize {
			// Fast path: states[lane][8:64] is zero — bulk copy.
			for lane := 0; lane < 4; lane++ {
				copy(states[lane][8:8+len(data[lane])], data[lane])
			}
			states = AreionSoEM512x4(&keys, &states)
		} else {
			for lane := 0; lane < 4; lane++ {
				laneN := chunkSize
				if laneN > len(data[lane]) {
					laneN = len(data[lane])
				}
				copy(states[lane][8:8+laneN], data[lane][0:laneN])
			}
			states = AreionSoEM512x4(&keys, &states)
			off := chunkSize
			for off < commonLen {
				end := off + chunkSize
				if end > commonLen {
					end = commonLen
				}
				for lane := 0; lane < 4; lane++ {
					laneEnd := end
					if laneEnd > len(data[lane]) {
						laneEnd = len(data[lane])
					}
					absorbXOR(states[lane][8:8+(laneEnd-off)], data[lane][off:laneEnd])
				}
				states = AreionSoEM512x4(&keys, &states)
				off = end
			}
		}

		var out [4][8]uint64
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 8; i++ {
				out[lane][i] = binary.LittleEndian.Uint64(states[lane][i*8:])
			}
		}
		return out
	}
	return single, batched
}

// absorbXOR XORs src into dst in 8-byte uint64 chunks where
// possible, with a byte-tail for the trailing < 8 bytes.
//
// Caller invariant: len(dst) == len(src). This is satisfied at
// every call site in the CBC-MAC slow path (the outer slicing
// ensures equal lengths). The helper does not double-check; the
// resulting smaller body cost lets the Go compiler inline this
// at the slow-path call sites, eliminating the per-round
// function-call overhead. A 20-byte absorb compiles to
// 2 uint64 XORs + 4 byte XORs instead of 20 single-byte XORs.
func absorbXOR(dst, src []byte) {
	n := len(dst)
	i := 0
	for ; i+8 <= n; i += 8 {
		d := binary.LittleEndian.Uint64(dst[i:])
		s := binary.LittleEndian.Uint64(src[i:])
		binary.LittleEndian.PutUint64(dst[i:], d^s)
	}
	for ; i < n; i++ {
		dst[i] ^= src[i]
	}
}
