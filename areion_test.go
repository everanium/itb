package itb

import (
	"crypto/rand"
	"runtime"
	"testing"

	"github.com/everanium/itb/internal/areionasm"
	"github.com/jedisct1/go-aes"
)

// TestAreionSoEM256x4Parity verifies that for arbitrary inputs, the
// 4-way batched AreionSoEM256x4 produces bit-exact identical output to
// four serial aes.AreionSoEM256 calls. This is the load-bearing
// invariant for any future ITB integration: divergence by even one bit
// would invalidate PRF security claims under the batched dispatch path.
func TestAreionSoEM256x4Parity(t *testing.T) {
	const trials = 256

	for trial := 0; trial < trials; trial++ {
		var keys [4][64]byte
		var inputs [4][32]byte
		for i := 0; i < 4; i++ {
			if _, err := rand.Read(keys[i][:]); err != nil {
				t.Fatalf("rand.Read keys[%d]: %v", i, err)
			}
			if _, err := rand.Read(inputs[i][:]); err != nil {
				t.Fatalf("rand.Read inputs[%d]: %v", i, err)
			}
		}

		batched := AreionSoEM256x4(&keys, &inputs)

		for i := 0; i < 4; i++ {
			serial := aes.AreionSoEM256(&keys[i], &inputs[i])
			if batched[i] != serial {
				t.Fatalf("trial %d lane %d: batched != serial\n"+
					"batched: %x\nserial:  %x", trial, i, batched[i], serial)
			}
		}
	}
}

// TestAreionSoEM512x4Parity is the analogous parity gate for the 512-bit
// SoEM. Same load-bearing invariant: batched lanes must match serial
// outputs bit-exact across arbitrary inputs.
func TestAreionSoEM512x4Parity(t *testing.T) {
	const trials = 256

	for trial := 0; trial < trials; trial++ {
		var keys [4][128]byte
		var inputs [4][64]byte
		for i := 0; i < 4; i++ {
			if _, err := rand.Read(keys[i][:]); err != nil {
				t.Fatalf("rand.Read keys[%d]: %v", i, err)
			}
			if _, err := rand.Read(inputs[i][:]); err != nil {
				t.Fatalf("rand.Read inputs[%d]: %v", i, err)
			}
		}

		batched := AreionSoEM512x4(&keys, &inputs)

		for i := 0; i < 4; i++ {
			serial := aes.AreionSoEM512(&keys[i], &inputs[i])
			if batched[i] != serial {
				t.Fatalf("trial %d lane %d: batched != serial\n"+
					"batched: %x\nserial:  %x", trial, i, batched[i], serial)
			}
		}
	}
}

// TestAreionSoEM256x4EdgeCases covers degenerate inputs that pure-random
// trials are unlikely to hit: all-zero keys + inputs, all-FF, alternating
// 0x55 / 0xAA, and a single-bit-set input. Catches subtle layout or
// indexing bugs that randomised trials might miss.
func TestAreionSoEM256x4EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		key  byte
		in   byte
	}{
		{"zero", 0x00, 0x00},
		{"all_ff", 0xFF, 0xFF},
		{"alt55", 0x55, 0x55},
		{"alt_aa", 0xAA, 0xAA},
		{"key_ff_in_zero", 0xFF, 0x00},
		{"key_zero_in_ff", 0x00, 0xFF},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var keys [4][64]byte
			var inputs [4][32]byte
			for i := 0; i < 4; i++ {
				for j := range keys[i] {
					keys[i][j] = c.key
				}
				for j := range inputs[i] {
					inputs[i][j] = c.in
				}
			}

			batched := AreionSoEM256x4(&keys, &inputs)

			for i := 0; i < 4; i++ {
				serial := aes.AreionSoEM256(&keys[i], &inputs[i])
				if batched[i] != serial {
					t.Fatalf("case %q lane %d: batched != serial\n"+
						"batched: %x\nserial:  %x",
						c.name, i, batched[i], serial)
				}
			}
		})
	}
}

// TestAreionSoEM512x4EdgeCases mirrors the 256-bit edge-case suite.
func TestAreionSoEM512x4EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		key  byte
		in   byte
	}{
		{"zero", 0x00, 0x00},
		{"all_ff", 0xFF, 0xFF},
		{"alt55", 0x55, 0x55},
		{"alt_aa", 0xAA, 0xAA},
		{"key_ff_in_zero", 0xFF, 0x00},
		{"key_zero_in_ff", 0x00, 0xFF},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var keys [4][128]byte
			var inputs [4][64]byte
			for i := 0; i < 4; i++ {
				for j := range keys[i] {
					keys[i][j] = c.key
				}
				for j := range inputs[i] {
					inputs[i][j] = c.in
				}
			}

			batched := AreionSoEM512x4(&keys, &inputs)

			for i := 0; i < 4; i++ {
				serial := aes.AreionSoEM512(&keys[i], &inputs[i])
				if batched[i] != serial {
					t.Fatalf("case %q lane %d: batched != serial\n"+
						"batched: %x\nserial:  %x",
						c.name, i, batched[i], serial)
				}
			}
		})
	}
}

// TestAreionSoEM256x4LaneIndependence checks that mutating one lane's
// key/input does not affect the other lanes' outputs. Confirms the SoA
// layout's lane separation is correct.
func TestAreionSoEM256x4LaneIndependence(t *testing.T) {
	var keys [4][64]byte
	var inputs [4][32]byte
	if _, err := rand.Read(keys[0][:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(inputs[0][:]); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 4; i++ {
		keys[i] = keys[0]
		inputs[i] = inputs[0]
	}

	// All four lanes have identical (key, input) → all four outputs equal.
	out1 := AreionSoEM256x4(&keys, &inputs)
	for i := 1; i < 4; i++ {
		if out1[i] != out1[0] {
			t.Fatalf("lane %d != lane 0 with identical inputs:\nlane 0: %x\nlane %d: %x",
				i, out1[0], i, out1[i])
		}
	}

	// Mutate lane 2 only; lanes 0, 1, 3 must keep prior outputs.
	keys[2][7] ^= 0x42
	out2 := AreionSoEM256x4(&keys, &inputs)
	if out2[0] != out1[0] {
		t.Fatalf("lane 0 perturbed by lane 2 mutation")
	}
	if out2[1] != out1[1] {
		t.Fatalf("lane 1 perturbed by lane 2 mutation")
	}
	if out2[3] != out1[3] {
		t.Fatalf("lane 3 perturbed by lane 2 mutation")
	}
	if out2[2] == out1[2] {
		t.Fatalf("lane 2 unchanged despite key mutation")
	}
}

// ─── Benchmarks: serial 4× vs batched throughput ───────────────────────

// BenchmarkAreionSoEM256_Serial4x measures the cost of four sequential
// aes.AreionSoEM256 calls per iteration. This is the baseline against
// which AreionSoEM256x4 is compared.
func BenchmarkAreionSoEM256_Serial4x(b *testing.B) {
	var keys [4][64]byte
	var inputs [4][32]byte
	rand.Read(keys[0][:])
	rand.Read(inputs[0][:])
	rand.Read(keys[1][:])
	rand.Read(inputs[1][:])
	rand.Read(keys[2][:])
	rand.Read(inputs[2][:])
	rand.Read(keys[3][:])
	rand.Read(inputs[3][:])

	b.SetBytes(4 * 32) // 4 lanes × 32-byte input
	b.ResetTimer()
	var sink [32]byte
	for i := 0; i < b.N; i++ {
		for j := 0; j < 4; j++ {
			out := aes.AreionSoEM256(&keys[j], &inputs[j])
			// Prevent dead-code elimination.
			for k := range sink {
				sink[k] ^= out[k]
			}
		}
	}
	_ = sink
}

// BenchmarkAreionSoEM256x4_Batched measures the cost of one batched
// AreionSoEM256x4 call per iteration. Direct comparison to
// BenchmarkAreionSoEM256_Serial4x — same total work (4 SoEM PRF calls),
// different dispatch (4-way SIMD vs 4 sequential).
func BenchmarkAreionSoEM256x4_Batched(b *testing.B) {
	var keys [4][64]byte
	var inputs [4][32]byte
	rand.Read(keys[0][:])
	rand.Read(inputs[0][:])
	rand.Read(keys[1][:])
	rand.Read(inputs[1][:])
	rand.Read(keys[2][:])
	rand.Read(inputs[2][:])
	rand.Read(keys[3][:])
	rand.Read(inputs[3][:])

	b.SetBytes(4 * 32)
	b.ResetTimer()
	var sink [4][32]byte
	for i := 0; i < b.N; i++ {
		out := AreionSoEM256x4(&keys, &inputs)
		// Prevent DCE.
		for j := 0; j < 4; j++ {
			for k := range sink[j] {
				sink[j][k] ^= out[j][k]
			}
		}
	}
	_ = sink
}

// BenchmarkAreionSoEM512_Serial4x is the 512-bit baseline.
func BenchmarkAreionSoEM512_Serial4x(b *testing.B) {
	var keys [4][128]byte
	var inputs [4][64]byte
	rand.Read(keys[0][:])
	rand.Read(inputs[0][:])
	rand.Read(keys[1][:])
	rand.Read(inputs[1][:])
	rand.Read(keys[2][:])
	rand.Read(inputs[2][:])
	rand.Read(keys[3][:])
	rand.Read(inputs[3][:])

	b.SetBytes(4 * 64)
	b.ResetTimer()
	var sink [64]byte
	for i := 0; i < b.N; i++ {
		for j := 0; j < 4; j++ {
			out := aes.AreionSoEM512(&keys[j], &inputs[j])
			for k := range sink {
				sink[k] ^= out[k]
			}
		}
	}
	_ = sink
}

// BenchmarkAreionSoEM512x4_Batched is the 512-bit batched comparison.
func BenchmarkAreionSoEM512x4_Batched(b *testing.B) {
	var keys [4][128]byte
	var inputs [4][64]byte
	rand.Read(keys[0][:])
	rand.Read(inputs[0][:])
	rand.Read(keys[1][:])
	rand.Read(inputs[1][:])
	rand.Read(keys[2][:])
	rand.Read(inputs[2][:])
	rand.Read(keys[3][:])
	rand.Read(inputs[3][:])

	b.SetBytes(4 * 64)
	b.ResetTimer()
	var sink [4][64]byte
	for i := 0; i < b.N; i++ {
		out := AreionSoEM512x4(&keys, &inputs)
		for j := 0; j < 4; j++ {
			for k := range sink[j] {
				sink[j][k] ^= out[j][k]
			}
		}
	}
	_ = sink
}

// ─── AVX2+VAES path direct-call parity (regardless of runtime CPU) ─────

// areion256Permutex4Avx2Direct invokes the AVX2+VAES assembly variant
// directly on amd64, bypassing the runtime VAES/AVX-512 dispatch. Used
// by the parity test below to validate the AVX2 path on hardware that
// would otherwise route to the AVX-512 path. Falls back to the portable
// Go implementation on non-amd64 builds (where the AVX2 ASM is not
// reachable and the test is uninteresting).
func areion256Permutex4Avx2Direct(states *[4][32]byte) {
	if runtime.GOARCH != "amd64" {
		areion256Permutex4Default(states)
		return
	}
	x0, x1 := pack256x4SoA(states)
	areionasm.Areion256Permutex4Avx2(&x0, &x1)
	unpack256x4SoA(&x0, &x1, states)
}

// TestAreionSoEM256x4AvxParityDirect verifies that the AVX2+VAES
// assembly variant produces bit-exact identical output to the serial
// aes.AreionSoEM256 reference, independent of which path runtime
// dispatch would select. Skipped on non-amd64 builds.
func TestAreionSoEM256x4Avx2ParityDirect(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("AVX2 parity test only runs on amd64")
	}
	if !areionasm.HasVAESAVX2NoAVX512 && !areionasm.HasVAESAVX512 {
		t.Skip("AVX2 parity test requires VAES (Intel Ice Lake+ or AMD Zen 3+)")
	}
	const trials = 256

	for trial := 0; trial < trials; trial++ {
		var keys [4][64]byte
		var inputs [4][32]byte
		for i := 0; i < 4; i++ {
			if _, err := rand.Read(keys[i][:]); err != nil {
				t.Fatalf("rand.Read keys[%d]: %v", i, err)
			}
			if _, err := rand.Read(inputs[i][:]); err != nil {
				t.Fatalf("rand.Read inputs[%d]: %v", i, err)
			}
		}

		// Build state1 / state2 the same way AreionSoEM256x4 does, but
		// run the AVX2 permutation directly instead of dispatching.
		var state1, state2 [4][32]byte
		const domainSepU64 = uint64(0x01)
		for i := 0; i < 4; i++ {
			for j := 0; j < 32; j++ {
				state1[i][j] = inputs[i][j] ^ keys[i][j]
				state2[i][j] = inputs[i][j] ^ keys[i][32+j]
			}
			state2[i][0] ^= byte(domainSepU64)
		}

		areion256Permutex4Avx2Direct(&state1)
		areion256Permutex4Avx2Direct(&state2)

		var batched [4][32]byte
		for i := 0; i < 4; i++ {
			for j := 0; j < 32; j++ {
				batched[i][j] = state1[i][j] ^ state2[i][j]
			}
		}

		for i := 0; i < 4; i++ {
			serial := aes.AreionSoEM256(&keys[i], &inputs[i])
			if batched[i] != serial {
				t.Fatalf("trial %d lane %d: AVX2 batched != serial\n"+
					"batched: %x\nserial:  %x", trial, i, batched[i], serial)
			}
		}
	}
}

// areion512Permutex4Avx2Direct invokes the AVX2+VAES Areion512 assembly
// variant directly, bypassing runtime dispatch. Mirrors
// areion256Permutex4Avx2Direct.
func areion512Permutex4Avx2Direct(states *[4][64]byte) {
	if runtime.GOARCH != "amd64" {
		areion512Permutex4Default(states)
		return
	}
	x0, x1, x2, x3 := pack512x4SoA(states)
	areionasm.Areion512Permutex4Avx2(&x0, &x1, &x2, &x3)
	unpack512x4SoA(&x0, &x1, &x2, &x3, states)
}

// TestAreionSoEM512x4Avx2ParityDirect validates the AVX2 path against
// the serial 512-bit reference. Mirrors the 256-bit Avx2 parity test.
func TestAreionSoEM512x4Avx2ParityDirect(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("AVX2 parity test only runs on amd64")
	}
	if !areionasm.HasVAESAVX2NoAVX512 && !areionasm.HasVAESAVX512 {
		t.Skip("AVX2 parity test requires VAES (Intel Ice Lake+ or AMD Zen 3+)")
	}
	const trials = 256

	for trial := 0; trial < trials; trial++ {
		var keys [4][128]byte
		var inputs [4][64]byte
		for i := 0; i < 4; i++ {
			if _, err := rand.Read(keys[i][:]); err != nil {
				t.Fatalf("rand.Read keys[%d]: %v", i, err)
			}
			if _, err := rand.Read(inputs[i][:]); err != nil {
				t.Fatalf("rand.Read inputs[%d]: %v", i, err)
			}
		}

		var state1, state2 [4][64]byte
		const domainSepU64 = uint64(0x01)
		for i := 0; i < 4; i++ {
			for j := 0; j < 64; j++ {
				state1[i][j] = inputs[i][j] ^ keys[i][j]
				state2[i][j] = inputs[i][j] ^ keys[i][64+j]
			}
			state2[i][0] ^= byte(domainSepU64)
		}

		areion512Permutex4Avx2Direct(&state1)
		areion512Permutex4Avx2Direct(&state2)

		var batched [4][64]byte
		for i := 0; i < 4; i++ {
			for j := 0; j < 64; j++ {
				batched[i][j] = state1[i][j] ^ state2[i][j]
			}
		}

		for i := 0; i < 4; i++ {
			serial := aes.AreionSoEM512(&keys[i], &inputs[i])
			if batched[i] != serial {
				t.Fatalf("trial %d lane %d: AVX2 batched != serial\n"+
					"batched: %x\nserial:  %x", trial, i, batched[i], serial)
			}
		}
	}
}

// areionSoEM256x4Avx2Direct invokes the AVX2 path for benchmarking
// independent of runtime dispatch.
func areionSoEM256x4Avx2Direct(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	var state1, state2 [4][32]byte
	const domainSepU64 = uint64(0x01)
	for i := 0; i < 4; i++ {
		for j := 0; j < 32; j++ {
			state1[i][j] = inputs[i][j] ^ keys[i][j]
			state2[i][j] = inputs[i][j] ^ keys[i][32+j]
		}
		state2[i][0] ^= byte(domainSepU64)
	}
	areion256Permutex4Avx2Direct(&state1)
	areion256Permutex4Avx2Direct(&state2)
	var out [4][32]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 32; j++ {
			out[i][j] = state1[i][j] ^ state2[i][j]
		}
	}
	return out
}

func areionSoEM512x4Avx2Direct(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	var state1, state2 [4][64]byte
	const domainSepU64 = uint64(0x01)
	for i := 0; i < 4; i++ {
		for j := 0; j < 64; j++ {
			state1[i][j] = inputs[i][j] ^ keys[i][j]
			state2[i][j] = inputs[i][j] ^ keys[i][64+j]
		}
		state2[i][0] ^= byte(domainSepU64)
	}
	areion512Permutex4Avx2Direct(&state1)
	areion512Permutex4Avx2Direct(&state2)
	var out [4][64]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 64; j++ {
			out[i][j] = state1[i][j] ^ state2[i][j]
		}
	}
	return out
}

// BenchmarkAreionSoEM256x4_BatchedAvx2 measures the AVX2-path batched
// throughput directly (for hardware without AVX-512 or for comparing
// the two SIMD widths on hardware that has both).
func BenchmarkAreionSoEM256x4_BatchedAvx2(b *testing.B) {
	if runtime.GOARCH != "amd64" {
		b.Skip("AVX2 benchmark only on amd64")
	}
	if !areionasm.HasVAESAVX2NoAVX512 && !areionasm.HasVAESAVX512 {
		b.Skip("AVX2 VAES benchmark requires VAES+AVX2 capability")
	}
	var keys [4][64]byte
	var inputs [4][32]byte
	rand.Read(keys[0][:])
	rand.Read(inputs[0][:])
	rand.Read(keys[1][:])
	rand.Read(inputs[1][:])
	rand.Read(keys[2][:])
	rand.Read(inputs[2][:])
	rand.Read(keys[3][:])
	rand.Read(inputs[3][:])
	b.SetBytes(4 * 32)
	b.ResetTimer()
	var sink [4][32]byte
	for i := 0; i < b.N; i++ {
		out := areionSoEM256x4Avx2Direct(&keys, &inputs)
		for j := 0; j < 4; j++ {
			for k := range sink[j] {
				sink[j][k] ^= out[j][k]
			}
		}
	}
	_ = sink
}

func BenchmarkAreionSoEM512x4_BatchedAvx2(b *testing.B) {
	if runtime.GOARCH != "amd64" {
		b.Skip("AVX2 benchmark only on amd64")
	}
	if !areionasm.HasVAESAVX2NoAVX512 && !areionasm.HasVAESAVX512 {
		b.Skip("AVX2 VAES benchmark requires VAES+AVX2 capability")
	}
	var keys [4][128]byte
	var inputs [4][64]byte
	rand.Read(keys[0][:])
	rand.Read(inputs[0][:])
	rand.Read(keys[1][:])
	rand.Read(inputs[1][:])
	rand.Read(keys[2][:])
	rand.Read(inputs[2][:])
	rand.Read(keys[3][:])
	rand.Read(inputs[3][:])
	b.SetBytes(4 * 64)
	b.ResetTimer()
	var sink [4][64]byte
	for i := 0; i < b.N; i++ {
		out := areionSoEM512x4Avx2Direct(&keys, &inputs)
		for j := 0; j < 4; j++ {
			for k := range sink[j] {
				sink[j][k] ^= out[j][k]
			}
		}
	}
	_ = sink
}

// ─── Pure Go fallback direct-call parity ───────────────────────────────

// TestAreionSoEM256x4PureGoParityDirect verifies that the portable Go
// fallback permutation (`areion256Permutex4Default`) produces bit-exact
// identical output to four serial aes.AreionSoEM256 calls. This guards
// against:
//
//  1. Upstream regressions in github.com/jedisct1/go-aes — if a future
//     minor release subtly changes AreionSoEM256 / AreionSoEM512 in a
//     way our fallback no longer mirrors, this test fails immediately.
//  2. Dispatch fall-through breakage in areion_amd64.go — if a future
//     refactor accidentally stops routing the Default branch, the
//     direct-call test still exercises it.
//
// Runs on every platform (amd64 with or without VAES, ARM64, software
// fallback); the Go path is the universal back-stop and must always
// match the upstream reference.
func TestAreionSoEM256x4PureGoParityDirect(t *testing.T) {
	const trials = 256

	for trial := 0; trial < trials; trial++ {
		var keys [4][64]byte
		var inputs [4][32]byte
		for i := 0; i < 4; i++ {
			if _, err := rand.Read(keys[i][:]); err != nil {
				t.Fatalf("rand.Read keys[%d]: %v", i, err)
			}
			if _, err := rand.Read(inputs[i][:]); err != nil {
				t.Fatalf("rand.Read inputs[%d]: %v", i, err)
			}
		}

		var state1, state2 [4][32]byte
		const domainSepU64 = uint64(0x01)
		for i := 0; i < 4; i++ {
			for j := 0; j < 32; j++ {
				state1[i][j] = inputs[i][j] ^ keys[i][j]
				state2[i][j] = inputs[i][j] ^ keys[i][32+j]
			}
			state2[i][0] ^= byte(domainSepU64)
		}

		areion256Permutex4Default(&state1)
		areion256Permutex4Default(&state2)

		var batched [4][32]byte
		for i := 0; i < 4; i++ {
			for j := 0; j < 32; j++ {
				batched[i][j] = state1[i][j] ^ state2[i][j]
			}
		}

		for i := 0; i < 4; i++ {
			serial := aes.AreionSoEM256(&keys[i], &inputs[i])
			if batched[i] != serial {
				t.Fatalf("trial %d lane %d: PureGo batched != serial\n"+
					"batched: %x\nserial:  %x", trial, i, batched[i], serial)
			}
		}
	}
}

// TestAreionSoEM512x4PureGoParityDirect mirrors the 256-bit Pure Go
// direct parity test for the 512-bit SoEM construction.
func TestAreionSoEM512x4PureGoParityDirect(t *testing.T) {
	const trials = 256

	for trial := 0; trial < trials; trial++ {
		var keys [4][128]byte
		var inputs [4][64]byte
		for i := 0; i < 4; i++ {
			if _, err := rand.Read(keys[i][:]); err != nil {
				t.Fatalf("rand.Read keys[%d]: %v", i, err)
			}
			if _, err := rand.Read(inputs[i][:]); err != nil {
				t.Fatalf("rand.Read inputs[%d]: %v", i, err)
			}
		}

		var state1, state2 [4][64]byte
		const domainSepU64 = uint64(0x01)
		for i := 0; i < 4; i++ {
			for j := 0; j < 64; j++ {
				state1[i][j] = inputs[i][j] ^ keys[i][j]
				state2[i][j] = inputs[i][j] ^ keys[i][64+j]
			}
			state2[i][0] ^= byte(domainSepU64)
		}

		areion512Permutex4Default(&state1)
		areion512Permutex4Default(&state2)

		var batched [4][64]byte
		for i := 0; i < 4; i++ {
			for j := 0; j < 64; j++ {
				batched[i][j] = state1[i][j] ^ state2[i][j]
			}
		}

		for i := 0; i < 4; i++ {
			serial := aes.AreionSoEM512(&keys[i], &inputs[i])
			if batched[i] != serial {
				t.Fatalf("trial %d lane %d: PureGo batched != serial\n"+
					"batched: %x\nserial:  %x", trial, i, batched[i], serial)
			}
		}
	}
}

// ─── Cross-path 3-way parity (AVX-512 vs AVX2 vs Pure Go) ──────────────

// areion256Permutex4Avx512Direct invokes the AVX-512 + VAES assembly
// variant directly, bypassing runtime dispatch. Mirrors the structure
// of areion256Permutex4Avx2Direct. Caller must ensure
// areionasm.HasVAESAVX512 is true (i.e. CPU supports it) before calling
// — direct invocation on hardware without AVX-512 would crash with an
// illegal instruction.
func areion256Permutex4Avx512Direct(states *[4][32]byte) {
	if runtime.GOARCH != "amd64" {
		areion256Permutex4Default(states)
		return
	}
	x0, x1 := pack256x4SoA(states)
	areionasm.Areion256Permutex4(&x0, &x1)
	unpack256x4SoA(&x0, &x1, states)
}

// areion512Permutex4Avx512Direct is the 512-bit counterpart.
func areion512Permutex4Avx512Direct(states *[4][64]byte) {
	if runtime.GOARCH != "amd64" {
		areion512Permutex4Default(states)
		return
	}
	x0, x1, x2, x3 := pack512x4SoA(states)
	areionasm.Areion512Permutex4(&x0, &x1, &x2, &x3)
	unpack512x4SoA(&x0, &x1, &x2, &x3, states)
}

// TestAreion256Permutex4CrossPath verifies that the three implementation
// paths (AVX-512 ZMM, AVX2+VAES YMM, portable Go fallback) produce
// bit-exact identical output on the same input. Stronger guarantee than
// any single-path-vs-serial test: catches drift between paths that
// could otherwise survive if one path were optimised in a way that
// silently broke the bit-exact invariant relied on by ITB's
// BatchHashFunc256 contract.
//
// Skipped if the host lacks AVX-512 (because the AVX-512 ASM cannot be
// invoked safely there). On AVX-512 + VAES hardware all three paths
// run on the same input.
func TestAreion256Permutex4CrossPath(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("Cross-path test requires amd64")
	}
	if !areionasm.HasVAESAVX512 {
		t.Skip("Cross-path test requires VAES + AVX-512 (all three paths runnable)")
	}

	const trials = 256

	for trial := 0; trial < trials; trial++ {
		var initial [4][32]byte
		for i := 0; i < 4; i++ {
			if _, err := rand.Read(initial[i][:]); err != nil {
				t.Fatalf("rand.Read initial[%d]: %v", i, err)
			}
		}

		// AVX-512 path
		a := initial
		areion256Permutex4Avx512Direct(&a)

		// AVX2 path
		b := initial
		areion256Permutex4Avx2Direct(&b)

		// Pure Go fallback path
		c := initial
		areion256Permutex4Default(&c)

		if a != b {
			t.Fatalf("trial %d: AVX-512 vs AVX2 divergence\n"+
				"avx512: %x\navx2:   %x", trial, a, b)
		}
		if b != c {
			t.Fatalf("trial %d: AVX2 vs Pure Go divergence\n"+
				"avx2:   %x\npurego: %x", trial, b, c)
		}
	}
}

// TestAreion512Permutex4CrossPath is the 512-bit counterpart.
func TestAreion512Permutex4CrossPath(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("Cross-path test requires amd64")
	}
	if !areionasm.HasVAESAVX512 {
		t.Skip("Cross-path test requires VAES + AVX-512 (all three paths runnable)")
	}

	const trials = 256

	for trial := 0; trial < trials; trial++ {
		var initial [4][64]byte
		for i := 0; i < 4; i++ {
			if _, err := rand.Read(initial[i][:]); err != nil {
				t.Fatalf("rand.Read initial[%d]: %v", i, err)
			}
		}

		// AVX-512 path
		a := initial
		areion512Permutex4Avx512Direct(&a)

		// AVX2 path
		b := initial
		areion512Permutex4Avx2Direct(&b)

		// Pure Go fallback path
		c := initial
		areion512Permutex4Default(&c)

		if a != b {
			t.Fatalf("trial %d: AVX-512 vs AVX2 divergence\n"+
				"avx512: %x\navx2:   %x", trial, a, b)
		}
		if b != c {
			t.Fatalf("trial %d: AVX2 vs Pure Go divergence\n"+
				"avx2:   %x\npurego: %x", trial, b, c)
		}
	}
}

// TestMakeAreionSoEM256HashRandom exercises MakeAreionSoEM256Hash's
// random-key entry point. The factory generates a fresh 32-byte
// fixed key, builds a (single, batched) hash pair bound to that
// key, and returns the key alongside the pair. The test confirms
// the random-key generator path runs without panic and that a
// parallel pair re-built from the returned key reproduces the
// digest bit-exact via MakeAreionSoEM256HashWithKey.
func TestMakeAreionSoEM256HashRandom(t *testing.T) {
	hRand, bRand, key := MakeAreionSoEM256Hash()
	if hRand == nil || bRand == nil {
		t.Fatalf("MakeAreionSoEM256Hash returned nil hash/batch")
	}
	var allZero [32]byte
	if key == allZero {
		t.Fatalf("MakeAreionSoEM256Hash returned all-zero key (random source failed)")
	}

	// Build a parallel pair from the same key — digests must match.
	hPair, _ := MakeAreionSoEM256HashWithKey(key)

	var seed [4]uint64
	for trial := 0; trial < 8; trial++ {
		var input [64]byte
		if _, err := rand.Read(input[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		got := hRand(input[:], seed)
		want := hPair(input[:], seed)
		if got != want {
			t.Fatalf("trial %d: random-key path digest != WithKey digest\n"+
				"random: %x\nwithkey: %x", trial, got, want)
		}
		var zero [4]uint64
		if got == zero {
			t.Fatalf("trial %d: digest is all-zero (chain-absorb produced no entropy)", trial)
		}
	}
}

// TestMakeAreionSoEM256HashWithKey exercises the explicit-key entry
// point. Two pairs built from the same fixed key must produce
// bit-identical digests; two pairs built from different keys must
// produce different digests on the same input.
func TestMakeAreionSoEM256HashWithKey(t *testing.T) {
	var key1, key2 [32]byte
	if _, err := rand.Read(key1[:]); err != nil {
		t.Fatalf("rand.Read key1: %v", err)
	}
	for {
		if _, err := rand.Read(key2[:]); err != nil {
			t.Fatalf("rand.Read key2: %v", err)
		}
		if key1 != key2 {
			break
		}
	}

	hA, _ := MakeAreionSoEM256HashWithKey(key1)
	hB, _ := MakeAreionSoEM256HashWithKey(key1)
	hC, _ := MakeAreionSoEM256HashWithKey(key2)

	var seed [4]uint64
	for trial := 0; trial < 8; trial++ {
		var input [48]byte
		if _, err := rand.Read(input[:]); err != nil {
			t.Fatalf("rand.Read input: %v", err)
		}
		dA := hA(input[:], seed)
		dB := hB(input[:], seed)
		dC := hC(input[:], seed)
		if dA != dB {
			t.Fatalf("trial %d: same-key pairs produced different digests\n"+
				"A: %x\nB: %x", trial, dA, dB)
		}
		if dA == dC {
			t.Fatalf("trial %d: different-key pairs produced identical digests\n"+
				"key1: %x\nkey2: %x\ndigest: %x", trial, key1, key2, dA)
		}
	}
}

// TestSoftPEXT24SoftPDEP24Roundtrip exercises the portable scalar
// fallbacks for the BMI2 PEXT / PDEP instructions used by the
// Lock Soup hot path. On amd64 hosts with BMI2 the chunk24lock /
// unchunk24lock dispatchers route to locksoupasm.Chunk24Lock /
// Unchunk24Lock, so the soft fallbacks are otherwise unreached
// by the integration tests. Verify the round-trip identity
// softPEXT24(softPDEP24(v, mask), mask) == v across the popcount-8
// mask family used by Lock Soup (each of the three lanes per chunk
// holds exactly 8 bits).
func TestSoftPEXT24SoftPDEP24Roundtrip(t *testing.T) {
	masks := []uint32{
		0x0000FF, // low 8 bits
		0x00FF00, // mid 8 bits
		0xFF0000, // high 8 bits
	}
	var stride3 uint32
	for i := 0; i < 24; i += 3 {
		stride3 |= 1 << uint(i)
	}
	masks = append(masks, stride3) // pop = 8

	for mi, mask := range masks {
		pop := 0
		for i := 0; i < 24; i++ {
			if mask>>uint(i)&1 == 1 {
				pop++
			}
		}
		if pop != 8 {
			continue
		}
		for v := 0; v < 256; v++ {
			b := byte(v)
			expanded := softPDEP24(b, mask)
			recovered := softPEXT24(expanded, mask)
			if recovered != b {
				t.Fatalf("mask[%d]=%06x v=%02x: round-trip failed (expanded=%06x, recovered=%02x)",
					mi, mask, b, expanded, recovered)
			}
		}
	}
}

// TestSoftPermute24Roundtrip exercises the portable scalar fallback
// for the AVX-512 VBMI permute kernel used by the Single Lock Soup
// hot path. softPermute24(x, perm) gathers bit perm[i] of x into
// bit i of the output; applying it again with the inverse permutation
// must round-trip to x for any 24-bit x.
func TestSoftPermute24Roundtrip(t *testing.T) {
	// Build a non-trivial permutation: reverse of identity in the
	// low 24 entries, identity in the slack high 8 entries.
	var perm, invPerm [32]byte
	for i := byte(0); i < 24; i++ {
		perm[i] = 23 - i
	}
	for i := byte(24); i < 32; i++ {
		perm[i] = i
	}
	for i := byte(0); i < 24; i++ {
		invPerm[perm[i]] = i
	}
	for i := byte(24); i < 32; i++ {
		invPerm[i] = i
	}

	for trial := 0; trial < 256; trial++ {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		x := (uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16) & 0xFFFFFF
		permuted := softPermute24(x, &perm)
		recovered := softPermute24(permuted, &invPerm)
		if recovered != x {
			t.Fatalf("trial %d: softPermute24 round-trip failed (x=%06x, permuted=%06x, recovered=%06x)",
				trial, x, permuted, recovered)
		}
	}

	// Identity permutation must produce x unchanged.
	var identity [32]byte
	for i := byte(0); i < 32; i++ {
		identity[i] = i
	}
	for trial := 0; trial < 16; trial++ {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		x := (uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16) & 0xFFFFFF
		if got := softPermute24(x, &identity); got != x {
			t.Fatalf("trial %d: identity softPermute24 changed x: in=%06x out=%06x", trial, x, got)
		}
	}
}
