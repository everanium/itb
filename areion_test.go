package itb

import (
	"crypto/rand"
	"runtime"
	"testing"

	"github.com/everanium/itb/internal/areionasm"
	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/third/goaes"
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
	// One output byte per lane keeps the call live without a per-byte
	// loop that would dominate the measured time.
	var sink byte
	for i := 0; i < b.N; i++ {
		out := AreionSoEM256x4(&keys, &inputs)
		sink ^= out[0][0] ^ out[1][0] ^ out[2][0] ^ out[3][0]
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
	// One output byte per lane keeps the call live without a per-byte
	// loop that would dominate the measured time.
	var sink byte
	for i := 0; i < b.N; i++ {
		out := AreionSoEM512x4(&keys, &inputs)
		sink ^= out[0][0] ^ out[1][0] ^ out[2][0] ^ out[3][0]
	}
	_ = sink
}

// ─── Direct-call parity of every tier (regardless of runtime CPU) ──────
//
// The helpers below invoke one assembly tier of the batched permutation
// directly on amd64, bypassing the runtime dispatch, under the constant
// table selected by `second` (false: P1 under areionRC, true: P2 under
// areionRC2). On non-amd64 builds they run the portable Go permutation.

// aesNiKernelsLinked reports whether the XMM AES-NI kernels can be
// invoked directly on this host and build: AES-NI present, and some
// Areion assembly tier linked and armed (every tier flag is false under
// the noitbasm / purego tags and under ITB_FORCE_HASH_TIER=scalar, where
// the areionasm entry points are panic stubs or deliberately disarmed).
func aesNiKernelsLinked() bool {
	return cpuid.AESNI && (areionasm.HasVAESAVX512 || areionasm.HasVAESAVX2NoAVX512 || areionasm.HasAESNIBatched)
}

func areionRCOf(second bool) *[15][16]byte {
	if second {
		return &areionRC2
	}
	return &areionRC
}

// areion256Permutex4Avx2Direct invokes the AVX2+VAES assembly variant.
func areion256Permutex4Avx2Direct(states *[4][32]byte, second bool) {
	if runtime.GOARCH != "amd64" {
		areion256Permutex4Default(states, areionRCOf(second))
		return
	}
	x0, x1 := pack256x4SoA(states)
	if second {
		areionasm.Areion256Permute2x4Avx2(&x0, &x1)
	} else {
		areionasm.Areion256Permutex4Avx2(&x0, &x1)
	}
	unpack256x4SoA(&x0, &x1, states)
}

// areion512Permutex4Avx2Direct invokes the AVX2+VAES Areion512 assembly
// variant directly. Mirrors areion256Permutex4Avx2Direct.
func areion512Permutex4Avx2Direct(states *[4][64]byte, second bool) {
	if runtime.GOARCH != "amd64" {
		areion512Permutex4Default(states, areionRCOf(second))
		return
	}
	x0, x1, x2, x3 := pack512x4SoA(states)
	if second {
		areionasm.Areion512Permute2x4Avx2(&x0, &x1, &x2, &x3)
	} else {
		areionasm.Areion512Permutex4Avx2(&x0, &x1, &x2, &x3)
	}
	unpack512x4SoA(&x0, &x1, &x2, &x3, states)
}

// areion256Permutex4AesNiDirect invokes the legacy-SSE AES-NI XMM
// assembly variant directly.
func areion256Permutex4AesNiDirect(states *[4][32]byte, second bool) {
	if runtime.GOARCH != "amd64" {
		areion256Permutex4Default(states, areionRCOf(second))
		return
	}
	x0, x1 := pack256x4SoA(states)
	if second {
		areionasm.Areion256Permute2x4AesNi(&x0, &x1)
	} else {
		areionasm.Areion256Permutex4AesNi(&x0, &x1)
	}
	unpack256x4SoA(&x0, &x1, states)
}

// areion512Permutex4AesNiDirect is the 512-bit AES-NI counterpart.
func areion512Permutex4AesNiDirect(states *[4][64]byte, second bool) {
	if runtime.GOARCH != "amd64" {
		areion512Permutex4Default(states, areionRCOf(second))
		return
	}
	x0, x1, x2, x3 := pack512x4SoA(states)
	if second {
		areionasm.Areion512Permute2x4AesNi(&x0, &x1, &x2, &x3)
	} else {
		areionasm.Areion512Permutex4AesNi(&x0, &x1, &x2, &x3)
	}
	unpack512x4SoA(&x0, &x1, &x2, &x3, states)
}

// soem256Via composes the SoEM22 PRF of four lanes from a batched
// permutation function: F = P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕ k1 ⊕ k2.
func soem256Via(perm func(*[4][32]byte, bool), keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	var state1, state2 [4][32]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 32; j++ {
			state1[i][j] = inputs[i][j] ^ keys[i][j]
			state2[i][j] = inputs[i][j] ^ keys[i][32+j]
		}
	}
	perm(&state1, false)
	perm(&state2, true)
	var out [4][32]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 32; j++ {
			out[i][j] = state1[i][j] ^ state2[i][j] ^ keys[i][j] ^ keys[i][32+j]
		}
	}
	return out
}

// soem512Via is the 512-bit form of soem256Via.
func soem512Via(perm func(*[4][64]byte, bool), keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	var state1, state2 [4][64]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 64; j++ {
			state1[i][j] = inputs[i][j] ^ keys[i][j]
			state2[i][j] = inputs[i][j] ^ keys[i][64+j]
		}
	}
	perm(&state1, false)
	perm(&state2, true)
	var out [4][64]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 64; j++ {
			out[i][j] = state1[i][j] ^ state2[i][j] ^ keys[i][j] ^ keys[i][64+j]
		}
	}
	return out
}

// checkSoEM256Tier runs trials random (key, input) tuples through the
// SoEM composition over perm and compares every lane with the serial
// aes.AreionSoEM256 reference.
func checkSoEM256Tier(t *testing.T, name string, perm func(*[4][32]byte, bool)) {
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
		batched := soem256Via(perm, &keys, &inputs)
		for i := 0; i < 4; i++ {
			serial := aes.AreionSoEM256(&keys[i], &inputs[i])
			if batched[i] != serial {
				t.Fatalf("trial %d lane %d: %s batched != serial\n"+
					"batched: %x\nserial:  %x", trial, i, name, batched[i], serial)
			}
		}
	}
}

// checkSoEM512Tier is the 512-bit form of checkSoEM256Tier.
func checkSoEM512Tier(t *testing.T, name string, perm func(*[4][64]byte, bool)) {
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
		batched := soem512Via(perm, &keys, &inputs)
		for i := 0; i < 4; i++ {
			serial := aes.AreionSoEM512(&keys[i], &inputs[i])
			if batched[i] != serial {
				t.Fatalf("trial %d lane %d: %s batched != serial\n"+
					"batched: %x\nserial:  %x", trial, i, name, batched[i], serial)
			}
		}
	}
}

// TestAreionSoEM256x4Avx2ParityDirect verifies that the AVX2+VAES
// assembly variants (P1 and P2) compose to bit-exact identical output
// to the serial aes.AreionSoEM256 reference, independent of which path
// runtime dispatch would select. Skipped on non-amd64 builds.
func TestAreionSoEM256x4Avx2ParityDirect(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("AVX2 parity test only runs on amd64")
	}
	if !areionasm.HasVAESAVX2NoAVX512 && !areionasm.HasVAESAVX512 {
		t.Skip("AVX2 parity test requires VAES (Intel Ice Lake+ or AMD Zen 3+)")
	}
	checkSoEM256Tier(t, "AVX2", areion256Permutex4Avx2Direct)
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
	checkSoEM512Tier(t, "AVX2", areion512Permutex4Avx2Direct)
}

// TestAreionSoEM256x4AesNiParityDirect verifies the legacy-SSE AES-NI
// XMM permutation variants (P1 and P2) and the XMM fused SoEM kernel
// against the serial reference on any amd64 host with AES-NI.
func TestAreionSoEM256x4AesNiParityDirect(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("AES-NI parity test only runs on amd64")
	}
	if !aesNiKernelsLinked() {
		t.Skip("AES-NI parity test requires AES-NI and the assembly build")
	}
	checkSoEM256Tier(t, "AES-NI permute", areion256Permutex4AesNiDirect)
	// The fused kernel against the serial reference directly.
	for trial := 0; trial < 64; trial++ {
		var keys [4][64]byte
		var inputs [4][32]byte
		for i := 0; i < 4; i++ {
			rand.Read(keys[i][:])
			rand.Read(inputs[i][:])
		}
		var s1b0, s1b1, s2b0, s2b1 aes.Block4
		for lane := 0; lane < 4; lane++ {
			for j := 0; j < 16; j++ {
				s1b0[lane*16+j] = inputs[lane][j] ^ keys[lane][j]
				s1b1[lane*16+j] = inputs[lane][16+j] ^ keys[lane][16+j]
				s2b0[lane*16+j] = inputs[lane][j] ^ keys[lane][32+j]
				s2b1[lane*16+j] = inputs[lane][16+j] ^ keys[lane][48+j]
			}
		}
		areionasm.Areion256SoEMPermutex4AesNi(&s1b0, &s1b1, &s2b0, &s2b1)
		for lane := 0; lane < 4; lane++ {
			var got [32]byte
			for j := 0; j < 16; j++ {
				got[j] = s1b0[lane*16+j] ^ keys[lane][j] ^ keys[lane][32+j]
				got[16+j] = s1b1[lane*16+j] ^ keys[lane][16+j] ^ keys[lane][48+j]
			}
			if want := aes.AreionSoEM256(&keys[lane], &inputs[lane]); got != want {
				t.Fatalf("trial %d lane %d: AES-NI fused SoEM-256 != serial\ngot:  %x\nwant: %x", trial, lane, got, want)
			}
		}
	}
}

// TestAreionSoEM512x4AesNiParityDirect is the 512-bit counterpart.
func TestAreionSoEM512x4AesNiParityDirect(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("AES-NI parity test only runs on amd64")
	}
	if !aesNiKernelsLinked() {
		t.Skip("AES-NI parity test requires AES-NI and the assembly build")
	}
	checkSoEM512Tier(t, "AES-NI permute", areion512Permutex4AesNiDirect)
	for trial := 0; trial < 64; trial++ {
		var keys [4][128]byte
		var inputs [4][64]byte
		for i := 0; i < 4; i++ {
			rand.Read(keys[i][:])
			rand.Read(inputs[i][:])
		}
		var s1, s2 [4]aes.Block4
		for lane := 0; lane < 4; lane++ {
			for b := 0; b < 4; b++ {
				for j := 0; j < 16; j++ {
					s1[b][lane*16+j] = inputs[lane][16*b+j] ^ keys[lane][16*b+j]
					s2[b][lane*16+j] = inputs[lane][16*b+j] ^ keys[lane][64+16*b+j]
				}
			}
		}
		areionasm.Areion512SoEMPermutex4AesNi(&s1[0], &s1[1], &s1[2], &s1[3], &s2[0], &s2[1], &s2[2], &s2[3])
		for lane := 0; lane < 4; lane++ {
			var got [64]byte
			for b := 0; b < 4; b++ {
				for j := 0; j < 16; j++ {
					got[16*b+j] = s1[b][lane*16+j] ^ keys[lane][16*b+j] ^ keys[lane][64+16*b+j]
				}
			}
			if want := aes.AreionSoEM512(&keys[lane], &inputs[lane]); got != want {
				t.Fatalf("trial %d lane %d: AES-NI fused SoEM-512 != serial\ngot:  %x\nwant: %x", trial, lane, got, want)
			}
		}
	}
}

// areionSoEM256x4Avx2Direct invokes the AVX2 path for benchmarking
// independent of runtime dispatch.
func areionSoEM256x4Avx2Direct(keys *[4][64]byte, inputs *[4][32]byte) [4][32]byte {
	return soem256Via(areion256Permutex4Avx2Direct, keys, inputs)
}

func areionSoEM512x4Avx2Direct(keys *[4][128]byte, inputs *[4][64]byte) [4][64]byte {
	return soem512Via(areion512Permutex4Avx2Direct, keys, inputs)
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
	// The two SoA half-states are built once; each iteration copies them
	// and runs the two YMM permutation kernels the AVX2 dispatcher arm
	// calls, so the timed loop measures the kernels rather than the
	// test-side AoS / SoA packing.
	var t1b0, t1b1, t2b0, t2b1 aes.Block4
	for lane := 0; lane < 4; lane++ {
		for j := 0; j < 16; j++ {
			t1b0[lane*16+j] = inputs[lane][j] ^ keys[lane][j]
			t1b1[lane*16+j] = inputs[lane][16+j] ^ keys[lane][16+j]
			t2b0[lane*16+j] = inputs[lane][j] ^ keys[lane][32+j]
			t2b1[lane*16+j] = inputs[lane][16+j] ^ keys[lane][48+j]
		}
	}
	b.SetBytes(4 * 32)
	b.ResetTimer()
	var sink byte
	for i := 0; i < b.N; i++ {
		s1b0, s1b1, s2b0, s2b1 := t1b0, t1b1, t2b0, t2b1
		areionasm.Areion256Permutex4Avx2(&s1b0, &s1b1)
		areionasm.Areion256Permute2x4Avx2(&s2b0, &s2b1)
		sink ^= s1b0[0] ^ s2b1[0]
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
	// Mirrors the 256-bit form: SoA half-states built once, the two YMM
	// permutation kernels timed.
	var t1, t2 [4]aes.Block4
	for lane := 0; lane < 4; lane++ {
		for blk := 0; blk < 4; blk++ {
			for j := 0; j < 16; j++ {
				t1[blk][lane*16+j] = inputs[lane][16*blk+j] ^ keys[lane][16*blk+j]
				t2[blk][lane*16+j] = inputs[lane][16*blk+j] ^ keys[lane][64+16*blk+j]
			}
		}
	}
	b.SetBytes(4 * 64)
	b.ResetTimer()
	var sink byte
	for i := 0; i < b.N; i++ {
		s1, s2 := t1, t2
		areionasm.Areion512Permutex4Avx2(&s1[0], &s1[1], &s1[2], &s1[3])
		areionasm.Areion512Permute2x4Avx2(&s2[0], &s2[1], &s2[2], &s2[3])
		sink ^= s1[0][0] ^ s2[3][0]
	}
	_ = sink
}

// BenchmarkAreionSoEM256x4_BatchedAesNi measures the XMM AES-NI fused
// SoEM kernel through the batched composition, independent of runtime
// dispatch (on VAES hosts it is the tier the dispatcher does not pick).
func BenchmarkAreionSoEM256x4_BatchedAesNi(b *testing.B) {
	if runtime.GOARCH != "amd64" || !aesNiKernelsLinked() {
		b.Skip("AES-NI benchmark requires amd64 with AES-NI and the assembly build")
	}
	var keys [4][64]byte
	var inputs [4][32]byte
	for i := 0; i < 4; i++ {
		rand.Read(keys[i][:])
		rand.Read(inputs[i][:])
	}
	// The SoA states are built once; each iteration copies them (the
	// kernel overwrites the state1 buffers), so the timed loop measures
	// the kernel rather than a per-byte state assembly.
	var t1b0, t1b1, t2b0, t2b1 aes.Block4
	for lane := 0; lane < 4; lane++ {
		for j := 0; j < 16; j++ {
			t1b0[lane*16+j] = inputs[lane][j] ^ keys[lane][j]
			t1b1[lane*16+j] = inputs[lane][16+j] ^ keys[lane][16+j]
			t2b0[lane*16+j] = inputs[lane][j] ^ keys[lane][32+j]
			t2b1[lane*16+j] = inputs[lane][16+j] ^ keys[lane][48+j]
		}
	}
	b.SetBytes(4 * 32)
	b.ResetTimer()
	var sink byte
	for i := 0; i < b.N; i++ {
		s1b0, s1b1, s2b0, s2b1 := t1b0, t1b1, t2b0, t2b1
		areionasm.Areion256SoEMPermutex4AesNi(&s1b0, &s1b1, &s2b0, &s2b1)
		sink ^= s1b0[0] ^ s1b1[0]
	}
	_ = sink
}

// BenchmarkAreionSoEM512x4_BatchedAesNi is the 512-bit counterpart.
func BenchmarkAreionSoEM512x4_BatchedAesNi(b *testing.B) {
	if runtime.GOARCH != "amd64" || !aesNiKernelsLinked() {
		b.Skip("AES-NI benchmark requires amd64 with AES-NI and the assembly build")
	}
	var keys [4][128]byte
	var inputs [4][64]byte
	for i := 0; i < 4; i++ {
		rand.Read(keys[i][:])
		rand.Read(inputs[i][:])
	}
	// The SoA states are built once; each iteration copies them (the
	// kernel overwrites the state1 buffers), so the timed loop measures
	// the kernel rather than a per-byte state assembly.
	var t1, t2 [4]aes.Block4
	for lane := 0; lane < 4; lane++ {
		for blk := 0; blk < 4; blk++ {
			for j := 0; j < 16; j++ {
				t1[blk][lane*16+j] = inputs[lane][16*blk+j] ^ keys[lane][16*blk+j]
				t2[blk][lane*16+j] = inputs[lane][16*blk+j] ^ keys[lane][64+16*blk+j]
			}
		}
	}
	b.SetBytes(4 * 64)
	b.ResetTimer()
	var sink byte
	for i := 0; i < b.N; i++ {
		s1, s2 := t1, t2
		areionasm.Areion512SoEMPermutex4AesNi(&s1[0], &s1[1], &s1[2], &s1[3], &s2[0], &s2[1], &s2[2], &s2[3])
		sink ^= s1[0][0]
	}
	_ = sink
}

// ─── Pure Go fallback direct-call parity ───────────────────────────────

// TestAreionSoEM256x4PureGoParityDirect verifies that the portable Go
// fallback permutation (`areion256Permutex4Default`, under both constant
// tables) composes to bit-exact identical output to four serial
// aes.AreionSoEM256 calls. This guards against:
//
//  1. Drift between the vendored third/goaes reference and the fallback —
//     if the reference's AreionSoEM256 / AreionSoEM512 changes in a way
//     the fallback no longer mirrors, this test fails immediately.
//  2. Dispatch fall-through breakage in areion_amd64.go — if a future
//     refactor accidentally stops routing the Default branch, the
//     direct-call test still exercises it.
//
// Runs on every platform (amd64 with or without VAES, ARM64, software
// fallback); the Go path is the universal back-stop and must always
// match the reference.
func TestAreionSoEM256x4PureGoParityDirect(t *testing.T) {
	checkSoEM256Tier(t, "PureGo", func(states *[4][32]byte, second bool) {
		areion256Permutex4Default(states, areionRCOf(second))
	})
}

// TestAreionSoEM512x4PureGoParityDirect mirrors the 256-bit Pure Go
// direct parity test for the 512-bit SoEM construction.
func TestAreionSoEM512x4PureGoParityDirect(t *testing.T) {
	checkSoEM512Tier(t, "PureGo", func(states *[4][64]byte, second bool) {
		areion512Permutex4Default(states, areionRCOf(second))
	})
}

// ─── Cross-path parity (AVX-512 vs AVX2 vs AES-NI vs Pure Go) ──────────

// areion256Permutex4Avx512Direct invokes the AVX-512 + VAES assembly
// variant directly, bypassing runtime dispatch. Mirrors the structure
// of areion256Permutex4Avx2Direct. Caller must ensure
// areionasm.HasVAESAVX512 is true (i.e. CPU supports it) before calling
// — direct invocation on hardware without AVX-512 would crash with an
// illegal instruction.
func areion256Permutex4Avx512Direct(states *[4][32]byte, second bool) {
	if runtime.GOARCH != "amd64" {
		areion256Permutex4Default(states, areionRCOf(second))
		return
	}
	x0, x1 := pack256x4SoA(states)
	if second {
		areionasm.Areion256Permute2x4(&x0, &x1)
	} else {
		areionasm.Areion256Permutex4(&x0, &x1)
	}
	unpack256x4SoA(&x0, &x1, states)
}

// areion512Permutex4Avx512Direct is the 512-bit counterpart.
func areion512Permutex4Avx512Direct(states *[4][64]byte, second bool) {
	if runtime.GOARCH != "amd64" {
		areion512Permutex4Default(states, areionRCOf(second))
		return
	}
	x0, x1, x2, x3 := pack512x4SoA(states)
	if second {
		areionasm.Areion512Permute2x4(&x0, &x1, &x2, &x3)
	} else {
		areionasm.Areion512Permutex4(&x0, &x1, &x2, &x3)
	}
	unpack512x4SoA(&x0, &x1, &x2, &x3, states)
}

// TestAreion256Permutex4CrossPath verifies that the four implementation
// paths (AVX-512 ZMM, AVX2+VAES YMM, AES-NI XMM, portable Go fallback)
// produce bit-exact identical output on the same input, under both
// constant tables. Stronger guarantee than any single-path-vs-serial
// test: catches drift between paths that could otherwise survive if one
// path were optimised in a way that silently broke the bit-exact
// invariant relied on by ITB's BatchHashFunc256 contract.
//
// Skipped if the host lacks AVX-512 (because the AVX-512 ASM cannot be
// invoked safely there). On AVX-512 + VAES hardware all four paths run
// on the same input.
func TestAreion256Permutex4CrossPath(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("Cross-path test requires amd64")
	}
	if !areionasm.HasVAESAVX512 {
		t.Skip("Cross-path test requires VAES + AVX-512 (all paths runnable)")
	}

	const trials = 256

	for _, second := range []bool{false, true} {
		for trial := 0; trial < trials; trial++ {
			var initial [4][32]byte
			for i := 0; i < 4; i++ {
				if _, err := rand.Read(initial[i][:]); err != nil {
					t.Fatalf("rand.Read initial[%d]: %v", i, err)
				}
			}

			a := initial
			areion256Permutex4Avx512Direct(&a, second)
			b := initial
			areion256Permutex4Avx2Direct(&b, second)
			c := initial
			areion256Permutex4Default(&c, areionRCOf(second))
			d := initial
			areion256Permutex4AesNiDirect(&d, second)

			if a != b {
				t.Fatalf("P2=%v trial %d: AVX-512 vs AVX2 divergence\n"+
					"avx512: %x\navx2:   %x", second, trial, a, b)
			}
			if b != c {
				t.Fatalf("P2=%v trial %d: AVX2 vs Pure Go divergence\n"+
					"avx2:   %x\npurego: %x", second, trial, b, c)
			}
			if c != d {
				t.Fatalf("P2=%v trial %d: Pure Go vs AES-NI divergence\n"+
					"purego: %x\naesni:  %x", second, trial, c, d)
			}
		}
	}
}

// TestAreion512Permutex4CrossPath is the 512-bit counterpart.
func TestAreion512Permutex4CrossPath(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("Cross-path test requires amd64")
	}
	if !areionasm.HasVAESAVX512 {
		t.Skip("Cross-path test requires VAES + AVX-512 (all paths runnable)")
	}

	const trials = 256

	for _, second := range []bool{false, true} {
		for trial := 0; trial < trials; trial++ {
			var initial [4][64]byte
			for i := 0; i < 4; i++ {
				if _, err := rand.Read(initial[i][:]); err != nil {
					t.Fatalf("rand.Read initial[%d]: %v", i, err)
				}
			}

			a := initial
			areion512Permutex4Avx512Direct(&a, second)
			b := initial
			areion512Permutex4Avx2Direct(&b, second)
			c := initial
			areion512Permutex4Default(&c, areionRCOf(second))
			d := initial
			areion512Permutex4AesNiDirect(&d, second)

			if a != b {
				t.Fatalf("P2=%v trial %d: AVX-512 vs AVX2 divergence\n"+
					"avx512: %x\navx2:   %x", second, trial, a, b)
			}
			if b != c {
				t.Fatalf("P2=%v trial %d: AVX2 vs Pure Go divergence\n"+
					"avx2:   %x\npurego: %x", second, trial, b, c)
			}
			if c != d {
				t.Fatalf("P2=%v trial %d: Pure Go vs AES-NI divergence\n"+
					"purego: %x\naesni:  %x", second, trial, c, d)
			}
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
	if hRand == nil {
		t.Fatalf("MakeAreionSoEM256Hash returned nil scalar hash")
	}
	// bRand may be nil on hosts without any VAES-capable asm path
	// (purego / non-amd64 / no-AESNI / -tags noitbasm builds). This
	// is the documented fall-through contract of MakeAreionSoEM256Hash
	// — the caller drives per-pixel hashing through the scalar arm in
	// that regime. The rest of this test only exercises hRand, so the
	// batched arm's absence is not a defect to fail on.
	_ = bRand
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

// The batched arm of MakeAreionSoEM{256,512}Hash has two routes: the
// single-lane fused cascade kernel per lane (the ITB buf shapes on a
// host with an Areion assembly tier) and the four-way SoEM over the
// batched permutation (every other length, and builds without such a
// tier). Both must reproduce the single arm lane by lane over the
// equal-length lanes ITB feeds; the tests below pin that on every
// build and forced tier, and pin the explicit contract panic on
// unequal lane lengths.

var areionBatchedLens = []int{0, 1, 5, 13, 20, 24, 36, 48, 68, 100}

func areionBatchedData(lens [4]int) (data [4][]byte) {
	for lane := range data {
		buf := make([]byte, lens[lane])
		for i := range buf {
			buf[i] = byte(lane*37 + i*3 + lens[lane])
		}
		data[lane] = buf
	}
	return data
}

func TestAreionBatchedArmMatchesSingle256(t *testing.T) {
	single, batched, _ := MakeAreionSoEM256Hash()
	var seeds [4][4]uint64
	for lane := range seeds {
		for i := range seeds[lane] {
			seeds[lane][i] = uint64(lane*4+i+1) * 0x9E3779B97F4A7C15
		}
	}
	check := func(lens [4]int) {
		data := areionBatchedData(lens)
		got := batched(&data, seeds)
		for lane := range got {
			if want := single(data[lane], seeds[lane]); got[lane] != want {
				t.Errorf("lens %v lane %d: batched %x, single %x", lens, lane, got[lane], want)
			}
		}
	}
	for _, n := range areionBatchedLens {
		check([4]int{n, n, n, n})
	}
	if areionasm.FusedAvailable() {
		data := areionBatchedData([4]int{20, 20, 20, 20})
		if allocs := testing.AllocsPerRun(50, func() { batched(&data, seeds) }); allocs != 0 {
			t.Errorf("fused route allocates: %v allocs/op", allocs)
		}
	}
}

func TestAreionBatchedArmMatchesSingle512(t *testing.T) {
	single, batched, _ := MakeAreionSoEM512Hash()
	var seeds [4][8]uint64
	for lane := range seeds {
		for i := range seeds[lane] {
			seeds[lane][i] = uint64(lane*8+i+1) * 0x9E3779B97F4A7C15
		}
	}
	check := func(lens [4]int) {
		data := areionBatchedData(lens)
		got := batched(&data, seeds)
		for lane := range got {
			if want := single(data[lane], seeds[lane]); got[lane] != want {
				t.Errorf("lens %v lane %d: batched %x, single %x", lens, lane, got[lane], want)
			}
		}
	}
	for _, n := range areionBatchedLens {
		check([4]int{n, n, n, n})
	}
	if areionasm.FusedAvailable() {
		data := areionBatchedData([4]int{20, 20, 20, 20})
		if allocs := testing.AllocsPerRun(50, func() { batched(&data, seeds) }); allocs != 0 {
			t.Errorf("fused route allocates: %v allocs/op", allocs)
		}
	}
}

func TestAreionBatchedArmUnequalLanesPanic(t *testing.T) {
	const want = "areion: batched arm requires equal lane lengths (ITB contract)"
	expectPanic := func(name string, f func()) {
		defer func() {
			if r := recover(); r != want {
				t.Errorf("%s: panic %v, want %q", name, r, want)
			}
		}()
		f()
	}
	data := areionBatchedData([4]int{20, 20, 20, 36})
	_, b256, _ := MakeAreionSoEM256Hash()
	expectPanic("256", func() { b256(&data, [4][4]uint64{}) })
	_, b512, _ := MakeAreionSoEM512Hash()
	expectPanic("512", func() { b512(&data, [4][8]uint64{}) })
}

// ─── Primitive audit: SoEM22 regression tests ──────────────────────────
//
// The checks below pin the properties the project's primitive audit
// requires of the Areion-SoEM round function beyond byte influence:
// no key-shift symmetry, no affinity in the data, no chunk-swap or
// trailing-zero collision in the chain absorb, and every key slot
// secret and effective. They run on the serial reference and on the
// batched arm, so a kernel cannot pass by folding what the reference
// absorbs.

// soemOldDomainSep is the retired domain constant of the single-
// permutation SoEM, kept test-local only to show the retired symmetry
// F(m) = F(m ⊕ k1 ⊕ k2 ⊕ d) is gone.
var soemOldDomainSep = [64]byte{0x01}

// TestAreionSoEMNoKeyShiftSymmetry checks F(m) ≠ F(m ⊕ k1 ⊕ k2) and
// F(m) ≠ F(m ⊕ k1 ⊕ k2 ⊕ d_old) for random keys and inputs, on the
// serial reference and on every lane of the batched arm. A sum of two
// evaluations of one permutation satisfies one of the two equalities
// for every m; SoEM22 with two permutations satisfies neither.
func TestAreionSoEMNoKeyShiftSymmetry(t *testing.T) {
	const trials = 256
	for trial := 0; trial < trials; trial++ {
		var k256 [4][64]byte
		var m256, s256, sd256 [4][32]byte
		var k512 [4][128]byte
		var m512, s512, sd512 [4][64]byte
		for lane := 0; lane < 4; lane++ {
			rand.Read(k256[lane][:])
			rand.Read(m256[lane][:])
			rand.Read(k512[lane][:])
			rand.Read(m512[lane][:])
			for i := 0; i < 32; i++ {
				s256[lane][i] = m256[lane][i] ^ k256[lane][i] ^ k256[lane][32+i]
				sd256[lane][i] = s256[lane][i] ^ soemOldDomainSep[i]
			}
			for i := 0; i < 64; i++ {
				s512[lane][i] = m512[lane][i] ^ k512[lane][i] ^ k512[lane][64+i]
				sd512[lane][i] = s512[lane][i] ^ soemOldDomainSep[i]
			}
		}
		f256, g256, gd256 := AreionSoEM256x4(&k256, &m256), AreionSoEM256x4(&k256, &s256), AreionSoEM256x4(&k256, &sd256)
		f512, g512, gd512 := AreionSoEM512x4(&k512, &m512), AreionSoEM512x4(&k512, &s512), AreionSoEM512x4(&k512, &sd512)
		for lane := 0; lane < 4; lane++ {
			if f256[lane] == g256[lane] || f256[lane] == gd256[lane] {
				t.Fatalf("trial %d lane %d: SoEM-256 key-shift symmetry present (batched)", trial, lane)
			}
			if f512[lane] == g512[lane] || f512[lane] == gd512[lane] {
				t.Fatalf("trial %d lane %d: SoEM-512 key-shift symmetry present (batched)", trial, lane)
			}
			if r := aes.AreionSoEM256(&k256[lane], &m256[lane]); r == aes.AreionSoEM256(&k256[lane], &s256[lane]) || r == aes.AreionSoEM256(&k256[lane], &sd256[lane]) {
				t.Fatalf("trial %d lane %d: SoEM-256 key-shift symmetry present (serial)", trial, lane)
			}
			if r := aes.AreionSoEM512(&k512[lane], &m512[lane]); r == aes.AreionSoEM512(&k512[lane], &s512[lane]) || r == aes.AreionSoEM512(&k512[lane], &sd512[lane]) {
				t.Fatalf("trial %d lane %d: SoEM-512 key-shift symmetry present (serial)", trial, lane)
			}
		}
	}
}

// auditLengths are the input lengths the audit runs at: the ITB per-pixel
// shapes (13 / 20 / 36 / 68), the ctr keystream block shape (24), the
// chunk boundaries of both widths and their neighbours, and a few long
// inputs.
var auditLengths = []int{0, 1, 7, 8, 13, 20, 23, 24, 25, 36, 47, 48, 55, 56, 57, 68, 72, 100, 137}

// xor3 returns a ⊕ b ⊕ c for equal-length slices.
func xor3(a, b, c []byte) []byte {
	out := make([]byte, len(a))
	for i := range out {
		out[i] = a[i] ^ b[i] ^ c[i]
	}
	return out
}

// distinctTriple draws a, b, c of n bytes with a, b, c and a ⊕ b ⊕ c
// pairwise distinct, so the affinity sum cannot vanish by repetition.
func distinctTriple(t *testing.T, n int) (a, b, c, d []byte) {
	for attempt := 0; attempt < 1000; attempt++ {
		a, b, c = randBytes(t, n), randBytes(t, n), randBytes(t, n)
		d = xor3(a, b, c)
		all := []string{string(a), string(b), string(c), string(d)}
		ok := true
		for i := 0; i < 4 && ok; i++ {
			for j := i + 1; j < 4; j++ {
				if all[i] == all[j] {
					ok = false
					break
				}
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("len %d: no distinct triple found", n)
	return
}

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAreionSoEMAffinity is the first-order affinity test
// f(a) ⊕ f(b) ⊕ f(c) ⊕ f(a ⊕ b ⊕ c) ≠ 0 under one key and seed, at every
// audit length, on the single arm and on the batched arm of both widths,
// and on the raw SoEM PRF itself. A construction affine in its data
// (such as XORing the data with a data-independent keystream) makes the
// sum vanish for every triple.
func TestAreionSoEMAffinity(t *testing.T) {
	var fk256 [32]byte
	var fk512 [64]byte
	rand.Read(fk256[:])
	rand.Read(fk512[:])
	h256, b256 := MakeAreionSoEM256HashWithKey(fk256)
	h512, b512 := MakeAreionSoEM512HashWithKey(fk512)
	var seed256 [4]uint64
	var seed512 [8]uint64
	for i := range seed256 {
		seed256[i] = uint64(i)*0x9e3779b97f4a7c15 + 1
	}
	for i := range seed512 {
		seed512[i] = uint64(i)*0x9e3779b97f4a7c15 + 7
	}
	for _, n := range auditLengths {
		if n == 0 {
			continue // a single possible input; the sum vanishes trivially
		}
		for trial := 0; trial < 8; trial++ {
			a, b, c, d := distinctTriple(t, n)
			var sum256 [4]uint64
			var sum512 [8]uint64
			for _, x := range [][]byte{a, b, c, d} {
				o := h256(x, seed256)
				for i := range sum256 {
					sum256[i] ^= o[i]
				}
				p := h512(x, seed512)
				for i := range sum512 {
					sum512[i] ^= p[i]
				}
			}
			if sum256 == [4]uint64{} {
				t.Fatalf("len %d trial %d: Areion-SoEM-256 single arm is affine on this triple", n, trial)
			}
			if sum512 == [8]uint64{} {
				t.Fatalf("len %d trial %d: Areion-SoEM-512 single arm is affine on this triple", n, trial)
			}
			// Batched arm: the four lanes carry a, b, c, a ⊕ b ⊕ c.
			lanes := [4][]byte{a, b, c, d}
			o4 := b256(&lanes, [4][4]uint64{seed256, seed256, seed256, seed256})
			p4 := b512(&lanes, [4][8]uint64{seed512, seed512, seed512, seed512})
			var bs256 [4]uint64
			var bs512 [8]uint64
			for lane := 0; lane < 4; lane++ {
				for i := range bs256 {
					bs256[i] ^= o4[lane][i]
				}
				for i := range bs512 {
					bs512[i] ^= p4[lane][i]
				}
			}
			if bs256 == [4]uint64{} || bs512 == [8]uint64{} {
				t.Fatalf("len %d trial %d: batched arm is affine on this triple", n, trial)
			}
		}
	}
	// The raw PRF, one key.
	var k256 [64]byte
	var k512 [128]byte
	rand.Read(k256[:])
	rand.Read(k512[:])
	for trial := 0; trial < 64; trial++ {
		var a, b, c, d [32]byte
		rand.Read(a[:])
		rand.Read(b[:])
		rand.Read(c[:])
		for i := range d {
			d[i] = a[i] ^ b[i] ^ c[i]
		}
		fa, fb, fc, fd := aes.AreionSoEM256(&k256, &a), aes.AreionSoEM256(&k256, &b), aes.AreionSoEM256(&k256, &c), aes.AreionSoEM256(&k256, &d)
		zero := true
		for i := range fa {
			if fa[i]^fb[i]^fc[i]^fd[i] != 0 {
				zero = false
				break
			}
		}
		if zero {
			t.Fatalf("trial %d: AreionSoEM256 is affine on this triple", trial)
		}
		var a5, b5, c5, d5 [64]byte
		rand.Read(a5[:])
		rand.Read(b5[:])
		rand.Read(c5[:])
		for i := range d5 {
			d5[i] = a5[i] ^ b5[i] ^ c5[i]
		}
		ga, gb, gc, gd := aes.AreionSoEM512(&k512, &a5), aes.AreionSoEM512(&k512, &b5), aes.AreionSoEM512(&k512, &c5), aes.AreionSoEM512(&k512, &d5)
		zero = true
		for i := range ga {
			if ga[i]^gb[i]^gc[i]^gd[i] != 0 {
				zero = false
				break
			}
		}
		if zero {
			t.Fatalf("trial %d: AreionSoEM512 is affine on this triple", trial)
		}
	}
}

// TestAreionSoEMChainCollisions checks the chain absorb for the two
// collision shapes a folding construction exhibits: swapping two absorb
// chunks of a multi-chunk input, and extending an input with trailing
// zero bytes (which the length tag in the first state block must
// separate). Every input bit passes through the full n-bit SoEM state
// (n = 256 / 512, the width of the length-tagged chaining state), so no
// narrower width than the digest itself is involved.
func TestAreionSoEMChainCollisions(t *testing.T) {
	var fk256 [32]byte
	var fk512 [64]byte
	rand.Read(fk256[:])
	rand.Read(fk512[:])
	h256, b256 := MakeAreionSoEM256HashWithKey(fk256)
	h512, b512 := MakeAreionSoEM512HashWithKey(fk512)
	seed256 := [4]uint64{1, 2, 3, 4}
	seed512 := [8]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	same := func(x, y []byte) {
		if h256(x, seed256) == h256(y, seed256) {
			t.Fatalf("Areion-SoEM-256 collision: len %d vs len %d", len(x), len(y))
		}
		if h512(x, seed512) == h512(y, seed512) {
			t.Fatalf("Areion-SoEM-512 collision: len %d vs len %d", len(x), len(y))
		}
		lx := [4][]byte{x, x, x, x}
		ly := [4][]byte{y, y, y, y}
		if b256(&lx, [4][4]uint64{seed256, seed256, seed256, seed256})[0] == b256(&ly, [4][4]uint64{seed256, seed256, seed256, seed256})[0] {
			t.Fatalf("Areion-SoEM-256 batched collision: len %d vs len %d", len(x), len(y))
		}
		if b512(&lx, [4][8]uint64{seed512, seed512, seed512, seed512})[0] == b512(&ly, [4][8]uint64{seed512, seed512, seed512, seed512})[0] {
			t.Fatalf("Areion-SoEM-512 batched collision: len %d vs len %d", len(x), len(y))
		}
	}
	for _, n := range auditLengths {
		x := randBytes(t, n)
		// Trailing-zero extension by 1, 8, 24 and 56 bytes.
		for _, ext := range []int{1, 8, 24, 56} {
			y := append(append([]byte(nil), x...), make([]byte, ext)...)
			same(x, y)
		}
		// Chunk swap at both widths' chunk sizes where the input spans two
		// chunks of that size.
		for _, chunk := range []int{24, 56} {
			if n >= 2*chunk {
				y := append([]byte(nil), x...)
				copy(y[0:chunk], x[chunk:2*chunk])
				copy(y[chunk:2*chunk], x[0:chunk])
				if string(y) == string(x) {
					continue
				}
				same(x, y)
			}
		}
	}
}

// TestAreionSoEMKeySlots lists the key slots of the Areion-SoEM round
// function and checks each is effective: k1 (the fixed key, SoEM's first
// subkey) and k2 (the seed components, SoEM's second subkey). There is no
// third slot — the round constants are the public permutation
// definition, the retired domain constant is gone, and the whitening is
// k1 ⊕ k2 itself. Flipping one bit of either slot changes the output of
// the single and the batched arm; a zero slot in one subkey leaves the
// output dependent on the other.
func TestAreionSoEMKeySlots(t *testing.T) {
	data := randBytes(t, 20)
	var fk [32]byte
	rand.Read(fk[:])
	seed := [4]uint64{11, 22, 33, 44}
	h, _ := MakeAreionSoEM256HashWithKey(fk)
	base := h(data, seed)
	for bit := 0; bit < 256; bit += 37 {
		fk2 := fk
		fk2[bit/8] ^= 1 << (bit % 8)
		h2, _ := MakeAreionSoEM256HashWithKey(fk2)
		if h2(data, seed) == base {
			t.Fatalf("k1 bit %d has no effect", bit)
		}
		s2 := seed
		s2[bit/64] ^= 1 << (bit % 64)
		if h(data, s2) == base {
			t.Fatalf("k2 bit %d has no effect", bit)
		}
	}
	// With k2 = 0 the output still depends on k1 (and vice versa).
	var zk [32]byte
	hz, _ := MakeAreionSoEM256HashWithKey(zk)
	if hz(data, [4]uint64{}) == h(data, [4]uint64{}) {
		t.Fatal("k1 has no effect under the zero seed")
	}
	if hz(data, seed) == hz(data, [4]uint64{}) {
		t.Fatal("k2 has no effect under the zero fixed key")
	}
	// Both subkeys enter the whitening: F(k1‖k2, m) ⊕ F(k1'‖k2, m) is not
	// the constant k1 ⊕ k1' (the permutations, not only the whitening,
	// depend on the key).
	var k1, k1b [64]byte
	var m [32]byte
	rand.Read(k1[:])
	rand.Read(m[:])
	k1b = k1
	k1b[3] ^= 0x80
	fa, fb := aes.AreionSoEM256(&k1, &m), aes.AreionSoEM256(&k1b, &m)
	constant := true
	for i := range fa {
		if fa[i]^fb[i] != k1[i]^k1b[i] {
			constant = false
			break
		}
	}
	if constant {
		t.Fatal("key difference passes straight through the whitening")
	}
}
