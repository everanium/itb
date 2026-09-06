//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"math/rand"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// x16Kernel is the batch-16 kernel signature shared by every tier entry
// and the dispatcher.
type x16Kernel func(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)

// x16FixedCases are the fixed (key, seed pair, bases) vectors every
// batch-16 tier is checked on. The bases include the byte-7 → byte-8
// carry of the in-register groupIdx synthesis (0x7FFF…, 0xFEFE…) and
// the uint64 wrap across the 16-lane batch (0xFFFF…).
var x16FixedCases = []struct {
	name         string
	key          [16]byte
	seed0, seed1 uint64
	bases        []uint64
}{
	{
		name:  "zero_key_zero_seeds",
		key:   [16]byte{},
		seed0: 0,
		seed1: 0,
		bases: []uint64{0, 1, 0x100, 0x7FFFFFFFFFFFFFFF},
	},
	{
		name: "ascending_key_distinct_seeds",
		key: [16]byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		},
		seed0: 0x0102030405060708,
		seed1: 0x090a0b0c0d0e0f00,
		bases: []uint64{0, 1, 0x100, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	},
	{
		name: "all_ones_key",
		key: [16]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		},
		seed0: 0xFFFFFFFFFFFFFFFF,
		seed1: 0xFFFFFFFFFFFFFFFF,
		bases: []uint64{0, 1, 0xFEFEFEFEFEFEFEFE},
	},
}

// checkX16Parity pins one batch-16 kernel to the scalar reference
// (scalarBatchX16): the fixed cases, 64 fixed-seed random iterations
// with the base pinned to a multiple of 16 (batch-aligned, as the
// worker loops issue it), and 16 fixed-seed random iterations with a
// fully random base so the byte-7 → byte-8 carry and the uint64 wrap
// fall inside a batch at random lane positions.
func checkX16Parity(t *testing.T, label string, kernel x16Kernel) {
	t.Helper()
	check := func(what string, key *[16]byte, seed0, seed1, base uint64) {
		var got, want [16][2]uint64
		kernel(key, seed0, seed1, base, &got)
		scalarBatchX16(key, base, seed0, seed1, &want)
		for i := 0; i < 16; i++ {
			if got[i] != want[i] {
				t.Errorf("%s %s base=%#x lane %d: %v != scalar %v", label, what, base, i, got[i], want[i])
			}
		}
	}
	for _, tc := range x16FixedCases {
		for _, base := range tc.bases {
			check(tc.name, &tc.key, tc.seed0, tc.seed1, base)
		}
	}
	rng := rand.New(rand.NewSource(1))
	randomKey := func() (key [16]byte) {
		for j := range key {
			key[j] = byte(rng.Intn(256))
		}
		return key
	}
	for iter := 0; iter < 64; iter++ {
		key := randomKey()
		seed0, seed1 := rng.Uint64(), rng.Uint64()
		base := (rng.Uint64() &^ 0xF) | (1 << 56) // batch-aligned, in [2^56, 2^64)
		check("random-aligned", &key, seed0, seed1, base)
	}
	for iter := 0; iter < 16; iter++ {
		key := randomKey()
		seed0, seed1 := rng.Uint64(), rng.Uint64()
		check("random-unaligned", &key, seed0, seed1, rng.Uint64())
	}
}

// TestAESITB128ChainAbsorb13x16AesNiParity pins the legacy-SSE AES-NI
// 16-lane kernel (aesni_amd64.s) to the scalar reference by direct
// call, independent of the dispatch flags.
func TestAESITB128ChainAbsorb13x16AesNiParity(t *testing.T) {
	if !aes.CPU.HasAESNI {
		t.Skip("AES-NI not available")
	}
	checkX16Parity(t, "aesni", aesITB128ChainAbsorb13x16AesNiAsm)
}

// TestAESITB128ChainAbsorb13x16VexParity pins the VEX-encoded AES-NI
// 16-lane kernel (vex_amd64.s) to the scalar reference by direct call.
func TestAESITB128ChainAbsorb13x16VexParity(t *testing.T) {
	if !aes.CPU.HasAESNI || !aes.CPU.HasAVX2 {
		t.Skip("VEX tier needs AES-NI + AVX2")
	}
	checkX16Parity(t, "vex", aesITB128ChainAbsorb13x16VexAsm)
}

// TestAESITB128ChainAbsorb13x16VaesAvx2Parity pins the VAES YMM 16-lane
// kernel (vaesavx2_amd64.s) to the scalar reference by direct call.
func TestAESITB128ChainAbsorb13x16VaesAvx2Parity(t *testing.T) {
	if !aes.CPU.HasVAES || !aes.CPU.HasAVX2 {
		t.Skip("VAES AVX2 tier needs VAES + AVX2")
	}
	checkX16Parity(t, "vaesavx2", aesITB128ChainAbsorb13x16VaesAvx2Asm)
}

// TestAESITB128ChainAbsorb13x16VaesAvx512Parity pins the VAES ZMM
// 16-lane kernel (avx512_amd64.s) to the scalar reference by direct call.
func TestAESITB128ChainAbsorb13x16VaesAvx512Parity(t *testing.T) {
	if !aes.CPU.HasVAES || !aes.CPU.HasAVX512 {
		t.Skip("VAES AVX512 tier needs VAES + AVX-512")
	}
	checkX16Parity(t, "avx512", aesITB128ChainAbsorb13x16VaesAvx512Asm)
}

// x16DispatchTiers lists every batch-16 dispatch state with the flag
// tuple that selects it and the silicon it needs. Each tuple is the
// complete four-flag state, so installing one cannot leave a
// higher-priority flag set from the previous state or from the
// forced-tier init.
var x16DispatchTiers = []struct {
	name                 string
	ok                   func() bool
	zmm, ymm, vex, aesni bool
}{
	{"avx512", func() bool { return aes.CPU.HasVAES && aes.CPU.HasAVX512 }, true, false, false, false},
	{"vaesavx2", func() bool { return aes.CPU.HasVAES && aes.CPU.HasAVX2 }, false, true, false, false},
	{"vex", func() bool { return aes.CPU.HasAESNI && aes.CPU.HasAVX2 }, false, false, true, false},
	{"aesni", func() bool { return aes.CPU.HasAESNI }, false, false, false, true},
	{"scalar", func() bool { return true }, false, false, false, false},
}

// saveX16Flags snapshots the four batch-16 dispatch flags and registers
// a Cleanup that restores them.
func saveX16Flags(t *testing.T) {
	t.Helper()
	zmm, ymm, vex, aesni := HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16
	t.Cleanup(func() {
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = zmm, ymm, vex, aesni
	})
}

// TestAESITB128ChainAbsorb13x16DispatcherParity installs each dispatch
// state the host can execute — all four flags set atomically per tier —
// and pins the dispatcher's output to the scalar reference on the fixed
// cases. The scalar state verifies the default arm.
func TestAESITB128ChainAbsorb13x16DispatcherParity(t *testing.T) {
	saveX16Flags(t)
	for _, tier := range x16DispatchTiers {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok() {
				t.Skipf("%s tier not executable on this host", tier.name)
			}
			HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = tier.zmm, tier.ymm, tier.vex, tier.aesni
			for _, tc := range x16FixedCases {
				for _, base := range tc.bases {
					var got, want [16][2]uint64
					AESITB128ChainAbsorb13x16(&tc.key, tc.seed0, tc.seed1, base, &got)
					scalarBatchX16(&tc.key, base, tc.seed0, tc.seed1, &want)
					for i := 0; i < 16; i++ {
						if got[i] != want[i] {
							t.Errorf("%s %s base=%#x lane %d: dispatcher %v != scalar %v",
								tier.name, tc.name, base, i, got[i], want[i])
						}
					}
				}
			}
		})
	}
}

// TestAESITB128ChainAbsorb13x16CrossTier installs every dispatch state
// the host can execute in turn and requires all of them to produce
// byte-identical output on the same inputs — the assembly tiers agree
// with each other, not only with the reference.
func TestAESITB128ChainAbsorb13x16CrossTier(t *testing.T) {
	if !aes.CPU.HasAESNI {
		t.Skip("AES-NI not available")
	}
	saveX16Flags(t)

	key := [16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	testCases := []struct {
		name  string
		base  uint64
		seed0 uint64
		seed1 uint64
	}{
		{"zero", 0, 0, 0},
		{"ascending", 0, 0x0102030405060708, 0x090a0b0c0d0e0f00},
		{"large", 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	}

	type tierResult struct {
		name   string
		output [16][2]uint64
	}
	tierResults := make(map[string][]tierResult)
	for _, tier := range x16DispatchTiers {
		if !tier.ok() {
			continue
		}
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = tier.zmm, tier.ymm, tier.vex, tier.aesni
		for _, tc := range testCases {
			var out [16][2]uint64
			AESITB128ChainAbsorb13x16(&key, tc.seed0, tc.seed1, tc.base, &out)
			tierResults[tc.name] = append(tierResults[tc.name], tierResult{tier.name, out})
		}
	}

	for tcName, results := range tierResults {
		baseline := results[0]
		for _, result := range results[1:] {
			for j := 0; j < 16; j++ {
				if result.output[j] != baseline.output[j] {
					t.Errorf("test case %s: %s lane %d mismatch: got %v, want %v (from %s)",
						tcName, result.name, j, result.output[j], baseline.output[j], baseline.name)
				}
			}
		}
	}
}
