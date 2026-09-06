//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"math/rand"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// TestAESITB128ChainAbsorb13x16AesNiParity verifies that the aesni_amd64.s
// 16-lane kernel produces byte-exact output matching the scalar reference
// (scalarBatchX16) across multiple test cases and random seeds.
func TestAESITB128ChainAbsorb13x16AesNiParity(t *testing.T) {
	if !aes.CPU.HasAESNI {
		t.Skip("AES-NI not available")
	}

	// Save and restore HasAESNIX16 flag for the test
	savedFlag := HasAESNIX16
	defer func() { HasAESNIX16 = savedFlag }()

	HasAESNIX16 = true // Force the aesni tier

	// Test cases with known patterns
	testCases := []struct {
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

	for _, tc := range testCases {
		for _, base := range tc.bases {
			// Call the asm function
			var asmOut [16][2]uint64
			aesITB128ChainAbsorb13x16AesNiAsm(&tc.key, tc.seed0, tc.seed1, base, &asmOut)

			// Call the scalar reference
			var scalarOut [16][2]uint64
			scalarBatchX16(&tc.key, base, tc.seed0, tc.seed1, &scalarOut)

			// Compare byte-exact
			for i := 0; i < 16; i++ {
				if asmOut[i][0] != scalarOut[i][0] || asmOut[i][1] != scalarOut[i][1] {
					t.Errorf("%s base=%#x lane %d: asm %v != scalar %v",
						tc.name, base, i, asmOut[i], scalarOut[i])
				}
			}
		}
	}
}

// TestAESITB128ChainAbsorb13x16VexParity verifies that the vex_amd64.s
// kernel produces byte-exact output matching the scalar reference.
func TestAESITB128ChainAbsorb13x16VexParity(t *testing.T) {
	if !aes.CPU.HasAESNI || !aes.CPU.HasAVX2 {
		t.Skip("VEX tier needs AES-NI + AVX2")
	}

	savedAVXFlag := HasAVXAESNIX16
	defer func() { HasAVXAESNIX16 = savedAVXFlag }()

	HasAVXAESNIX16 = true

	// Test cases with known patterns
	testCases := []struct {
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

	for _, tc := range testCases {
		for _, base := range tc.bases {
			var vexOut [16][2]uint64
			AESITB128ChainAbsorb13x16(&tc.key, tc.seed0, tc.seed1, base, &vexOut)

			var scalarOut [16][2]uint64
			scalarBatchX16(&tc.key, base, tc.seed0, tc.seed1, &scalarOut)

			for i := 0; i < 16; i++ {
				if vexOut[i][0] != scalarOut[i][0] || vexOut[i][1] != scalarOut[i][1] {
					t.Errorf("%s base=%#x lane %d: vex %v != scalar %v",
						tc.name, base, i, vexOut[i], scalarOut[i])
				}
			}
		}
	}
}

// TestAESITB128ChainAbsorb13x16VaesAvx2Parity verifies that the vaesavx2_amd64.s
// kernel produces byte-exact output matching the scalar reference.
func TestAESITB128ChainAbsorb13x16VaesAvx2Parity(t *testing.T) {
	if !aes.CPU.HasAESNI || !aes.CPU.HasAVX2 || !aes.CPU.HasVAES {
		t.Skip("VAES AVX2 tier needs AES-NI + AVX2 + VAES")
	}

	savedVAESFlag := HasVAESAVX2X16
	defer func() { HasVAESAVX2X16 = savedVAESFlag }()

	HasVAESAVX2X16 = true

	// Test cases with known patterns
	testCases := []struct {
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

	for _, tc := range testCases {
		for _, base := range tc.bases {
			var vaesOut [16][2]uint64
			AESITB128ChainAbsorb13x16(&tc.key, tc.seed0, tc.seed1, base, &vaesOut)

			var scalarOut [16][2]uint64
			scalarBatchX16(&tc.key, base, tc.seed0, tc.seed1, &scalarOut)

			for i := 0; i < 16; i++ {
				if vaesOut[i][0] != scalarOut[i][0] || vaesOut[i][1] != scalarOut[i][1] {
					t.Errorf("%s base=%#x lane %d: vaes %v != scalar %v",
						tc.name, base, i, vaesOut[i], scalarOut[i])
				}
			}
		}
	}

	// Random coverage: ~64 iterations with fixed seed for reproducibility
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 64; iter++ {
		var key [16]byte
		for j := 0; j < 16; j++ {
			key[j] = byte(rng.Intn(256))
		}
		seed0 := rng.Uint64()
		seed1 := rng.Uint64()
		base := (rng.Uint64() & ^uint64(0xF)) | (1 << 56) // Ensure base is in [2^56, 2^64)

		var vaesOut [16][2]uint64
		AESITB128ChainAbsorb13x16(&key, seed0, seed1, base, &vaesOut)

		var scalarOut [16][2]uint64
		scalarBatchX16(&key, base, seed0, seed1, &scalarOut)

		for i := 0; i < 16; i++ {
			if vaesOut[i][0] != scalarOut[i][0] || vaesOut[i][1] != scalarOut[i][1] {
				t.Errorf("random iter %d base=%#x lane %d: vaes %v != scalar %v",
					iter, base, i, vaesOut[i], scalarOut[i])
			}
		}
	}
}

// TestAESITB128ChainAbsorb13x16VaesAvx512Parity verifies that the avx512_amd64.s
// kernel produces byte-exact output matching the scalar reference.
func TestAESITB128ChainAbsorb13x16VaesAvx512Parity(t *testing.T) {
	if !aes.CPU.HasAESNI || !aes.CPU.HasAVX2 || !aes.CPU.HasVAES || !aes.CPU.HasAVX512 {
		t.Skip("VAES AVX512 tier needs AES-NI + AVX2 + VAES + AVX-512")
	}

	savedAVX512Flag := HasVAESAVX512X16
	defer func() { HasVAESAVX512X16 = savedAVX512Flag }()

	HasVAESAVX512X16 = true

	// Test cases with known patterns
	testCases := []struct {
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

	for _, tc := range testCases {
		for _, base := range tc.bases {
			var avx512Out [16][2]uint64
			AESITB128ChainAbsorb13x16(&tc.key, tc.seed0, tc.seed1, base, &avx512Out)

			var scalarOut [16][2]uint64
			scalarBatchX16(&tc.key, base, tc.seed0, tc.seed1, &scalarOut)

			for i := 0; i < 16; i++ {
				if avx512Out[i][0] != scalarOut[i][0] || avx512Out[i][1] != scalarOut[i][1] {
					t.Errorf("%s base=%#x lane %d: avx512 %v != scalar %v",
						tc.name, base, i, avx512Out[i], scalarOut[i])
				}
			}
		}
	}

	// Random coverage: ~64 iterations with fixed seed for reproducibility
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 64; iter++ {
		var key [16]byte
		for j := 0; j < 16; j++ {
			key[j] = byte(rng.Intn(256))
		}
		seed0 := rng.Uint64()
		seed1 := rng.Uint64()
		base := (rng.Uint64() & ^uint64(0xF)) | (1 << 56)

		var avx512Out [16][2]uint64
		AESITB128ChainAbsorb13x16(&key, seed0, seed1, base, &avx512Out)

		var scalarOut [16][2]uint64
		scalarBatchX16(&key, base, seed0, seed1, &scalarOut)

		for i := 0; i < 16; i++ {
			if avx512Out[i][0] != scalarOut[i][0] || avx512Out[i][1] != scalarOut[i][1] {
				t.Errorf("random iter %d base=%#x lane %d: avx512 %v != scalar %v",
					iter, base, i, avx512Out[i], scalarOut[i])
			}
		}
	}
}

// TestAESITB128ChainAbsorb13x16DispatcherParity verifies that the dispatcher
// correctly routes to the appropriate tier and produces parity with scalar.
func TestAESITB128ChainAbsorb13x16DispatcherParity(t *testing.T) {
	if !aes.CPU.HasAESNI {
		t.Skip("AES-NI not available")
	}

	key := [16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	seed0 := uint64(0x0102030405060708)
	seed1 := uint64(0x090a0b0c0d0e0f00)
	base := uint64(0x1122334455667788)

	var scalarOut [16][2]uint64
	scalarBatchX16(&key, base, seed0, seed1, &scalarOut)

	// Test vaesavx512 tier if available
	if aes.CPU.HasAVX2 && aes.CPU.HasVAES && aes.CPU.HasAVX512 {
		savedAVX512Flag := HasVAESAVX512X16
		defer func() { HasVAESAVX512X16 = savedAVX512Flag }()
		HasVAESAVX512X16 = true

		var dispOut [16][2]uint64
		AESITB128ChainAbsorb13x16(&key, seed0, seed1, base, &dispOut)

		for i := 0; i < 16; i++ {
			if dispOut[i][0] != scalarOut[i][0] || dispOut[i][1] != scalarOut[i][1] {
				t.Errorf("vaesavx512 dispatcher lane %d: got %v, want %v",
					i, dispOut[i], scalarOut[i])
			}
		}
	}

	// Test vaesavx2 tier if available
	if aes.CPU.HasAVX2 && aes.CPU.HasVAES {
		savedVAESFlag := HasVAESAVX2X16
		defer func() { HasVAESAVX2X16 = savedVAESFlag }()
		HasVAESAVX2X16 = true

		var dispOut [16][2]uint64
		AESITB128ChainAbsorb13x16(&key, seed0, seed1, base, &dispOut)

		for i := 0; i < 16; i++ {
			if dispOut[i][0] != scalarOut[i][0] || dispOut[i][1] != scalarOut[i][1] {
				t.Errorf("vaesavx2 dispatcher lane %d: got %v, want %v",
					i, dispOut[i], scalarOut[i])
			}
		}
	}

	// Test vex tier if available
	if aes.CPU.HasAVX2 && !aes.CPU.HasVAES {
		savedAVXFlag := HasAVXAESNIX16
		defer func() { HasAVXAESNIX16 = savedAVXFlag }()
		HasAVXAESNIX16 = true

		var dispOut [16][2]uint64
		AESITB128ChainAbsorb13x16(&key, seed0, seed1, base, &dispOut)

		for i := 0; i < 16; i++ {
			if dispOut[i][0] != scalarOut[i][0] || dispOut[i][1] != scalarOut[i][1] {
				t.Errorf("vex dispatcher lane %d: got %v, want %v",
					i, dispOut[i], scalarOut[i])
			}
		}
	}

	// Test aesni tier if available (when vex is not)
	if !aes.CPU.HasAVX2 {
		savedFlag := HasAESNIX16
		defer func() { HasAESNIX16 = savedFlag }()
		HasAESNIX16 = true

		var dispOut [16][2]uint64
		AESITB128ChainAbsorb13x16(&key, seed0, seed1, base, &dispOut)

		for i := 0; i < 16; i++ {
			if dispOut[i][0] != scalarOut[i][0] || dispOut[i][1] != scalarOut[i][1] {
				t.Errorf("aesni dispatcher lane %d: got %v, want %v",
					i, dispOut[i], scalarOut[i])
			}
		}
	}
}

// TestAESITB128ChainAbsorb13x16CrossTier verifies that all 4 amd64 tiers
// (avx512 / vaesavx2 / vex / aesni) forced via env-var produce byte-identical output.
// This test forces each available tier and records outputs, then asserts equivalence.
func TestAESITB128ChainAbsorb13x16CrossTier(t *testing.T) {
	if !aes.CPU.HasAESNI {
		t.Skip("AES-NI not available")
	}

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

	// Collect outputs from each available tier, organized per test case
	type tierResult struct {
		name   string
		output [16][2]uint64
	}

	// Save current flags
	savedAVX512 := HasVAESAVX512X16
	savedVAES := HasVAESAVX2X16
	savedVEX := HasAVXAESNIX16
	savedAESNI := HasAESNIX16
	defer func() {
		HasVAESAVX512X16 = savedAVX512
		HasVAESAVX2X16 = savedVAES
		HasAVXAESNIX16 = savedVEX
		HasAESNIX16 = savedAESNI
	}()

	// Organize results per test case
	tierResults := make(map[string][]tierResult)

	// Test AVX512 tier if available
	if aes.CPU.HasAVX512 && aes.CPU.HasVAES {
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = true, false, false, false
		for _, tc := range testCases {
			var out [16][2]uint64
			AESITB128ChainAbsorb13x16(&key, tc.seed0, tc.seed1, tc.base, &out)
			tierResults[tc.name] = append(tierResults[tc.name], tierResult{"avx512", out})
		}
	}

	// Test VAES AVX2 tier if available
	if aes.CPU.HasAVX2 && aes.CPU.HasVAES {
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, true, false, false
		for _, tc := range testCases {
			var out [16][2]uint64
			AESITB128ChainAbsorb13x16(&key, tc.seed0, tc.seed1, tc.base, &out)
			tierResults[tc.name] = append(tierResults[tc.name], tierResult{"vaesavx2", out})
		}
	}

	// Test VEX AES-NI tier if available
	if aes.CPU.HasAVX2 && aes.CPU.HasAESNI {
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, true, false
		for _, tc := range testCases {
			var out [16][2]uint64
			AESITB128ChainAbsorb13x16(&key, tc.seed0, tc.seed1, tc.base, &out)
			tierResults[tc.name] = append(tierResults[tc.name], tierResult{"vex", out})
		}
	}

	// Test Legacy AES-NI tier if available
	if aes.CPU.HasAESNI {
		HasVAESAVX512X16, HasVAESAVX2X16, HasAVXAESNIX16, HasAESNIX16 = false, false, false, true
		for _, tc := range testCases {
			var out [16][2]uint64
			AESITB128ChainAbsorb13x16(&key, tc.seed0, tc.seed1, tc.base, &out)
			tierResults[tc.name] = append(tierResults[tc.name], tierResult{"aesni", out})
		}
	}

	// Verify all tiers produce the same output for each test case
	for tcName, results := range tierResults {
		if len(results) > 1 {
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
}