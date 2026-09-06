//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"math/rand"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// TestAESITB128ChainAbsorb13x16NeonParity verifies that the neon_arm64.s
// 16-lane kernel produces byte-exact output matching the scalar reference
// (scalarBatchX16) across multiple test cases and random seeds.
func TestAESITB128ChainAbsorb13x16NeonParity(t *testing.T) {
	if !aes.CPU.HasARMCrypto {
		t.Skip("ARM crypto extension not available")
	}

	// Save and restore HasARMAESX16 flag for the test
	savedFlag := HasARMAESX16
	defer func() { HasARMAESX16 = savedFlag }()

	HasARMAESX16 = true // Force the neon tier

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
			aesITB128ChainAbsorb13x16NeonAsm(&tc.key, tc.seed0, tc.seed1, base, &asmOut)

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

		var asmOut [16][2]uint64
		aesITB128ChainAbsorb13x16NeonAsm(&key, seed0, seed1, base, &asmOut)

		var scalarOut [16][2]uint64
		scalarBatchX16(&key, base, seed0, seed1, &scalarOut)

		for i := 0; i < 16; i++ {
			if asmOut[i][0] != scalarOut[i][0] || asmOut[i][1] != scalarOut[i][1] {
				t.Errorf("random iter %d base=%#x lane %d: neon %v != scalar %v",
					iter, base, i, asmOut[i], scalarOut[i])
			}
		}
	}
}

// TestAESITB128ChainAbsorb13x16DispatcherParity verifies that the dispatcher
// correctly routes to the appropriate tier (neon on arm64) and produces parity with scalar.
func TestAESITB128ChainAbsorb13x16DispatcherParity(t *testing.T) {
	if !aes.CPU.HasARMCrypto {
		t.Skip("ARM crypto extension not available")
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

	// Test neon tier if available
	if aes.CPU.HasARMCrypto {
		savedFlag := HasARMAESX16
		defer func() { HasARMAESX16 = savedFlag }()
		HasARMAESX16 = true

		var dispOut [16][2]uint64
		AESITB128ChainAbsorb13x16(&key, seed0, seed1, base, &dispOut)

		for i := 0; i < 16; i++ {
			if dispOut[i][0] != scalarOut[i][0] || dispOut[i][1] != scalarOut[i][1] {
				t.Errorf("neon dispatcher lane %d: got %v, want %v",
					i, dispOut[i], scalarOut[i])
			}
		}
	}
}
