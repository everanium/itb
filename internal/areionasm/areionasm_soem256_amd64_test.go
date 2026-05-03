//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"crypto/rand"
	"testing"

	"github.com/jedisct1/go-aes"
)

// TestAreion256SoEMPermutex4Interleaved_Parity verifies that the fused
// kernel produces the same result as the reference path:
//
//	state1 = Areion256Permutex4(s1)
//	state2 = Areion256Permutex4(s2)
//	output = state1 ⊕ state2
//
// against random inputs. A divergence here (round-body copy direction,
// VAESENC operand swap, RC index mismatch, output XOR direction) would
// surface as the fused kernel disagreeing with the per-half kernel on
// at least one of the four lanes / two halves.
func TestAreion256SoEMPermutex4Interleaved_Parity(t *testing.T) {
	if !HasVAESAVX512 {
		t.Skip("requires VAES + AVX-512")
	}

	for trial := 0; trial < 64; trial++ {
		// Random SoA inputs for both half-states.
		var s1b0, s1b1, s2b0, s2b1 aes.Block4
		if _, err := rand.Read(s1b0[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(s1b1[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(s2b0[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(s2b1[:]); err != nil {
			t.Fatal(err)
		}

		// Reference path: two separate permutes + manual XOR.
		var refS1b0, refS1b1, refS2b0, refS2b1 aes.Block4
		refS1b0 = s1b0
		refS1b1 = s1b1
		refS2b0 = s2b0
		refS2b1 = s2b1
		Areion256Permutex4(&refS1b0, &refS1b1)
		Areion256Permutex4(&refS2b0, &refS2b1)
		for i := 0; i < 64; i++ {
			refS1b0[i] ^= refS2b0[i]
			refS1b1[i] ^= refS2b1[i]
		}

		// Fused path: single kernel call.
		gotS1b0 := s1b0
		gotS1b1 := s1b1
		gotS2b0 := s2b0
		gotS2b1 := s2b1
		Areion256SoEMPermutex4Interleaved(&gotS1b0, &gotS1b1, &gotS2b0, &gotS2b1)

		if gotS1b0 != refS1b0 {
			t.Fatalf("trial %d: b0 mismatch\n  got:  %x\n  want: %x", trial, gotS1b0[:], refS1b0[:])
		}
		if gotS1b1 != refS1b1 {
			t.Fatalf("trial %d: b1 mismatch\n  got:  %x\n  want: %x", trial, gotS1b1[:], refS1b1[:])
		}
	}
}

// TestAreion256SoEMPermutex4Interleaved_FixedVector pins the SoA
// fused-kernel result against a deterministic input pair so a future
// silent VAES instruction-selection regression (e.g. swapped VAESENC
// operands resulting in mostly-correct but bit-shifted ciphertext)
// fails fast with a recognisable diff rather than only being caught
// by the random-input parity sweep.
func TestAreion256SoEMPermutex4Interleaved_FixedVector(t *testing.T) {
	if !HasVAESAVX512 {
		t.Skip("requires VAES + AVX-512")
	}

	var s1b0, s1b1, s2b0, s2b1 aes.Block4
	for i := 0; i < 64; i++ {
		s1b0[i] = byte(i)
		s1b1[i] = byte(i + 64)
		s2b0[i] = byte(i + 128)
		s2b1[i] = byte(i + 192)
	}

	// Reference.
	refS1b0 := s1b0
	refS1b1 := s1b1
	refS2b0 := s2b0
	refS2b1 := s2b1
	Areion256Permutex4(&refS1b0, &refS1b1)
	Areion256Permutex4(&refS2b0, &refS2b1)
	for i := 0; i < 64; i++ {
		refS1b0[i] ^= refS2b0[i]
		refS1b1[i] ^= refS2b1[i]
	}

	// Fused.
	Areion256SoEMPermutex4Interleaved(&s1b0, &s1b1, &s2b0, &s2b1)

	if s1b0 != refS1b0 || s1b1 != refS1b1 {
		t.Fatalf("fixed-vector mismatch\n  got b0:  %x\n  want b0: %x\n  got b1:  %x\n  want b1: %x",
			s1b0[:], refS1b0[:], s1b1[:], refS1b1[:])
	}
}
