//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"crypto/rand"
	"testing"

	"github.com/jedisct1/go-aes"
)

// TestAreion512SoEMPermutex4Interleaved_Parity verifies that the fused
// 512-bit kernel produces the same result as the reference path:
//
//	state1 = Areion512Permutex4(s1)
//	state2 = Areion512Permutex4(s2)
//	output = state1 ⊕ state2
//
// across random inputs. Tests round-body correctness, the
// interleaved-rotation semantics (each round's (a,b,c,d) shift), and
// the final cyclic rotation fused into the SoEM XOR pattern.
func TestAreion512SoEMPermutex4Interleaved_Parity(t *testing.T) {
	if !HasVAESAVX512 {
		t.Skip("requires VAES + AVX-512")
	}

	for trial := 0; trial < 64; trial++ {
		var a1, b1, c1, d1, a2, b2, c2, d2 aes.Block4
		if _, err := rand.Read(a1[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(b1[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(c1[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(d1[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(a2[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(b2[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(c2[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(d2[:]); err != nil {
			t.Fatal(err)
		}

		// Reference: two separate permutes + manual XOR.
		refA1, refB1, refC1, refD1 := a1, b1, c1, d1
		refA2, refB2, refC2, refD2 := a2, b2, c2, d2
		Areion512Permutex4(&refA1, &refB1, &refC1, &refD1)
		Areion512Permutex4(&refA2, &refB2, &refC2, &refD2)
		for i := 0; i < 64; i++ {
			refA1[i] ^= refA2[i]
			refB1[i] ^= refB2[i]
			refC1[i] ^= refC2[i]
			refD1[i] ^= refD2[i]
		}

		// Fused.
		gotA1, gotB1, gotC1, gotD1 := a1, b1, c1, d1
		gotA2, gotB2, gotC2, gotD2 := a2, b2, c2, d2
		Areion512SoEMPermutex4Interleaved(&gotA1, &gotB1, &gotC1, &gotD1, &gotA2, &gotB2, &gotC2, &gotD2)

		if gotA1 != refA1 {
			t.Fatalf("trial %d: a1 mismatch\n  got:  %x\n  want: %x", trial, gotA1[:], refA1[:])
		}
		if gotB1 != refB1 {
			t.Fatalf("trial %d: b1 mismatch\n  got:  %x\n  want: %x", trial, gotB1[:], refB1[:])
		}
		if gotC1 != refC1 {
			t.Fatalf("trial %d: c1 mismatch\n  got:  %x\n  want: %x", trial, gotC1[:], refC1[:])
		}
		if gotD1 != refD1 {
			t.Fatalf("trial %d: d1 mismatch\n  got:  %x\n  want: %x", trial, gotD1[:], refD1[:])
		}
	}
}

// BenchmarkAreion512SoEM_TwoCallsPlusXor measures the baseline cost
// of the two-call + XOR-loop path the fused kernel replaces.
func BenchmarkAreion512SoEM_TwoCallsPlusXor(b *testing.B) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var a1, b1_, c1, d1, a2, b2_, c2, d2 aes.Block4
	for i := 0; i < 64; i++ {
		a1[i] = byte(i)
		b1_[i] = byte(i + 64)
		c1[i] = byte(i + 128)
		d1[i] = byte(i + 192)
		a2[i] = byte(i + 32)
		b2_[i] = byte(i + 96)
		c2[i] = byte(i + 160)
		d2[i] = byte(i + 224)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion512Permutex4(&a1, &b1_, &c1, &d1)
		Areion512Permutex4(&a2, &b2_, &c2, &d2)
		for j := 0; j < 64; j++ {
			a1[j] ^= a2[j]
			b1_[j] ^= b2_[j]
			c1[j] ^= c2[j]
			d1[j] ^= d2[j]
		}
	}
}

// BenchmarkAreion512SoEM_FusedKernel measures the fused VAES kernel.
func BenchmarkAreion512SoEM_FusedKernel(b *testing.B) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var a1, b1_, c1, d1, a2, b2_, c2, d2 aes.Block4
	for i := 0; i < 64; i++ {
		a1[i] = byte(i)
		b1_[i] = byte(i + 64)
		c1[i] = byte(i + 128)
		d1[i] = byte(i + 192)
		a2[i] = byte(i + 32)
		b2_[i] = byte(i + 96)
		c2[i] = byte(i + 160)
		d2[i] = byte(i + 224)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion512SoEMPermutex4Interleaved(&a1, &b1_, &c1, &d1, &a2, &b2_, &c2, &d2)
	}
}
