//go:build amd64 && !purego && !noitbasm

package blake2basm

import (
	"crypto/rand"
	"testing"
)

// TestBlake2b512ChainAbsorb13x4 verifies the Interlocked Barrier PRF
// fill kernel matches the BLAKE2b-512 reference at the 13-byte shape.
func TestBlake2b512ChainAbsorb13x4(t *testing.T) {
	runChainAbsorb512Test(t, "Blake2b512ChainAbsorb13x4", 13, Blake2b512ChainAbsorb13x4)
}

// TestScalarBatch512ChainAbsorb13_Parity verifies the scalar 4-lane
// fallback at the 13-byte shape.
func TestScalarBatch512ChainAbsorb13_Parity(t *testing.T) {
	runScalarBatch512Test(t, "scalarBatch512ChainAbsorb13", 13, scalarBatch512ChainAbsorb13)
}

// TestBlake2b512ChainAbsorb13x4_BitSensitivity flips each of the 104
// bits of the 13-byte input (per lane) and requires that lane's
// digest to change.
func TestBlake2b512ChainAbsorb13x4_BitSensitivity(t *testing.T) {
	if !HasAVX512Fused {
		t.Skip("requires AVX-512 fused path")
	}
	var b2key [64]byte
	if _, err := rand.Read(b2key[:]); err != nil {
		t.Fatal(err)
	}
	var seeds [4][8]uint64
	for lane := 0; lane < 4; lane++ {
		var sb [64]byte
		if _, err := rand.Read(sb[:]); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			for b := 0; b < 8; b++ {
				seeds[lane][i] |= uint64(sb[i*8+b]) << (8 * b)
			}
		}
	}
	base := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		base[i] = make([]byte, 13)
		if _, err := rand.Read(base[i]); err != nil {
			t.Fatal(err)
		}
	}
	run := func(d [][]byte) [4][8]uint64 {
		var dp [4]*byte
		for i := 0; i < 4; i++ {
			dp[i] = &d[i][0]
		}
		var out [4][8]uint64
		Blake2b512ChainAbsorb13x4(&Blake2bIV512Param, &b2key, &seeds, &dp, &out)
		return out
	}
	baseOut := run(base)
	for lane := 0; lane < 4; lane++ {
		for bit := 0; bit < 13*8; bit++ {
			flipped := make([][]byte, 4)
			for i := 0; i < 4; i++ {
				flipped[i] = append([]byte(nil), base[i]...)
			}
			flipped[lane][bit/8] ^= 1 << (bit % 8)
			out := run(flipped)
			if out[lane] == baseOut[lane] {
				t.Fatalf("lane %d bit %d flip produced identical digest", lane, bit)
			}
		}
	}
}

func benchB2b512Chain13(b *testing.B, fused bool) {
	if !HasAVX512Fused {
		b.Skip("requires AVX-512 fused path")
	}
	var b2key [64]byte
	var seeds [4][8]uint64
	for i := range b2key {
		b2key[i] = byte(i)
	}
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 8; i++ {
			seeds[lane][i] = uint64(lane*8+i) + 0xCAFEBABE
		}
	}
	bufs, ptrs := makeLaneData512(13)
	var out [4][8]uint64
	b.ResetTimer()
	if fused {
		for i := 0; i < b.N; i++ {
			Blake2b512ChainAbsorb13x4(&Blake2bIV512Param, &b2key, &seeds, &ptrs, &out)
		}
	} else {
		for i := 0; i < b.N; i++ {
			for lane := 0; lane < 4; lane++ {
				_ = runReferenceClosure512(b2key, bufs[lane], seeds[lane])
			}
		}
	}
}

func BenchmarkBlake2b512ChainAbsorb13x4_Reference(b *testing.B) { benchB2b512Chain13(b, false) }
func BenchmarkBlake2b512ChainAbsorb13x4_Fused(b *testing.B)     { benchB2b512Chain13(b, true) }
